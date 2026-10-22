"""Phases 3-5: features per IP, anomaly detection, risk scoring and explanations."""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.metrics import precision_recall_fscore_support
import time

FEATURES = ["failed", "invalid", "unique_users", "rate_per_min", "break_in", "duration_min", "root_share"]


# ---------- Phase 3: features ----------
def ip_features(df):
    """One row per source IP describing how it behaved."""
    df = df[df["ip"].notna()]
    rows = []
    for ip, g in df.groupby("ip"):
        fails = g[g["event"] == "failed_password"]
        if len(fails) >= 2:
            span = (fails["timestamp"].max() - fails["timestamp"].min()).total_seconds() / 60
        else:
            span = 0.0
        users = fails["user"].dropna()
        rows.append({
            "ip": ip,
            "events": len(g),
            "failed": len(fails),
            "invalid": int((g["event"] == "invalid_user").sum()),
            "unique_users": users.nunique(),
            "duration_min": round(span, 1),
            "rate_per_min": round(len(fails) / max(span, 1.0), 1),
            "break_in": int((g["event"] == "break_in_warning").sum()),
            "accepted": int((g["event"] == "accepted_login").sum()),
            "root_share": round((users == "root").mean(), 2) if len(users) else 0.0,
            "top_user": users.value_counts().index[0] if len(users) else None,
            "top_user_n": int(users.value_counts().iloc[0]) if len(users) else 0,
            "first_seen": g["timestamp"].min(),
            "last_seen": g["timestamp"].max(),
        })
    return pd.DataFrame(rows)


# ---------- Phase 4: ML anomaly score ----------
def ml_scores(feat):
    """Isolation Forest score per IP, scaled to 0 (normal) .. 1 (most unusual)."""
    X = np.log1p(feat[FEATURES].astype(float).values)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
    raw = -model.score_samples(X)
    return (raw - raw.min()) / (raw.max() - raw.min() + 1e-9)


# ---------- Phase 5: risk + explanation ----------
def risk_level(r):
    if r["failed"] >= 20 and r["rate_per_min"] >= 10:
        return "High"
    if (r["failed"] >= 15 and r["rate_per_min"] >= 3) or (r["unique_users"] >= 10 and r["failed"] >= 20):
        return "Medium"
    if r["ml_score"] >= 0.75 and r["failed"] >= 10:
        return "Medium"
    if r["failed"] >= 5:
        return "Low"
    return None


def simple_rule_flags(r):
    """What a classic fixed-threshold tool (fail2ban style) would catch."""
    return r["failed"] >= 20 and r["rate_per_min"] >= 10


def mapping(technique):
    tags = [("MITRE", technique)]
    if technique.startswith("T1110"):
        tags += [("OWASP", "A07 Identification & Authentication Failures"),
                 ("CIS", "Control 6 Access Control Management"),
                 ("ISO 27001", "A.8.16 Monitoring activities")]
    else:
        tags += [("CIS", "Control 6 Access Control Management"), ("ISO 27001", "A.8.15 Logging")]
    tags.append(("CIS", "Control 8 Audit Log Management"))
    return tags


def explain(r, typical_fails):
    why = []
    why.append(f"{r['failed']} failed logins at {r['rate_per_min']} per minute. "
               f"A typical IP in this file made {typical_fails:g}.")
    if r["unique_users"] >= 5:
        why.append(f"Tried {r['unique_users']} different usernames, a sign of password spraying.")
    elif r["top_user"]:
        why.append(f"{r['top_user_n']} of {r['failed']} attempts targeted '{r['top_user']}'.")
    if r["break_in"]:
        why.append(f"Server raised {r['break_in']} 'POSSIBLE BREAK-IN ATTEMPT' warnings for this address.")
    if not r["rule_hit"] and r["ml_score"] >= 0.6:
        why.append("Too slow for a fixed 10-per-minute rule, but the ML model rated its behavior unusual.")
    return why


def summary(r):
    kind = "password spraying (many usernames)" if r["unique_users"] >= 5 else f"password guessing against '{r['top_user']}'"
    return (f"{r['ip']} made {r['failed']} failed login attempts over {r['duration_min']} minutes, "
            f"which looks like {kind}. Recommended action: block this IP and make sure root login over SSH is disabled.")


def build_alerts(df):
    feat = ip_features(df)
    feat["ml_score"] = ml_scores(feat).round(2)
    feat["rule_hit"] = feat.apply(simple_rule_flags, axis=1)
    feat["risk"] = feat.apply(risk_level, axis=1)
    typical = float(feat["failed"].median())

    alerts = []
    for _, r in feat[feat["risk"].notna()].iterrows():
        tech = "T1110.003 Password Spraying" if r["unique_users"] >= 5 else "T1110.001 Password Guessing"
        alerts.append({
            "risk": r["risk"], "ip": r["ip"], "ml_score": r["ml_score"],
            "title": f"{r['failed']} failed logins in {r['duration_min']} min, {r['unique_users']} username(s)",
            "first_seen": r["first_seen"], "last_seen": r["last_seen"],
            "technique": tech, "rule_hit": bool(r["rule_hit"]),
            "why": explain(r, typical), "summary": summary(r), "tags": mapping(tech),
            "stats": {"Failed logins": r["failed"], "Rate / min": r["rate_per_min"],
                      "Usernames tried": r["unique_users"], "Duration (min)": r["duration_min"]},
        })

    # successful login shortly after an attack = worth a look
    attack_ends = feat[feat["risk"].isin(["High", "Medium"])]["last_seen"]
    for _, a in df[df["event"] == "accepted_login"].iterrows():
        recent = attack_ends[(attack_ends <= a["timestamp"]) &
                             (attack_ends >= a["timestamp"] - pd.Timedelta(minutes=30))]
        if len(recent):
            alerts.append({
                "risk": "Medium", "ip": a["ip"], "ml_score": None,
                "title": f"Successful login for '{a['user']}' right after an attack",
                "first_seen": a["timestamp"], "last_seen": a["timestamp"],
                "technique": "T1078 Valid Accounts", "rule_hit": False,
                "why": [f"Login succeeded at {a['timestamp']:%H:%M}, within 30 minutes of {len(recent)} attack(s).",
                        "Could be the real user, or an attacker who guessed the password."],
                "summary": f"User '{a['user']}' logged in from {a['ip']} just after a password attack. Confirm with the user that it was them.",
                "tags": mapping("T1078 Valid Accounts"),
                "stats": {"User": a["user"], "Time": f"{a['timestamp']:%H:%M:%S}", "Nearby attacks": len(recent), "Successful logins": 1},
            })

    order = {"High": 0, "Medium": 1, "Low": 2}
    alerts.sort(key=lambda a: (order[a["risk"]], -(a["ml_score"] or 0)))
    for i, a in enumerate(alerts, 1):
        a["id"] = f"A-{i:02d}"
    return feat, alerts


# ---------- Phase 7: evaluation on the labeled BGL sample ----------
def evaluate_bgl(csv_path, window=20):
    b = pd.read_csv(csv_path)
    b["win"] = np.arange(len(b)) // window
    X = np.log1p(pd.crosstab(b["win"], b["EventId"]).values)
    y = b.groupby("win")["Label"].apply(lambda s: (s != "-").any()).values
    rate = y.mean()

    models = {
        "Isolation Forest": lambda: IsolationForest(n_estimators=200, contamination=rate, random_state=42).fit_predict(X),
        "Local Outlier Factor": lambda: LocalOutlierFactor(n_neighbors=20, contamination=rate).fit_predict(X),
        "One-Class SVM": lambda: OneClassSVM(nu=rate, gamma="scale").fit_predict(X),
    }
    rows = []
    for name, fn in models.items():
        t = time.perf_counter()
        pred = fn() == -1
        sec = time.perf_counter() - t
        p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        rows.append({"Model": name, "Precision": p, "Recall": r, "F1": f, "Time (s)": sec})
    rule = b.groupby("win")["Level"].apply(lambda s: s.isin(["FATAL", "SEVERE"]).any()).values
    p, r, f, _ = precision_recall_fscore_support(y, rule, average="binary", zero_division=0)
    rows.append({"Model": "Rule baseline (FATAL/SEVERE)", "Precision": p, "Recall": r, "F1": f, "Time (s)": 0.0})
    labels = b.loc[b["Label"] != "-", "Label"].value_counts()
    return pd.DataFrame(rows), labels, {"lines": len(b), "anomalies": int((b["Label"] != "-").sum()),
                                         "windows": len(y), "bad_windows": int(y.sum()), "window": window}
