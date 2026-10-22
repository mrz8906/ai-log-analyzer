"""Phase 2: turn raw OpenSSH log lines into a structured table."""
import re
import pandas as pd

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)
IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

# (event name, pattern that pulls out the username if there is one)
EVENT_RULES = [
    ("failed_password", re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from")),
    ("accepted_login", re.compile(r"Accepted password for (?P<user>\S+) from")),
    ("invalid_user", re.compile(r"^Invalid user (?P<user>\S*) from")),
    ("break_in_warning", re.compile(r"POSSIBLE BREAK-IN ATTEMPT")),
    ("auth_failure", re.compile(r"authentication failure")),
    ("too_many_failures", re.compile(r"Too many authentication failures|maximum authentication attempts")),
    ("disconnect", re.compile(r"Received disconnect|Connection closed")),
]


def classify(message):
    for name, rx in EVENT_RULES:
        m = rx.search(message)
        if m:
            user = m.groupdict().get("user")
            return name, (user or None)
    return "other", None


def parse_openssh(lines, year=2017):
    """lines: iterable of strings. Returns one row per log line that matches."""
    rows = []
    for raw in lines:
        m = LINE_RE.match(raw.strip())
        if not m:
            continue
        d = m.groupdict()
        event, user = classify(d["message"])
        ip = IP_RE.search(d["message"])
        rows.append({
            "timestamp": pd.to_datetime(f"{year} {d['month']} {d['day']} {d['time']}", format="%Y %b %d %H:%M:%S"),
            "pid": int(d["pid"]),
            "event": event,
            "user": user,
            "ip": ip.group(1) if ip else None,
            "message": d["message"],
        })
    return pd.DataFrame(rows)


def parse_file(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return parse_openssh(f)
