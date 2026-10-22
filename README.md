# AI-Powered Log Analyzer
Final Year Project — ML-based anomaly detection for system logs.

## Run the demo dashboard
```powershell
cd D:\Projects\FYP
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app/dashboard.py
```
It opens at http://localhost:8501 and analyzes `data/loghub-master/OpenSSH/OpenSSH_2k.log` by default. Upload another OpenSSH log from the sidebar.

## Project structure
- `src/parser.py` — turns raw OpenSSH lines into a table (time, event, user, IP)
- `src/detect.py` — per-IP features, Isolation Forest score, risk level, explanations, framework mapping, BGL evaluation
- `app/dashboard.py` — Streamlit dashboard (Overview, Alerts, Models, Compliance)

## Data
Not stored in Git. Download Loghub (https://github.com/logpai/loghub) into `data/loghub-master/`.
