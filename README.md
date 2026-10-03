# Cybersecurity Awareness & Threat Intelligence Dashboard

Defensive, offline-first student project implementing synthetic threat intelligence, IOC validation, risk/confidence scoring, local enrichment/search, alerts, SQLite storage, SOC dashboard, awareness modules and a 33-question quiz.

## Windows
```powershell
py -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python generate_data.py
python app.py
```
Open http://127.0.0.1:5000

## Tests
```powershell
pytest -q
```

Safe demo indicators include `192.0.2.25`, `example.com`, and `CVE-2026-1234`. They are used as data only; the application never contacts them.

This project does not scan, exploit, execute files, visit suspicious URLs, or provide malware/phishing functionality.
