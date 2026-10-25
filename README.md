# LogGuard Mini-SIEM

LogGuard is a small Python project that looks through authentication logs and helps spot login activity that may deserve a closer look. I built it as a practical way to explore a few CEH-related topics, including failed-login analysis, brute-force indicators, basic incident investigation, and security reporting.

The project is intended for learning and demonstration. It does not try passwords, connect to other machines, or automatically block IP addresses.

## What it can do

- Read common Linux OpenSSH authentication log entries.
- Import events from a CSV file.
- Count failed logins by IP address and username.
- Flag repeated failures within a time window.
- Highlight cases where one IP appears to target several usernames.
- Flag a successful login when recent failures for the same username and IP came before it.
- Show event trends and summaries in a Streamlit dashboard.
- Export normalized events and alerts as CSV or JSON.

These detections are indicators, not proof that an attack happened. For example, a user who forgets a password several times or a shared network address can produce activity that looks suspicious.

## Tools used

- **Python** for the application and detection logic
- **Streamlit** for the dashboard
- **Pandas** for working with log data
- **Matplotlib** for charts
- **Regular expressions** for parsing common OpenSSH log messages
- **Pytest** for basic automated tests

## Project files

```text
logguard_siem/
├── app.py                  # Streamlit dashboard
├── logguard.py             # Log parsing and alert rules
├── requirements.txt        # Python dependencies
├── README.md
├── data/
│   ├── sample_auth.log     # Example Linux SSH log
│   └── sample_events.csv   # Example normalized events
└── tests/
    └── test_logguard.py    # Tests for parsing and detection
```

## Getting started

You will need Python 3.10 or newer and `pip`.

### Windows

Open PowerShell in the project folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell does not allow environment activation, run the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Streamlit will print a local address in the terminal, usually `http://localhost:8501`. Open that address in your browser.

You do not need to upload a file to try the app. It loads `data/sample_auth.log` by default, so the dashboard should have example events and alerts as soon as it opens.

## Using your own data

The upload field accepts `.log`, `.txt`, and `.csv` files.

For Linux, the parser supports common OpenSSH messages such as failed passwords, invalid usernames, and accepted logins. Linux syslog timestamps often do not include a year, so the parser uses the current year for those entries.

For CSV files, include at least `timestamp` and `event`. `username`, `ip`, and `details` are optional, but they make the results more useful.

Example:

```csv
timestamp,event,username,ip,details
2026-10-25T10:00:00,failure,alice,192.0.2.10,invalid password
2026-10-25T10:01:00,success,alice,192.0.2.10,login succeeded
```

Accepted event values include `failure`, `success`, `invalid_user`, and `other`. A few common alternatives, such as `failed_login` and `login_success`, are also recognized.

The CSV option can be used for synthetic Windows login events or events exported from another tool, as long as they are converted to this format first. The project does **not** currently read raw Windows `.evtx` files directly.

## How the alerts work

The sidebar lets you change the detection settings.

1. **Repeated authentication failures:** raises an alert when an IP has at least the selected number of failure or invalid-user events inside the selected time window.
2. **Multiple usernames targeted:** flags an IP that has failed authentication attempts against several different usernames in the same time window. This can resemble username enumeration or password spraying.
3. **Failure followed by success:** flags a successful login when recent failures for the same username and IP occurred before it.

The dashboard also shows the number of events, failed and successful logins, trends over time, and the IP addresses with the most failures. You can download the normalized event list or the alerts for further review.

## Run the tests

From the project folder, run:

```bash
pytest -q
```

The tests cover basic Linux log parsing, CSV import, and the main alert patterns.

## Current limitations

This is a learning project rather than a production SIEM. The parser handles common OpenSSH messages, not every possible Linux distribution or authentication service. The app processes uploaded files in the current session and does not provide long-term event storage, live collection, user accounts, or automatic incident response.

Detection thresholds will need tuning for a real environment. Shared IP addresses, VPNs, scheduled jobs, and legitimate login mistakes can all lead to false positives. Review the surrounding evidence before treating an alert as an incident.

## Ideas for future improvements

- Add direct support for Windows `.evtx` files.
- Save imported events and alert history in SQLite.
- Add time-range filters and alert acknowledgement.
- Let users maintain allowlists for known internal systems.
- Add more parsing tests and a few larger sample datasets.
- Package the application with Docker or add automated tests to a CI workflow.

## Responsible use

Only analyze logs you own or have permission to review. Use the included sample data or a controlled lab when demonstrating the project. LogGuard is designed to help inspect authentication events; it is not intended to identify or accuse a person based on an IP address alone.
