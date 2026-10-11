# Digital Risk Protection Platform

A small Flask application for reviewing URL patterns and keeping a local scan history. The current starter version performs **local heuristic checks only**. It does not contact VirusTotal, Gemini, or the submitted website, so it cannot confirm that a URL is malicious or safe.

## Requirements

- Windows 10/11
- Python 3.10 or newer

## Run locally (Windows / VS Code)

Open this folder in VS Code, then run these commands in the integrated PowerShell terminal:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If PowerShell blocks virtual-environment activation, use the environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open <http://127.0.0.1:5001> in your browser. Stop the server with **Ctrl+C**.

## What this starter includes

- A responsive dashboard with totals, elevated-pattern counts, and recent scans.
- A URL form that checks for a few suspicious URL patterns locally.
- A risk score and an explanation of which local patterns matched.
- A SQLite scan history stored at `data/security_scans.sqlite3`.
- Input validation and clear error messages.

The score is a lightweight indicator, not a verified threat verdict. A "Low" result means only that few or no configured patterns matched; it is **not** proof that a website is safe. External reputation checks are not enabled in this starter. No URL is fetched or sent to a third party.

The optional `.env` file can provide `FLASK_SECRET_KEY`, `DATABASE_PATH`, and `PORT`; do not commit secrets. The application generates a temporary secret key when `FLASK_SECRET_KEY` is unset.
