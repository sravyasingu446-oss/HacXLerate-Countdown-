import ipaddress
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, url_for

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config["DATABASE"] = os.getenv(
    "DATABASE_PATH", str(BASE_DIR / "data" / "security_scans.sqlite3")
)

SUSPICIOUS_TERMS = re.compile(
    r"(?:login|verify|account|secure|update|payment|wallet|password|bank|confirm|"
    r"signin|support|gift|free|unlock)",
    re.IGNORECASE,
)


def init_db():
    """Create the local scan-history table if it does not already exist."""
    database = Path(app.config["DATABASE"])
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                verification_status TEXT NOT NULL
            )
            """
        )


def analyze_url(value):
    """Score basic URL patterns locally; this is not a reputation lookup."""
    raw_url = value.strip()
    if not raw_url or len(raw_url) > 2048 or re.search(r"\s", raw_url):
        raise ValueError("Enter a URL with no spaces and at most 2,048 characters.")

    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError(
            "Enter a valid URL, including its protocol (http:// or https://)."
        ) from error

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("Only complete http:// or https:// URLs can be scanned.")

    findings = []
    score = 0

    def add_finding(points, message):
        nonlocal score
        score += points
        findings.append(message)

    if parsed.scheme.lower() != "https":
        add_finding(15, "The URL does not use HTTPS.")

    if parsed.username is not None or parsed.password is not None:
        add_finding(35, "The URL contains embedded username or password information.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if "xn--" in hostname.lower():
            add_finding(20, "The hostname contains an internationalized (punycode) label.")
        if len(hostname) > 45:
            add_finding(10, "The hostname is unusually long.")
        if len(hostname.split(".")) > 4:
            add_finding(10, "The hostname has an unusually large number of subdomains.")
    else:
        add_finding(25, "The URL uses an IP address instead of a domain name.")

    if SUSPICIOUS_TERMS.search(f"{hostname}{parsed.path}"):
        add_finding(15, "The hostname or path contains a commonly abused keyword.")

    score = min(score, 100)
    risk_level = "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    if not findings:
        findings.append(
            "No configured suspicious URL patterns matched; this does not verify that the site is safe."
        )

    return {
        "url": raw_url,
        "risk_score": score,
        "risk_level": risk_level,
        "evidence": findings,
        "verification_status": "Not checked — external reputation integration is not enabled.",
    }


def save_scan(result):
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (url, scanned_at, risk_score, risk_level, evidence_json, verification_status)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                result["url"],
                scanned_at,
                result["risk_score"],
                result["risk_level"],
                json.dumps(result["evidence"]),
                result["verification_status"],
            ),
        )
        return cursor.lastrowid


def get_dashboard_data():
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        connection.row_factory = sqlite3.Row
        total = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        elevated = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_level IN ('Medium', 'High')"
        ).fetchone()[0]
        low = connection.execute(
            "SELECT COUNT(*) FROM scans WHERE risk_level = 'Low'"
        ).fetchone()[0]
        history = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 10"
        ).fetchall()

    return {"total": total, "elevated": elevated, "low": low, "history": history}


@app.route("/")
def index():
    dashboard = get_dashboard_data()
    selected_scan = None
    scan_id = request.args.get("scan_id", type=int)
    if scan_id is not None:
        with sqlite3.connect(app.config["DATABASE"]) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if row is not None:
            selected_scan = dict(row)
            selected_scan["evidence"] = json.loads(selected_scan.pop("evidence_json"))

    return render_template(
        "index.html", dashboard=dashboard, selected_scan=selected_scan
    )


@app.post("/scan")
def scan():
    try:
        result = analyze_url(request.form.get("url", ""))
        scan_id = save_scan(result)
    except ValueError as error:
        flash(str(error), "error")
        return redirect(url_for("index") + "#scanner")
    except sqlite3.Error:
        app.logger.exception("Could not save URL scan to SQLite.")
        flash("The scan could not be saved. Check the local database and try again.", "error")
        return redirect(url_for("index") + "#scanner")

    flash("Local URL pattern analysis complete.", "success")
    return redirect(url_for("index", scan_id=scan_id) + "#result")


init_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.getenv("PORT", "5001")),
        debug=os.getenv("FLASK_DEBUG") == "1",
    )
