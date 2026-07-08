"""
app.py
Application entrypoint for the PowerPlay Sports Systems
Issue & Vulnerability Tracking System.

Author: self
"""
import os
from flask import Flask, send_from_directory

import db as dblayer
from routes import api

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or dblayer.DB_PATH

    if db_path:
        dblayer.DB_PATH = db_path

    dblayer.init_db(app.config["DB_PATH"])
    app.register_blueprint(api)

    # allow the frontend (running from any origin) to call this API
    @app.after_request
    def add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        return resp

    # serve the frontend from the same server, for convenience
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    return app
def seed_data():
    """Add sample PowerPlay Sports Systems issues/vulnerabilities (only if
    the database is empty, so this is safe to call every time the app starts)."""
    conn = dblayer.get_db()
    existing = conn.execute("SELECT COUNT(*) AS c FROM issues").fetchone()["c"]
    if existing:
        conn.close()
        return

    samples = [
        dict(title="Live scoring API returns wrong strike rate for tied overs",
             description="The /score endpoint miscalculates strike rate when an over ends in a tie ball count.",
             issue_type="BUG", severity="MEDIUM", priority="P3", status="OPEN",
             affected_system="Live Scoring Engine", reporter="qa.team", assignee=None,
             tags=["scoring", "api"]),
        dict(title="Ticket payment gateway vulnerable to SQL injection",
             description="The promo-code field on the ticket checkout page is not parameterised, allowing SQL injection.",
             issue_type="VULNERABILITY", severity="CRITICAL", priority="P1", status="OPEN",
             cve_id="CVE-2026-77213", cvss_score=9.6, affected_system="Ticketing & Payments Portal",
             reporter="security-scan-bot", assignee="a.raza", tags=["sqli", "payments"]),
        dict(title="Fan app crashes when viewing player stats offline",
             description="App throws an unhandled exception when opening cached player stats without network connectivity.",
             issue_type="BUG", severity="LOW", priority="P4", status="OPEN",
             affected_system="Fan Mobile App", reporter="qa.team", assignee=None,
             tags=["mobile", "stats"]),
        dict(title="Add multi-language commentary support",
             description="Fans have requested Urdu and Hindi live text commentary in addition to English.",
             issue_type="FEATURE_REQUEST", severity="LOW", priority="P4", status="OPEN",
             affected_system="Live Scoring Engine", reporter="product.owner", assignee=None,
             tags=["feature", "commentary"]),
        dict(title="Unauthorised access attempt on admin scoring console",
             description="Repeated failed login attempts from one IP range against the admin scoring console overnight.",
             issue_type="INCIDENT", severity="HIGH", priority="P1", status="RESOLVED",
             affected_system="Admin Scoring Console", reporter="soc.analyst", assignee="a.raza",
             tags=["incident", "brute-force"]),
        dict(title="Session tokens not invalidated on logout in fan app",
             description="JWT session tokens remain valid for their full TTL even after the user explicitly logs out.",
             issue_type="VULNERABILITY", severity="MEDIUM", priority="P2", status="OPEN",
             cve_id="CVE-2026-30871", cvss_score=5.3, affected_system="Fan Mobile App",
             reporter="pen-test-vendor", assignee=None, tags=["session", "auth"]),
    ]
    for s in samples:
        dblayer.create_issue(conn, s)
    conn.close()
    print(f"Seeded {len(samples)} sample issues.")


if __name__ == "__main__":
    application = create_app()
    seed_data()
    application.run(debug=True, port=5000)