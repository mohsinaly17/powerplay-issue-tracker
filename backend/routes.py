"""
routes.py
REST API endpoints for the PowerPlay Sports Systems Issue & Vulnerability
Tracker.

Author: self

Endpoints:
  GET    /api/health                 liveness check
  POST   /api/issues                 create
"""
from flask import Blueprint, request, jsonify, g

import db
from validation import validate_issue_payload, validate_status_payload, ValidationError

api = Blueprint("api", __name__, url_prefix="/api")


def get_conn():
    """Reuse one database connection per request (Flask's `g` object)."""
    if "conn" not in g:
        g.conn = db.get_db()
    return g.conn


@api.teardown_app_request
def close_conn(exc):
    conn = g.pop("conn", None)
    if conn is not None:
        conn.close()


@api.get("/health")
def health():
    return jsonify({"status": "ok"})


@api.post("/issues")
def create_issue():
    payload = request.get_json(silent=True) or {}
    try:
        data = validate_issue_payload(payload, partial=False)
    except ValidationError as err:
        return jsonify({"errors": err.errors}), 400

    conn = get_conn()
    if data.get("cve_id") and db.cve_exists(conn, data["cve_id"]):
        return jsonify({"errors": {"cve_id": ["cve_id already exists (must be unique)"]}}), 409

    issue_id = db.create_issue(conn, data)
    row = db.get_issue(conn, issue_id)
    return jsonify(db.row_to_dict(row)), 201