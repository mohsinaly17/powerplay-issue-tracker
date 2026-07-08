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
@api.get("/issues")
def list_issues():
    search = request.args.get("q")
    filters = {f: request.args.get(f) for f in
               ("status", "severity", "issue_type", "priority", "assignee", "reporter")}
    sort_by = request.args.get("sort_by", "date_reported")
    order = request.args.get("order", "desc")
    try:
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 20)), 1), 100)
    except ValueError:
        return jsonify({"error": "page and per_page must be integers"}), 400

    conn = get_conn()
    total, items = db.list_issues(conn, search=search, filters=filters,
                                   sort_by=sort_by, order=order,
                                   page=page, per_page=per_page)
    return jsonify({"total": total, "page": page, "per_page": per_page, "items": items})


@api.get("/issues/<int:issue_id>")
def get_issue(issue_id):
    conn = get_conn()
    row = db.get_issue(conn, issue_id)
    if not row:
        return jsonify({"error": "Issue not found"}), 404
    history = None
    if request.args.get("history", "false").lower() == "true":
        history = db.get_history(conn, issue_id)
    return jsonify(db.row_to_dict(row, history=history))