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
@api.put("/issues/<int:issue_id>")
def update_issue(issue_id):
    conn = get_conn()
    row = db.get_issue(conn, issue_id)
    if not row:
        return jsonify({"error": "Issue not found"}), 404

    payload = request.get_json(silent=True) or {}
    try:
        data = validate_issue_payload(payload, partial=True)
    except ValidationError as err:
        return jsonify({"errors": err.errors}), 400

    if "status" in payload and payload["status"] != row["status"]:
        return jsonify({"error": "Use PATCH /api/issues/<id>/status to change status"}), 400

    if data.get("cve_id") and db.cve_exists(conn, data["cve_id"], exclude_id=issue_id):
        return jsonify({"errors": {"cve_id": ["cve_id already exists (must be unique)"]}}), 409

    db.update_issue_fields(conn, issue_id, data)
    updated = db.get_issue(conn, issue_id)
    return jsonify(db.row_to_dict(updated))


@api.patch("/issues/<int:issue_id>/status")
def update_status(issue_id):
    conn = get_conn()
    row = db.get_issue(conn, issue_id)
    if not row:
        return jsonify({"error": "Issue not found"}), 404

    payload = request.get_json(silent=True) or {}
    try:
        data = validate_status_payload(payload)
    except ValidationError as err:
        return jsonify({"errors": err.errors}), 400

    new_status = data["status"]
    old_status = row["status"]
    allowed = db.ALLOWED_TRANSITIONS.get(old_status, set())
    if new_status != old_status and new_status not in allowed:
        return jsonify({
            "error": f"Illegal transition {old_status} -> {new_status}. "
                     f"Allowed: {sorted(allowed)}"
        }), 409

    db.update_status(conn, issue_id, new_status, data.get("note"))
    db.add_history(conn, issue_id, old_status, new_status, data.get("note"))
    conn.commit()
    updated = db.get_issue(conn, issue_id)
    return jsonify(db.row_to_dict(updated))
@api.delete("/issues/<int:issue_id>")
def delete_issue(issue_id):
    conn = get_conn()
    row = db.get_issue(conn, issue_id)
    if not row:
        return jsonify({"error": "Issue not found"}), 404
    db.delete_issue(conn, issue_id)
    return jsonify({"deleted": issue_id}), 200


@api.get("/reports/summary")
def report_summary():
    conn = get_conn()
    return jsonify(db.report_summary(conn))


@api.get("/reports/aging")
def report_aging():
    try:
        days = int(request.args.get("days", 7))
    except ValueError:
        return jsonify({"error": "days must be an integer"}), 400
    conn = get_conn()
    items = db.report_aging(conn, days=days)
    return jsonify({"cutoff_days": days, "count": len(items), "items": items})