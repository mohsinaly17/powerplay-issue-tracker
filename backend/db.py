
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tracker.db")

# Allowed values for each enum-like field
ISSUE_TYPES = ("BUG", "VULNERABILITY", "FEATURE_REQUEST", "INCIDENT")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUSES = ("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "WONT_FIX")
PRIORITIES = ("P1", "P2", "P3", "P4")

# Which status can move to which (integrity rule)
ALLOWED_TRANSITIONS = {
    "OPEN": {"IN_PROGRESS", "WONT_FIX", "CLOSED"},
    "IN_PROGRESS": {"RESOLVED", "OPEN", "WONT_FIX"},
    "RESOLVED": {"CLOSED", "IN_PROGRESS"},
    "CLOSED": {"OPEN"},
    "WONT_FIX": {"OPEN"},
}

# Used so we can sort severity/priority logically (CRITICAL > HIGH), not alphabetically
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
PRIORITY_RANK = {"P4": 0, "P3": 1, "P2": 2, "P1": 3}

SORTABLE_COLUMNS = {"date_reported", "date_updated", "title", "status"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()
def get_db(path=None):
    """Open a connection to the SQLite database file."""
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, like a dict
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path=None):
    """Create the tables if they don't already exist."""
    conn = get_db(path)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        issue_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'P3',
        status TEXT NOT NULL DEFAULT 'OPEN',
        cve_id TEXT UNIQUE,
        cvss_score REAL,
        affected_system TEXT NOT NULL,
        reporter TEXT NOT NULL,
        assignee TEXT,
        tags TEXT,
        date_reported TEXT NOT NULL,
        date_updated TEXT NOT NULL,
        date_resolved TEXT
    );

    CREATE TABLE IF NOT EXISTS issue_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issue_id INTEGER NOT NULL,
        from_status TEXT,
        to_status TEXT NOT NULL,
        note TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
    CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity);
    CREATE INDEX IF NOT EXISTS idx_issues_type ON issues(issue_type);
    """)
    conn.commit()
    conn.close()


def row_to_dict(row, history=None):
    """Convert a database row into a plain dictionary (for JSON output)."""
    d = dict(row)
    d["tags"] = d["tags"].split(",") if d.get("tags") else []
    if history is not None:
        d["history"] = history
    return d
# ------------------------------------------------------------------ CRUD ---
def create_issue(conn, data):
    """Insert a new issue and record its creation in the history table."""
    ts = now_iso()
    cur = conn.execute("""
        INSERT INTO issues (title, description, issue_type, severity, priority,
                             status, cve_id, cvss_score, affected_system, reporter,
                             assignee, tags, date_reported, date_updated, date_resolved)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["title"], data["description"], data["issue_type"], data["severity"],
        data.get("priority", "P3"), data.get("status", "OPEN"), data.get("cve_id"),
        data.get("cvss_score"), data["affected_system"], data["reporter"],
        data.get("assignee"), ",".join(data.get("tags", []) or []),
        ts, ts, None,
    ))
    issue_id = cur.lastrowid
    add_history(conn, issue_id, None, data.get("status", "OPEN"), "Issue created")
    conn.commit()
    return issue_id


def get_issue(conn, issue_id):
    """Fetch a single issue by its id."""
    row = conn.execute("SELECT * FROM issues WHERE id = ?", (issue_id,)).fetchone()
    return row


def get_history(conn, issue_id):
    """Fetch the full audit trail for one issue, oldest first."""
    rows = conn.execute(
        "SELECT * FROM issue_history WHERE issue_id = ? ORDER BY timestamp ASC",
        (issue_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def add_history(conn, issue_id, from_status, to_status, note):
    """Append one row to the audit trail (never overwrites past history)."""
    conn.execute("""
        INSERT INTO issue_history (issue_id, from_status, to_status, note, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (issue_id, from_status, to_status, note, now_iso()))


def cve_exists(conn, cve_id, exclude_id=None):
    """Check whether a CVE ID is already used by another issue (integrity check)."""
    if exclude_id:
        row = conn.execute(
            "SELECT id FROM issues WHERE cve_id = ? AND id != ?", (cve_id, exclude_id)
        ).fetchone()
    else:
        row = conn.execute("SELECT id FROM issues WHERE cve_id = ?", (cve_id,)).fetchone()
    return row is not None