
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