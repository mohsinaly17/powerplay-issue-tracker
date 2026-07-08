
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