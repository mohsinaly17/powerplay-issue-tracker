"""
validation.py
Checks incoming request data before it's saved to the database - required
fields, allowed values (enums), string lengths, and number ranges.

Author: self
"""
import re

from db import ISSUE_TYPES, SEVERITIES, STATUSES, PRIORITIES

# CVE IDs must look like: CVE-2026-12345
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ValidationError(Exception):
    """Raised when incoming data fails validation. Carries a dict of
    field-name -> list of error messages."""
    def __init__(self, errors):
        self.errors = errors
        super().__init__(str(errors))


def _require(data, field, errors):
    """Add an error if a required field is missing or empty."""
    if field not in data or data[field] in (None, ""):
        errors.setdefault(field, []).append("This field is required.")