"""
validation.py
Checks incoming request data before it's saved to the database - required
fields, allowed values (enums), string lengths, and number ranges.

Author: self
"""
import re

from db import ISSUE_TYPES, SEVERITIES, STATUSES, PRIORITIES

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ValidationError(Exception):
    def __init__(self, errors):
        self.errors = errors
        super().__init__(str(errors))


def _require(data, field, errors):
    if field not in data or data[field] in (None, ""):
        errors.setdefault(field, []).append("This field is required.")


def validate_issue_payload(data, partial=False):
    errors = {}
    cleaned = {}

    required_fields = ("title", "description", "issue_type", "severity",
                        "affected_system", "reporter")
    if not partial:
        for f in required_fields:
            _require(data, f, errors)

    if "title" in data:
        t = data["title"]
        if not isinstance(t, str) or not (3 <= len(t) <= 200):
            errors.setdefault("title", []).append("title must be a string of 3-200 characters.")
        else:
            cleaned["title"] = t

    if "description" in data:
        d = data["description"]
        if not isinstance(d, str) or len(d) < 3:
            errors.setdefault("description", []).append("description must be at least 3 characters.")
        else:
            cleaned["description"] = d

    if "issue_type" in data:
        if data["issue_type"] not in ISSUE_TYPES:
            errors.setdefault("issue_type", []).append(f"issue_type must be one of {ISSUE_TYPES}.")
        else:
            cleaned["issue_type"] = data["issue_type"]

    if "severity" in data:
        if data["severity"] not in SEVERITIES:
            errors.setdefault("severity", []).append(f"severity must be one of {SEVERITIES}.")
        else:
            cleaned["severity"] = data["severity"]

    if "priority" in data:
        if data["priority"] not in PRIORITIES:
            errors.setdefault("priority", []).append(f"priority must be one of {PRIORITIES}.")
        else:
            cleaned["priority"] = data["priority"]
    elif not partial:
        cleaned["priority"] = "P3"

    if "status" in data:
        if data["status"] not in STATUSES:
            errors.setdefault("status", []).append(f"status must be one of {STATUSES}.")
        else:
            cleaned["status"] = data["status"]
    elif not partial:
        cleaned["status"] = "OPEN"

    if "affected_system" in data:
        a = data["affected_system"]
        if not isinstance(a, str) or not (2 <= len(a) <= 120):
            errors.setdefault("affected_system", []).append("affected_system must be 2-120 characters.")
        else:
            cleaned["affected_system"] = a

    if "reporter" in data:
        r = data["reporter"]
        if not isinstance(r, str) or not (2 <= len(r) <= 80):
            errors.setdefault("reporter", []).append("reporter must be 2-80 characters.")
        else:
            cleaned["reporter"] = r

    if "assignee" in data:
        cleaned["assignee"] = data["assignee"]

    if "tags" in data:
        tags = data["tags"]
        if tags is None:
            cleaned["tags"] = []
        elif isinstance(tags, list) and all(isinstance(t, str) for t in tags):
            cleaned["tags"] = tags
        else:
            errors.setdefault("tags", []).append("tags must be a list of strings.")

    cve_id = data.get("cve_id")
    cvss_score = data.get("cvss_score")
    if "cve_id" in data:
        cleaned["cve_id"] = cve_id
    if "cvss_score" in data:
        if cvss_score is not None:
            try:
                score = float(cvss_score)
                if not (0.0 <= score <= 10.0):
                    errors.setdefault("cvss_score", []).append("cvss_score must be between 0.0 and 10.0.")
                else:
                    cleaned["cvss_score"] = score
            except (TypeError, ValueError):
                errors.setdefault("cvss_score", []).append("cvss_score must be numeric.")
        else:
            cleaned["cvss_score"] = None

    effective_type = cleaned.get("issue_type", data.get("issue_type"))
    if effective_type == "VULNERABILITY":
        if cve_id and not CVE_REGEX.match(cve_id):
            errors.setdefault("cve_id", []).append("cve_id must match format CVE-YYYY-NNNN.")
        if not partial and cvss_score is None:
            errors.setdefault("cvss_score", []).append("cvss_score is required for VULNERABILITY issues.")
    elif effective_type is not None and cve_id:
        errors.setdefault("cve_id", []).append("cve_id may only be set on VULNERABILITY issues.")

    if errors:
        raise ValidationError(errors)
    return cleaned


def validate_status_payload(data):
    errors = {}
    if "status" not in data or data["status"] not in STATUSES:
        errors.setdefault("status", []).append(f"status is required and must be one of {STATUSES}.")
    if errors:
        raise ValidationError(errors)
    return {"status": data["status"], "note": data.get("note")}