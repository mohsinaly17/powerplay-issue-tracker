# PowerPlay Sports Systems — Issue & Vulnerability Tracking System

## Company context
PowerPlay Sports Systems runs a live cricket-scoring mobile app, a fan
engagement platform, and an online ticket/subscription payment system.
This project tracks both ordinary software issues (bugs, feature requests)
and security vulnerabilities across these systems in one place.

## Functional requirements
- Create a new issue/vulnerability record
- Read (view) a single issue, and list all issues
- Update an issue's details
- Change an issue's status through a controlled workflow (with history)
- Delete an issue
- Search issues by keyword (title, description, affected system, CVE ID)
- Filter issues by status, severity, type, priority, assignee
- Sort issues by date, severity, priority, status
- Paginate long result lists
- Reporting: counts by status/severity/type, list of "aging" open issues

## Data requirements
Each issue record stores:
- id, title, description
- issue_type: BUG / VULNERABILITY / FEATURE_REQUEST / INCIDENT
- severity: LOW / MEDIUM / HIGH / CRITICAL
- priority: P1-P4
- status: OPEN / IN_PROGRESS / RESOLVED / CLOSED / WONT_FIX
- cve_id, cvss_score (vulnerability-only fields)
- affected_system, reporter, assignee, tags
- date_reported, date_updated, date_resolved

## Validation & integrity rules
- All required fields must be present
- Enum fields restricted to fixed value lists
- CVSS score must be between 0.0 and 10.0
- CVE ID must be unique and match format CVE-YYYY-NNNN
- CVE/CVSS fields only allowed on VULNERABILITY type issues
- Status can only move through allowed transitions (e.g. cannot jump
  straight from OPEN to RESOLVED)
- Every status change is recorded in an audit history table