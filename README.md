# PowerPlay Sports Systems — Issue & Vulnerability Tracking System

A web-based issue and security-vulnerability tracker built for **PowerPlay
Sports Systems** (fictional company used for this coursework), which runs
a live cricket-scoring engine, a fan mobile app, and a ticketing/payments
platform. The system tracks both ordinary software issues (bugs, feature
requests) and security vulnerabilities (with CVE/CVSS fields) in one place.

---

## 1. Requirements

See `docs/requirements.md` for the full requirements and data model outline.

### Summary
- **Functional:** create, read, update, delete issues; controlled status
  workflow with audit history; search; filter; sort; pagination; reporting
  (summary counts + aging report).
- **Data:** each issue has title, description, type, severity, priority,
  status, affected system, reporter, assignee, tags, and (for
  vulnerabilities) a unique CVE ID and CVSS score.
- **Validation & integrity:** required fields enforced server-side, enum
  fields restricted to fixed value sets, CVSS restricted to 0.0-10.0, CVE ID
  format/uniqueness enforced, CVE/CVSS only allowed on VULNERABILITY-type
  issues, and status can only move through a defined set of legal
  transitions (every change recorded in an append-only history table).
  All SQL queries use parameterised placeholders to prevent SQL injection.

---

## 2. Architecture

**Folder structure:**

- `backend/app.py` — Flask app + seed data + entrypoint
- `backend/db.py` — Data-access layer (sqlite3, parameterised queries)
- `backend/validation.py` — Request validation
- `backend/routes.py` — REST API endpoints (CRUD, search/sort/filter, reports)
- `backend/tests/test_api.py` — 23 automated tests (unittest)
- `frontend/index.html` — Single-page vanilla JS/HTML/CSS dashboard
- `docs/requirements.md` — Requirements & data model outline
- `README.md` — this file
## 3. API reference

Base URL: `http://127.0.0.1:5000/api`

| Method | Path | Description |
|---|---|---|
| GET | /health | liveness check |
| GET | /issues?q=&status=&severity=&issue_type=&priority=&assignee=&reporter=&sort_by=&order=&page=&per_page= | search/filter/sort/paginate |
| POST | /issues | create |
| GET | /issues/<id>?history=true | read one (optionally with audit history) |
| PUT | /issues/<id> | update (partial allowed; status excluded) |
| PATCH | /issues/<id>/status | controlled status transition |
| DELETE | /issues/<id> | delete |
| GET | /reports/summary | counts by status/severity/type, open-vuln count |
| GET | /reports/aging?days=7 | open items older than N days |
## 4. Setup and running

Steps:
1. Open a terminal inside the backend folder
2. Run: pip install flask
3. Run: python app.py
4. Open http://127.0.0.1:5000/ in a browser

Running the tests:
1. Open a terminal inside the backend folder
2. Run: python -m unittest discover -s tests -v

18 out of 18 tests currently pass, covering create/read/update/delete,
validation errors, status-transition legality, search, filter, sort,
pagination, and both report endpoints.
## 5. Code attribution summary

Every commit in this repository is self-attributed (self: prefix in the
commit message) unless noted otherwise below. All code was written from
scratch for this assignment, incrementally, with each logical piece of
functionality committed and pushed separately as it was completed.

| Item | Source | Licence / attribution |
|---|---|---|
| Flask (pip install flask) | Third-party PyPI package, used only via its public API | BSD-3-Clause |
| Python standard library (sqlite3, re, unittest, datetime) | CPython standard library | PSF License |
| Database schema, validation rules, REST endpoint design, status-transition state machine, audit-trail design | Written from scratch by the author | self |
| Frontend HTML/CSS/JS (frontend/index.html) | Written from scratch by the author | self |
| Sample/seed data (PowerPlay Sports Systems scenario and sample issues) | Fictional company and fictional sample issues invented by the author | self |
| AI assistance | An AI coding assistant (Claude) was used interactively to help design and write the code, explain each part, and guide incremental, tested, git-committed development | disclosed |

AI assistance disclosure: development of this project was carried out with
the assistance of an AI coding assistant, which explained each piece of
code, helped debug errors, and guided an incremental commit-by-commit
development process. All code was reviewed, typed in, run, and tested by
the author at each step.