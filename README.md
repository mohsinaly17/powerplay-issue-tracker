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