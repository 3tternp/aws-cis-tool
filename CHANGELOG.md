# Changelog

## 1.1.0 - 2026-11-27

### Reports

- Redesigned HTML and PDF reports with an executive dashboard: compliance score, Critical/High/Medium/Low counts of failed findings, passed/failed/manual/error totals, per-category chart and a "Fix first" list.
- Every check now has a severity rating, a plain-English recommendation and an AWS CLI remediation command (`aws_cis_tool/remediation.py`).
- HTML report: search, status/severity/category filters, click-to-filter severity cards, copy buttons, dark mode, print friendly.
- JSON report now includes `severity_summary`, `manual_checks_by_severity`, `compliance_score` and per-result `severity` / `recommendation` / `command`.
- Findings are sorted by status and severity (most severe first).

### Added

- New modern web dashboard (`python gui.py`) replacing the Tkinter GUI: live progress, compliance ring, search/filter, expandable evidence, light/dark theme, report downloads.
- `--access-key/--secret-key/--session-token` CLI options.
- Shared scan runner (`aws_cis_tool/runner.py`) used by CLI and UI; each check is isolated so one failure cannot abort a scan.

### Fixed

- Scanning with access keys failed ~45 checks with "You must specify a region" when no region was set; region now defaults to us-east-1.
- Pasted keys with stray whitespace/quotes are cleaned; `ASIA` keys without a session token are rejected with a clear message.
- Clear messages for invalid key, signature mismatch, expired token and missing permissions (hint: SecurityAudit + ViewOnlyAccess).
- Adaptive retries and timeouts on all AWS clients to survive throttling.
- Removed committed `__pycache__` files.

## 1.0.0 - 2026-03-23

### Added

- Added Security category checks for GuardDuty, Security Hub, EBS default encryption, and S3 account-level Block Public Access.
- Added Security Hub CIS standard evaluation (region-scoped).
- Added multi-region coverage checks for GuardDuty and Security Hub across enabled regions.
- Added Security checks for EC2 IMDSv2 requirement and EBS volume encryption.
- Added Dockerfile for running the CLI scanner in a container.
- Added changelog viewing in CLI (`--changelog`) and GUI.
- Added Logging checks for CloudTrail S3 bucket public access, bucket access logging, and KMS CMK rotation.
- Added Storage checks aligned to CIS v1.5 S3 numbering (2.1.1, 2.1.2, 2.1.3, 2.1.5).
- Added Monitoring section aligned to CIS v1.5 (4.1 - 4.14 log metric filters and alarms).
- Added Networking manual check 5.5 for least-access VPC peering route tables.

### Improved

- Manual verification checks now include step-by-step instructions and PoC commands in reports.
- Aligned check IDs and README sections to CIS AWS Foundations Benchmark v1.5 numbering.
