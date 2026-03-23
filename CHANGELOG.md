# Changelog

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
