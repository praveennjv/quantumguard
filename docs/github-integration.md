# GitHub integration

- **CI scan:** `integrations/github/scan` (future package name `quantumguard/scan`).
- **SARIF upload** to GitHub code scanning.
- **Fail the job** with exit code 1 when `--fail-on` threshold is met.
- **Baseline** to ignore accepted findings.
- **Permissions:** `contents: read` for scan; `security-events: write` only on the upload job/step as needed.

GitLab, Jenkins, and Azure DevOps folders are placeholders for Milestone 5.
