# Threat model

## In scope

- Discovery of cryptographic APIs and libraries in supported languages
- Mis-scoring or missing quantum-relevant algorithms
- Leakage of customer source via logs or the GitHub Action
- Supply-chain compromise of the scanner or action

## Out of scope

- Detecting that a quantum computer is attacking a system
- Breaking customer cryptography
- Automatic production code rewrites

## Assets

- Customer source (must stay local by default)
- Findings/CBOM (sensitive metadata)
- GitHub tokens used by Actions (never printed)

## Adversaries

- Malicious PR that poisons detection rules
- Dependency confusion against `quantumguard` packages
- Log scraping in CI

## Mitigations

- Pin GitHub Actions by version; prefer SHA pins when publishing
- Minimal `permissions:`
- Tests for false positives
- SECURITY.md private reporting
