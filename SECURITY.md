# Security Policy

## Product disclaimer

QuantumGuard inventories cryptography and estimates **future** quantum-security risk. It does **not** detect active quantum attacks.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for vulnerabilities in QuantumGuard.

Email **security@quantumguard.dev** (replace with the project security alias when the organization is created) with:

- Description
- Affected component (CLI, action, API, dashboard)
- Scanner version
- Reproduction that does not include customer secrets
- Impact

We aim to acknowledge reports within 5 business days.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Secret handling

Do not commit `.env`, private keys, or customer scan corpora that contain production source.
