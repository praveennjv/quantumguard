# QuantumGuard

Developer-first cryptographic discovery, Cryptographic Bill of Materials (CBOM), and **quantum-security risk** platform.

QuantumGuard answers:

> Where is cryptography used, which parts are vulnerable to *future* quantum computers, which of those findings matter for this business, and what should we migrate first?

**QuantumGuard does not detect active quantum attacks.** It inventories cryptographic usage and estimates risk using versioned, configurable models.

Pipeline: **Discover → Inventory → Analyze → Assess quantum risk → Prioritize → Remediate (guidance) → Monitor**.

## Why quantum security matters

A cryptographically relevant quantum computer (CRQC) would break widely deployed public-key algorithms (RSA, finite-field DH/DSA, ECDH/ECDSA, X25519, Ed25519) via Shor's algorithm. Recorded traffic that used those KEMs can be decrypted later (**Harvest Now, Decrypt Later**). Symmetric algorithms and hashes are not “Shor-broken”; Grover's algorithm is a different, usually less urgent, factor.

Not every RSA or ECC call is Critical. Risk depends on usage, exposure, data lifetime, and business context.

## What QuantumGuard detects (MVP)

| Family | Examples |
| --- | --- |
| Public-key | RSA, DSA, DH, ECDH, ECDSA, Ed25519, Ed448, X25519, X448 |
| Symmetric | AES (GCM/CBC/CTR), DES, 3DES, ChaCha20, ChaCha20-Poly1305 |
| Hash | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3 |
| KDF | PBKDF2, bcrypt, scrypt, Argon2 |
| JWT / TLS / certs | Signing algorithms, TLS configuration, X.509 load sites |
| Libraries | Crypto packages in source and lockfiles (inventory) |

Detection uses language adapters → AST → intermediate representation → detectors. Regex is not the sole signal.

## Supported languages

**Milestone 1:** Java, Python, JavaScript, TypeScript.

Designed for later adapters: Go, C, C++, C#, Rust.

## Installation

```bash
python -m pip install -e ".[dev]"
quantumguard version
```

## CLI

```bash
quantumguard scan .
quantumguard scan ./src
quantumguard scan --format sarif
quantumguard scan --format cbom
quantumguard scan --format json
quantumguard scan --format html
quantumguard scan --fail-on critical
quantumguard scan --fail-on high
quantumguard scan --baseline baseline.json
quantumguard scan --context context.yml --risk-model v3-data-lifetime
quantumguard version
quantumguard rules
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | No policy violation |
| 1 | Policy violation (`--fail-on`) |
| 2 | Scanner error |

## GitHub Actions

The in-repo action lives at [`integrations/github/scan`](integrations/github/scan). The intended public name is `quantumguard/scan` (not assumed to exist yet).

```yaml
name: QuantumGuard Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  quantumguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Run QuantumGuard
        uses: ./integrations/github/scan
        with:
          fail-on: high
          output-format: sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: quantumguard-results.sarif
```

The action uses least privilege, does not print secrets, and emits SARIF for code scanning.

## CBOM

`--format cbom` writes a CycloneDX 1.6-oriented Cryptographic Bill of Materials: application → components/libraries → cryptographic assets (algorithms) with evidence locations.

## Quantum risk scoring

Scores are **0–100** with severities Informational, Low, Medium, High, Critical. Every score stores a **risk model version**:

| Model | What it uses |
| --- | --- |
| `v1-algorithm-only` | Algorithm class (RSA is not auto-Critical) |
| `v2-application-context` | + criticality, exposure, sensitivity |
| `v3-data-lifetime` | + retention / HNDL |
| `v4-business` | + business ownership / criticality |

## HNDL

Harvest Now, Decrypt Later is assessed when Shor-vulnerable key establishment or transport protects confidential data with long lifetime and (typically) external exposure. Without context, HNDL is marked potential/low rather than inflated to Critical.

## Architecture

Local-first: source stays in the customer environment. The scanner emits metadata, CBOM, and findings. Cloud/SaaS ingest of *crypto metadata* is a later deployment mode (private cloud, self-hosted, Kubernetes, air-gapped).

```
Language Adapter → AST → IR → Detectors → Risk engine → SARIF / CBOM / JSON
```

See [docs/architecture.md](docs/architecture.md).

## Dashboard

Milestone 3. A static prototype is in [`dashboard/`](dashboard/).

## Roadmap

See [docs/roadmap.md](docs/roadmap.md). MVP is CLI + GitHub Action + AST detection + risk + SARIF/CBOM + CI gate.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately; do not file public PoCs for QuantumGuard itself.
