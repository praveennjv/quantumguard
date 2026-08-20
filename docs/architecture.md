# Architecture

QuantumGuard is a **modular monolith** in this repository. Do not split microservices until product surfaces (SaaS API, dashboard, scanner) have stable contracts.

## Local-first scan

```
Customer environment
  repository
    → QuantumGuard scanner (CLI / GitHub Action)
      → crypto metadata + CBOM + findings
        → optional QuantumGuard cloud (later)
```

Source code does not need to leave the customer environment for MVP scans.

## Scanner internals

```
Language Adapter → AST → IR nodes → detectors → risk engine → reporters
```

Adapters: `scanner/languages/*`. Detectors: `scanner/detectors/*`. Risk: `scanner/risk/*`.

## Multi-tenancy (later)

Organization → business units → teams → users → applications → repositories → environments → findings.

MVP has no hosted control plane. `api/` contains a sketched FastAPI module for later ingest of **findings**, not source.

## Trust

- Least privilege for GitHub Actions
- No secret logging
- Signed releases planned in `release.yml` (sigstore when publishing)
- CodeQL + dependency review in GitHub workflows
