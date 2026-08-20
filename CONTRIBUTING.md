# Contributing to QuantumGuard

1. Open an issue (bug, feature, detection rule, or false positive) before large changes.
2. Keep PRs focused. Detection rule changes need fixtures under `tests/`.
3. Do not claim a detector is complete without tests.
4. Never add code that auto-modifies customer repositories in MVP.
5. Do not describe QuantumGuard as detecting active quantum attacks.

```bash
python -m pip install -e ".[dev]"
make test
```

Use the pull request template. Note security impact and false-positive considerations.
