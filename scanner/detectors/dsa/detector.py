from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains


def _match(node) -> dict | None:
    if callee_contains(node, "KeyPairGenerator.getInstance", "Signature.getInstance") and arg_contains(node, "DSA"):
        return {"algorithm": "DSA", "library": "JCA"}
    if callee_contains(node, "dsa.generate_private_key", "DSA.generate"):
        return {"algorithm": "DSA"}
    if callee_contains(node, "generateKeyPairSync") and arg_contains(node, "dsa"):
        return {"algorithm": "DSA", "library": "node:crypto"}
    return None


RULES = [
    Rule(
        id="QG-PK-DSA",
        algorithm="DSA",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="digital signature",
        usage_hint="DSA signatures",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="DSA is a finite-field discrete-log signature scheme. It is also obsolete in modern TLS and many PKI profiles.",
        why_quantum="Shor's algorithm solves the discrete logarithm problem used by DSA.",
        recommended_action="Replace DSA with a modern signature algorithm. For quantum-aware planning, evaluate ML-DSA or SLH-DSA.",
        migration_complexity="low",
    )
]
