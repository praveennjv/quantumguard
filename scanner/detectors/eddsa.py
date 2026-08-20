from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains


def _match(node) -> dict | None:
    if callee_contains(node, "ed25519", "Ed25519", "ED25519"):
        return {"algorithm": "Ed25519", "curve": "Ed25519", "usage": "signature"}
    if callee_contains(node, "ed448", "Ed448"):
        return {"algorithm": "Ed448", "curve": "Ed448", "usage": "signature"}
    if callee_contains(node, "generateKeyPairSync") and arg_contains(node, "ed25519", "ed448"):
        return {"algorithm": "Ed25519" if arg_contains(node, "ed25519") else "Ed448"}
    return None


RULES = [
    Rule(
        id="QG-PK-EDDSA",
        algorithm="Ed25519",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="digital signature",
        usage_hint="EdDSA",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Ed25519/Ed448 are elliptic-curve signatures. They are excellent classically and still Shor-vulnerable.",
        why_quantum="Shor's algorithm applies to the elliptic-curve groups used by EdDSA.",
        recommended_action="Do not rush replacement of Ed25519 for short-lived signatures without context. For long-term authenticity (software updates, PKI), evaluate ML-DSA/SLH-DSA or hybrids.",
        migration_complexity="medium",
    )
]
