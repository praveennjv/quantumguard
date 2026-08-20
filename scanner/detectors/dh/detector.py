from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, int_arg


def _match(node) -> dict | None:
    if callee_contains(node, "KeyPairGenerator.getInstance", "KeyAgreement.getInstance") and arg_contains(
        node, "DH", "DiffieHellman"
    ):
        return {"algorithm": "DH", "usage": "key agreement", "library": "JCA"}
    if callee_contains(node, "dh.generate_parameters", "DiffieHellman", "createDiffieHellman"):
        bits = int_arg(node)
        return {"algorithm": "DH", "key_size": bits, "usage": "key agreement"}
    if callee_contains(node, "generateKeyPairSync") and arg_contains(node, "dh"):
        return {"algorithm": "DH", "library": "node:crypto"}
    return None


RULES = [
    Rule(
        id="QG-PK-DH",
        algorithm="DH",
        variant="finite-field",
        quantum_status="quantum-vulnerable",
        purpose_hint="key establishment",
        usage_hint="finite-field Diffie-Hellman",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Finite-field Diffie-Hellman is vulnerable to Shor's algorithm and to classical log attacks when parameters are weak.",
        why_quantum="Shor's algorithm solves the discrete logarithm problem that DH relies on.",
        recommended_action="Prefer ML-KEM or hybrid KEMs. Avoid custom DH groups. Treat recorded DH traffic as HNDL-relevant when data lifetime is long.",
        migration_complexity="medium",
    )
]
