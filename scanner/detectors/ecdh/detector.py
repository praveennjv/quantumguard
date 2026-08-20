from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg


def _match(node) -> dict | None:
    if callee_contains(node, "KeyAgreement.getInstance") and arg_contains(node, "ECDH"):
        return {"algorithm": "ECDH", "usage": "key agreement", "library": "JCA"}
    if callee_contains(node, "ec.ECDH", "exchange", "createECDH") or (
        callee_contains(node, "ECDH") and not callee_contains(node, "ECDSA")
    ):
        curve = first_string_arg(node)
        return {"algorithm": "ECDH", "curve": curve, "usage": "key agreement"}
    if callee_contains(node, "generateKeyPairSync") and arg_contains(node, "x25519", "x448"):
        algo = first_string_arg(node)
        return {"algorithm": str(algo).upper() if algo else "X25519", "usage": "key agreement"}
    if callee_contains(node, "X25519", "x25519", "X448"):
        name = "X25519" if "25519" in (node.callee + str(node.args)).lower() else "X448"
        return {"algorithm": name, "usage": "key agreement"}
    if callee_contains(node, "subtle.generateKey") and arg_contains(node, "ECDH"):
        return {"algorithm": "ECDH", "library": "WebCrypto"}
    return None


RULES = [
    Rule(
        id="QG-PK-ECDH",
        algorithm="ECDH",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="key establishment",
        usage_hint="elliptic-curve Diffie-Hellman",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="ECDH/X25519/X448 establish shared secrets using elliptic-curve discrete log. Recorded handshakes can be decrypted later if the KEM is broken.",
        why_quantum="Shor's algorithm breaks ECDH. This is the primary Harvest Now, Decrypt Later concern for TLS and similar protocols.",
        recommended_action="Evaluate ML-KEM or hybrid key establishment (e.g. X25519+ML-KEM). Prioritize internet-exposed sessions that protect long-lived confidential data.",
        migration_complexity="medium",
    )
]
