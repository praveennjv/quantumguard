from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg


def _match(node) -> dict | None:
    if callee_contains(node, "KeyPairGenerator.getInstance") and arg_contains(node, "EC"):
        return {"algorithm": "ECDSA", "library": "JCA"}
    if callee_contains(node, "Signature.getInstance") and arg_contains(node, "ECDSA", "SHA256withECDSA", "SHA384withECDSA"):
        return {"algorithm": "ECDSA", "usage": "signature", "library": "JCA"}
    if callee_contains(node, "ec.generate_private_key", "SECP256R1", "SECP384R1", "ecdsa"):
        curve = first_string_arg(node)
        return {"algorithm": "ECDSA", "curve": curve, "library": "cryptography"}
    if callee_contains(node, "generateKeyPairSync", "generateKeyPair") and arg_contains(node, "ec"):
        return {"algorithm": "ECDSA", "library": "node:crypto"}
    if callee_contains(node, "createSign", "createVerify") and arg_contains(node, "ecdsa", "sha256", "sha384"):
        # too broad; only if snippet mentions ecdsa/ec
        if "ec" in (node.snippet or "").lower() or arg_contains(node, "ecdsa"):
            return {"algorithm": "ECDSA", "library": "node:crypto"}
    if callee_contains(node, "subtle.generateKey") and arg_contains(node, "ECDSA"):
        return {"algorithm": "ECDSA", "library": "WebCrypto"}
    if callee_contains(node, "jwt.encode", "jwt.decode", "jsonwebtoken", "jose") and arg_contains(
        node, "ES256", "ES384", "ES512"
    ):
        return {"algorithm": "ECDSA", "usage": "JWT signing", "purpose": "authentication"}
    return None


RULES = [
    Rule(
        id="QG-PK-ECDSA",
        algorithm="ECDSA",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="digital signature",
        usage_hint="ECDSA signature or EC key generation",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="ECDSA authenticity depends on elliptic-curve discrete log, which a cryptographically relevant quantum computer can solve with Shor's algorithm.",
        why_quantum="Shor's algorithm applies to elliptic-curve groups used by ECDSA (P-256, P-384, etc.).",
        recommended_action="For signatures, evaluate ML-DSA or SLH-DSA, or a hybrid classical+PQC signature scheme. Prioritize internet-facing authentication and software-update signing.",
        migration_complexity="medium",
    )
]
