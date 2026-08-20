from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg


def _match(node) -> dict | None:
    algo = first_string_arg(node)
    if callee_contains(node, "jwt.encode", "jwt.decode", "jwt.sign", "jsonwebtoken", "Jwts.builder", "JWT.create"):
        return {
            "algorithm": "JWT",
            "variant": algo,
            "usage": "JWT",
            "purpose": "authentication",
        }
    if arg_contains(node, "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "EdDSA"):
        if callee_contains(node, "jwt", "jose", "sign", "encode", "SignJWT"):
            return {"algorithm": "JWT", "variant": algo, "usage": "JWT signing", "purpose": "authentication"}
    if callee_contains(node, "SignJWT", "jwtVerify", "createRemoteJWKSet"):
        return {"algorithm": "JWT", "usage": "JWT", "purpose": "authentication", "library": "jose"}
    return None


RULES = [
    Rule(
        id="QG-JWT",
        algorithm="JWT",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="authentication",
        usage_hint="JWT signing or verification",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="JWTs inherit the quantum (and classical) properties of their signing/encryption algorithms. RSA/ECDSA JWT signatures will not remain secure against a CRQC.",
        why_quantum="RS256/ES256 and similar algorithms are Shor-vulnerable. HMAC JWTs are Grover-reduced, not Shor-broken.",
        recommended_action="Record the exact JWS/JWE algorithm. Prioritize asymmetric JWT used for federation, API auth, and long-lived tokens. Plan PQC or hybrid signatures when standards in your ecosystem allow.",
        migration_complexity="high",
    )
]
