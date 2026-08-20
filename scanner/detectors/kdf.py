from __future__ import annotations

from scanner.detectors.common import Rule, callee_contains, first_string_arg


def _match(node) -> dict | None:
    if callee_contains(node, "pbkdf2", "PBKDF2"):
        return {"algorithm": "PBKDF2", "usage": "password hashing / KDF"}
    if callee_contains(node, "bcrypt"):
        return {"algorithm": "bcrypt", "usage": "password hashing"}
    if callee_contains(node, "scrypt"):
        return {"algorithm": "scrypt", "usage": "password hashing / KDF"}
    if callee_contains(node, "argon2", "Argon2"):
        return {"algorithm": "Argon2", "usage": "password hashing"}
    algo = first_string_arg(node)
    if algo and str(algo).lower() in {"pbkdf2", "scrypt", "argon2", "bcrypt"}:
        return {"algorithm": str(algo), "usage": "KDF"}
    return None


RULES = [
    Rule(
        id="QG-KDF",
        algorithm="KDF",
        variant=None,
        quantum_status="grover-reduced",
        purpose_hint="password or key derivation",
        usage_hint="KDF / password hash",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Password hashes and KDFs are usually not Shor-broken. Weak iteration counts and MD5/SHA-1 based PBKDF2 are classical issues.",
        why_quantum="Grover's algorithm reduces brute-force cost; memory-hard functions (Argon2) remain preferred.",
        recommended_action="Prefer Argon2id for passwords. Do not treat KDFs as equivalent to RSA/ECDH quantum risk.",
        migration_complexity="low",
    )
]
