from __future__ import annotations

from scanner.detectors.common import Rule, callee_contains

CRYPTO_LIBS = {
    "cryptography": "python-cryptography",
    "Crypto.Cipher": "pycryptodome",
    "Crypto.PublicKey": "pycryptodome",
    "nacl": "pynacl",
    "hashlib": "stdlib-hashlib",
    "ssl": "stdlib-ssl",
    "jwt": "pyjwt",
    "jose": "python-jose|jose",
    "jsonwebtoken": "jsonwebtoken",
    "node:crypto": "node-crypto",
    "crypto": "node-crypto",
    "forge": "node-forge",
    "BouncyCastle": "bouncycastle",
    "org.bouncycastle": "bouncycastle",
    "javax.crypto": "JCA",
    "java.security": "JCA",
    "io.jsonwebtoken": "jjwt",
}


def _match(node) -> dict | None:
    hay = f"{node.callee} {' '.join(node.imports.values())}".lower()
    for needle, lib in CRYPTO_LIBS.items():
        if needle.lower() in hay and callee_contains(node, needle.split(".")[-1]):
            return {"algorithm": "CRYPTO-LIBRARY", "library": lib, "usage": "library-call"}
    return None


RULES = [
    Rule(
        id="QG-LIB",
        algorithm="CRYPTO-LIBRARY",
        variant=None,
        quantum_status="unknown",
        purpose_hint="cryptographic library",
        usage_hint="library usage",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Cryptographic libraries are inventory signals. They are not automatically vulnerabilities.",
        why_quantum="Library presence does not imply quantum risk until algorithms and usage are identified.",
        recommended_action="Use library hits as CBOM edges. Prefer algorithm-specific findings for scoring.",
        migration_complexity="low",
    )
]
