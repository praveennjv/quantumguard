from __future__ import annotations

from scanner.detectors.certificates import RULES as CERT
from scanner.detectors.dh import RULES as DH
from scanner.detectors.dsa import RULES as DSA
from scanner.detectors.ecdh import RULES as ECDH
from scanner.detectors.ecdsa import RULES as ECDSA
from scanner.detectors.eddsa import RULES as EDDSA
from scanner.detectors.hashing import RULES as HASH
from scanner.detectors.jwt import RULES as JWT
from scanner.detectors.kdf import RULES as KDF
from scanner.detectors.libraries import RULES as LIBS
from scanner.detectors.rsa import RULES as RSA
from scanner.detectors.symmetric import RULES as SYM
from scanner.detectors.tls import RULES as TLS

ALL_RULES = RSA + ECDSA + ECDH + DH + DSA + EDDSA + HASH + SYM + JWT + TLS + CERT + KDF + LIBS


def list_rules() -> list[dict]:
    return [
        {
            "id": r.id,
            "algorithm": r.algorithm,
            "languages": r.languages,
            "quantum_status": r.quantum_status,
        }
        for r in ALL_RULES
    ]
