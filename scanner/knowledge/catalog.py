"""Algorithm catalog. PQC entries are versioned and may change as standards evolve."""

from __future__ import annotations

from typing import Any

ALGORITHMS: dict[str, dict[str, Any]] = {
    "RSA": {
        "type": "public-key",
        "quantum_status": "quantum-vulnerable",
        "summary": "Factorization-based public-key scheme; broken by Shor.",
        "standard": "PKCS #1 / FIPS 186",
    },
    "ECDSA": {
        "type": "signature",
        "quantum_status": "quantum-vulnerable",
        "summary": "Elliptic-curve DSA; discrete log is Shor-vulnerable.",
        "standard": "FIPS 186",
    },
    "ECDH": {
        "type": "key-establishment",
        "quantum_status": "quantum-vulnerable",
        "summary": "Elliptic-curve Diffie-Hellman; primary HNDL concern for recorded traffic.",
        "standard": "SP 800-56A",
    },
    "DH": {
        "type": "key-establishment",
        "quantum_status": "quantum-vulnerable",
        "summary": "Finite-field Diffie-Hellman; Shor-vulnerable.",
        "standard": "SP 800-56A",
    },
    "DSA": {
        "type": "signature",
        "quantum_status": "quantum-vulnerable",
        "summary": "Finite-field DSA; obsolete and Shor-vulnerable.",
        "standard": "FIPS 186",
    },
    "Ed25519": {
        "type": "signature",
        "quantum_status": "quantum-vulnerable",
        "summary": "EdDSA on Curve25519; excellent classically, still Shor-vulnerable.",
        "standard": "RFC 8032",
    },
    "X25519": {
        "type": "key-establishment",
        "quantum_status": "quantum-vulnerable",
        "summary": "Montgomery DH; widely used in TLS 1.3; HNDL-relevant.",
        "standard": "RFC 7748",
    },
    "AES": {
        "type": "symmetric",
        "quantum_status": "grover-reduced",
        "summary": "Block cipher; Grover motivates AES-256 for long-term data, not emergency replacement of all AES-128.",
        "standard": "FIPS 197",
    },
    "MD5": {
        "type": "hash",
        "quantum_status": "classical-weak",
        "summary": "Collision-broken classically.",
        "standard": "RFC 1321",
    },
    "SHA-1": {
        "type": "hash",
        "quantum_status": "classical-weak",
        "summary": "Collision-broken classically.",
        "standard": "FIPS 180",
    },
    "SHA-256": {
        "type": "hash",
        "quantum_status": "grover-reduced",
        "summary": "SHA-2; still appropriate for most uses.",
        "standard": "FIPS 180",
    },
    "ML-KEM": {
        "type": "kem",
        "quantum_status": "quantum-resistant-candidate",
        "summary": "NIST FIPS 203 module-lattice KEM. Parameters and ecosystem support can still evolve.",
        "standard": "FIPS 203",
        "catalog_version": "2026.08",
    },
    "ML-DSA": {
        "type": "signature",
        "quantum_status": "quantum-resistant-candidate",
        "summary": "NIST FIPS 204 module-lattice signature. Treat as current standard, not immutable.",
        "standard": "FIPS 204",
        "catalog_version": "2026.08",
    },
    "SLH-DSA": {
        "type": "signature",
        "quantum_status": "quantum-resistant-candidate",
        "summary": "NIST FIPS 205 stateless hash-based signature.",
        "standard": "FIPS 205",
        "catalog_version": "2026.08",
    },
    "HQC": {
        "type": "kem",
        "quantum_status": "quantum-resistant-candidate",
        "summary": "Code-based KEM selected by NIST for additional KEM diversity. Final parameters may change.",
        "standard": "NIST additional KEM (track evolving spec)",
        "catalog_version": "2026.08",
    },
}


def algorithm_info(name: str) -> dict[str, Any] | None:
    return ALGORITHMS.get(name)
