"""Guidance-only PQC migration suggestions. Never rewrites customer code."""

from __future__ import annotations

from scanner.knowledge.catalog import algorithm_info
from scanner.models import Finding

SUGGESTIONS = {
    "RSA": "Evaluate ML-KEM (encryption/KEM) or ML-DSA/SLH-DSA (signatures), possibly as hybrids.",
    "ECDH": "Evaluate ML-KEM or hybrid key establishment (X25519+ML-KEM where supported).",
    "X25519": "Evaluate hybrid X25519+ML-KEM for TLS and similar protocols.",
    "ECDSA": "Evaluate ML-DSA or SLH-DSA for signatures; wait for protocol/profile support.",
    "Ed25519": "Evaluate ML-DSA/SLH-DSA for long-term authenticity; hybrids where possible.",
    "DH": "Replace finite-field DH with ML-KEM or a modern hybrid KEM.",
    "DSA": "Replace DSA; do not migrate DSA to another finite-field scheme.",
    "JWT": "Track JOSE/COSE PQC algorithm registries; do not invent custom JWT algs.",
    "TLS": "Prefer TLS 1.3 and follow IETF hybrid KEM drafts as they stabilize.",
}


def guidance_for(finding: Finding) -> dict:
    return {
        "current": finding.algorithm,
        "risk": finding.why_quantum,
        "potential_migration": SUGGESTIONS.get(
            finding.algorithm, "See QuantumGuard knowledge base; confirm current NIST/IETF status."
        ),
        "migration_complexity": finding.migration_complexity,
        "pqc_catalog": {
            name: algorithm_info(name)
            for name in ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC")
        },
        "note": "Guidance only. QuantumGuard does not automatically modify production code.",
    }
