"""Versioned quantum-security risk models.

v1: algorithm-only (conservative, context-free)
v2: algorithm + application context
v3: v2 + data lifetime / HNDL
v4: v3 + business criticality

These models estimate future cryptographic risk. They do not imply an active
quantum attack was observed.
"""

from __future__ import annotations

from scanner.models import QuantumStatus, ScanContext, Severity

PK_SHOR = {
    "RSA",
    "DSA",
    "DH",
    "ECDH",
    "ECDSA",
    "Ed25519",
    "Ed448",
    "X25519",
    "X448",
    "JWT",
    "TLS",
    "X.509",
}

CLASSICAL_BROKEN = {"MD5", "SHA-1", "DES", "3DES"}
GROVER = {"AES", "ChaCha20", "ChaCha20-Poly1305", "SHA-256", "SHA-384", "SHA-512", "SHA-3", "PBKDF2", "bcrypt", "scrypt", "Argon2"}


def classify_quantum(algorithm: str, variant: str | None = None) -> QuantumStatus:
    if algorithm in CLASSICAL_BROKEN or (variant or "") in CLASSICAL_BROKEN:
        if algorithm in {"MD5", "SHA-1", "DES", "3DES"}:
            return QuantumStatus.CLASSICAL_WEAK
    if algorithm in PK_SHOR:
        if algorithm == "JWT" and variant and str(variant).upper().startswith("HS"):
            return QuantumStatus.GROVER_REDUCED
        return QuantumStatus.QUANTUM_VULNERABLE
    if algorithm in GROVER or (algorithm == "AES"):
        return QuantumStatus.GROVER_REDUCED
    if algorithm in {"CRYPTO-LIBRARY"}:
        return QuantumStatus.NOT_APPLICABLE
    return QuantumStatus.UNKNOWN


def _clamp(score: int) -> int:
    return max(0, min(100, score))


def _severity(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 45:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFORMATIONAL


def score_finding(
    *,
    algorithm: str,
    variant: str | None,
    key_size: int | None,
    curve: str | None,
    mode: str | None,
    usage: str | None,
    purpose: str | None,
    context: ScanContext,
    hndl_level: str | None = None,
) -> tuple[int, Severity, str]:
    model = context.risk_model
    score = 25
    algo = algorithm

    if algo in {"RSA"}:
        score = 58
        if key_size and key_size < 2048:
            score = 82
        elif key_size and key_size >= 4096:
            score = 52
    elif algo in {"DSA"}:
        score = 72
    elif algo in {"DH"}:
        score = 62
        if key_size and key_size < 2048:
            score = 80
    elif algo in {"ECDH", "X25519", "X448"}:
        score = 55
    elif algo in {"ECDSA", "Ed25519", "Ed448"}:
        score = 50
    elif algo == "JWT":
        v = (variant or "").upper()
        if v.startswith("RS") or v.startswith("ES") or v.startswith("PS") or v == "EDDSA":
            score = 60
        elif v.startswith("HS"):
            score = 28
        else:
            score = 48
    elif algo == "TLS":
        v = (variant or "").lower()
        if "ssl" in v or "tlsv1" == v.replace(".", "") or "1.0" in v or "1.1" in v:
            score = 78
        else:
            score = 40
    elif algo in {"MD5"}:
        score = 55
    elif algo in {"SHA-1"}:
        score = 50
    elif algo in {"DES"}:
        score = 80
    elif algo in {"3DES"}:
        score = 68
    elif algo == "AES":
        score = 12 if (mode or "").upper() == "GCM" else 18
        if mode and mode.upper() == "ECB":
            score = 48
    elif algo in {"ChaCha20", "ChaCha20-Poly1305"}:
        score = 10
    elif algo in {"SHA-256", "SHA-384", "SHA-512", "SHA-3"}:
        score = 8
    elif algo in {"PBKDF2", "bcrypt", "scrypt", "Argon2"}:
        score = 15
    elif algo in {"X.509"}:
        score = 35
    elif algo == "CRYPTO-LIBRARY":
        score = 5

    usage_l = (usage or "").lower() + " " + (purpose or "").lower()
    if "auth" in usage_l or "jwt" in usage_l or "sign" in usage_l:
        score += 8
    if "key agreement" in usage_l or "key establishment" in usage_l:
        score += 6

    if model in {"v2-application-context", "v3-data-lifetime", "v4-business"}:
        crit = (context.criticality or "medium").lower()
        if crit in {"critical", "high"}:
            score += 10
        elif crit == "low":
            score -= 8
        if context.internet_exposure:
            score += 8
        sens = (context.data_sensitivity or "").lower()
        if sens in {"high", "secret", "restricted", "financial", "pii"}:
            score += 8

    if model in {"v3-data-lifetime", "v4-business"}:
        years = context.data_lifetime_years or 0
        if years >= 10 and algo in PK_SHOR:
            score += 12
        elif years >= 5 and algo in {"ECDH", "DH", "RSA", "X25519"}:
            score += 8
        if hndl_level == "high":
            score += 10
        elif hndl_level == "critical":
            score += 18

    if model == "v4-business":
        if (context.business_owner or "") and crit == "critical":
            score += 5

    # Never auto-promote all ECC/RSA to Critical in v1
    if model == "v1-algorithm-only" and score >= 90 and algo in {"RSA", "ECDSA", "ECDH", "Ed25519"}:
        score = 75

    score = _clamp(score)
    return score, _severity(score), model
