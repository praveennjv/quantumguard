"""Harvest Now, Decrypt Later (HNDL) assessment.

HNDL applies when an adversary can record ciphertext today and decrypt it after
a cryptographically relevant quantum computer exists. It is not a claim that
such an attack is occurring.
"""

from __future__ import annotations

from scanner.models import ScanContext

KEX = {"ECDH", "DH", "X25519", "X448", "RSA", "TLS"}


def assess_hndl(algorithm: str, usage: str | None, context: ScanContext) -> tuple[str | None, str | None]:
    if algorithm not in KEX and algorithm != "AES":
        return None, None
    if algorithm == "AES":
        return "low", "Symmetric ciphertext is Grover-reduced, not Shor-broken; HNDL urgency is lower than for public-key key establishment."

    usage_l = (usage or "").lower()
    kex = algorithm in KEX or "key agreement" in usage_l or algorithm == "TLS"
    if not kex:
        return None, None

    years = context.data_lifetime_years or 0
    sensitive = (context.data_sensitivity or "").lower() in {
        "high",
        "secret",
        "restricted",
        "financial",
        "pii",
        "health",
    }
    exposed = context.internet_exposure
    crit = (context.criticality or "").lower() in {"high", "critical"}

    reasons = [
        f"algorithm={algorithm} is Shor-vulnerable key establishment or transport",
    ]
    if sensitive:
        reasons.append(f"data_sensitivity={context.data_sensitivity}")
    if years:
        reasons.append(f"data_lifetime_years={years}")
    if exposed:
        reasons.append("internet_exposure=true")
    if crit:
        reasons.append(f"application criticality={context.criticality}")

    if sensitive and years >= 10 and exposed:
        level = "high"
    elif (sensitive or crit) and (years >= 5 or exposed):
        level = "medium"
    elif context.risk_model == "v1-algorithm-only":
        level = "low"
        reasons.append("no application context supplied; HNDL is potential only")
    else:
        level = "low"

    return level, "; ".join(reasons)
