from __future__ import annotations

from scanner.detectors.common import Rule, callee_contains


def _match(node) -> dict | None:
    if callee_contains(
        node,
        "X509Certificate",
        "load_pem_x509_certificate",
        "load_der_x509_certificate",
        "CertificateFactory",
        "X509EncodedKeySpec",
        "tls.createSecureContext",
        "fs.readFileSync",
    ):
        snippet = (node.snippet or "").lower()
        if any(k in snippet for k in ("cert", "x509", ".pem", "certificate")):
            return {"algorithm": "X.509", "usage": "certificate", "purpose": "pki"}
    if callee_contains(node, "load_pem_x509", "CertificateFactory.getInstance", "x509"):
        return {"algorithm": "X.509", "usage": "certificate"}
    return None


RULES = [
    Rule(
        id="QG-CERT",
        algorithm="X.509",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="public-key infrastructure",
        usage_hint="certificate load or issuance",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Certificates bind identities to public keys. If the key algorithm is RSA/ECDSA, both authenticity and (for encryption certs) confidentiality planning are affected.",
        why_quantum="Certificate public keys that are RSA/ECC are Shor-vulnerable. Migration requires CA, client, and protocol ecosystem support.",
        recommended_action="Extract the leaf and issuer key algorithms and sizes in later milestones. Track certificate lifetime against PQC rollout.",
        migration_complexity="high",
    )
]
