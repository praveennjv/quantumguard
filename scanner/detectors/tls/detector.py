from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg


def _match(node) -> dict | None:
    if callee_contains(
        node,
        "PROTOCOL_SSLv",
        "PROTOCOL_TLSv1",
        "OP_NO_TLSv1",
        "set_ciphers",
        "SSLContext",
        "enabledProtocols",
        "setEnabledProtocols",
        "setEnabledCipherSuites",
        "https.Agent",
        "minVersion",
        "maxVersion",
        "secureProtocol",
    ) or arg_contains(node, "TLSv1", "SSLv3", "TLSv1.1", "TLS_RSA_", "RC4", "NULL"):
        proto = first_string_arg(node)
        return {"algorithm": "TLS", "variant": proto, "protocol": proto or "TLS", "usage": "TLS configuration"}
    if callee_contains(node, "ssl.wrap_socket", "create_default_context") and arg_contains(node, "TLSv1", "SSLv"):
        return {"algorithm": "TLS", "protocol": first_string_arg(node), "usage": "TLS configuration"}
    return None


RULES = [
    Rule(
        id="QG-TLS",
        algorithm="TLS",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="transport security",
        usage_hint="TLS version or cipher configuration",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="TLS security is bounded by the handshake KEM/signature and the record cipher. TLS 1.0/1.1 and RSA key-transport suites are classically weak; classical ECDHE remains HNDL-relevant.",
        why_quantum="Handshake key establishment using RSA/ECDH/X25519 is Shor-vulnerable. Hybrid or ML-KEM TLS is the migration path when your stack supports it.",
        recommended_action="Disable TLS 1.0/1.1. Prefer TLS 1.3. Track cipher suites and certificate algorithms separately. Plan hybrid KEMs when clients and servers can negotiate them.",
        migration_complexity="high",
    )
]
