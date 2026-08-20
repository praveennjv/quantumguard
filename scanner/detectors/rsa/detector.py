"""RSA detection across Java, Python, JavaScript, TypeScript."""

from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg, int_arg
from scanner.ir import IRNode


def _match(node: IRNode) -> dict | None:
    algo = first_string_arg(node)
    rsa_call = callee_contains(
        node,
        "RSA",
        "generate_private_key",
        "rsa.generate",
        "generateKeyPair",
        "generateKeyPairSync",
        "RSA.generate",
        "PKCS1_OAEP",
        "PKCS1_v1_5",
        "rsa_padding",
        "createSign",
        "createVerify",
        "publicEncrypt",
        "privateDecrypt",
        "KeyPairGenerator",
        "Cipher.getInstance",
        "Signature.getInstance",
    )
    rsa_alg = algo and "rsa" in str(algo).lower()
    if callee_contains(node, "KeyPairGenerator.getInstance") and arg_contains(node, "RSA"):
        return {"algorithm": "RSA", "library": "JCA"}
    if callee_contains(node, "Cipher.getInstance") and arg_contains(node, "RSA"):
        padding = first_string_arg(node)
        return {"algorithm": "RSA", "padding": padding, "library": "JCA"}
    if callee_contains(node, "Signature.getInstance") and arg_contains(node, "RSA", "SHA256withRSA", "SHA1withRSA"):
        return {"algorithm": "RSA", "usage": "signature", "library": "JCA"}
    if callee_contains(node, "rsa.generate_private_key", "RSA.generate", "cryptography.hazmat.primitives.asymmetric.rsa"):
        bits = int_arg(node)
        return {"algorithm": "RSA", "key_size": bits, "library": "cryptography"}
    if callee_contains(node, "Crypto.PublicKey.RSA", "PKCS1_OAEP", "PKCS1_v1_5"):
        bits = int_arg(node)
        return {"algorithm": "RSA", "key_size": bits, "library": "pycryptodome"}
    if callee_contains(node, "generateKeyPairSync", "generateKeyPair") and arg_contains(node, "rsa"):
        return {"algorithm": "RSA", "library": "node:crypto"}
    if callee_contains(node, "publicEncrypt", "privateDecrypt", "privateEncrypt"):
        if arg_contains(node, "RSA", "oaep", "pkcs1") or rsa_call:
            return {"algorithm": "RSA", "library": "node:crypto"}
    if callee_contains(node, "crypto.subtle.generateKey", "subtle.generateKey") and arg_contains(node, "RSA-OAEP", "RSASSA-PKCS1", "RSA-PSS"):
        return {"algorithm": "RSA", "library": "WebCrypto"}
    if rsa_alg and callee_contains(node, "getInstance", "createSign", "createVerify", "generate"):
        return {"algorithm": "RSA"}
    return None


RULES = [
    Rule(
        id="QG-PK-RSA",
        algorithm="RSA",
        variant=None,
        quantum_status="quantum-vulnerable",
        purpose_hint="asymmetric encryption or signature",
        usage_hint="RSA key generation or operation",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="RSA public-key operations depend on integer factorization, which is classically hard but broken by a cryptographically relevant quantum computer using Shor's algorithm.",
        why_quantum="Shor's algorithm reduces RSA to polynomial time. Harvest-now-decrypt-later is relevant when RSA encrypts long-lived confidential data.",
        recommended_action="Inventory usage. For encryption/KEM, evaluate ML-KEM or a hybrid KEM. For signatures, evaluate ML-DSA or SLH-DSA. Do not treat every RSA site as equally urgent.",
        migration_complexity="medium",
    )
]
