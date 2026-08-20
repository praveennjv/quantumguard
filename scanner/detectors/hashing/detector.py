from __future__ import annotations

from scanner.detectors.common import Rule, callee_contains, first_string_arg


def _match(node) -> dict | None:
    algo = first_string_arg(node)
    algo_l = str(algo).lower() if algo is not None else ""
    callee = (node.callee or "").lower()
    if callee_contains(node, "md5", "MD5") or algo_l in {"md5"}:
        return {"algorithm": "MD5", "variant": "MD5"}
    if callee_contains(node, "sha1", "SHA-1", "SHA1") or (algo and str(algo).lower() in {"sha1", "sha-1"}):
        if "sha128" in callee:
            return None
        return {"algorithm": "SHA-1", "variant": "SHA-1"}
    if callee_contains(node, "sha3", "SHA3") or (algo and "sha3" in str(algo).lower()):
        return {"algorithm": "SHA-3", "variant": algo or "SHA-3"}
    if callee_contains(node, "sha512", "SHA-512", "SHA512") or (algo and str(algo).lower() in {"sha512", "sha-512"}):
        return {"algorithm": "SHA-512", "variant": "SHA-512"}
    if callee_contains(node, "sha384", "SHA-384", "SHA384") or (algo and str(algo).lower() in {"sha384", "sha-384"}):
        return {"algorithm": "SHA-384", "variant": "SHA-384"}
    if callee_contains(node, "sha256", "SHA-256", "SHA256") or (algo and str(algo).lower() in {"sha256", "sha-256"}):
        return {"algorithm": "SHA-256", "variant": "SHA-256"}
    if callee_contains(node, "MessageDigest.getInstance", "hashlib", "createHash", "createHmac"):
        if not algo:
            return None
        name = str(algo).upper().replace("_", "-")
        if name in {"MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-384", "SHA-512", "SHA-3"}:
            if name == "SHA1":
                name = "SHA-1"
            if name == "SHA256":
                name = "SHA-256"
            return {"algorithm": name, "variant": name}
    return None


RULES = [
    Rule(
        id="QG-HASH",
        algorithm="HASH",
        variant=None,
        quantum_status="grover-reduced",
        purpose_hint="hashing",
        usage_hint="cryptographic hash",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="Broken hashes (MD5, SHA-1) fail classically. SHA-2/SHA-3 remain usable but Grover's algorithm reduces preimage work, which is why longer outputs are preferred for long-term designs.",
        why_quantum="Grover's algorithm provides a square-root speedup against unstructured search, including preimage attacks. This does not make SHA-256 equivalent to a broken hash today.",
        recommended_action="Replace MD5/SHA-1 immediately. Keep SHA-256/384/512 or SHA-3; prefer SHA-384/512 for long-term collision resistance goals. Do not treat SHA-256 as a PQC emergency.",
        migration_complexity="low",
    )
]
