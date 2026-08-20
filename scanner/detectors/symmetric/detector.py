from __future__ import annotations

from scanner.detectors.common import Rule, arg_contains, callee_contains, first_string_arg


def _match(node) -> dict | None:
    algo = (first_string_arg(node) or "")
    lower = algo.lower()
    if callee_contains(node, "DES", "TripleDES", "DESede", "3des") or "desede" in lower or lower in {"des", "3des", "tripledes"}:
        if "hmac" in (node.callee or "").lower():
            return None
        name = "3DES" if any(x in lower for x in ("3des", "triple", "desede")) or "deSede" in algo or "DESede" in str(node.args) else "DES"
        if callee_contains(node, "3DES", "TripleDES", "DESede") or "desede" in lower or "triple" in lower:
            name = "3DES"
        if callee_contains(node, ".DES") or lower == "des" or "DES/ECB" in str(node.args):
            if "aes" not in lower:
                name = "DES" if name != "3DES" else name
        if arg_contains(node, "DESede", "TripleDES", "3DES") or callee_contains(node, "DESede", "TripleDES"):
            name = "3DES"
        if arg_contains(node, "DES/") or lower == "des" or arg_contains(node, '"DES"'):
            if not arg_contains(node, "DESede") and not callee_contains(node, "AES"):
                name = "DES" if not arg_contains(node, "DESede") else "3DES"
        return {"algorithm": name, "mode": algo or None}
    if "chacha20-poly1305" in lower or callee_contains(node, "ChaCha20Poly1305", "chacha20-poly1305"):
        return {"algorithm": "ChaCha20-Poly1305", "mode": "AEAD"}
    if "chacha20" in lower or callee_contains(node, "ChaCha20", "chacha20"):
        return {"algorithm": "ChaCha20"}
    if callee_contains(node, "AESGCM", "AES-GCM") or "aes-256-gcm" in lower or "aes-128-gcm" in lower or "gcm" in lower and "aes" in lower:
        return {"algorithm": "AES", "mode": "GCM", "variant": "AES-GCM"}
    if "cbc" in lower and "aes" in lower:
        return {"algorithm": "AES", "mode": "CBC", "variant": "AES-CBC"}
    if "ctr" in lower and "aes" in lower:
        return {"algorithm": "AES", "mode": "CTR", "variant": "AES-CTR"}
    if callee_contains(node, "AES", "Cipher.getInstance", "createCipheriv", "createDecipheriv") and (
        "aes" in lower or callee_contains(node, "AES.new", "algorithms.AES")
    ):
        mode = None
        if "gcm" in lower:
            mode = "GCM"
        elif "cbc" in lower:
            mode = "CBC"
        elif "ctr" in lower:
            mode = "CTR"
        return {"algorithm": "AES", "mode": mode, "variant": f"AES-{mode}" if mode else "AES"}
    return None


RULES = [
    Rule(
        id="QG-SYM",
        algorithm="AES",
        variant=None,
        quantum_status="grover-reduced",
        purpose_hint="symmetric encryption",
        usage_hint="block/stream cipher",
        library_hint=None,
        languages="java,python,javascript,typescript",
        match=_match,
        why_problem="DES and 3DES are classically obsolete. AES remains appropriate; Grover's algorithm motivates 256-bit keys for very long-term confidentiality, not panic replacement of AES-128 in every app.",
        why_quantum="Grover's algorithm halves the effective key length against brute force. AES-128 is often treated as ~64-bit quantum brute-force work; AES-256 is the usual long-term symmetric choice.",
        recommended_action="Remove DES/3DES. Prefer AES-GCM or ChaCha20-Poly1305. Plan AES-256 for long-lived data; do not mark all AES as quantum-critical.",
        migration_complexity="low",
    )
]
