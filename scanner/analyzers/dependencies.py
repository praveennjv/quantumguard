"""Lightweight dependency inventory for CBOM edges (not a full SCA product)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

CRYPTO_HINTS = {
    "cryptography",
    "pycryptodome",
    "pycrypto",
    "pyjwt",
    "python-jose",
    "pynacl",
    "bcrypt",
    "argon2",
    "jsonwebtoken",
    "jose",
    "node-forge",
    "libsodium",
    "bouncycastle",
    "jjwt",
    "nimbus-jose",
}


def discover_libraries(root: Path) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if root.is_file():
        root = root.parent
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            deps = {}
            deps.update(data.get("dependencies") or {})
            deps.update(data.get("devDependencies") or {})
            for name, ver in deps.items():
                if any(h in name.lower() for h in CRYPTO_HINTS):
                    found.append({"ecosystem": "npm", "name": name, "version": ver, "crypto": True})
        except json.JSONDecodeError:
            pass
    req = root / "requirements.txt"
    if req.exists():
        for line in req.read_text(encoding="utf-8").splitlines():
            name = re.split(r"[<>=\[]", line.strip(), maxsplit=1)[0].strip()
            if name.lower() in CRYPTO_HINTS or any(h in name.lower() for h in CRYPTO_HINTS):
                found.append({"ecosystem": "pypi", "name": name, "version": line.strip(), "crypto": True})
    pom = root / "pom.xml"
    if pom.exists():
        text = pom.read_text(encoding="utf-8")
        if "bouncycastle" in text.lower() or "jjwt" in text.lower():
            found.append({"ecosystem": "maven", "name": "crypto-related-pom", "version": None, "crypto": True})
    return found
