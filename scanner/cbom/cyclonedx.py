"""CycloneDX 1.6-compatible Cryptographic Bill of Materials (subset)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from scanner.models import ScanResult


def to_cyclonedx(result: ScanResult) -> dict[str, Any]:
    components = []
    for lib in result.libraries:
        components.append(
            {
                "type": "library",
                "name": lib.get("name"),
                "version": lib.get("version") or "unknown",
                "bom-ref": f"lib-{lib.get('name')}",
            }
        )
    crypto_assets = []
    for finding in result.findings:
        crypto_assets.append(
            {
                "bom-ref": finding.id,
                "type": "algorithm",
                "name": finding.algorithm,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": finding.purpose,
                        "parameterSetIdentifier": finding.variant or finding.curve or finding.mode,
                        "executionEnvironment": finding.environment,
                    },
                    "oid": None,
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": finding.location.file,
                            "line": finding.location.line,
                        }
                    ]
                },
            }
        )
        components.append(
            {
                "type": "cryptographic-asset",
                "name": finding.algorithm,
                "bom-ref": finding.id,
                "cryptoProperties": {
                    "assetType": "algorithm",
                },
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"name": "QuantumGuard", "version": result.version}],
            "component": {
                "type": "application",
                "name": result.target,
            },
            "properties": [
                {"name": "quantumguard:risk-model", "value": result.risk_model},
                {
                    "name": "quantumguard:disclaimer",
                    "value": "Does not detect active quantum attacks.",
                },
            ],
        },
        "components": components,
        "properties": [
            {"name": "quantumguard:crypto-asset-count", "value": str(len(crypto_assets))}
        ],
    }
