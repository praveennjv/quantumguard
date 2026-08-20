from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class QuantumStatus(StrEnum):
    QUANTUM_VULNERABLE = "quantum-vulnerable"
    GROVER_REDUCED = "grover-reduced"
    QUANTUM_RESISTANT_CANDIDATE = "quantum-resistant-candidate"
    CLASSICAL_WEAK = "classical-weak"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not-applicable"


SEVERITY_ORDER = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Location:
    file: str
    line: int
    column: int = 1
    end_line: int | None = None
    function: str | None = None
    class_name: str | None = None


@dataclass
class Finding:
    id: str
    rule_id: str
    algorithm: str
    variant: str | None
    key_size: int | None
    curve: str | None
    mode: str | None
    padding: str | None
    library: str | None
    usage: str | None
    purpose: str | None
    protocol: str | None
    data_flow: str | None
    dependency: str | None
    location: Location
    language: str
    snippet: str
    evidence: str
    confidence: float
    quantum_status: QuantumStatus
    severity: Severity
    score: int
    risk_model: str
    why_problem: str
    why_quantum: str
    recommended_action: str
    migration_complexity: str | None = None
    hndl_risk: str | None = None
    hndl_rationale: str | None = None
    application: str | None = None
    environment: str | None = None
    business_owner: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["quantum_status"] = self.quantum_status.value
        return data


@dataclass
class ScanContext:
    application: str | None = None
    environment: str = "unspecified"
    business_owner: str | None = None
    criticality: str = "medium"
    internet_exposure: bool = False
    data_sensitivity: str = "unspecified"
    data_lifetime_years: int | None = None
    data_retention: str | None = None
    fail_on: str = "high"
    risk_model: str = "v1-algorithm-only"

    @classmethod
    def from_mapping(cls, data: dict[str, Any] | None) -> ScanContext:
        if not data:
            return cls()
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class ScanResult:
    version: str
    risk_model: str
    target: str
    findings: list[Finding]
    libraries: list[dict[str, Any]]
    stats: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "risk_model": self.risk_model,
            "target": self.target,
            "disclaimer": (
                "QuantumGuard inventories cryptography and estimates future quantum-security "
                "risk. It does not detect active quantum attacks."
            ),
            "stats": self.stats,
            "libraries": self.libraries,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
