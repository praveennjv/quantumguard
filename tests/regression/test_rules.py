from scanner.detectors.registry import ALL_RULES, list_rules
from scanner.risk.engine import classify_quantum
from scanner.models import QuantumStatus


def test_rules_are_registered():
    ids = {r.id for r in ALL_RULES}
    assert "QG-PK-RSA" in ids
    assert "QG-PK-ECDSA" in ids
    assert list_rules()


def test_quantum_classification_is_nuanced():
    assert classify_quantum("RSA") == QuantumStatus.QUANTUM_VULNERABLE
    assert classify_quantum("AES") == QuantumStatus.GROVER_REDUCED
    assert classify_quantum("MD5") == QuantumStatus.CLASSICAL_WEAK
    assert classify_quantum("JWT", "HS256") == QuantumStatus.GROVER_REDUCED
    assert classify_quantum("JWT", "RS256") == QuantumStatus.QUANTUM_VULNERABLE
