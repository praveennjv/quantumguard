from pathlib import Path

from scanner.analyzers.engine import scan_path
from scanner.cli.main import EXIT_OK, EXIT_POLICY, main
from scanner.models import ScanContext
from scanner.reporting.sarif import to_sarif
from scanner.cbom import to_cyclonedx

ROOT = Path(__file__).resolve().parents[1]


def test_python_vulnerable_detects_rsa_ecc_hashes():
    result = scan_path(ROOT / "tests/vulnerable/python")
    algos = {f.algorithm for f in result.findings}
    assert "RSA" in algos
    assert "ECDSA" in algos
    assert "MD5" in algos
    assert "SHA-1" in algos
    assert any(f.evidence for f in result.findings)


def test_rsa_is_not_automatically_critical_without_context():
    result = scan_path(ROOT / "tests/vulnerable/python", ScanContext(risk_model="v1-algorithm-only"))
    rsa = [f for f in result.findings if f.algorithm == "RSA"]
    assert rsa
    assert all(f.severity.value != "critical" for f in rsa)
    assert all(f.risk_model == "v1-algorithm-only" for f in rsa)


def test_java_vulnerable_detects_core_algorithms():
    result = scan_path(ROOT / "tests/vulnerable/java")
    algos = {f.algorithm for f in result.findings}
    assert "RSA" in algos
    assert "ECDH" in algos
    assert "MD5" in algos


def test_javascript_and_typescript():
    js = scan_path(ROOT / "tests/vulnerable/javascript")
    ts = scan_path(ROOT / "tests/vulnerable/typescript")
    assert "RSA" in {f.algorithm for f in js.findings}
    assert "RSA" in {f.algorithm for f in ts.findings}
    assert any(f.algorithm == "JWT" for f in list(js.findings) + list(ts.findings))


def test_comments_are_not_findings():
    result = scan_path(ROOT / "tests/false-positive/python")
    assert result.findings == []


def test_sarif_and_cbom_export():
    result = scan_path(ROOT / "tests/vulnerable/python")
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    cbom = to_cyclonedx(result)
    assert cbom["bomFormat"] == "CycloneDX"


def test_hndl_elevates_with_context():
    ctx = ScanContext(
        risk_model="v3-data-lifetime",
        internet_exposure=True,
        data_sensitivity="financial",
        data_lifetime_years=10,
        criticality="critical",
        application="payment-api",
    )
    result = scan_path(ROOT / "tests/vulnerable/python", ctx)
    ecdh = [f for f in result.findings if f.algorithm in {"ECDH", "X25519"}]
    assert ecdh
    assert any(f.hndl_risk == "high" for f in ecdh)


def test_cli_fail_on_and_version(tmp_path, capsys):
    assert main(["version"]) == EXIT_OK
    code = main(["scan", str(ROOT / "tests/false-positive/python"), "--fail-on", "high", "--quiet"])
    assert code == EXIT_OK
    code = main(
        [
            "scan",
            str(ROOT / "tests/vulnerable/java"),
            "--fail-on",
            "high",
            "--format",
            "json",
            "--output",
            str(tmp_path / "out.json"),
            "--quiet",
        ]
    )
    assert code == EXIT_POLICY
    assert (tmp_path / "out.json").exists()


def test_rules_command():
    assert main(["rules"]) == EXIT_OK
