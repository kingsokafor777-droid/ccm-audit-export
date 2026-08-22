from __future__ import annotations

import json
from pathlib import Path

from ccm_audit_export.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_exports_and_verifies_fixture_package(tmp_path, capsys) -> None:
    output = tmp_path / "package"
    request_path = ROOT / "fixtures" / "safe-request.json"
    assert main(["export", str(request_path), "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert main(["verify", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_cli_rejects_invalid_request_and_tampered_package(tmp_path, capsys) -> None:
    assert (
        main(
            [
                "export",
                str(tmp_path / "missing.json"),
                "--output",
                str(tmp_path / "missing"),
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().out)["valid"] is False
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    assert main(["export", str(malformed), "--output", str(tmp_path / "output")]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False
    package = tmp_path / "package"
    request_path = ROOT / "fixtures" / "safe-request.json"
    assert main(["export", str(request_path), "--output", str(package)]) == 0
    capsys.readouterr()
    (package / "manifest.json").write_text("{}", encoding="utf-8")
    assert main(["verify", str(package)]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_exported_schema_inventory_is_complete() -> None:
    names = {path.name for path in (ROOT / "schemas" / "v1").glob("*.json")}
    assert names == {
        "evidence-reference.schema.json",
        "export-record.schema.json",
        "export-request.schema.json",
        "package-manifest.schema.json",
        "redaction-policy.schema.json",
        "verification-result.schema.json",
    }
