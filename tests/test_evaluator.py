from __future__ import annotations

import json

import pytest

from ccm_audit_export.evaluator import (
    _selected_value,
    _verify_record_content,
    render_package,
    verify_package,
    write_package,
)
from ccm_audit_export.models import (
    ExportDisposition,
    RedactionAction,
    RedactionSelector,
)

from .helpers import evidence, policy, request, rule


def test_renderer_produces_reproducible_included_redacted_and_omitted_records() -> None:
    rules = policy(
        rule(
            "rule_omit_sensitive_asset",
            selector=RedactionSelector.ASSET_ID,
            match_value="asset_sensitive",
            action=RedactionAction.OMIT_RECORD,
        ),
        rule(
            "rule_redact_resource",
            selector=RedactionSelector.RESOURCE_IDENTIFIER,
            match_value="resource_sensitive",
            action=RedactionAction.REPLACE_WITH_DIGEST,
        ),
    )
    package_request = request(
        evidence("reference_included", "evidence_included"),
        evidence(
            "reference_omitted",
            "evidence_omitted",
            asset_id="asset_sensitive",
        ),
        evidence(
            "reference_redacted",
            "evidence_redacted",
            resource_identifier="resource_sensitive",
        ),
        redaction_policy=rules,
    )
    first = render_package(package_request)
    second = render_package(package_request)
    assert first == second
    assert first.manifest.verify_integrity()
    assert {record.disposition for record in first.manifest.records} == {
        ExportDisposition.INCLUDED,
        ExportDisposition.OMITTED,
        ExportDisposition.REDACTED,
    }
    assert "manifest.json" in first.files and "policy.json" in first.files
    assert len([path for path in first.files if path.startswith("evidence/")]) == 2


def test_renderer_applies_metadata_redaction_and_first_matching_rule() -> None:
    rules = policy(
        rule(
            "rule_alpha",
            selector=RedactionSelector.METADATA,
            match_value="internal",
            action=RedactionAction.REPLACE_WITH_DIGEST,
            metadata_key="classification",
        ),
        rule(
            "rule_zeta",
            selector=RedactionSelector.ASSET_ID,
            match_value="asset_identity",
            action=RedactionAction.OMIT_RECORD,
        ),
    )
    rendered = render_package(
        request(
            evidence(
                "reference_metadata",
                "evidence_metadata",
                metadata={"classification": "internal"},
            ),
            redaction_policy=rules,
        )
    )
    record = rendered.manifest.records[0]
    assert record.disposition == ExportDisposition.REDACTED
    payload = json.loads(rendered.files[record.evidence_path].decode("utf-8"))
    assert payload["redaction"]["rule_id"] == "rule_alpha"
    assert payload["reference"]["metadata"]["classification"] == record.selected_value_hash


def test_subject_selector_uses_the_supplied_subject_identifier() -> None:
    subject_rule = rule(
        "rule_subject",
        selector=RedactionSelector.SUBJECT_IDENTIFIER,
        match_value="subject_operator_a",
        action=RedactionAction.OMIT_RECORD,
    )
    reference = evidence(
        "reference_subject",
        "evidence_subject",
        subject_identifier="subject_operator_a",
    )
    assert _selected_value(reference, subject_rule) == "subject_operator_a"


def test_write_and_verify_package_rejects_nonempty_or_unexpected_destinations(tmp_path) -> None:
    destination = tmp_path / "package"
    manifest = write_package(request(), destination)
    assert verify_package(destination).valid
    assert manifest.manifest_hash is not None
    with pytest.raises(ValueError, match="not empty"):
        write_package(request(), destination)
    (destination / "unexpected.txt").write_text("not declared", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected files"):
        write_package(request(), destination, overwrite=True)
    file_destination = tmp_path / "not-a-directory"
    file_destination.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="directory path"):
        write_package(request(), file_destination)


def test_verifier_detects_modified_missing_unexpected_policy_and_manifest_files(tmp_path) -> None:
    destination = tmp_path / "package"
    write_package(request(), destination)
    evidence_path = next((destination / "evidence").glob("*.json"))
    evidence_path.write_text("{}", encoding="utf-8")
    result = verify_package(destination)
    assert not result.valid and any("digest mismatch" in error for error in result.errors)
    write_package(request(), destination, overwrite=True)
    (destination / "policy.json").write_text("{}", encoding="utf-8")
    policy_result = verify_package(destination)
    assert not policy_result.valid and any("policy" in error for error in policy_result.errors)
    write_package(request(), destination, overwrite=True)
    (destination / "extra.json").write_text("{}", encoding="utf-8")
    unexpected_result = verify_package(destination)
    assert not unexpected_result.valid
    assert any("unexpected" in error for error in unexpected_result.errors)
    (destination / "extra.json").unlink()
    (destination / "policy.json").unlink()
    missing_result = verify_package(destination)
    assert not missing_result.valid and any("missing" in error for error in missing_result.errors)


def test_verifier_handles_malformed_or_manifest_tampered_packages(tmp_path) -> None:
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "manifest.json").write_text("{", encoding="utf-8")
    assert not verify_package(malformed).valid
    destination = tmp_path / "package"
    write_package(request(), destination)
    manifest_path = destination / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["tenant_id"] = "tenant_tampered"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = verify_package(destination)
    assert not result.valid and any("sealed integrity" in error for error in result.errors)


def test_record_content_verifier_catches_included_and_redacted_declarations(tmp_path) -> None:
    included_destination = tmp_path / "included"
    included_request = request()
    write_package(included_request, included_destination)
    included_record = verify_package(included_destination)
    assert included_record.valid
    rendered = render_package(included_request)
    record = rendered.manifest.records[0]
    assert record.evidence_path is not None
    payload_path = included_destination / record.evidence_path
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    payload["reference"]["asset_id"] = "asset_other"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    included_errors = _verify_record_content(
        record,
        included_destination,
        included_request.redaction_policy,
    )
    assert any("source descriptor" in error for error in included_errors)

    redacted_destination = tmp_path / "redacted"
    redacted_rules = policy(
        rule(
            "rule_redact_resource",
            selector=RedactionSelector.RESOURCE_IDENTIFIER,
            match_value="resource_sensitive",
            action=RedactionAction.REPLACE_WITH_DIGEST,
        )
    )
    redacted_request = request(
        evidence(
            "reference_redacted",
            "evidence_redacted",
            resource_identifier="resource_sensitive",
        ),
        redaction_policy=redacted_rules,
    )
    redacted_manifest = write_package(redacted_request, redacted_destination)
    redacted_record = redacted_manifest.records[0]
    assert redacted_record.evidence_path is not None
    redacted_path = redacted_destination / redacted_record.evidence_path
    redacted_payload = json.loads(redacted_path.read_text(encoding="utf-8"))
    redacted_payload["record_id"] = "export_record_other"
    redacted_payload["redaction"] = {
        "rule_id": "rule_missing",
        "selected_value_hash": "sha256:" + ("d" * 64),
    }
    redacted_path.write_text(json.dumps(redacted_payload), encoding="utf-8")
    redacted_errors = _verify_record_content(
        redacted_record,
        redacted_destination,
        redacted_request.redaction_policy,
    )
    assert any("record ID mismatch" in error for error in redacted_errors)
    assert any("redaction rule mismatch" in error for error in redacted_errors)
    assert any("selected-value digest mismatch" in error for error in redacted_errors)
    absent_rule_errors = _verify_record_content(
        redacted_record,
        redacted_destination,
        policy(),
    )
    assert any("absent from policy" in error for error in absent_rule_errors)
    redacted_payload.pop("redaction")
    redacted_path.write_text(json.dumps(redacted_payload), encoding="utf-8")
    missing_declaration_errors = _verify_record_content(
        redacted_record,
        redacted_destination,
        redacted_request.redaction_policy,
    )
    assert any("missing redaction" in error for error in missing_declaration_errors)


def test_verifier_detects_resealed_policy_identity_and_version_mismatch(tmp_path) -> None:
    destination = tmp_path / "package"
    manifest = write_package(request(), destination)
    mismatched = manifest.model_copy(
        update={
            "policy_hash": "sha256:" + ("d" * 64),
            "redaction_policy_id": "other_redaction_policy",
            "redaction_policy_version": "2.0.0",
        }
    ).seal()
    (destination / "manifest.json").write_text(
        json.dumps(mismatched.model_dump(mode="json", exclude_none=True)),
        encoding="utf-8",
    )
    result = verify_package(destination)
    assert not result.valid
    assert "policy hash mismatch" in result.errors
    assert "policy ID mismatch" in result.errors
    assert "policy version mismatch" in result.errors
