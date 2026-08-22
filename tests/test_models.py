from __future__ import annotations

import pytest
from pydantic import ValidationError

from ccm_audit_export.evaluator import render_package
from ccm_audit_export.models import (
    EvidenceReference,
    ExportDisposition,
    ExportRecord,
    ExportRequest,
    PackageFile,
    PackageManifest,
    RedactionAction,
    RedactionRule,
    RedactionSelector,
    VerificationResult,
)

from .helpers import HASH_A, evidence, policy, request, rule


def test_evidence_reference_rejects_malformed_or_payload_like_contracts() -> None:
    bad_hash = evidence("reference_bad_hash", "evidence_bad_hash").model_dump()
    bad_hash["evidence_hash"] = "sha256:wrong"
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(bad_hash)
    bad_metadata = evidence("reference_bad_metadata", "evidence_bad_metadata").model_dump()
    bad_metadata["metadata"] = {"Bad-Key": "value"}
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(bad_metadata)
    payload_like = evidence("reference_payload_like", "evidence_payload_like").model_dump()
    payload_like["metadata"] = {"raw_payload": "never allowed"}
    with pytest.raises(ValidationError):
        EvidenceReference.model_validate(payload_like)
    with pytest.raises(ValidationError):
        evidence(
            "reference_many_labels",
            "evidence_many_labels",
            metadata={f"label_{index}": "value" for index in range(33)},
        )


def test_redaction_policy_requires_ordered_unique_closed_rule_shapes() -> None:
    metadata_without_key = {
        "rule_id": "rule_metadata",
        "selector": RedactionSelector.METADATA,
        "match_value": "internal",
        "action": RedactionAction.REPLACE_WITH_DIGEST,
        "rationale": "synthetic rationale",
    }
    with pytest.raises(ValidationError):
        RedactionRule.model_validate(metadata_without_key)
    with pytest.raises(ValidationError):
        RedactionRule(
            rule_id="rule_nonmetadata_key",
            selector=RedactionSelector.ASSET_ID,
            match_value="asset_a",
            action=RedactionAction.OMIT_RECORD,
            rationale="synthetic rationale",
            metadata_key="classification",
        )
    later = rule(
        "rule_zeta",
        selector=RedactionSelector.ASSET_ID,
        match_value="asset_a",
        action=RedactionAction.OMIT_RECORD,
    )
    earlier = rule(
        "rule_alpha",
        selector=RedactionSelector.ASSET_ID,
        match_value="asset_b",
        action=RedactionAction.OMIT_RECORD,
    )
    with pytest.raises(ValidationError):
        policy(later, earlier)
    with pytest.raises(ValidationError):
        policy(earlier, earlier)


def test_request_rejects_duplicate_reference_and_evidence_ids() -> None:
    first = evidence("reference_alpha", "evidence_alpha")
    duplicate_reference = evidence("reference_alpha", "evidence_beta")
    with pytest.raises(ValidationError):
        request(first, duplicate_reference)
    duplicate_evidence = evidence("reference_beta", "evidence_alpha")
    with pytest.raises(ValidationError):
        request(first, duplicate_evidence)
    with pytest.raises(ValidationError):
        ExportRequest(
            package_id="audit_package_empty_inventory",
            tenant_id="demo_tenant",
            source_manifest_hash=HASH_A,
            package_created_at="2026-08-24T00:00:00Z",
            redaction_policy=policy(),
            evidence_references=(),
        )


def test_record_manifest_and_verification_result_contracts_fail_closed() -> None:
    with pytest.raises(ValidationError):
        ExportRecord(
            record_id="export_record_alpha",
            reference_id="reference_alpha",
            disposition=ExportDisposition.OMITTED,
            source_descriptor_hash=HASH_A,
        )
    with pytest.raises(ValidationError):
        ExportRecord(
            record_id="export_record_included",
            reference_id="reference_included",
            disposition=ExportDisposition.INCLUDED,
            source_descriptor_hash=HASH_A,
            matching_rule_id="rule_alpha",
            evidence_path="evidence/export_record_included.json",
            evidence_sha256=HASH_A,
        )
    with pytest.raises(ValidationError):
        ExportRecord(
            record_id="export_record_redacted",
            reference_id="reference_redacted",
            disposition=ExportDisposition.REDACTED,
            source_descriptor_hash=HASH_A,
            matching_rule_id="rule_alpha",
            selected_value_hash=HASH_A,
        )
    rendered = render_package(request())
    first_file = rendered.manifest.files[0]
    with pytest.raises(ValidationError):
        PackageManifest(
            package_id=rendered.manifest.package_id,
            tenant_id=rendered.manifest.tenant_id,
            source_manifest_hash=rendered.manifest.source_manifest_hash,
            package_created_at=rendered.manifest.package_created_at,
            redaction_policy_id=rendered.manifest.redaction_policy_id,
            redaction_policy_version=rendered.manifest.redaction_policy_version,
            policy_hash=rendered.manifest.policy_hash,
            records=rendered.manifest.records,
            files=(PackageFile(path=first_file.path, sha256=first_file.sha256),),
            package_root_hash=rendered.manifest.package_root_hash,
        )
    with pytest.raises(ValidationError):
        VerificationResult(valid=True, errors=("invalid",))
    with pytest.raises(ValidationError):
        VerificationResult(valid=False)


def test_manifest_rejects_duplicate_unsorted_and_inconsistent_file_inventories() -> None:
    rendered = render_package(
        request(
            evidence("reference_alpha", "evidence_alpha"),
            evidence("reference_beta", "evidence_beta"),
        )
    )
    manifest = rendered.manifest
    duplicate_records = (*manifest.records, manifest.records[0])
    with pytest.raises(ValidationError):
        PackageManifest.model_validate({**manifest.model_dump(), "records": duplicate_records})
    reversed_records = tuple(reversed(manifest.records))
    with pytest.raises(ValidationError):
        PackageManifest.model_validate({**manifest.model_dump(), "records": reversed_records})
    duplicate_files = (*manifest.files, manifest.files[0])
    with pytest.raises(ValidationError):
        PackageManifest.model_validate({**manifest.model_dump(), "files": duplicate_files})
    mismatched_record = manifest.records[0].model_copy(update={"evidence_sha256": HASH_A})
    with pytest.raises(ValidationError):
        PackageManifest.model_validate(
            {**manifest.model_dump(), "records": (mismatched_record, *manifest.records[1:])}
        )
