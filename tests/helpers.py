"""Deterministic synthetic ccm-audit-export contract builders."""

from __future__ import annotations

from ccm_audit_export.models import (
    EvidenceReference,
    ExportRequest,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
    RedactionSelector,
)

HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
HASH_D = "sha256:" + ("d" * 64)


def evidence(
    reference_id: str,
    evidence_id: str,
    *,
    asset_id: str = "asset_identity",
    resource_identifier: str | None = "resource_identity_summary",
    subject_identifier: str | None = None,
    metadata: dict[str, str] | None = None,
) -> EvidenceReference:
    return EvidenceReference(
        reference_id=reference_id,
        evidence_id=evidence_id,
        evidence_hash=HASH_B,
        source_id="source_assessor",
        collector_id="collector_identity",
        control_id="identity_mfa_coverage",
        control_version="1.0.0",
        observed_at="2026-08-21T00:00:00Z",
        asset_id=asset_id,
        resource_identifier=resource_identifier,
        subject_identifier=subject_identifier,
        metadata=metadata or {"environment": "synthetic"},
    )


def policy(*rules: RedactionRule) -> RedactionPolicy:
    return RedactionPolicy(policy_id="demo_redaction_policy", version="1.0.0", rules=rules)


def rule(
    rule_id: str,
    *,
    selector: RedactionSelector,
    match_value: str,
    action: RedactionAction,
    metadata_key: str | None = None,
) -> RedactionRule:
    return RedactionRule(
        rule_id=rule_id,
        selector=selector,
        match_value=match_value,
        action=action,
        rationale=f"synthetic rationale for {rule_id}",
        metadata_key=metadata_key,
    )


def request(
    *references: EvidenceReference,
    redaction_policy: RedactionPolicy | None = None,
) -> ExportRequest:
    return ExportRequest(
        package_id="audit_package_identity_review",
        tenant_id="demo_tenant",
        source_manifest_hash=HASH_A,
        package_created_at="2026-08-24T00:00:00Z",
        redaction_policy=redaction_policy or policy(),
        evidence_references=references
        or (evidence("reference_identity_mfa", "evidence_identity_mfa"),),
        description="synthetic payload-blind evidence package",
    )
