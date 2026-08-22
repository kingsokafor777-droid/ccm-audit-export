"""Build deterministic synthetic ccm-audit-export request and extracted-package fixtures."""

from __future__ import annotations

import json
from pathlib import Path

from ccm_audit_export.evaluator import write_package
from ccm_audit_export.models import (
    EvidenceReference,
    ExportRequest,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
    RedactionSelector,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)
HASH_C = "sha256:" + ("c" * 64)
HASH_D = "sha256:" + ("d" * 64)


def build_request() -> ExportRequest:
    return ExportRequest(
        package_id="audit_package_identity_review",
        tenant_id="demo_tenant",
        source_manifest_hash=HASH_A,
        package_created_at="2026-08-24T00:00:00Z",
        description="synthetic payload-blind technical evidence-reference package",
        redaction_policy=RedactionPolicy(
            policy_id="demo_redaction_policy",
            version="1.0.0",
            rules=(
                RedactionRule(
                    rule_id="rule_omit_sensitive_asset",
                    selector=RedactionSelector.ASSET_ID,
                    match_value="asset_sensitive",
                    action=RedactionAction.OMIT_RECORD,
                    rationale="synthetic omitted asset reference",
                ),
                RedactionRule(
                    rule_id="rule_redact_resource_identifier",
                    selector=RedactionSelector.RESOURCE_IDENTIFIER,
                    match_value="resource_sensitive",
                    action=RedactionAction.REPLACE_WITH_DIGEST,
                    rationale="synthetic resource identifier redaction",
                ),
            ),
        ),
        evidence_references=(
            EvidenceReference(
                reference_id="reference_identity_mfa",
                evidence_id="evidence_identity_mfa",
                evidence_hash=HASH_B,
                source_id="source_assessor",
                collector_id="collector_aws_identity",
                control_id="identity_mfa_coverage",
                control_version="1.0.0",
                observed_at="2026-08-21T00:00:00Z",
                asset_id="asset_identity",
                resource_identifier="resource_identity_summary",
                metadata={"environment": "synthetic", "classification": "internal"},
            ),
            EvidenceReference(
                reference_id="reference_sensitive_asset",
                evidence_id="evidence_sensitive_asset",
                evidence_hash=HASH_C,
                source_id="source_assessor",
                collector_id="collector_aws_storage",
                control_id="storage_encryption",
                control_version="1.0.0",
                observed_at="2026-08-21T00:00:00Z",
                asset_id="asset_sensitive",
                resource_identifier="resource_asset_summary",
                metadata={"environment": "synthetic"},
            ),
            EvidenceReference(
                reference_id="reference_storage_logging",
                evidence_id="evidence_storage_logging",
                evidence_hash=HASH_D,
                source_id="source_assessor",
                collector_id="collector_aws_logging",
                control_id="storage_logging",
                control_version="1.0.0",
                observed_at="2026-08-21T00:00:00Z",
                asset_id="asset_storage",
                resource_identifier="resource_sensitive",
                subject_identifier="subject_operator_a",
                metadata={"environment": "synthetic"},
            ),
        ),
    )


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    request = build_request()
    rendered = json.dumps(
        request.model_dump(mode="json", exclude_none=True),
        indent=2,
        sort_keys=True,
    )
    (FIXTURES / "safe-request.json").write_text(rendered + "\n", encoding="utf-8")
    write_package(request, FIXTURES / "safe-package", overwrite=True)


if __name__ == "__main__":
    main()
