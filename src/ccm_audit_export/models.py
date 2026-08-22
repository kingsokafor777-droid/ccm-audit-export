"""Strict payload-blind public contracts for deterministic CCM audit-package exports."""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .canonical import require_digest, sha256_digest, stable_identifier

SCHEMA_VERSION: Final = "ccm.audit_export/v1"
UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
METADATA_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
RELATIVE_PATH_PATTERN = re.compile(r"^(?:policy\.json|evidence/[a-z][a-z0-9_]{1,63}\.json)$")
UTCDateTime = Annotated[str, StringConstraints(pattern=UTC_TIMESTAMP_PATTERN.pattern)]
StableId = Annotated[str, StringConstraints(pattern=ID_PATTERN.pattern)]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    """Public contract base that rejects coercion and undeclared fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RedactionSelector(str, Enum):
    ASSET_ID = "asset_id"
    RESOURCE_IDENTIFIER = "resource_identifier"
    SUBJECT_IDENTIFIER = "subject_identifier"
    METADATA = "metadata"


class RedactionAction(str, Enum):
    OMIT_RECORD = "omit_record"
    REPLACE_WITH_DIGEST = "replace_with_digest"


class ExportDisposition(str, Enum):
    INCLUDED = "included"
    OMITTED = "omitted"
    REDACTED = "redacted"


class EvidenceReference(StrictModel):
    """Payload-blind technical evidence reference suitable for controlled handoff."""

    reference_id: StableId
    evidence_id: StableId
    evidence_hash: str
    source_id: StableId
    collector_id: StableId
    control_id: StableId
    control_version: NonEmpty
    observed_at: UTCDateTime
    asset_id: StableId
    resource_identifier: NonEmpty | None = None
    subject_identifier: NonEmpty | None = None
    metadata: dict[str, str] = Field(
        default_factory=dict,
        json_schema_extra={"additionalProperties": {"type": "string"}},
    )

    @field_validator("evidence_hash")
    @classmethod
    def _validate_evidence_hash(cls, value: str) -> str:
        return require_digest(value)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 32:
            raise ValueError("metadata has a maximum of 32 declared labels")
        if any(not METADATA_KEY_PATTERN.fullmatch(key) for key in value):
            raise ValueError("metadata keys must be lower-case snake_case")
        return value

    @model_validator(mode="after")
    def _validate_payload_blind_reference(self) -> EvidenceReference:
        forbidden = {"raw_payload", "secret", "token", "password", "credential", "attachment"}
        if forbidden & set(self.metadata):
            raise ValueError("metadata must not carry raw payload or secret-like fields")
        return self


class RedactionRule(StrictModel):
    """Closed, exact-match declaration for an export-time record transformation."""

    rule_id: StableId
    selector: RedactionSelector
    match_value: NonEmpty
    action: RedactionAction
    rationale: NonEmpty
    metadata_key: Annotated[str, StringConstraints(pattern=METADATA_KEY_PATTERN.pattern)] | None = (
        None
    )

    @model_validator(mode="after")
    def _validate_selector_shape(self) -> RedactionRule:
        if self.selector == RedactionSelector.METADATA and self.metadata_key is None:
            raise ValueError("metadata selector requires metadata_key")
        if self.selector != RedactionSelector.METADATA and self.metadata_key is not None:
            raise ValueError("metadata_key is valid only with the metadata selector")
        return self


class RedactionPolicy(StrictModel):
    """Immutable declared redaction policy applied in deterministic rule-ID order."""

    policy_id: StableId
    version: NonEmpty
    rules: tuple[RedactionRule, ...] = ()

    @model_validator(mode="after")
    def _validate_rules(self) -> RedactionPolicy:
        rule_ids = tuple(rule.rule_id for rule in self.rules)
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("redaction policy rule IDs must be unique")
        if rule_ids != tuple(sorted(rule_ids)):
            raise ValueError("redaction policy rules must be ordered by rule_id")
        return self


class ExportRequest(StrictModel):
    """All caller-supplied inputs for one reproducible local evidence-package export."""

    schema_version: Literal["ccm.audit_export/v1"] = SCHEMA_VERSION
    package_id: StableId
    tenant_id: StableId
    source_manifest_hash: str
    package_created_at: UTCDateTime
    redaction_policy: RedactionPolicy
    evidence_references: tuple[EvidenceReference, ...]
    description: NonEmpty | None = None

    @field_validator("source_manifest_hash")
    @classmethod
    def _validate_source_manifest_hash(cls, value: str) -> str:
        return require_digest(value)

    @model_validator(mode="after")
    def _validate_reference_inventory(self) -> ExportRequest:
        if not self.evidence_references:
            raise ValueError("an export request requires at least one evidence reference")
        reference_ids = tuple(item.reference_id for item in self.evidence_references)
        evidence_ids = tuple(item.evidence_id for item in self.evidence_references)
        if len(set(reference_ids)) != len(reference_ids):
            raise ValueError("evidence reference IDs must be unique")
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("evidence IDs must be unique within one export")
        return self


class PackageFile(StrictModel):
    """Declared non-manifest package file and its exact-byte SHA-256 digest."""

    path: Annotated[str, StringConstraints(pattern=RELATIVE_PATH_PATTERN.pattern)]
    sha256: str

    @field_validator("sha256")
    @classmethod
    def _validate_file_digest(cls, value: str) -> str:
        return require_digest(value)


class ExportRecord(StrictModel):
    """Manifested result for one input reference; omitted records never have a file."""

    record_id: StableId
    reference_id: StableId
    disposition: ExportDisposition
    source_descriptor_hash: str
    matching_rule_id: StableId | None = None
    selected_value_hash: str | None = None
    evidence_path: (
        Annotated[
            str,
            StringConstraints(pattern=r"^evidence/[a-z][a-z0-9_]{1,63}\.json$"),
        ]
        | None
    ) = None
    evidence_sha256: str | None = None

    @field_validator("source_descriptor_hash", "selected_value_hash", "evidence_sha256")
    @classmethod
    def _validate_record_hashes(cls, value: str | None) -> str | None:
        return None if value is None else require_digest(value)

    @model_validator(mode="after")
    def _validate_disposition(self) -> ExportRecord:
        if self.disposition == ExportDisposition.INCLUDED:
            if self.matching_rule_id is not None or self.selected_value_hash is not None:
                raise ValueError("included records must not have redaction details")
            if self.evidence_path is None or self.evidence_sha256 is None:
                raise ValueError("included records require an evidence path and digest")
        elif self.disposition == ExportDisposition.OMITTED:
            if self.matching_rule_id is None or self.selected_value_hash is None:
                raise ValueError(
                    "omitted records require a matching rule and selected-value digest"
                )
            if self.evidence_path is not None or self.evidence_sha256 is not None:
                raise ValueError("omitted records must not declare evidence files")
        else:
            if self.matching_rule_id is None or self.selected_value_hash is None:
                raise ValueError(
                    "redacted records require a matching rule and selected-value digest"
                )
            if self.evidence_path is None or self.evidence_sha256 is None:
                raise ValueError("redacted records require an evidence path and digest")
        return self


class PackageManifest(StrictModel):
    """Sealed inventory and integrity root for an extracted audit-preparation package."""

    schema_version: Literal["ccm.audit_export/v1"] = SCHEMA_VERSION
    package_id: StableId
    tenant_id: StableId
    source_manifest_hash: str
    package_created_at: UTCDateTime
    redaction_policy_id: StableId
    redaction_policy_version: NonEmpty
    policy_hash: str
    records: tuple[ExportRecord, ...]
    files: tuple[PackageFile, ...]
    package_root_hash: str
    manifest_id: StableId | None = None
    manifest_hash: str | None = None

    @field_validator("source_manifest_hash", "policy_hash", "package_root_hash", "manifest_hash")
    @classmethod
    def _validate_manifest_hashes(cls, value: str | None) -> str | None:
        return None if value is None else require_digest(value)

    @model_validator(mode="after")
    def _validate_manifest_inventory(self) -> PackageManifest:
        record_ids = tuple(record.record_id for record in self.records)
        if len(set(record_ids)) != len(record_ids):
            raise ValueError("manifest record IDs must be unique")
        if record_ids != tuple(sorted(record_ids)):
            raise ValueError("manifest records must be ordered by record_id")
        paths = tuple(entry.path for entry in self.files)
        if len(set(paths)) != len(paths):
            raise ValueError("manifest file paths must be unique")
        if paths != tuple(sorted(paths)):
            raise ValueError("manifest files must be ordered by path")
        if paths.count("policy.json") != 1:
            raise ValueError("manifest must declare exactly one policy.json file")
        file_map = {entry.path: entry.sha256 for entry in self.files}
        for record in self.records:
            if record.evidence_path is None:
                continue
            if file_map.get(record.evidence_path) != record.evidence_sha256:
                raise ValueError(
                    "record evidence file declaration must match manifest file inventory"
                )
        return self

    def root_projection(self) -> tuple[dict[str, str], ...]:
        return tuple({"path": item.path, "sha256": item.sha256} for item in self.files)

    def computed_root_hash(self) -> str:
        return sha256_digest(self.root_projection())

    def hash_projection(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"manifest_id", "manifest_hash"},
            exclude_none=True,
        )

    def computed_hash(self) -> str:
        return sha256_digest(self.hash_projection())

    def seal(self) -> PackageManifest:
        content_hash = self.computed_hash()
        return self.model_copy(
            update={
                "manifest_hash": content_hash,
                "manifest_id": stable_identifier(
                    "export_manifest",
                    {"manifest_hash": content_hash},
                ),
            }
        )

    def verify_integrity(self) -> bool:
        return (
            self.package_root_hash == self.computed_root_hash()
            and self.manifest_hash is not None
            and self.manifest_hash == self.computed_hash()
            and self.manifest_id is not None
            and self.manifest_id
            == stable_identifier(
                "export_manifest",
                {"manifest_hash": self.manifest_hash},
            )
        )


class VerificationResult(StrictModel):
    """Structured result for an offline extracted-package verification attempt."""

    valid: bool
    package_id: StableId | None = None
    manifest_hash: str | None = None
    package_root_hash: str | None = None
    errors: tuple[NonEmpty, ...] = ()

    @model_validator(mode="after")
    def _validate_result(self) -> VerificationResult:
        if self.valid and self.errors:
            raise ValueError("valid verification results cannot contain errors")
        if not self.valid and not self.errors:
            raise ValueError("invalid verification results require at least one error")
        return self
