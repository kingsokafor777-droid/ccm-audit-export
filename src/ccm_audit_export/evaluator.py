"""Pure renderer and verifier for deterministic extracted CCM audit-export packages."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .canonical import sha256_bytes, sha256_digest, stable_identifier
from .models import (
    EvidenceReference,
    ExportDisposition,
    ExportRecord,
    ExportRequest,
    PackageFile,
    PackageManifest,
    RedactionAction,
    RedactionPolicy,
    RedactionRule,
    RedactionSelector,
    VerificationResult,
)


@dataclass(frozen=True)
class RenderedPackage:
    """Sealed manifest plus exact non-manifest and manifest file bytes."""

    manifest: PackageManifest
    files: dict[str, bytes]


def _render_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _selected_value(reference: EvidenceReference, rule: RedactionRule) -> str | None:
    if rule.selector == RedactionSelector.ASSET_ID:
        return reference.asset_id
    if rule.selector == RedactionSelector.RESOURCE_IDENTIFIER:
        return reference.resource_identifier
    if rule.selector == RedactionSelector.SUBJECT_IDENTIFIER:
        return reference.subject_identifier
    assert rule.metadata_key is not None
    return reference.metadata.get(rule.metadata_key)


def _matching_rule(reference: EvidenceReference, policy: RedactionPolicy) -> RedactionRule | None:
    for rule in policy.rules:
        if _selected_value(reference, rule) == rule.match_value:
            return rule
    return None


def _selection_digest(reference: EvidenceReference, rule: RedactionRule, value: str) -> str:
    return sha256_digest(
        {
            "reference_id": reference.reference_id,
            "rule_id": rule.rule_id,
            "selector": rule.selector.value,
            "metadata_key": rule.metadata_key,
            "value": value,
        }
    )


def _redacted_reference(
    reference: EvidenceReference,
    rule: RedactionRule,
    selected_value_hash: str,
) -> dict[str, Any]:
    payload = reference.model_dump(mode="json", exclude_none=True)
    if rule.selector == RedactionSelector.METADATA:
        assert rule.metadata_key is not None
        metadata = dict(payload["metadata"])
        metadata[rule.metadata_key] = selected_value_hash
        payload["metadata"] = metadata
    else:
        payload[rule.selector.value] = selected_value_hash
    return payload


def _record_id(
    request: ExportRequest,
    reference: EvidenceReference,
    rule: RedactionRule | None,
) -> str:
    return stable_identifier(
        "export_record",
        {
            "package_id": request.package_id,
            "reference_id": reference.reference_id,
            "descriptor_hash": sha256_digest(reference.model_dump(mode="json", exclude_none=True)),
            "rule_id": None if rule is None else rule.rule_id,
        },
    )


def _render_record(
    request: ExportRequest,
    reference: EvidenceReference,
) -> tuple[ExportRecord, tuple[str, bytes] | None]:
    rule = _matching_rule(reference, request.redaction_policy)
    descriptor = reference.model_dump(mode="json", exclude_none=True)
    descriptor_hash = sha256_digest(descriptor)
    record_id = _record_id(request, reference, rule)
    if rule is None:
        path = f"evidence/{record_id}.json"
        rendered = _render_json({"record_id": record_id, "reference": descriptor})
        digest = sha256_bytes(rendered)
        return (
            ExportRecord(
                record_id=record_id,
                reference_id=reference.reference_id,
                disposition=ExportDisposition.INCLUDED,
                source_descriptor_hash=descriptor_hash,
                evidence_path=path,
                evidence_sha256=digest,
            ),
            (path, rendered),
        )
    selected = _selected_value(reference, rule)
    assert selected is not None
    selected_hash = _selection_digest(reference, rule, selected)
    if rule.action == RedactionAction.OMIT_RECORD:
        return (
            ExportRecord(
                record_id=record_id,
                reference_id=reference.reference_id,
                disposition=ExportDisposition.OMITTED,
                source_descriptor_hash=descriptor_hash,
                matching_rule_id=rule.rule_id,
                selected_value_hash=selected_hash,
            ),
            None,
        )
    path = f"evidence/{record_id}.json"
    rendered = _render_json(
        {
            "record_id": record_id,
            "reference": _redacted_reference(reference, rule, selected_hash),
            "redaction": {
                "rule_id": rule.rule_id,
                "selector": rule.selector.value,
                "metadata_key": rule.metadata_key,
                "selected_value_hash": selected_hash,
                "rationale": rule.rationale,
            },
        }
    )
    digest = sha256_bytes(rendered)
    return (
        ExportRecord(
            record_id=record_id,
            reference_id=reference.reference_id,
            disposition=ExportDisposition.REDACTED,
            source_descriptor_hash=descriptor_hash,
            matching_rule_id=rule.rule_id,
            selected_value_hash=selected_hash,
            evidence_path=path,
            evidence_sha256=digest,
        ),
        (path, rendered),
    )


def render_package(request: ExportRequest) -> RenderedPackage:
    """Render a sealed package entirely from strict caller-supplied input contracts."""

    policy_payload = request.redaction_policy.model_dump(mode="json", exclude_none=True)
    rendered_files: dict[str, bytes] = {"policy.json": _render_json(policy_payload)}
    records: list[ExportRecord] = []
    for reference in sorted(request.evidence_references, key=lambda item: item.reference_id):
        record, file_entry = _render_record(request, reference)
        records.append(record)
        if file_entry is not None:
            path, rendered = file_entry
            rendered_files[path] = rendered
    files = tuple(
        PackageFile(path=path, sha256=sha256_bytes(rendered))
        for path, rendered in sorted(rendered_files.items())
    )
    manifest = PackageManifest(
        package_id=request.package_id,
        tenant_id=request.tenant_id,
        source_manifest_hash=request.source_manifest_hash,
        package_created_at=request.package_created_at,
        redaction_policy_id=request.redaction_policy.policy_id,
        redaction_policy_version=request.redaction_policy.version,
        policy_hash=sha256_digest(policy_payload),
        records=tuple(sorted(records, key=lambda item: item.record_id)),
        files=files,
        package_root_hash=sha256_digest(
            tuple({"path": item.path, "sha256": item.sha256} for item in files)
        ),
    ).seal()
    rendered_files["manifest.json"] = _render_json(
        manifest.model_dump(mode="json", exclude_none=True)
    )
    return RenderedPackage(manifest=manifest, files=rendered_files)


def write_package(
    request: ExportRequest,
    destination: Path,
    *,
    overwrite: bool = False,
) -> PackageManifest:
    """Write generated files without deleting existing package content."""

    rendered = render_package(request)
    expected_paths = set(rendered.files)
    if destination.exists():
        if not destination.is_dir():
            raise ValueError("export destination must be a directory path")
        existing_files = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file()
        }
        if existing_files and not overwrite:
            raise ValueError("export destination is not empty; pass overwrite explicitly")
        unexpected = existing_files - expected_paths
        if unexpected:
            raise ValueError("export destination contains unexpected files; no files were deleted")
    destination.mkdir(parents=True, exist_ok=True)
    for relative_path, content in rendered.files.items():
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return rendered.manifest


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _verify_record_content(
    record: ExportRecord,
    package_path: Path,
    policy: RedactionPolicy,
) -> list[str]:
    if record.disposition == ExportDisposition.OMITTED:
        return []
    assert record.evidence_path is not None
    errors: list[str] = []
    payload = _read_json(package_path / record.evidence_path)
    if payload.get("record_id") != record.record_id:
        errors.append(f"record ID mismatch in {record.evidence_path}")
    if record.disposition == ExportDisposition.INCLUDED:
        reference = EvidenceReference.model_validate(payload.get("reference"))
        descriptor_hash = sha256_digest(reference.model_dump(mode="json", exclude_none=True))
        if descriptor_hash != record.source_descriptor_hash:
            errors.append(f"source descriptor hash mismatch in {record.evidence_path}")
        return errors
    redaction = payload.get("redaction")
    if not isinstance(redaction, dict):
        return [*errors, f"missing redaction declaration in {record.evidence_path}"]
    if redaction.get("rule_id") != record.matching_rule_id:
        errors.append(f"redaction rule mismatch in {record.evidence_path}")
    if redaction.get("selected_value_hash") != record.selected_value_hash:
        errors.append(f"redaction selected-value digest mismatch in {record.evidence_path}")
    if record.matching_rule_id not in {rule.rule_id for rule in policy.rules}:
        errors.append(f"redaction rule is absent from policy for {record.evidence_path}")
    return errors


def verify_package(destination: Path) -> VerificationResult:
    """Fail closed while verifying a previously extracted package with no network access."""

    manifest_path = destination / "manifest.json"
    errors: list[str] = []
    try:
        manifest = PackageManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        return VerificationResult(valid=False, errors=(f"invalid manifest: {type(exc).__name__}",))
    if not manifest.verify_integrity():
        errors.append("manifest sealed integrity does not verify")
    actual_files = {
        path.relative_to(destination).as_posix()
        for path in destination.rglob("*")
        if path.is_file()
    }
    expected_files = {"manifest.json", *(entry.path for entry in manifest.files)}
    missing = sorted(expected_files - actual_files)
    unexpected = sorted(actual_files - expected_files)
    errors.extend(f"missing package file: {path}" for path in missing)
    errors.extend(f"unexpected package file: {path}" for path in unexpected)
    for entry in manifest.files:
        target = destination / entry.path
        if not target.is_file():
            continue
        if sha256_bytes(target.read_bytes()) != entry.sha256:
            errors.append(f"digest mismatch: {entry.path}")
    try:
        policy = RedactionPolicy.model_validate_json(
            (destination / "policy.json").read_text(encoding="utf-8")
        )
        if sha256_digest(policy.model_dump(mode="json", exclude_none=True)) != manifest.policy_hash:
            errors.append("policy hash mismatch")
        if policy.policy_id != manifest.redaction_policy_id:
            errors.append("policy ID mismatch")
        if policy.version != manifest.redaction_policy_version:
            errors.append("policy version mismatch")
        for record in manifest.records:
            errors.extend(_verify_record_content(record, destination, policy))
    except (OSError, json.JSONDecodeError, ValidationError, ValueError, TypeError) as exc:
        errors.append(f"invalid package content: {type(exc).__name__}")
    if errors:
        return VerificationResult(valid=False, errors=tuple(sorted(set(errors))))
    return VerificationResult(
        valid=True,
        package_id=manifest.package_id,
        manifest_hash=manifest.manifest_hash,
        package_root_hash=manifest.package_root_hash,
    )
