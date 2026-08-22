"""Export ccm-audit-export public JSON Schemas deterministically."""

from __future__ import annotations

import json
from pathlib import Path

from ccm_audit_export.models import (
    EvidenceReference,
    ExportRecord,
    ExportRequest,
    PackageManifest,
    RedactionPolicy,
    VerificationResult,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "v1"
MODELS = {
    "evidence-reference.schema.json": EvidenceReference,
    "export-record.schema.json": ExportRecord,
    "export-request.schema.json": ExportRequest,
    "package-manifest.schema.json": PackageManifest,
    "redaction-policy.schema.json": RedactionPolicy,
    "verification-result.schema.json": VerificationResult,
}


def main() -> None:
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for filename, model in MODELS.items():
        content = json.dumps(
            model.model_json_schema(),
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
        (SCHEMAS / filename).write_text(content + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
