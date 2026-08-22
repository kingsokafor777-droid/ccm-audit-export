"""File-only CLI for deterministic CCM audit-package export and verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .evaluator import verify_package, write_package
from .models import ExportRequest


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _read_request(path: Path) -> ExportRequest:
    try:
        return ExportRequest.model_validate_json(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"could not read JSON request from {path}") from exc


def _export(request_path: Path, output: Path, overwrite: bool) -> int:
    try:
        manifest = write_package(_read_request(request_path), output, overwrite=overwrite)
    except (ValidationError, ValueError) as exc:
        _emit({"valid": False, "error": str(exc)})
        return 2
    _emit(
        {
            "valid": True,
            "manifest_id": manifest.manifest_id,
            "manifest_hash": manifest.manifest_hash,
            "package_root_hash": manifest.package_root_hash,
        }
    )
    return 0


def _verify(output: Path) -> int:
    result = verify_package(output)
    _emit(result.model_dump(mode="json", exclude_none=True))
    return 0 if result.valid else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ccm-audit-export")
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export", help="render a deterministic evidence-reference package")
    export.add_argument("request", type=Path)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--overwrite", action="store_true")
    verify = commands.add_parser("verify", help="verify an extracted package")
    verify.add_argument("package", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "export":
        return _export(args.request, args.output, args.overwrite)
    return _verify(args.package)
