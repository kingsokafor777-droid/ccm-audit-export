# ccm-audit-export

`ccm-audit-export` is a **deterministic, offline, payload-minimizing** package that
renders supplied technical-evidence references into reproducible audit-preparation
packages. It creates a closed export inventory, declares redaction actions, produces
canonical SHA-256 integrity manifests, and verifies an extracted package without a
network, database, scheduler, cloud credential, raw evidence payload, or wall-clock
dependency.

> **Scope boundary:** An export package is a review artifact, not an audit opinion,
> certification, authorization, legal record, or framework-conformance determination.
> The package does not authenticate people, validate external source systems, preserve
> original evidence bytes, execute retention or deletion, or make acceptance decisions.

NIST SP 800-53A describes a methodology and procedures for control assessments, while
NIST SP 800-37 places assessment, authorization, and continuous monitoring in a broader
risk-management process. This component deliberately provides reproducible technical
artifact preparation only; qualified reviewers and applicable organizational processes
remain responsible for assessment and authorization decisions.[1][2]

## What it guarantees

| Capability | Deterministic behavior |
|---|---|
| **Package inventory** | Every source input is transformed into one sorted evidence-reference record or rejected. |
| **Redaction declaration** | Each omission is explicit, rule-bound, reasoned, and represented by a stable SHA-256 digest of the redaction descriptor—not by a hidden mutation. |
| **Integrity manifest** | Each rendered evidence-reference file and the policy record is SHA-256 hashed, then sealed in a canonical manifest. |
| **Offline verification** | The verifier detects missing, unexpected, modified, malformed, or manifest-tampered package entries. |
| **Reproducibility** | The same strict request produces byte-identical package files and manifest hash. |

## What it does not do

The package contains **metadata and evidence references only**. It does not include
credentials, cloud API calls, source snapshots, personal data, screenshots, raw logs,
or attachments. Redaction is an export-time declaration, not a deletion/retention
operation. A redaction rule does not constitute a legal, privacy, audit, or records
management determination.

## Quick start

```bash
python -m pip install -e .

# Build a deterministic synthetic package.
ccm-audit-export export fixtures/safe-request.json --output /tmp/ccm-package

# Verify an extracted package using its sealed manifest.
ccm-audit-export verify /tmp/ccm-package
```

The fixture is synthetic. Its evidence IDs and hashes are examples only; they do not
represent AWS, Azure, customer, audit, or production evidence.

## Package layout

```text
<output>/
  manifest.json                         # sealed inventory and integrity root
  policy.json                           # rendered redaction-policy declaration
  evidence/<evidence-reference-id>.json # payload-blind exported reference records
```

## Quality and release posture

The repository requires Ruff, formatter, strict mypy, branch-aware pytest coverage,
generated fixture/schema drift checks, wheel-content verification, immutable-pinned CI
and CodeQL workflows, and protected `main` after hosted verification. See
[`docs/design.md`](docs/design.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), and
[`SECURITY.md`](SECURITY.md) for contracts and reporting boundaries.

## References

[1] [NIST SP 800-53A Rev. 5 — Assessing Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final)

[2] [NIST SP 800-37 Rev. 2 — Risk Management Framework](https://csrc.nist.gov/pubs/sp/800/37/r2/final)
