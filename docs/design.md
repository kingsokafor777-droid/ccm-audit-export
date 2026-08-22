# ccm-audit-export design contract

## 1. Purpose and boundary

`ccm-audit-export` converts **supplied payload-blind evidence references** into a
reproducible, extracted package. It is a local pure transformation: the request contains
all inputs, `export_package()` produces files, and `verify_package()` validates those
files. There is no cloud collector, database, web service, scheduler, background worker,
credential, raw evidence payload, or current-clock call.

The package supports technical preparation and reviewer handoff. It does not assess a
system independently, attest to control effectiveness, authorize risk, certify
conformance, decide redaction legality, preserve retention records, or prove that a
referenced source remains available.

## 2. Input and output contracts

| Contract | Required properties |
|---|---|
| **Export request** | Stable package/tenant IDs, supplied assessment or case manifest hash, explicit package timestamp, source evidence references, closed redaction policy, and optional description metadata. |
| **Evidence reference** | Stable reference ID, evidence ID, evidence SHA-256, source/collector identifiers, control ID/version, observed timestamp, and closed metadata labels. No raw evidence body is permitted. |
| **Redaction rule** | Stable rule ID, one closed selector (`asset_id`, `resource_identifier`, `subject_identifier`, or `metadata.<key>`), an allowed action (`omit_record` or `replace_with_digest`), and a non-empty rationale. |
| **Export record** | Original reference ID, stable record ID, policy decision, descriptor digest, and only permitted fields. Omitted records have no exported evidence-reference file. |
| **Manifest** | Canonical package projection, policy digest, per-file digests, sorted inventory, package root digest, manifest hash, and deterministic ID. |

## 3. Redaction semantics

Redaction rules are applied in ascending `rule_id` order. A rule selector matches an
exact string value. The first matching rule wins. Records with no match are included.

| Action | Rendered result | Integrity behavior |
|---|---|---|
| `omit_record` | No evidence file is written; the manifest retains an omission record with rule ID, rationale, and digest of the removed descriptor. | The verifier confirms that no file exists for the omitted record and that the declared omission remains intact. |
| `replace_with_digest` | The selected value is replaced by a SHA-256 descriptor digest; all unrelated allowed metadata remains. | The verifier checks the rendered file against its manifest digest and recomputes the descriptor digest from the preserved redaction record. |

Redaction never silently removes a record or property. A rule may not match more than one
selector at once, may not use wildcards, and may not target secret/raw-payload fields
because those fields are not part of the input contract.

## 4. Integrity and reproducibility

The canonical profile is `ccm-jcs/v1`: UTF-8 JSON, sorted object keys, lower-case
`sha256:<hex>` digests, no floating-point values, and I-JSON-safe integers only. The
package root is the SHA-256 digest of the sorted list of `(relative path, file digest)`
pairs, excluding `manifest.json`. The manifest hash is computed over the manifest without
`manifest_hash` or `manifest_id`.

Verification fails closed for malformed JSON, missing files, unexpected files, duplicate
relative paths, digest mismatch, policy mismatch, manifest mismatch, invariant violation,
or non-canonical derived IDs. It does not attempt network recovery or infer a missing
source payload.

## 5. Supplied-time rule

`package_created_at` is caller-supplied and preserved verbatim. The package never reads a
system clock. Therefore a repeat export of equal inputs produces equal package bytes and
equal sealed manifests.

## 6. Security and operational responsibilities

Callers must classify source data, choose lawful/approved redaction policy, protect the
output directory, retain or delete original evidence under their own policy, and obtain
independent review. Operators must transfer packages through approved channels. This
library does not enforce data residency, retention, legal holds, identity, approvals, or
records-management controls.

## References

[1] [NIST SP 800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final)

[2] [NIST SP 800-37 Rev. 2](https://csrc.nist.gov/pubs/sp/800/37/r2/final)

[3] [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
