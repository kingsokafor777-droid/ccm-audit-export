# ccm-audit-export research basis

This repository uses the following primary sources to define its narrow technical
artifact boundary. These sources inform documentation only; they are not implemented as
control text, audit methodology, authorization logic, or a certification rule engine.

| Source | Relevant design consequence |
|---|---|
| [NIST SP 800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final) | Assessment procedures are part of a broader methodology; a deterministic evidence-reference package cannot independently conduct an assessment or render an opinion. |
| [NIST SP 800-37 Rev. 2](https://csrc.nist.gov/pubs/sp/800/37/r2/final) | Assessment, authorization, accountability, and continuous monitoring belong to organizational risk-management processes; the package records no authorization decision. |
| [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | NIST cautions that mappings are not necessarily one-to-one or equivalent; ccm-audit-export preserves supplied identifiers rather than inferring conformance. |

> The package is a reproducible technical-preparation artifact. The reviewer, auditor,
> system owner, records authority, and authorizing authority retain their respective
> responsibilities.
