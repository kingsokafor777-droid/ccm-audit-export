# Contributing

Contributions must preserve ccm-audit-export’s strict local-first boundary. Public
contracts are frozen, unknown fields are rejected, schemas and fixtures are regenerated,
and deterministic behavior is mandatory.

Do not add cloud SDKs, HTTP clients, databases, schedulers, background workers, current
time calls, random values, credentials, raw evidence payloads, source attachments,
automatic deletion, retention execution, identity verification, authorization logic, or
certification/audit-opinion language. Redaction remains a declared export transformation;
it is not a legal, privacy, retention, or records-management decision.

Run `make fixtures schemas quality package-check` before opening a pull request. Update
tests and generated schemas for any public-contract change. Do not place real customer,
cloud, or audit evidence in fixtures, issues, commits, or releases.
