# flux: a SARIF 2.1.0 profile for the cschooley security toolkit

Status: draft v0.1 (Nov 2026)

## What flux is (and isn't)

flux is **not a new schema**. It is a profile of [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) (OASIS): a set of conventions on which fields are required, how fingerprints are computed, and which property-bag keys the toolkit uses. A flux document is a valid SARIF document. Any SARIF consumer can read it; flux-aware tools get extra guarantees.

Producers and consumers:

| Tool | Role |
|---|---|
| scurf (Rust SAST) | produces |
| tap-http (Rust DAST / MITM proxy) | produces and consumes |
| sarifview (VS Code) | consumes / merges |
| sec-actions, ghas-actions | produce / gate on |
| Kudzu | consumes (system of record), produces (retest requests, known findings) |

Kudzu may use any internal model it likes. flux is the interchange format, not a database schema.

## Rules

1. **Valid SARIF 2.1.0.** Validate against the official JSON schema. No top-level extensions.
2. **Custom data only in property bags**, under the `flux/` key prefix (e.g. `properties["flux/status"]`).
3. **Standard fields first.** If SARIF has a field for it, use the field, not a property.

## Field mapping

| Concept | SARIF field | flux convention |
|---|---|---|
| Vuln class | `result.ruleId`, `run.tool.driver.rules[]` | Rule IDs stable per tool |
| CWE / CAPEC | `run.taxonomies[]`, `result.taxa[]` | CWE taxonomy required where applicable |
| Severity | `result.level` | `error` / `warning` / `note` |
| Confidence / priority | `result.rank` (0-100) | Tool-reported confidence |
| Dedup key | `result.fingerprints` | Required. See Fingerprints |
| Same issue across runs | `result.correlationGuid` | Assigned on first confirmation, preserved after |
| Run-over-run diff | `result.baselineState` | `new` / `unchanged` / `updated` / `absent` |
| Triage: rejected, accepted risk | `result.suppressions[]` | `status` + `justification` required |
| Duplicate | `result.suppressions[]` | `justification` references the original `correlationGuid` |
| Tracked ticket | `result.workItemUris[]` | Kudzu / Jira / GitHub issue URIs |
| First/last seen | `result.provenance` | `firstDetectionTimeUtc`, `lastDetectionTimeUtc` |
| SAST code location | `result.locations[].physicalLocation` | File + region |
| DAST endpoint | `result.locations[]` | `artifactLocation.uri` = URL (query stripped); method in `logicalLocations` |
| SAST location on a DAST-confirmed finding | `result.relatedLocations[]` | Preserved when DAST confirms a SAST hypothesis |
| HTTP evidence | `result.webRequest`, `result.webResponse` | See Evidence |
| Data flow | `result.codeFlows[]` | SAST optional |

## flux property-bag keys

| Key | Type | Meaning |
|---|---|---|
| `flux/status` | `candidate` \| `suspected` \| `confirmed` \| `fixed` | Verification state (orthogonal to suppression) |
| `flux/confirmedBy` | string[] | Tools that confirmed, e.g. `["scurf", "tap-http"]` |
| `flux/replayIds` | string[] | tap-http replay API IDs backing the evidence |
| `flux/redacted` | boolean | Evidence has been scrubbed (see Redaction) |
| `flux/hypothesisFor` | string | On tap-http output: `correlationGuid` of the ingested finding it tested |
| `flux/fingerprintVersion` | string | Fingerprint algorithm version |

`flux/status` is about whether the issue is real. `suppressions` is about what a human decided to do with it. A finding can be `confirmed` and suppressed (accepted risk).

## Fingerprints

Every result carries `fingerprints` with at least one flux key:

- **DAST:** `flux/dast/v1` = SHA-256 of `host | method | normalized path | parameter name | ruleId`
  - Normalized path: lowercase host, numeric and UUID segments replaced with `{id}`, trailing slash removed, query string removed.
- **SAST:** `flux/sast/v1` = SHA-256 of `repo | file path | function/symbol | ruleId` (avoid line numbers; they drift).

Changing the algorithm means a new version suffix. Consumers match on any shared key.

## Evidence (DAST)

- Request/response pairs use SARIF `webRequest` / `webResponse`.
- Large or multiple exchanges: include the decisive pair inline, reference the rest via `flux/replayIds`.
- Evidence is appended, never replaced, as findings move from `suspected` to `confirmed`.

## Redaction

Required before any flux document leaves the producing tool's local store (export, promotion, upload):

- Scrub `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and token-shaped values (JWTs, bearer tokens, API keys by pattern) in headers, bodies, and URLs.
- Replace with `[REDACTED:<kind>]`.
- Set `flux/redacted: true`.
- Unredacted export requires an explicit opt-in flag and leaves `flux/redacted: false` so consumers can refuse it.

## Flows

**Promotion (tap-http to Kudzu):** results with `flux/status` in `suspected` / `confirmed`, unsuppressed, redacted.

**Hypotheses (scurf to tap-http):** SAST results with `flux/status: suspected`. tap-http tests them and emits a result with the same `correlationGuid`, `flux/hypothesisFor` set, the SAST location moved to `relatedLocations`, and status `confirmed` or left `suspected` with a note in `result.message`.

**Retest (Kudzu to tap-http):** open findings out, results back with `baselineState` (`unchanged` = still vulnerable, `absent` = not reproduced) and `flux/status: fixed` where appropriate.

**Known findings / suppressions (Kudzu to tools):** consumed so producers can badge results as tracked (`workItemUris`) or previously rejected (`suppressions`) instead of re-raising them.

## Optional exporters

- **OCSF** (Vulnerability Finding class) for SIEM / security data lake consumers. A one-way export, not interchange.

## Repo contents (planned)

- `SPEC.md`: this document
- `schema/flux-properties.schema.json`: JSON schema for the `flux/` property bag
- `examples/`: SAST result, DAST result, SAST-confirmed-by-DAST, suppressed duplicate, retest result
- `validate/`: small validator (SARIF schema + flux rules)
