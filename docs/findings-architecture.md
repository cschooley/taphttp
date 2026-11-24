# Findings architecture: taphttp and spall

Status: design intent (Nov 2026). Verify against current code before implementing.

## Decision

taphttp stays what CLAUDE.md says it is: a headless proxy that captures, logs, and replays. It does **not** get a GUI, a findings model, or agent tooling.

The SPA dashboard, the MCP server for agentic assessments, candidate triage, and flux export live in **[spall](https://github.com/cschooley/spall)**, a separate tool that consumes taphttp's traffic log and replay API. A thick Burp-style client was rejected; SPA + MCP is the chosen shape for spall. Per the flux spec, spall is the DAST producer; taphttp produces no findings itself.

```
browser/agent traffic -> taphttp (capture, log, replay)
                              |  JSON lines / sqlite, replay API
                              v
                       spall (SPA, MCP, triage)
                              |  flux (SARIF 2.1.0 profile)
                              v
                     Kudzu / sarifview / any SARIF consumer
```

## Format

Findings are **flux**, a SARIF 2.1.0 profile. Spec vendored at `docs/flux/SPEC.md` (source of truth: the `flux` repo). Never invent a findings format.

## What taphttp must provide (in scope here)

These are the things spall needs from taphttp. They are expensive to retrofit, so get them right now:

1. **Stable exchange IDs.** Every `TrafficEntry.id` is stable and never reused. Findings evidence references these IDs (`flux/replayIds`).
2. **Replays are recorded.** A replayed request/response is stored as its own `TrafficEntry`, linked to the original by `replay_of`, and failed attempts are recorded too (with `error` set). Evidence and retest both depend on this, and so does a rules-of-engagement record of what was sent. A replay's caller can attach `meta` (who caused it); it is stored, never sent upstream. New requests made with `POST /send` (spall's `fetch`) are recorded the same way, with `origin: "send"`; every entry's `origin` says whether it was proxied, replayed or sent.
3. **Programmatic access.** Query and replay are usable without the CLI (the `taphttp-types` crate and the Lever HTTP API), per the existing "separable modules" rule.
4. **Raw storage, no redaction.** taphttp stores traffic as captured. Redaction is spall's job at export time (via the flux crate).

Nothing else in this document is taphttp's job.

## spall design (lives in the spall repo)

### Two tiers: candidates vs findings

| | spall (workbench) | Kudzu (system of record) |
|---|---|---|
| Holds | Candidates | Findings |
| Lifetime | Per engagement | Durable |
| Lifecycle | Triage only | Full (ticketing, SLA, retest, closure) |

The SPA shows candidates live while testing. Only triaged candidates are exported.

Triage in flux terms:
- New: `flux/status: candidate`
- Promoted: `flux/status: suspected` or `confirmed`, exported
- Rejected: `suppressions[]` with `status: rejected` + `justification`
- Duplicate: `suppressions[]`, justification references the original `correlationGuid`

Suppressions are retained so the same false positive is not re-raised.

### Agent autonomy boundary (MCP)

- `propose_finding`: available to the agent.
- `promote_finding`: not exposed to the agent by default; requires a human in the SPA.
- Optional later: explicit opt-in auto-promotion rules. Never the default.

Promotion flows toward Jira. An agent must not file tickets unsupervised.

### No Kudzu coupling

spall reads and writes flux only. Kudzu ingests flux.

### Flux out

Fingerprint at candidate creation (`flux/dast/v1`), `webRequest`/`webResponse` evidence, `flux/replayIds`, redaction applied on export.

### Flux in

1. SAST hypotheses from scurf: target the endpoint, keep `correlationGuid`, move SAST location to `relatedLocations`, append evidence.
2. Retest from Kudzu: replay via taphttp, emit `baselineState` (`unchanged` / `absent`).
3. Known findings and suppressions: badge candidates as tracked (`workItemUris`) or previously rejected.

### Implementation order

1. taphttp requirements above.
2. spall: candidate model, SPA triage, flux export with redaction.
3. MCP with `propose_finding` only.
4. Flux in: suppressions and retest.
5. Flux in: scurf hypothesis correlation.
