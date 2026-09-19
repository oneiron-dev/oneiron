# W7-C11 review disposition — reviewed head 41c32f86

## Review collection

The all-state, paginated PR head lookup returned `[[]]`. Paginated repository PR
search for `W7-C11` returned zero items (`incomplete_results=false`). The actual
branch is `w7/W7-C11` in `oneiron-dev/oneiron`. Thus no C11 PR exists, and there
are no Qodo, Codex or CodeRabbit issue comments, reviews or inline threads to
paginate or answer. No provider quota error occurred. Do not post to PR933 or
another ticket. The explanation below must accompany C11's eventual publication.

Original Opus/Grok roots, their calendar and pack/conflict/stream subreviews,
unfinished notes/recovery/DAG/ports subreview records, and the earlier `.w7`
audits are preserved. `target/w7-logs/review-fix/internal-ledger.md` gives the
complete deduplicated source index S1–S12; `ports-context.md` records migration
seams and remaining calls found during the edit. No replacement reviewers or
build fanout was launched.

## Dispositions

- **F-GROK-1..7 (S2; step 21): fix.** Claim reads, writes, lifecycle, target checks,
  expression preference and session-scoped visibility now consume the entity,
  edge and short-ID ports. This also removes related uncited direct reads.
  Historical/raw corruption handling, bounded scans, D19/policy checks and
  session overlay composition are retained. The earlier census counted claim/
  as part of the adapter; this repair removes that disputed boundary rather
  than broadening the exemption. Production claim-subtree census is empty.
- **F-GROK-8 (S2/S3; steps 6–9): fix.** Both calendar connectors now commit EVENT
  birth with an Auto/Active projector-recorded imported origin and the required
  source/external ID fields in one transaction. Semantic candidates still cross
  the imported-evidence Gate as Proposed. Feed and connector drift share one
  origin-preserving writer, including native recurrence/calendar fields.
- **F-OPUS-1 (S1): skip as invalid.** NOTE (1–5), calendar engine (6–9), recovery
  (10–12), criticality (15–16), persistent conflicts/ranking (18–20), MESSAGE
  streaming (24) and all 24 implementation-note entries already exist at the
  reviewed commit. The partial diff did not show them. Source/test paths are
  listed in the internal ledger and the existing per-step notes.
- **S4, S6, S7, S8:** retain existing landable findings and evidence for
  criticality/conflict/stream, recovery, DAG, Android and ports. Unfinished
  subreview drafts are preserved as drafts, not promoted to final reviews.
- **F-S5-DRAFT:** skip. The seventh descriptor is the existing opinion/take kind,
  not a missing required kind. The raw NOTE test also refuses at an earlier
  authoring guard; replicated and authored doors still enforce the kind gate.
- **S9 F1/F5:** skip as disproved by current compilation evidence and the existing
  include_forks HTTP assertion. **S9 F2/F3/F4/F6/F7:** skip as nonblocking
  documentation/naming/extra-coverage suggestions; engine guards and required
  acceptance are covered. No correctness change was alleged by these rows.
- **S10 clock residual:** already fixed by 5c00dadf, before this review. **S10
  regeneration-completion caller:** host-projector API by recorded design; these
  port contracts do not promise an autonomous regeneration worker.

## Validation

Pending for the current source. Earlier 9,154-test factory pass remains evidence
for its head, not a pass for these edits. First focused compile found two edit
mistakes (one removed borrow and a nested scoped-read helper caller); both were
fixed. Current focused test uses the installed dispatcher, MacBook exclusion,
normal Mini/Arch capacity guards, target `/home/lexi/w7-build/target/W7-C11`, two
compiler jobs and four test threads. No gate result or factory state is edited.
