# PR 934 review repair ledger

Base local HEAD `1bf652c08cfa842a870eb68614a68a275de2d4dd`; reviewed/published head `dde11af41fc748496a1308408cff5063ce47d879`.

Fresh complete receipts: 10 issue comments, 2 reviews, 23 inline comments and 23 GraphQL threads; no next page at either thread level. Raw files are in `/home/lexi/w7-build/tickets/W7-C01/recovery-fix-review/`. Qodo review `5255259763`, Codex review `5255271289`. Codex completed; Cursor explicit usage-limit failure; CodeRabbit explicitly skipped (235 > 150 files); Greptile disabled. No provider is pending.

Internal Grok and final Opus findings from the recovery are merged below, including their recovered child lanes. PR933 packet is a different worktree; its 24 groups and root adjudication do not authorize edits to C08 here. Its schema-retry and missing conflict-test allegations were rejected by that root as blocking.

| Group | Finding | Inline IDs | Disposition |
|---|---|---|---|
| R01 | Timestamp units | 4052813444 | Implemented; focused regressions passed. |
| R02 | Held budget settlement and rescheduling | 4052803187, 4052813445 | Implemented; focused regressions passed. |
| R03 | Maintenance live owner proofs | 4052813454 | Implemented; focused regressions passed. |
| R04 | Tool argument schema | 4052803184 | Implemented; focused regressions passed. |
| R05 | OSV unavailable receipts and hub update path | 4052803171, 4052813453 | Implemented; focused regressions passed. |
| R06 | Qualification observed writes and idempotency | 4052803165, 4052813436 | Implemented; focused regressions passed. |
| R07 | Archived diary author | 4052803177 | Implemented; focused regressions passed. |
| R08 | Connector-scoped OAuth issuer drift | 4052813434 | Implemented; focused regressions passed. |
| R09 | Cross-key predicate identity | 4052803163 | Implemented; focused regressions passed. |
| R10 | Evidence diversity | 4052813449 | Implemented; focused regressions passed. |
| R11 | Visible vector top-k | 4052803173, 4052813437 | Implemented; focused regressions passed. |
| R12 | Typed owner intent and digest scan | 4052813447 | Implemented; focused regressions passed. |
| R13 | Memory history thread | 4052803168 | Implemented; focused regressions passed. |
| R14 | Stored widen proposer type | 4052813441 | Implemented; focused regressions passed. |
| R15 | Bounded gate auto signals | 4052813438 | Implemented; focused regressions passed. |
| R16 | Observable action definition test | 4052803153 | Implemented; focused regressions passed. |
| R17 | Connector subscription lookup | 4052813451 | Implemented; focused regressions passed. |
| R18 | BM25 diary visibility (already filtered) | 4052803159 | Skip: already enforces visibility before BM25 top-k. |
| R19 | Import source IDs (contract required) | 4052803145 | Skip: OF-201 requires per-source adapters; third-party format identifiers are not downstream product modules. |

## Repair decisions

- R01/R10: selection converts stored Unix seconds to milliseconds at assembly.
  Diversity counts distinct store-backed speaker sources inside the partition,
  not repeated copies of the partition conversation. Epoch-scale regression
  tests check hold/release, recency ordering and diversity ordering.
- R02: a selection hold returns `Deferred` with consumed units and a retry time.
  The runner settles the reservation and uses the existing queue retry door in
  one transaction. The new scheduled try receives authority and run-tree rows.
  Unscoped retries re-read a bounded conversation slice to admit new evidence;
  explicit branch grants never expand. Exact stored heads absorb already
  promoted evidence. No manual `resume_parked` is needed.
- R03/R07/R14: maintenance reads/writes prove a live PERSON owner in the same
  transaction; diary reads reject archived authors; widen admission validates
  the stored entity kind against the asserted agent class.
- R04: resolved tool descriptors enforce the supported structural JSON Schema
  subset before header extraction and freezing. Required properties, nested
  types, arrays, enums, constants and additional-property rules are checked.
  Unsupported assertions fail closed. No validator dependency was added.
- R05: OSV outage/malformed results persist `Unknown` + `Partial` receipts.
  Incomplete OSV coverage requires owner review without inventing a risk score.
  Automatic hub updates query outside the writer transaction, then co-commit
  the new content hash and verdict. Risky active updates become Proposed.
  A later clean result replaces an earlier incomplete receipt.
- R06: qualification reconciles each stable reported write reference with
  exactly one trace write. Designated write probes must declare mutation and
  a string idempotency argument. A changed key must permit a distinct effect.
- R08: cache keys retain vault, actor and issuer, and add a connector-registration
  discriminator. Drift/revocation affects only that connector. Tests retain
  RFC 9207 pre-redemption issuer checks and prove independent-provider use.
- R09: cross-predicate merges must select a listed candidate identity. The
  selected identity controls predicate, deterministic ID and prior-head binding.
  Heterogeneous open questions record all predicates rather than claiming that
  the first predicate is the group's semantic answer.
- R11: direct vector search expands the HNSW request until it fills the visible
  limit or exhausts the population. It does not return private identifiers.
- R12/R17: shared claim-put maintenance builds predicate and pending-producer
  indexes for local writes, replay and rematerialization. Digest/subscription
  reads use those indexes. Overwrites and deletion remove old entries, and
  transaction rollback preserves both directions. Urgent breakthroughs require
  an approved live `profile.intent`, owned by the authenticated subject and
  sourced as UserStated, with a nonempty text value.
- R13/R16: current memory and all revisions share the memory ID as their thread;
  shared action definitions are compared by value, not allocation identity.
- R15: automatic-checker inputs use a reverse sample capped at 1,024 receipts.
  These remain advisory observations, not exact admission counters. Work no
  longer grows with the vault's complete decision history.

Canon notes: the engine's millisecond execution clock must not be compared
with evidence-header Unix seconds. A selection hold is a scheduled continuation
with settled spend, not an unspent operator park. OAuth issuer drift belongs to
one connector registration, not the whole actor. Existing docs-repo pages were
not changed. The previous seven-comment disposition remains historical only;
it predates the completed Qodo/Codex reviews collected for this repair.

## Repair validation

Source revision `24e1cb89` contains the final regression corrections. The
following navigation-only commit `2cb9d2cd` changes no Rust bytes. Production
Rust bytes have not changed since `778817e6`.

- **556 distinct selected sync/test-hooks tests passed**, across `oneiron` and
  `oneiron-server`. The union retains 172 passes from the first run and 389
  passes from the second (eight overlap), then reruns the three corrected
  regressions successfully. The retained passing cases were not disabled or
  reclassified. The first fixture's missing subject was corrected before its
  successful second-run result.
- **361 selected featureless library tests passed**: 358 unchanged passes plus
  the same three corrected regressions rerun with no default features.
- Production-server clippy passed: `cargo clippy -p oneiron-server -- -D warnings`.
- Featureless all-target clippy passed:
  `cargo clippy -p oneiron --all-targets --no-default-features -- -D warnings`.
- Sync/test-hooks all-target clippy passed:
  `cargo clippy -p oneiron -p oneiron-server --all-targets --features sync,test-hooks -- -D warnings`.
- Native `rustfmt --edition 2024 --config skip_children=true --check` on every
  changed Rust file passed. `scripts/codemap/check.sh` passed (2,558 files,
  16 current artifacts). Root surface passed (701 names). Ratchet passed
  (2/2 giant files, 97/98 allows, 91/91 prints, 33/33 process globals).
  `git diff --check 1bf652c0 HEAD` passed.

The runtime commands used `cargo nextest run`, three test threads, and explicit
module filters. Both changed crates compiled with `--features sync,test-hooks`;
base-mode coverage used `-p oneiron --lib --no-default-features`. After fixing
fixtures, only these three tests were rerun in both modes:

- `production_executor_carries_scope_and_refuses_unlisted_evidence_and_output`
- `diary_note_is_actor_private_across_reads_recall_and_pack_neighbors`
- `hub_updates_scan_new_dependencies_before_exposing_them`

The corrected fixtures retain the stronger assertions: the diary test keeps
the default policy manifest while configuring vectors; the scope test asserts
the durable attenuation refusal, with independent missing-signal coverage;
the hub test advances the version and still requires Proposed on risky bytes.
The epoch test also covers evidence-free candidates, whose extraction timestamp
is already milliseconds. Moving its last config value removes a redundant clone.

Full command arguments, raw outputs, complete review snapshots and successful
test-name sets are retained under
`/home/lexi/w7-build/tickets/W7-C01/recovery-fix-review/`. The files
`sync-final-passed.json`, `featureless-final-passed.json`, `validation-summary.json`
and the `*-unit.json` records identify the evidence and commands. The fresh
pre-fix review refresh had 11 issue comments (the added one was this repair's
explanation), two unchanged reviews and 23 complete inline threads. No newer
provider finding was omitted.

The GitHub explanation is comment `5741670831` on PR 934. These are scoped repair
results, not a full-workspace VERDICT. No full gate, internal-review completion,
provider success, merge rehearsal or merge is claimed. The PR stays open for the
factory's remaining verification, review and publication steps.
