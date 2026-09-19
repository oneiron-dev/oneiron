# PR 934 review repair ledger

Base local HEAD `1bf652c08cfa842a870eb68614a68a275de2d4dd`; reviewed/published head `dde11af41fc748496a1308408cff5063ce47d879`.

Fresh complete receipts: 10 issue comments, 2 reviews, 23 inline comments and 23 GraphQL threads; no next page at either thread level. Raw files are in `/home/lexi/w7-build/tickets/W7-C01/recovery-fix-review/`. Qodo review `5255259763`, Codex review `5255271289`. Codex completed; Cursor explicit usage-limit failure; CodeRabbit explicitly skipped (235 > 150 files); Greptile disabled. No provider is pending.

Internal Grok and final Opus findings from the recovery are merged below, including their recovered child lanes. PR933 packet is a different worktree; its 24 groups and root adjudication do not authorize edits to C08 here. Its schema-retry and missing conflict-test allegations were rejected by that root as blocking.

| Group | Finding | Inline IDs | Disposition |
|---|---|---|---|
| R01 | Timestamp units | 4052813444 | Implemented; runtime validation pending. |
| R02 | Held budget settlement and rescheduling | 4052803187, 4052813445 | Implemented; runtime validation pending. |
| R03 | Maintenance live owner proofs | 4052813454 | Implemented; runtime validation pending. |
| R04 | Tool argument schema | 4052803184 | Implemented; runtime validation pending. |
| R05 | OSV unavailable receipts and hub update path | 4052803171, 4052813453 | Implemented; runtime validation pending. |
| R06 | Qualification observed writes and idempotency | 4052803165, 4052813436 | Implemented; runtime validation pending. |
| R07 | Archived diary author | 4052803177 | Implemented; runtime validation pending. |
| R08 | Connector-scoped OAuth issuer drift | 4052813434 | Implemented; runtime validation pending. |
| R09 | Cross-key predicate identity | 4052803163 | Implemented; runtime validation pending. |
| R10 | Evidence diversity | 4052813449 | Implemented; runtime validation pending. |
| R11 | Visible vector top-k | 4052803173, 4052813437 | Implemented; runtime validation pending. |
| R12 | Typed owner intent and digest scan | 4052813447 | Implemented; runtime validation pending. |
| R13 | Memory history thread | 4052803168 | Implemented; runtime validation pending. |
| R14 | Stored widen proposer type | 4052813441 | Implemented; runtime validation pending. |
| R15 | Bounded gate auto signals | 4052813438 | Implemented; runtime validation pending. |
| R16 | Observable action definition test | 4052803153 | Implemented; runtime validation pending. |
| R17 | Connector subscription lookup | 4052813451 | Implemented; runtime validation pending. |
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

## Validation status (in progress)

- Native `rustfmt --edition 2024` on changed files: passed.
- `scripts/ratchet/root-surface-check.sh`: passed, 701 names.
- `scripts/ratchet/check.sh`: passed, 2/2 giant files, 97/98 allows,
  91/91 prints, 33/33 process globals.
- `python3 scripts/codemap/codemap.py`: generated 2,558-file navigation.
- `git diff --check`: passed.
- Factory-routed focused core nextest is still queued for shared host capacity.
  No compilation or runtime pass is claimed yet. The wrapper found the Mini
  below its 30 GiB reserve and continued its normal host admission loop.

Source commits are local; PR 934 remains open. No review or merge completion is
claimed. Final crate test results and the GitHub explanation will be recorded
when the queued validation completes.

Follow-up before runtime validation: the first compiler run found the merge
prior lookup was private to the resources subtree. Its visibility now reaches
only the owning consolidation module. Scheduled retries also copy a private
execution-scope pin in the settlement transaction, so removing an ephemeral
caller scope on a later worker cannot widen the retry. The retry regression
runs both unbounded and caller-attenuated branches. The timestamp test also
covers evidence-free candidates: extraction timestamps are already milliseconds.
