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


## Tests-after-review regression repair

Before this repair, complete GitHub receipts were refreshed again: PR 934 has
11 issue comments, two reviews, 23 inline comments and 23 complete review
threads at published head `dde11af41fc748496a1308408cff5063ce47d879`.
There are no new or edited provider findings relative to the prior repair;
the only changed comment is the repair explanation `5741670831`. The final
original Opus and Grok verdicts were recovered and reconciled with R01–R19
above. No new review fanout was started. Codex completed; CodeRabbit skipped
the file-count limit; Cursor reported a provider usage-limit error.

PR 933 was also refreshed: 15 comments, six reviews and 40 complete inline
threads at `8504e48978737cc41eae473f85d88ef3087131e4`, branch `w7/W7-C08`.
The supplied F01–F24 candidates, original root adjudication rejecting O01/O02
as blocking, and newer C08 findings remain that ticket's responsibility.
The C08 owner's explanation `5741607767` records its individual F01–F24
fix/skip decisions. They are not C01 findings and are not dismissed as invalid
for C08. No C08 source or resolution flags were changed here.

The standard six-crate test stage then exposed one R11 regression:
`hnsw::tests::hnsw_corruption_variants_fail_closed` returned an empty vector
for a populated graph whose stored count was corrupted to zero. All other
core library cases passed (7,081 passed, one failed, four ignored), and the
other crate/integration/doctest targets passed. Those unchanged results are
retained, not relabeled as a successful complete run.

R11's `limit.min(population)` turned a nonzero caller request into a zero-limit
HNSW call. That call correctly short-circuits explicit zero-limit requests,
but this hid the existing graph consistency check. The first requested size
now uses `limit.min(population.max(1))`. Positive requests reach consistency
validation even at population zero; explicit caller zero still stays zero.
Visible-neighbor expansion, filtering and SLIM source-vector counting are
unchanged. The existing corruption regression and typed-error assertions are
retained without weakening or duplicating them. No canon-page change is needed.

Validation completed on source commit `332831bd`, with the source hash
unchanged through both builds:

- `cargo nextest run -p oneiron --lib --features sync,test-hooks -E <five-test filter> --test-threads=3 --no-fail-fast`: **5 passed, 0 failed, 7,081 skipped**.
- `cargo nextest run -p oneiron --lib --no-default-features -E <same filter> --test-threads=3 --no-fail-fast`: **5 passed, 0 failed, 6,578 skipped**.

The exact filter selects the unchanged corruption regression,
`search_vector_empty_graph_and_dimension_validation`,
`diary_note_is_actor_private_across_reads_recall_and_pack_neighbors`,
`hnsw_dropped_marker_is_not_empty_corpus`, and
`hnsw_lazy_search_matches_persisted_discipline_with_fast_dims`.
Both core library test targets compiled successfully. The standard wrapper
selected Arch with ticket-owned `target/`, at most three Cargo jobs and three
test threads. Both durable jobs reached terminal exit 0; partial logs and
in-flight systemd `Result=success` fields were not used as pass evidence.

Pinned native rustfmt on the changed file, `scripts/codemap/check.sh`
(2,558 files; 16 artifacts current), and `git diff --check` passed.
These are scoped core-crate regression results, not a rerun of the complete
six-crate or full-workspace gate. Earlier unchanged green results remain valid.
No failing test was removed, disabled or weakened. No source outside `oneiron`
changed for this repair.

A final complete PR934 refresh still had 11 comments, two reviews and 23
complete inline threads at the same published head, with no new or edited
findings. The initial process-bound test command ended before compilation;
it produced no test result. The replacement durable jobs above supply the
terminal evidence. Publication and remaining factory stages remain separate.

Raw refreshed reviews, IDs/head bindings, the intake ledger, exact failure,
commands and logs are in
`/home/lexi/w7-build/tickets/W7-C01/recovery-fix-tests-after-review/`.

## Recovered-review and bot-thread closure

Fresh intake before this pass: local HEAD `9cfc08b636cc04f5cf67d685531dd0fb2e5186f7`,
published PR934 HEAD `dde11af41fc748496a1308408cff5063ce47d879`. The complete snapshot contains
12 issue comments, two reviews, 23 inline comments and 23 review threads.
REST pagination was exhausted; GraphQL had no remaining thread or nested-comment
pages, and all inline IDs matched. The 23 original bot findings are unchanged
from the complete repair snapshot, not from the obsolete seven-comment snapshot.

Raw JSON, exact heads, body timestamps, original internal root/child transcripts,
reply IDs, validation commands and logs are retained at
`/home/lexi/w7-build/recovery/pr934-bots-20260919T140317Z`. The R01–R19 table above remains the deduplicated bot/internal ledger.
All 23 inline threads now have individual fix/skip explanations referencing the
existing local repairs and completed standard-test evidence. No thread resolution
flag, published branch, or PR state was changed.

The original Opus root ended with a substantive verdict at 11:07Z; its ten
children had no terminal verdict, and the root explicitly completed those lanes
inline. Their raw transcripts and final root findings were retained, not discarded
or counted as independent clean reviews. The later Grok root's existing seven
completed lane reports and one unfinished connector lane were recovered; the
root completed the connector assessment and identified the missing OF-188 test.
No new reviewers or editors were spawned.

### Current-code adjudication of the recheck

| ID | Source | Finding and disposition |
| --- | --- | --- |
| I20 | review-opus-2 | projection_index file allegedly truncated. Skip: the complete projection_index.rs is present and compiled by terminal standard tests; review input truncation is not a code defect. |
| I21 | review-opus-2 | MCP nav allegedly bypasses authority/world scope. Skip: project_nav_results always uses Summary -> ScopedRead::get_entity_parts -> live claim policy gate. Connector authority is resolved upstream; mcp_admit_scoped_call refuses retired nav adapters for world/facet-narrowed credentials. Those adapters are not registered wire tool names. There is no demonstrated bypass. |
| I22 | review-opus-2 | standing key allegedly omits world/facet/relationship checks. Skip: begin_standing_block_session rechecks exact registered handle and agent; ScopedRead::is_entity_readable checks live policy, and body subject/world are matched to handle. Scope envelope attenuation is a different door, not raw key-constructor validation. |
| I23 | review-opus-2 | whole-vault export allegedly needs extra companion/standing privacy filter. Skip: step 35 explicitly requires enumerate every row and exclude only overlay membership; identity-only local Vault API is not an agent/companion export authorization door. |
| I24 | review-opus-2 | dispatch allegedly merges cross-axis scope. Skip: dispatch calls Scope::attenuate before enqueue; it rejects any changed/erased bound axis plus non-subset resource sets. No union/merge widens resources. |
| I25 | review-opus-2 | projection deindex removal allegedly missing. Skip: maintain_claim_projection_index removes old keys before replacement; batch/deindex.rs:166 removes keys on delete. Active/Proposed eligibility rebuilt from new ClaimBody on lifecycle writes. |
| I26 | review-grok-2 | OF-188 request-id/idempotency-key equality negative fixture absent. Fix test coverage: assert IdempotencyArgument for both designated write and timeout-retry cases when key equals request id. Production rejects equality already. |

I26 is repaired in `54361d57`: the new qualification fixture asserts the typed
`IdempotencyArgument` refusal for both the write and timeout-retry probes when
the explicit key equals the transport request ID. Production rejection already
existed; no production behavior changed. The added test moved its file from the
small to medium code-map bucket, so the two generated map artifacts were updated.
No canon-page correction or docs-repo edit was needed.

### Cross-ticket recovery boundary

The supplied PR933 F01–F24 report and original root adjudication were consumed.
O01 (three calls versus three corrective retries) and O02 (conflict-fallback
coverage) were rejected as blocking by that root; child previews were not promoted
to final findings. Each F01–F24 group is routed in `pr933-applicability.json`.
Only F05 shares a C01-changed file path; its C08-added test is not in this branch.
All other candidate paths are unchanged by C01. These are C08-owned findings,
not C01 dismissals of their merits. The updated PR933 snapshot (16 issue comments, 22 reviews, 40 complete threads
and 96 inline comments/replies) is preserved separately. Its original root now
has a terminal DEFECTS verdict: it recovered nine child transcripts and closed
the six incomplete lanes inline. That verdict confirms the O01/O02 rejection
and rejects F05 as a false positive (the C08 test has function-local imports).
No C08 source or review state was edited.

### Validation boundary

The factory's **completed** standard six-crate rerun returned exit 0 at 13:28:36Z
on `9cfc08b6`, after the HNSW repair. The final complete log section is preserved
as `prior-standard-tests.log`. Earlier interrupted or failing sections are not
counted as terminal passes. Existing scoped regression/lint results above are
reused because production Rust bytes did not change in this pass.

The changed server crate's standard command completed on source commit
`54361d573b7f70b0e0a8aa681c954f9b92782ec8`:

`cargo test -p oneiron-server --no-fail-fast -- --test-threads=3`

**889 passed, zero failed, five ignored, zero filtered out**, across seven
reported targets. The new
`mcp::qualification::tests::write_probes_refuse_request_ids_as_idempotency_keys`
test passed. Server library, binary and integration targets compiled. No Rust
bytes changed after this test-source commit. Existing unchanged production lint
and six-crate test evidence are retained, not replaced by a claimed workspace gate.

The first process-bound command disappeared at the seat handoff before acquiring
a build slot; its admission-only log is not test evidence. Local and MacBook
checks found no remaining C01 build before replacement. The replacement oneshot
`w7-c01-bots-server-54361d57.service` finished at 14:18:26Z with
`ActiveState=active`, `SubState=exited`, `MainPID=0`, `Result=success`, and
`ExecMainStatus=0`. These terminal fields and the complete test log are preserved.

Actual host correction: the durable service invoked the wrapper but omitted
`W7_CARGO_WORK` / `W7_CARGO_HOSTS`, so its documented fallback ran on Arch in this
worktree's own `target/`, with `CARGO_BUILD_JOBS=3` and three test threads. This
was a routing error, not an intentional host override or evidence of scheduler
admission. No competing C01 build was present. The passing result is preserved
with the actual host; no redundant replacement build was started. Future durable
starts must retain those non-secret routing settings and use `--no-block`.

Native rustfmt on the changed test, `scripts/codemap/check.sh` (2,558 files;
16 current artifacts) and `git diff --check` passed. The final complete GitHub
refresh contains 12 issue comments, 25 reviews (including the 23 reply reviews),
46 inline comments/replies and 23 complete threads, at the same published head.
No new or changed external finding was present; the additions are the recorded
inline responses. This completes this repair/reply pass, not publication,
merge approval or a new internal-review verdict on unpublished commits.

Codex is completed, not quota-failed or pending. Qodo is completed. CodeRabbit
explicitly skipped the 235-file PR because its limit is 150, Cursor reported an
explicit usage-limit error, and Greptile is disabled. None is being blindly waited
on or described as an approval of unpublished repair commits.
