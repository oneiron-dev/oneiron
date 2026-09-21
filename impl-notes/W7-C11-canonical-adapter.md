# W7-C11 canonical NOTE integration

## Merge and front-patch receipt

Base: `a729552c5a8960600cfd1fadff1251c67e5932eb` (C13-int).
Incoming: `9b06b0e487029e0d9eb9fea2b254e53adc7bf410` (C11).
The initial open merge matched 720 paths: 81 unmerged and 639 clean staged.
No index replacement, checkout, reset, push, or edits to another worktree occurred.

All seven fronts from `recovery/stack-prep-20260921/` were applied verbatim in
order before adapter work. Each individual `git apply --check` returned 0.
The combined check returned 0. Each apply returned 0:

| Order | Patch | Individual check | Apply |
|---|---|---|---|
| 1 | c11-front-01-note.patch | 0 | 0 |
| 2 | c11-front-02-witness.patch | 0 | 0 |
| 3 | c11-front-03-modules.patch | 0 | 0 |
| 4 | c11-front-04-config.patch | 0 | 0 |
| 5 | c11-front-05-context.patch | 0 | 0 |
| 6 | c11-front-06-serialize.patch | 0 | 0 |
| 7 | c11-front-07-remainder.patch | 0 | 0 |

## Authority and persistence

- The four-key NOTE core remains immutable. Program `head` is the note ID,
  not a mutable storage pointer. Creation uses canonical EntityDoc birth and
  persistence. Readers share one `d:e` plus ordered `u:e` loader in both lanes.
- Local edits and proposal landing use the C12 semantic operation gate in the
  same writer transaction as policy, citation checks, authorship and `nr:e`
  receipts. Verified actor/class and absence of `ds:e` replica authority remain
  mandatory. A citation-guarded `Proposed` result does not decide a C11 fork or
  create a successful C11 landing receipt.
- Fork content lives only in `note_proposal_doc:v1`, as isolated body-only
  values. It inherits no pins, authorship, or Loro history. Merge records an
  exact immutable base/proposed text pair. Switch is a semantic replacement
  through the gate, not snapshot import. Both C11 receipt heads name the note.
- Ordinary windows cannot install live NOTE documents or trusted workflow
  receipts. `proposal-values-v2` carries untrusted proposals to a bounded,
  per-window `note_inbox:v1` row. A remote `fork.actor` cannot authorize a local
  landing. No inbox row is automatically promoted or re-exported as trusted.
- The existing authenticated document socket remains the active NOTE sync
  lane: bound authority subscription for state import; authenticated semantic
  operations for peer writes. No fifth canonical Loro root is introduced.
- Host-local recovery has a separate crate-private path. History-free rebuild
  uses fresh Loro peers and copies exact existing semantic authorship values.
  It never calls deterministic birth with edited text. Speculative preflight
  executes the same NOTE transaction as durable restoration. Value-equal
  live documents are not rewritten or queue-cleaned.
- Recovery refuses outgoing/incoming/queued citation dependencies, pending
  citation erasure, hard deletion, replica subscriptions, queued local intent,
  authority-floor fences, and generic record-head NOTE carriers. Citation
  rebasing needs an explicit value-basis adapter; substring reanchoring or
  dropping pins is not accepted. NOTE restoration is one writer transaction;
  the complete existing multi-pass vault recovery is not claimed atomic.
- Recovery validation requires every live NOTE core to have its canonical
  value and stable head. Pending merge targets match displayed proposal text,
  and every isolated proposal value binds a pending fork. These checks run
  before quarantine. Native carriers serialize text values, not nested Loro
  snapshots that might retain retired pin/body history.
- Erasure keeps canonical cleanup plus C11 fork/proposal cleanup and shared
  explainer redaction. Unpartitionable untrusted inbox text is conservatively
  discarded on purge. Deleted owners, decided forks and redacted explainers
  cannot regain content through recovery.
- Moving NOTE cores onto normal entity replay exposed a missing pending-delete
  fence. NOTE entity writes and edge endpoint hydration/writes now check
  unproven `rm:` markers inside their writer transaction. A core/edge replay
  cannot claim healing or clear a purge retry. The original delete-safety
  assertion and stale-window erasure regression remain unchanged.

## Other required compile adapters

Both conversation families remain present. HEAD room/thread APIs and routes
are unchanged. C11 uses `append_dag_record`, `resolve_dag_scope`,
`spawn_dag_sub_session`, `mint_dag_scope_summary`, `/dag/records`, and its own
local HEAD key. Explicit per-conversation topology ownership refuses mixed
adoption. Maintenance skips room-owned and empty unowned conversations.
This is separate-conversation coexistence, not mixed topology semantics on
one adopted conversation.

Other compile-only changes retain the validated BatchTxn vector/text family,
use the scoped typed entity-read port, keep EVENT/origin creation atomic,
remove stale OpenAPI imports for removed host-policy routes, and update test
fixture types/imports for existing C10 and canonical NOTE signatures. No test
assertion was weakened to obtain a compile result.

## Intentionally open ledger

- `PINNED-SOURCE-RANKING`: selected historical ranking evidence still needs its
  own adapter. No ranking policy change in this integration.
- `PROVIDER-TINY-BUDGET`: preserve provider schemas at impossible tiny budgets.
  No removal of messages, contents or secrets_nulled to force fit.
- `PINNED-NOTE-HYDRATION`: historical source references can accompany current
  live markdown in the existing projection. This risk is not fixed here.
- Native C11 workflow replication is staged/untrusted, not authenticated
  authority replication. Promotion or an authenticated workflow sidecar is
  future work. A bare window cannot authorize review or receipt installation.
- Citation-bearing history-free NOTE recovery and generic record-head value
  recovery are explicit refusals, not successful recovery with lost provenance.
- Legacy C11 tests that require ordinary windows to mutate active NOTE text,
  Switch to change the live storage address, or mutable NOTE core bodies do
  not describe the canonical contract. Their assertions are retained. Any
  observed failures are ledgered below, not silently deleted or weakened.

## Validation

All native Cargo commands ran on the MacBook through the release dispatcher,
with the worktree's isolated target and 3-job cap. No Cargo build ran on Arch.
Final source checks include the backup changes and pending-delete fence.

| Check | Result | Log |
|---|---|---|
| `cargo check --workspace --all-targets` | exit 0, zero errors | `/tmp/w7-c11-note-check-workspace-final-08.log` |
| `cargo check -p oneiron --all-targets --no-default-features` | exit 0, zero errors | `/tmp/w7-c11-note-check-nodefault-final-09.log` |
| Sync `canonical_adapter` smoke | 10 passed, 0 failed | `/tmp/w7-c11-note-smoke-sync-04.log` |
| No-default adapter + backup smoke | 10 passed, 0 failed | `/tmp/w7-c11-note-smoke-nodefault-06.log` |
| Final sync NOTE + adapter + backup run | 47 passed, 5 retained failures | `/tmp/w7-c11-note-smoke-retained-final-07.log` |
| Code map regeneration and `--check` | exit 0; 3,103 files, 20 artifacts current | `/tmp/w7-c11-note-codemap-final-check.log` |
| `git diff --check` | exit 0 | precommit check |

The final retained run includes the 10 sync adapter tests and the original
stale-window erasure regression after its source fix. The no-default run
includes eight featureless adapter tests and both carried backup regressions.
Commands, failure names and log hashes are recorded in
`W7-C11-canonical-adapter-validation.json`. Build warnings remain; zero errors
is not a zero-warning or full-workspace-test claim.

Cargo validated the auto-merged lockfile on the MacBook. Its produced
`Cargo.lock` was copied back with rsync, not edited by hand. It is unchanged:
SHA-256 `c30977d2d0823c190ba3854de6afdf47dab3fc68652c1b60a1bc1787d1e695f0`.
No dependency was upgraded merely to regenerate the lock.

## Retained test-failure ledger

The retained sync NOTE suite plus adapter and backup tests ran 52 tests:
47 passed, 5 failed, none ignored. The five failures are left unchanged:

| Test suffix | Observed result | Contract difference |
|---|---|---|
| `five_forks_route_two_to_land_and_three_to_one_bundle_merge_keeps_concurrent_edits` | landed 0, expected 2 | Scoped note.edit grant alone cannot bypass the C12 author/owner gate. |
| `source_bridge_is_lazy_and_source_is_unchanged` | expected empty core markdown | Canonical NOTE core retains immutable birth markdown. |
| `already_open_window_materializes_document_only_updates` | live, expected live update | Ordinary windows cannot authorize live document mutation. |
| `incomplete_document_is_refused_before_core_admission_and_selection_cannot_leak` | expected window refusal | An ordinary window does not need a live NOTE snapshot to admit its immutable core. |
| `normal_window_delivers_editable_note_edits_forks_and_head_moves` | alpha, expected alpha edited | Live NOTE edits and reviewed state need the authenticated document lane. |

The first retained run also exposed an integration-specific pending-delete
fence omission. That source bug was fixed, not ledgered as acceptable. The
original `replay_purges_notes_and_stale_window_cannot_restore_erased_sidecars`
test now passes without assertion changes. All original C12 document, citation,
authorship, receipt, authority and erasure tests in the NOTE suite pass.
This is not a full workspace test-suite pass or a new remote CI/review result.

## Backup review

The prerequisite was met before any backup apply: workspace/all-targets #6
returned 0 and no-default/all-targets #7 returned 0.

| Backup item | Disposition | Reason |
|---|---|---|
| `a4ec59fd` Sudachi exact-path exclusions | Applied additively | Pinned vendor paths still exist; preserve upstream bytes. |
| Exact failed-receipt job-ID spelling rule | Applied additively | Receipt is still carried; rule remains uniquely scoped. |
| `W7-C11-ci-typos-validation.json` | Applied byte-for-byte | Historical evidence, verified equal to the original git object. Not a new test pass. |
| Bundle notes and review disposition | Applied with historical-provenance notice | Retain assessment history without claiming a current review gate. |
| Dirty `calendar/origin.rs` plus late-binding regression | Applied | Declared Dreamer source invalidation must survive delayed claim binding. |
| Dirty `conversation_dag/membership.rs` plus regression | Applied | `None` is the trunk identity; later session attachment is a mutation. |
| Dirty follow-up notes | Applied with historical-provenance notice | Pending old producer status is not a current result. |

No semantic backup change was dropped. The complete bundle patch did not
apply because newer HEAD spelling rules follow REQUESTs. Only its spelling
additions were inserted into the current config; DecodeParms, mke2fs and all
of360-gold rules remain. The other bundle files passed patch check and apply.
The four dirty source/test paths passed check and apply after adapting only
C11 method spellings to their new `_dag_` namespace. No backup branch was
checked out, imported over the index, pushed, or cherry-picked into the open
merge.

## Staged whitespace check

The full staged `git diff --cached --check` reports five trailing-whitespace
locations in the immutable Sudachi 0.6.11 vendor tree (char.def:8/19,
config.rs:171, input_text/buffer/mod.rs:260/372). A staged comparison against
MERGE_HEAD confirms that the complete vendor tree is byte-unchanged. Those
upstream bytes were preserved. The staged check excluding that exact pinned
tree passes; the ordinary worktree `git diff --check` also passed. This is
recorded, not relabeled as a clean full staged whitespace check.
