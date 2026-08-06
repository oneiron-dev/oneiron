# WORKLOG — ONE-1756 [ED-00] CRDT prereq: proposal artifacts ride LoroText + actor→op binding

Lane ED · stack ED-A layer 1 of 3 (**1756** → 1757 → 1758) · branch `ONE-1756`
cut off `main` @ `8225cec4f`.
Blueprint: `/Users/olety/.claude-wave5/blueprints/ED/ONE-1756.md`.
Canon: ARCH-0056 §2–3 · ARCH-0032 (bodies map stays docs-only; out of this cut).

## What landed

**`crates/oneiron/src/edit_distance.rs` (new module root, UNCONDITIONAL)** — the
types + retention + registration the whole ED ladder consumes.

- `ProposalArtifactRef` (entity-id newtype), `LoroOpRef` (encoded `Frontiers`
  bytes — the form `fork_at` / `find_id_spans_between` actually consume, so the
  window is replayable rather than merely descriptive), `OpSpan`,
  `OpAttribution`, `FinalizedProposalText`.
- Retention: `put_finalized_proposal_text` / `finalized_proposal_text` — one
  MessagePack record per artifact in `vault_meta` under
  `edit_distance/proposal_artifact/v1\0`, carrying BOTH texts, both op refs,
  `source_turn_ref` and every attributed span. ED-09's reservoir resolves its
  (proposed, final) training pairs from these rows, so retention is a contract.
- Peer→actor registration: `register_peer_actor` (engine-authored, superseding),
  `peer_actor_at` (window-resolved — the row that was live AT COMMIT TIME),
  `active_peer_actor`, `peer_actor_stamp_is_honored` (the trust rule).
- No new entity-type byte, no registry row: bindings are CLAIMs, artifacts are
  `vault_meta` rows. Nothing here needs a reservation.

**`crates/oneiron/src/edit_distance/proposal_text.rs` (new, `#[cfg(feature = "sync")]`)**
— the Loro half.

- `ProposalTextArtifact::open / edit_as / export_snapshot / from_snapshot /
  finalize`. The body is a `LoroText` root container; an artifact header
  (`artifact_ref`, `source_turn_ref`) rides a sibling `LoroMap`.
- Every write commits with `CommitOptions::commit_msg` carrying
  `oneiron.edit_distance.v1 <open|edit> actor=<hex>.<class>`. The message is the
  durable half of Loro commit metadata (`Change` = id/deps/timestamp/commit_msg/ops);
  `origin` is local event metadata and does NOT survive snapshot/reopen, which
  is exactly the boundary attribution has to cross. `BRIDGE_ORIGIN` is untouched.
- **The window base is the open commit.** `proposed_ref` cannot be stored inside
  the doc — writing it would change the version it names. The opening commit
  marks itself (`open` stamp) and the base is derived as the version right after
  that change, so `from_snapshot(bytes)` needs nothing but the bytes and a
  reopened artifact behaves identically to a never-closed one. The differing
  stamp is also what stops Loro folding the first edit into the open commit
  (changes merge only when commit messages are EQUAL) — pinned by
  `the_open_commit_never_merges_with_the_first_edit`.
- **Replay is exact, not approximate.** `finalize` forks the doc at the base,
  reads `proposed_text` out of the fork, then feeds that same fork the window
  ONE change at a time (`ExportMode::updates_in_range` → `import`) in causal
  (lamport) order. Each span therefore carries the real text on either side of
  its own ops, and the reconstructed text is asserted equal to `final_text`
  before the record is written — a replay that does not reconstruct the final
  text is an `InvariantViolation`, never a silently wrong record.

**`claim.rs`** — `PREDICATE_ACTOR_PEER_BINDING = "actor.peer_binding"` const only.
Reserved-by-namespace, so `put_claim` rejects it and `register_peer_actor` is the
only author. Not added to `CLAIM_PREDICATE_REGISTRY` (that registry admits only
public `core.*`/`companion.*`/`eiri.*`).

**`sync/window.rs`** — `PROPOSAL_TEXT_COMMIT_MSG_PREFIX` const only, declared
beside the `BRIDGE_ORIGIN` convention so a sync-layer author sees both commit-metadata
reservations in one place. No behavior change; the sync suite is the canary and
is green.

**`lib.rs`** — `pub mod edit_distance;` (module line only, matching the
`edit_settle`/`edit_roundtrip` neighbours which export no prelude symbols).

## Deviations from the blueprint (GATE-2 board)

1. **Predicate rides `actor.*`, not `edge.*`** — MECHANICAL, not preference.
   `Vault::supersede_reserved_claim_in_txn` routes through
   `reserved_claim_for_lifecycle_in` (`claim.rs:2516`), which **rejects `edge.*`
   by design** ("edge provenance owns its own lifecycle mechanics") and admits
   only the ENGINE-driven `skill.*` / `actor.*`. Done-means #6 requires
   supersede-on-re-register, so an `edge.*` predicate could not have satisfied
   the ticket. `actor.*` is also the semantically correct home (ARCH-0053 §9,
   ONE-1739 precedent). CLAIMS.md's `claim.rs` row is unaffected — still one
   additive const, still no registry entry, no collision with 1759's `edit_cost`.

2. **~~Stamp-trust rule widened~~ — REVERSED in the VERDICT-FIX round; the
   landed rule is now the blueprint's.** The reasoning below stands as the
   PROPOSED AMENDMENT the board rules on (see VERDICT-FIX F1); it is no longer a
   description of the code. Original entry:

   **Stamp-trust rule widened** — blueprint: "honored only when the stamped
   actor is registered to the change's peer; mismatch OR UNREGISTERED →
   fallback". Landed: **honored unless the stamped actor is bound to a DIFFERENT
   peer at commit time.** The security property is preserved verbatim (a remote
   peer cannot forge attribution to a foreign actor — `a_stamp_naming_another_peers_actor_is_not_honored`).
   Three groundings for the widening:
   - Under the literal rule the stamp channel is **information-free**: every
     honored stamp equals what `peer_actor_at` already returns, so `Stamped` and
     `Registered` can never disagree and the ticket's chosen mechanism (option B,
     commit-metadata stamp) does no work at all.
   - Blueprint §2's own rationale requires finer-than-peer grain
     ("agent-vs-agent on one host and human-vs-agent attribution inside one
     device"); the literal rule forbids exactly that, since one peer has one
     active binding.
   - Done-means #1 ("edited by two distinct actors … attributes each span to the
     correct actor") is unsatisfiable under the literal rule when the two actors
     share a device peer — the one-device case the ticket names.
   Covered both ways: `co_resident_actors_on_one_peer_are_distinguished_by_the_stamp`
   and `a_stamp_naming_another_peers_actor_is_not_honored`.

3. **`register_peer_actor(vault, peer_id: u64, actor)`**, not `client_id: &str`.
   The peer id is a `PeerID`/`u64` at every producer and consumer
   (`SyncClient::client_id()`, `LoroDoc::set_peer_id`, `ChangeMeta.id.peer`); a
   hex-string parameter would round-trip a u64 through text and reintroduce the
   case-aliasing class `loro_support::tombstone_map_contains_id` was written to
   defend against.

4. **`ProposalTextArtifact::open(initial, actor, source_turn_ref: Option<EntityId>)`**
   — third parameter. Done-means #3 requires `source_turn_ref` recorded AT MINT
   (ED-09's fence probe resolves it by entity id), so it cannot be back-filled;
   one door with an `Option` beats two near-identical constructors.

5. **`finalize(self, vault: &Vault)`** — the same blueprint requires finalize to
   PERSIST, which needs the vault handle the keystone signature omits.

6. **`edit_as(&mut self, actor, edit: impl FnOnce(&LoroText) -> Result<()>)`** —
   `&LoroText`, not `&mut`: every `LoroText` mutator takes `&self`. A failing
   `edit` is still committed under its own actor's stamp, because its
   already-applied ops would otherwise fold into the NEXT actor's change
   (`a_failed_edit_still_lands_under_its_own_actor`).

7. **`ops_by_actor: Vec<(OpAttribution, OpSpan)>`** — first element widened from
   `WriteActor` so done-means #6's "marked device-peer fallback" is
   representable without inventing a sentinel actor id.

8. **`sync/loro_support.rs` unchanged.** The claim allowed additive helpers; the
   landed ones (`doc_from_snapshot`, `export_snapshot`, `import_doc`,
   `map_get_bytes`, `map_insert_bytes`) were sufficient, so nothing was added.

9. `peer_actor_stamp_is_honored` is `pub`, not `pub(crate)` — its only in-crate
   caller is sync-gated, so `pub(crate)` is dead code in a non-sync build, and
   it is the rule ED-02 (out-of-band edits) will consume directly.

## Gates

| gate | feature set | result |
|---|---|---|
| `cargo fmt` | — | clean |
| `cargo clippy --all-targets -D warnings` | `--all-features` | **green** |
| `cargo clippy --all-targets` | default (non-sync) | **0 findings in this lane's files**; pre-existing red on `batch.rs:4348` `facet_of_endpoints_provably_off_table` (only caller is `sync/selector.rs`, i.e. dead without the sync feature) — untouched by this lane, present on main |
| `cargo build -p oneiron` | default (non-sync) | **green**, zero warnings from this lane |
| `cargo test -p oneiron` | `--all-features` | **green** — 3522 passed / 0 failed / 17 ignored (lib) + every integration binary green, incl. the full sync suite and bridge-origin tests |
| lane tests | `--all-features` | 14 new, all green |

Non-sync verification is a BUILD, not a clippy run: `oneiron` declares no default
features, so `cargo build -p oneiron` IS the `--no-default-features` build, and
it compiles with `edit_distance` present and the Loro half cfg'd out.

## Done-means

- [x] Two distinct actors, finalized: each span attributed to the correct actor;
      replay between `proposed_ref`/`final_ref` reconstructs `final_text` exactly
      (asserted inside `finalize`, so a mis-replay cannot be persisted).
- [x] Durability across reopen — `two_peers_across_a_reopen_attribute_and_replay_exactly`
      snapshots MID-window through `loro_support`, reopens (a new peer), edits as
      a second actor, and both attributions survive.
- [x] Finalize persists both texts + `source_turn_ref`, retrievable by proposal
      ref after reopen.
- [x] Non-sync build compiles: root present, Loro half cfg'd out.
- [x] Stamp is engine-written — `no_public_door_accepts_a_caller_supplied_stamp`
      (source-scan in the landed `napi_surface_never_constructs_auto_approval`
      style: exactly one commit-message chokepoint; builder and parser private).
- [x] Registration: engine-authored, ONE active row per peer (supersede on
      re-register), queryable, time-resolved; ties and unregistered peers land on
      the device-peer fallback, never a guess.
- [x] Snapshot/export round-trip through existing `loro_support` helpers; no
      wire/protocol change; sync suite green incl. bridge origin tests.
- [x] `CommitOptions::origin` users unaffected — this lane adds a commit-MESSAGE
      convention and touches no origin path; the parser ignores any message that
      is not ours.

## Simplify pass (K3, post-impl)

> Superseded in part by the VERDICT-FIX round below: the peer index helpers
> (`peer_actor_index_key`/`_prefix`/`_claim_id`) and `peer_actor_at`'s
> lost-witness `InvariantViolation` no longer exist — F5 replaced the index with
> a single claim-substrate read path and F4 replaced recency resolution with one
> window predicate.

**Verdict: NO EDIT WARRANTED.** Deletion-biased pass over the lane diff; every
candidate was scrutinized and rejected:

- The `KEY_*`/`SPAN_KEY_*` alias consts are not duplication to delete — they are
  what ties encode/decode field names to the pinned pub key-set arrays
  (`PROPOSAL_ARTIFACT_RECORD_KEYS`/`SPAN_KEYS`); deleting them means cryptic
  array indexing or driftable literals.
- Every private helper earns its place: used ≥2× (`change_last_op`,
  `meta_entity_id`, `binding_covers`, `peer_binding_rows_in_txn`) or is one half
  of an encode/decode pair. Test helpers consume `peer_binding_value`,
  `peer_actor_index_key`, `peer_binding_rows_in_txn` directly.
- `WindowChange.len: u16` narrowing: dropping the `try_from` would only
  reintroduce `as i32` casts downstream — net-neutral churn, rejected.
- `peer_actor_at`'s impossible-path `InvariantViolation` survives scrutiny: any
  restructure still needs the same witness, and the ambiguity-tie semantics are
  a done-means contract.
- The one-clone-per-span in `replay_window` is inherent (each span owns its
  `after_text`, which is the next span's `before_text`).
- No dead code: clippy is clean on `--all-features`; the only default-features
  warning is the pre-existing `batch.rs` one on main (documented above).

Gates re-run at the simplify point: `cargo fmt --check` clean · clippy
`--all-features --all-targets` clean · clippy default (non-sync) clean for lane
files · 14/14 lane tests green `--all-features`, 5/5 green non-sync (the
`proposal_text` half correctly cfg'd out).

## VERDICT-FIX (round 1 — 5 verdict-verified REAL findings)

Base `62735dd64`. Four findings were reproduced empirically before the fix
(scratch harness `/tmp/one1756-repro`, an external crate driving only the public
API); F5 was verdict-verified by derivation and then reproduced in-crate against
the pre-fix source. Every fix carries a red-before / green-after receipt.

**Baseline (pre-fix) harness output:**

```
UNREGISTERED_ATTR=Stamped(WriteActor { .., actor_class: Agent })   # F1 — the VICTIM's actor
DIVERGENT_FINAL_STORED=draft right                                 # F3 — clone 2 overwrote clone 1
PRE_SWITCH_EDIT_CHARGED_TO_NEW=true                                # F4
SHIFTED_PROPOSED_TEXT=seed hidden                                  # F2 — base moved past the edit
SHIFTED_WINDOW_SPANS=1
```

**Post-fix, same harness:**

```
UNREGISTERED_ATTR=Registered(WriteActor { .., actor_class: Human }) # the writing peer's own binding
DIVERGENT_FINALIZE_REFUSED=true
DIVERGENT_FINAL_STORED=draft left                                   # first record survives
PRE_SWITCH_EDIT_CHARGED_TO_NEW=false
SHIFTED_FINALIZE_REFUSED=true err=corrupted index: proposal artifact has more than one open commit
```

### F1 (P1) `unregistered-actor-stamp-is-honored` → the blueprint rule

`peer_actor_stamp_is_honored` rejected a stamp only when it found an overlapping
binding to ANOTHER peer, so an UNREGISTERED stamped actor fell through to
`Ok(true)`. `WriteActor::new` and `edit_as` are public and `commit_msg`
replicates, so that was an attribution forgery channel: any caller could mint a
`WriteActor` for an entity it does not speak for and have the engine record it
as `Stamped`.

**Fix (chokepoint, `edit_distance.rs`):** the rule is now the ratified blueprint
line — a stamp is honored ONLY when the stamped actor is bound to THIS peer at
commit time; mismatch OR unregistered → registration fallback → device peer. The
rule reads the same binding rows the fallback does (see F5), so the two can no
longer disagree.

**Deviation-2 (the landed "stamp-trust rule widened") is hereby REVERSED in
code.** The implementer's grounding — that under the literal rule the stamp
channel is information-free, and one-device human-vs-agent attribution
(blueprint §2 / done-means #1) becomes unreachable — is a real argument about
the SPEC, not about this implementation, and it is **banked as a proposed
blueprint amendment for the GATE-2 board**:

> *Proposed amendment (needs owner ruling):* admit an unregistered stamped actor
> when the writing peer has an ACTIVE binding and the stamped actor is
> co-resident by some positive evidence (e.g. a second binding row for the same
> peer, or an `actor.*` claim tying the actor to the peer's device). The shape
> that keeps both properties is "one peer may hold MORE THAN ONE active binding"
> — then co-resident actors are distinguishable AND every honored stamp still
> rests on engine-authored evidence. That is a registration-model change
> (`active_peer_actor`'s one-row invariant, the supersede rule), which is why it
> belongs to the blueprint and not to a fix round.

Until ruled, co-resident actors on one device peer must each be registered to be
told apart; the fallback is honest (`Registered`), never a guess.

### F2 (P1) `forged-open-marker-truncates-edit-window` → fail closed

`window_base` traversed from the final heads and stopped at the FIRST (latest)
commit parsing as `StampKind::Open`. The marker rides a commit MESSAGE, which
replicates, so a synced peer could commit its own `open` stamp and move
`proposed_ref` past every earlier edit — and finalize's replay-equality check
cannot catch it, because replay starts at the shifted base and reconstructs the
final text perfectly from there (baseline: `proposed_text` became `seed hidden`,
window collapsed to one span).

**Fix (`proposal_text.rs::window_base`):** exactly-one-open enforcement. The
traversal no longer breaks early; it collects every open marker and matches on
the slice — zero → `no open commit` (unchanged), one → the base, more than one →
`Error::CorruptedIndex("proposal artifact has more than one open commit")`.
Fail-closed as specified: an artifact whose history is not the history this
engine wrote has nothing to attribute.

### F3 (P2) `divergent-finalize-silently-overwrites-artifact` → write-once

`put_finalized_proposal_text` was blind last-writer-wins, and `from_snapshot`
preserves `artifact_ref`, so two clones of one artifact each finalized their own
history under the same key — silently swapping ED-09's reservoir (proposed,
final) pair.

**Fix:** read-before-write inside the existing write txn — identical bytes are
idempotent `Ok(())` (a retried finalize is not an error), different bytes are
refused and the stored record survives.

*Packet note:* the house pattern for this shape is a dedicated error variant
(`RedactionReceiptDivergence`, `IdentityTopologyEventDivergence`). `error.rs` is
outside this fix's packet, so the refusal rides
`Error::InvariantViolation("proposal artifact is already finalized with a
different record")`. Promoting it to `ProposalArtifactDivergence { artifact }` is
a one-line follow-up when the packet allows.

### F4 (P2) `second-granularity switch misattribution` → the switch second is ambiguous

A re-registration writes `valid_to = T` (exclusive) on the old row and
`valid_from = T` on the new one, so ops stamped exactly T — including ops written
BEFORE the switch — resolved to the NEW actor. Valid time is second-granular;
op timestamps are not, so the exclusive end is a tie-break the clock cannot
justify. (The lane's own re-registration fixture dodged this by pinning
`switch_at = now + 10`.)

**Fix:** one window predicate, `PeerBinding::claims_second`, with BOTH ends
inclusive — a row closing at T still speaks for second T, exactly as its
successor does. `peer_actor_at` then resolves by CLAIM rather than by recency:
two claimants naming different actors on one second → `None` → `DevicePeer`,
"never a guess between two actors". This also subsumes the old
`valid_from`-tie special case, so the max-`valid_from` / lost-witness
`InvariantViolation` branch is deleted. The stamp rule shares the predicate, so a
stamp naming EITHER actor that honestly held the peer that second is still
honored — the stamp resolves the ambiguity it does not create.

### F5 (P2) `replica-invisible binding index` → ONE read path

The peer→binding lookup went through a local `vault_meta` index
(`edit_distance/peer_actor/v1\0`) while the stamp rule read claims BY SUBJECT
through `claim_of` edges. Replication materializes claim entities and edges but
no local index rows, so on a replica the two read paths answered differently for
the same claim. Reproduced in-crate against the pre-fix source with a binding
written exactly as replication lands it (claim + edge, no index row):

```
probe_f5_replicated_binding_read_paths_agree ... FAILED
  left: (true, None)          # stamp rule sees the binding, peer_actor_at does not
 right: (true, Some(actor))
```

**Fix:** the `vault_meta` peer index is DELETED, and both resolvers read the
CLAIM substrate — which is what replicates — through one helper,
`peer_bindings_in_txn`, over a new `Vault::claims_with_predicate_in_txn`
(`claim.rs`, the one out-of-module read the fix needed). One parse site
(`PeerBinding::from_row`), one window predicate, one candidate set:
`peer_actor_at`, `active_peer_actor` and `peer_actor_stamp_is_honored` cannot
diverge because they no longer read different things. Pre-release, the orphaned
index rows are inert (no-legacy law).

*Cost:* the O(1) index lookup becomes one type-0 (CLAIM) scan per resolution,
paid at finalize over the artifact's window. Correct-and-shared beats fast-and-
divergent here; if a profile ever shows it, the fix is a peer→binding index that
the REPLICATED write path also maintains (a sync-side chokepoint), never a
second read path bolted onto the local one.

*Known hole (banked):* replicated binding rows are now trusted as evidence, and
federated admission accepts the reserved predicate. A hostile replica can
therefore add a second well-formed binding for a peer and force the switch/tie
ambiguity — i.e. deny attribution (`DevicePeer`), never forge it. Malformed rows
are skipped rather than poisoning the read, which is the same safe direction.
Tightening admission for `actor.peer_binding` is an admission-side question
(`sync/selector.rs`), outside this packet.

### Verification

| gate | feature set | result |
|---|---|---|
| repro harness `/tmp/one1756-repro` | `sync` | all 4 markers flipped (above) |
| in-crate F5 probe on pre-fix source | `--all-features` | FAILED before, green after |
| `cargo fmt --check` | — | clean |
| `cargo clippy --all-targets` | `--all-features` | **zero findings** |
| `cargo build -p oneiron` | default (non-sync) | **green**; only the pre-existing `batch.rs:4348` dead-code warning that is already on main |
| `cargo test -p oneiron --all-features` | `--all-features` | **green** — 3528 passed / 0 failed / 17 ignored (lib), 3862 passed / 0 failed across all 42 binaries, incl. the full sync suite |
| lane tests | `--all-features` | 19 (was 14): +5 new, 3 rewritten to the fixed semantics |
| lane tests | default (non-sync) | 9/9 green (the `proposal_text` half correctly cfg'd out) |

Tests rewritten because they pinned the DEVIATED rule (not because they were in
the way): `co_resident_actors_on_one_peer_are_distinguished_by_the_stamp` →
`an_unregistered_stamped_actor_falls_back_to_the_peer_registration`;
`an_unregistered_peer_falls_back_to_the_device_peer`'s first half now expects
`DevicePeer`; `a_failed_edit_still_lands_under_its_own_actor` now binds the
agent to the peer and asserts TWO spans with distinct trust arms (`Stamped` then
`Registered`), which is the no-fold property it actually exists to pin.

New: `the_reregistration_second_is_ambiguous`,
`an_unregistered_stamped_actor_is_not_honored`,
`a_replicated_binding_resolves_through_both_read_paths`,
`a_divergent_finalize_cannot_overwrite_the_stored_record`,
`a_second_open_marker_is_refused_rather_than_shifting_the_window`.

## Seams / notes for ED-01+

- `LoroOpRef` is `Frontiers::encode()` bytes. ED-01's `source=recorded_ops` lane
  gets its op window by `Frontiers::decode` on both ends, then either
  `find_id_spans_between` (ops) or `export(ExportMode::updates(...))` (delta
  bytes). No new accessor was added for a consumer that does not exist yet.
- `OpSpan` carries the full artifact text on both sides of its change. That is
  O(spans × text) in the record — deliberate at proposal scale (a span handed to
  an ED-04 miner in isolation still describes its own substitution) and worth
  revisiting only if proposal bodies ever grow past human scale.
- Co-resident actors on ONE device peer are indistinguishable until each is
  bound: under the blueprint's stamp rule (restored in VERDICT-FIX F1) an
  honored stamp can only agree with a binding. Both the stamped and the
  unstamped shared-peer cases therefore wait on the banked amendment
  (multi-binding peers) or on ED-02, which owns out-of-band edits.
- `distance.rs` (embedding cosine) is untouched — the name-collision law holds.
