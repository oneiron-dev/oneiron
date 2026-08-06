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

2. **Stamp-trust rule widened** — blueprint: "honored only when the stamped
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

## Seams / notes for ED-01+

- `LoroOpRef` is `Frontiers::encode()` bytes. ED-01's `source=recorded_ops` lane
  gets its op window by `Frontiers::decode` on both ends, then either
  `find_id_spans_between` (ops) or `export(ExportMode::updates(...))` (delta
  bytes). No new accessor was added for a consumer that does not exist yet.
- `OpSpan` carries the full artifact text on both sides of its change. That is
  O(spans × text) in the record — deliberate at proposal scale (a span handed to
  an ED-04 miner in isolation still describes its own substitution) and worth
  revisiting only if proposal bodies ever grow past human scale.
- Multi-actor-per-peer attribution now works via the stamp, but an UNSTAMPED
  out-of-band edit on a shared-peer device still resolves to that peer's single
  binding. Distinguishing co-resident actors on unstamped ops is ED-02 territory
  (the ticket names out-of-band edits as exactly that).
- `distance.rs` (embedding cosine) is untouched — the name-collision law holds.
