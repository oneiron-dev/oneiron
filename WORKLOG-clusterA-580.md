# WORKLOG — PR #580 post-merge fix-forward (Cluster A, ONE-1259)

Branch: `w5/postmerge-580` off `ONE-1259@f199af8` · worktree
`/Volumes/Cinema/w5-lt/surfaces-wire-580f`

Three REAL post-merge qodo findings on the merged surfaces-wire PR, fixed
forward as three sequential commits. Each fix is mutation-verified: the guard
was reverted, the new test observed to fail, and the guard restored.

| # | Finding | Commit |
|---|---|---|
| F1 | P2 status-blind negative cache in the idempotency middleware | `8d12194` |
| F2 | P3 replayed ack `accepted_at` drift vs `status.created_at` | `a10d1e3` |
| F3 | P3 OpenAPI erasure of the closed `rejection_reason` enum | `d087514` |

---

## F1 — the idempotency middleware cached failures (chokepoint)

`idempotency_middleware` persisted **every** response under the
`Idempotency-Key`, status and all, and `lookup` replayed it verbatim for the
24h TTL. `/v1/core/surface-events` runs under that middleware, and
`route_inbound_surface_event` rejects with a typed 422 on identity states that
*can* transition (`Requested`/`PendingFulfillment` → `Active`). A client that
retried the same key after the identity was fulfilled got the stale 422 back,
with no escape but inventing a new key — which defeats the header.

**Fix (chokepoint, not call site):** guard the insert on `parts.status <
StatusCode::BAD_REQUEST` in `crates/oneiron-server/src/idempotency.rs`. Every
idempotent route inherits it; no handler learns the rule. Replay still means
the effect never runs twice, it just no longer means a refusal is frozen.

The response-body clone now happens only on the cached path.

**Tests**
- `idempotency::tests::failed_response_is_not_replayed_after_the_condition_clears`
  — middleware-level: a handler that 422s once then 200s. The retry reaches the
  handler (counter 2), and the success that *did* land still replays (counter
  stays 2).
- `api::tests::v1_core_surface_event_rejection_is_not_cached_under_the_idempotency_key`
  — the real scenario: identity seeded `Requested` → 422
  `inactive_receiving_identity`; two `transition_channel_identity` calls to
  `Active`; same key, same body → 202 `replayed: false`.

**Mutation-verify:** guard → `if true`, both tests FAILED; restored, both green.

Test-helper refactor: `spawn_counted_app_with_config` now delegates to
`spawn_app_with_config(..., MethodRouter)` so a second handler can be mounted
without duplicating the harness. No existing test changed behaviour.

## F2 — a replayed ack claimed the replay's clock

`enqueue_inbound_surface_event` set `accepted_at: now` on every admission
including `replayed: true`, where `admit_surface_event_once` returned the
**pre-existing** `AttemptRecord`. `handoff_status` surfaces that record's
`created_at` on `GET`, so the two endpoints describing one attempt disagreed
about when it was admitted, and the ack's answer depended on which submission
won the race.

**Fix:** `accepted_at: record.attempt.created_at`. First admission is
unchanged (the row was stamped with this call's `now`); a replay now reports
the admission it found. Field doc on `SurfaceEventAck::accepted_at` states the
rule.

**Tests** — `surface_event::tests::surface_event_once_per_correlation_survives_terminal_state`
extended: three submissions at 1_800_001_000 / _001 / _200 must all report
`accepted_at == 1_800_001_000`, and `surface_event_handoff_status().created_at`
must equal it. The clock separation is what makes this a guard.

**Mutation-verify:** `accepted_at: now` restored → engine test FAILED.

The HTTP replay test also asserts `ack.accepted_at == status.created_at`, but
that one is a **contract pin, not a drift guard**: both calls land in the same
Unix second and there is no clock seam at the API layer to inject. Noted in the
test comment so nobody mistakes it for coverage. Injecting a clock into
`unix_seconds_now` for this would be more machinery than the finding is worth.

## F3 — the four rejection reasons were erased to `string`

`rejection_reason` serialized a closed engine enum, but carried
`#[schema(value_type = String)] + skip_serializing_if`, so the generated schema
said optional bare `string` while the handler doc promised "which of the four
rejection reasons applied". A generated client got an untyped, maybe-absent
field on the one body whose entire job is naming which of four things failed.

**Fix:**
- `SurfaceEventRejectionReasonPayload` mirrors the engine enum with
  `Serialize + ToSchema`, exactly as `SurfaceSourceAppPayload`,
  `SurfaceInteractionKindPayload` and `SurfaceEventHandoffStatePayload` already
  mirror theirs — the file's established idiom for an engine enum crossing this
  boundary.
- The field becomes `Option<SurfaceEventRejectionReasonPayload>` with
  `#[schema(required = true)]` and no `skip_serializing_if`: a rejection is
  exactly the outcome that carries a reason.
- **`#[non_exhaustive]` removed from `oneiron::InboundSurfaceRejectionReason`.**
  This is what makes the projection compile-checked: with the attribute, a
  downstream exhaustive match is impossible and any fifth reason would ship a
  schema that silently omits it. The enum is closed by ruling (same as
  `SurfaceSourceApp`, which never carried the attribute), and `non_exhaustive`
  only buys semver headroom this pre-release crate has no consumer for.
- Snapshot regenerated via `ONEIRON_UPDATE_TEST_FIXTURES=1`: +19 / -2.
  `SurfaceEventRejectionReasonPayload` gains its four-value `enum`,
  `rejection_reason` becomes `oneOf[null, $ref]`, and joins `required`.
  (The `null` arm is the honest reading of `Option`; removing it would need a
  fallible conversion for a state the engine never produces.)

**Tests** — `api::tests::v1_core_surface_event_rejection_reason_schema_is_the_closed_engine_set`
asserts the published `enum` array equals the engine's four `as_str()` values
*in order*, and that each mirrored variant serializes to that same string. The
variant *set* is compile-enforced by the `From` impl; this pins the *spellings*
so neither side can be renamed alone.

**Mutation-verify:** reverting to `value_type = String` + `skip_serializing_if`
FAILED three tests — the contract snapshot, the referenced-schemas test, and
the new engine-set test.

**Not done, deliberately:** an end-to-end HTTP test for
`tombstoned_receiving_identity`. Three of four reasons now have route-level
coverage (unknown, non-agent-bound, and inactive via F1's new test); the fourth
needs an `Active → Released → Quarantine`(min-window)`→ Tombstone` chain to
seed, and the reason derivation is already covered engine-side while the API
projection is now compile-checked. Cost without signal.

**Lint:** `#[expect(clippy::enum_variant_names, reason = ...)]` on the mirror.
The lint fires here and not on the engine twin only because
`avoid-breaking-exported-api` exempts `pub` items; the variant names are the
engine's and their snake_case *is* the wire contract, so renaming to satisfy a
style lint would mean four `#[serde(rename)]` attributes papering over it.

---

## Gates

- `cargo fmt --all -- --check`: clean.
- `cargo clippy -p oneiron -p oneiron-server --all-features --all-targets`:
  clean (zero warnings).
- Full `cargo test -p oneiron -p oneiron-server --all-features --no-fail-fast`:
  every target green (engine lib 3167 passed) except one pre-existing red.

### Pre-existing red, charged to no lane

`handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
fails on the **clean `f199af8` tip** — verified by stashing all three fixes and
re-running the single test. It compares the `tokio-tungstenite` package axum
resolves against the row the byte-property test uses:

```
  left: "...#tokio-tungstenite@0.28.0"
 right: "...#tokio-tungstenite@0.29.0"
```

A workspace dep-resolution skew, nothing to do with surface events. `Cargo.lock`
was **not** touched by this lane.

`embed::tests::partial_remote_completion_is_logged_when_local_batch_fails` red
once under full parallel load and passed in isolation and on the clean re-run —
a global-log-capture flake, unrelated (no file in `embed` was touched).

## Scope

Files touched, all within the ONE-1259 packet:

- `crates/oneiron/src/surface_event.rs`
- `crates/oneiron/src/surface_event/tests.rs`
- `crates/oneiron-server/src/idempotency.rs`
- `crates/oneiron-server/src/idempotency/tests.rs`
- `crates/oneiron-server/src/api/surface_events.rs`
- `crates/oneiron-server/src/api/tests.rs`
- `crates/oneiron-server/tests/fixtures/v1_core_openapi_contract.snapshot.json`

No `Cargo.toml`, no `Cargo.lock`, no `claim.rs`, no `api.rs` route-table edit.
Nothing pushed or merged from this worktree.
