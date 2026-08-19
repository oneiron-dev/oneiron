# WORKLOG — ONE-1437 [SURF-ENG-04] Reactive local-first data layer

branch: `ONE-1437` cut off `f199af8` (ONE-1259 CY-CLOSED tip; #580 merged to main as `ee4a481`)
worktree: `/Volumes/Cinema/w5-lt/surfaces-wire`
blueprint: `/Users/olety/.claude-wave5/blueprints/SURFACES-WIRE/ONE-1437.md`

## Packet (claims) — verified `git diff --name-only f199af8`

- `crates/oneiron-server/src/api/reactive.rs` (new, 211 lines)
- `crates/oneiron-server/src/api.rs` (mod + re-export seam only, +7)
- `crates/oneiron-server/src/api/tests.rs` (8 fixtures, +409)
- `crates/oneiron-server/src/broadcast.rs` (`ReactiveChangeSubscriber` arm, +72)
- `crates/oneiron-server/src/server.rs` (Observer-A producer wire, +61)

Zero deletions, zero modified lines outside those files. Not touched:
`protocol.rs`, `handler.rs`, `sync/transport.rs`, `sync/bridge.rs`, `lib.rs`,
`Cargo.toml`, `Cargo.lock`. No route, no tag, no principal binding, no
Observer-B tee, no `livequery.rs`.

## Shape as built

**Producer (server.rs).** `WindowManager` already funnels every persisted local
window commit through one shared `OutboundSink` (bridge.rs Observer A), and on
the server nothing was attached to it — local commits were pushed onto a durable
`SyncQueue` that no server-side code drains. `spawn_local_change_producer`
attaches a server-owned receiver there and re-publishes each update as the
existing WindowSync `UPDATE` frame with `conn_id = 0`. `BroadcastSubscriber` and
the WS forwarding path are byte-for-byte unchanged.

**Classifier (broadcast.rs).** `ReactiveChangeSubscriber` reads the same
channel with no echo suppression (a writer's own device must still refresh its
LMDB view) and no disconnect escalation (lag is a freshness problem, not a
connection fault). `persistent_change` routes each frame through the read-only
`protocol::parse_message` seam; only `RootUpdate` and WindowSync `UPDATE`
survive.

**Contract (api/reactive.rs).** `ReactiveLocalRead::open` subscribes, then
reads, then returns — synchronous, no `Loading` state representable.
`refresh_on_change` waits past irrelevant notices, re-reads once on a match, and
treats `Lagged` as `InvalidateAll` → one coarse full re-read.

## Deviations from the blueprint skeleton (GATE-2 items)

1. **`ReactiveChangeSubscriber::recv` returns `Option<ReactiveChange>`, not
   `Result<Option<ReactiveChange>, ReactiveChangeError>`.** Forced, not
   preference: the blueprint's own pinned semantics (`Closed` → `Ok(None)`,
   `Lagged(n)` → `InvalidateAll`, non-persistent → skip in-loop) leave the error
   type with no constructible variant. An unconstructed variant is `dead_code`
   and the cheap gate runs `-D warnings`, so `ReactiveChangeError` could not
   ship. `ReactiveReadError` (the other skeleton error type) does have two real
   producers — `ChannelClosed` and `Read(oneiron::Error)` — and is kept.
2. **`spawn_local_change_producer` returns `None` outside a Tokio runtime.**
   `SyncServer::new` is a sync fn with non-async `#[test]` call sites, so an
   unconditional `tokio::spawn` would panic there. Both production call sites
   (`commands::serve_with_config`, `commands::revoke`) are `async fn`. In the
   no-runtime case nothing is attached, so Observer A keeps its existing
   `SyncQueue` fallback and no unread sender can accumulate updates.
3. **`#[allow(dead_code)]` on `mod reactive`.** The contract has no in-tree
   caller by design (ONE-1925's client-framework binding and ONE-1495's cloud
   carrier are the consumers), so the non-test lib build sees 11 unused items.
   Same posture and same justification style as `protocol::close_codes`.
   Verified load-bearing: removing the attribute produces exactly those 11
   warnings and nothing else.

## Observation, not a hole

Two call sites already publish their own coarse VV-delta for a commit the
producer now also publishes from Observer A's bytes: the reassert-drain tick
(`server.rs`) and the fenced-carrier scrub (`handler.rs`). The frames are CRDT
updates, so a client importing both converges identically; suppressing either
would be a WS-hot-path edit this packet forbids. Recorded so the screener sees
it was weighed, not missed.

## Gates

- `cargo fmt --check` → exit 0
- `cargo clippy -p oneiron-server --all-targets --all-features -- -D warnings` → exit 0
- `cargo test -p oneiron-server --lib --all-features` → **388 passed, 1 failed**
  (baseline 380+1: `handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
  pins `tokio-tungstenite@0.29.0` while axum resolves `0.28.0` — pre-existing,
  no file in this packet touches it. 388 = 380 baseline + 8 new.)
- `cargo test -p oneiron-server --tests --all-features --no-fail-fast` →
  `ws_sync` 41/41, `core_discover` 10/10, `skills_pack` 7/7 — the WS hot path is
  undisturbed by the producer.

## Fixtures (all green)

| fixture | proves |
|---|---|
| `local_reactive_read_is_synchronous` | runs with **no Tokio runtime at all**: snapshot immediate, one read, revision 0 |
| `local_reactive_read_keeps_snapshot_when_channel_closes` | `ChannelClosed` is terminal but the cached read survives; zero re-queries |
| `local_reactive_read_refreshes_on_matching_sync` | window `UPDATE` and root update each cause exactly one re-query, revision 1 |
| `local_reactive_read_ignores_nonpersistent_frames` | ephemeral, root-VV, lease, VV_REQUEST/VV_RESPONSE/SELECTOR_VV_REQUEST, empty, unknown-tag — all against `AnyPersistent`, so the frame class does the rejecting |
| `local_reactive_read_ignores_unrelated_window` | `2026-03` update does not wake a `2026-02` query |
| `local_reactive_read_recovers_from_lag` | capacity-2 channel overflowed with unrelated-window frames → one coarse re-read, current snapshot |
| `local_reactive_read_observes_bridge_and_own_connection_origins` | `conn_id` 0 and 7 both wake the reactive read while `BroadcastSubscriber(7)` still suppresses its own echo on the same channel |
| `local_vault_write_reaches_reactive_read_through_engine_observer` | **production wiring**: `put_entity` → `reverse_rematerialize` → Observer A → `OutboundSink` → producer → `broadcast_tx` → refresh. No encoded frame is injected anywhere in the fixture |

The negative fixtures assert via `tokio::time::timeout` on `refresh_on_change`
rather than counting reads after the fact — a read count cannot distinguish
"woke on the noise frame" from "woke on the later real frame".

## SIMPLIFY pass (K3, ff328ed — final commit, on top of abf5bcd)

Deletion-biased, zero assertion/fixture/public-API change (tests.rs untouched):

- `spawn_local_change_producer` → unit return (was `Option<JoinHandle>` whose
  handle is detached-by-design and was dropped at the one call site). Attach
  moved below the runtime check so a no-runtime server never arms an unread
  Observer-A sender; `let Ok(handle) = try_current()` replaces the named
  `runtime` binding (plain tokio::spawn idiom).
- `refresh_on_change`: loop-break → plain `return Ok(&self.snapshot)`;
  `revision += 1` (local cache epoch, untriggerable wrap; saturating_ idiom is
  reserved for untrusted/wire-driven arithmetic in this codebase).
- Doc dedupe: ReactiveChangeSubscriber carried the no-echo-suppression
  rationale twice (struct + recv) — kept at recv, where the conn_id is
  actually discarded; the "Two things separate it" framing collapsed to the
  lag-escalation contrast. api.rs seam comment and the double-link
  InvalidateAll doc trimmed.

Gates after: fmt exit 0 · clippy `--all-targets --all-features -D warnings`
exit 0 · lib suite 388 passed + 1 pre-existing baseline failure (tokio-
tungstenite 0.29/0.28 pin, same as pre-simplify) · the 8 `local_reactive_*`
fixtures green by name filter · ws_sync 41/41, core_discover 10/10,
skills_pack 7/7. Packet still exactly the five claimed files.
