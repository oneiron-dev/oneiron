# WORKLOG — ONE-1259 (SURFACES-WIRE, layer 1 of the SURF-api stack)

Branch: `ONE-1259` · worktree `/Volumes/Cinema/w5-lt/surfaces-wire`
Blueprint: `/Users/olety/.claude-wave5/blueprints/SURFACES-WIRE/ONE-1259.md`

## Plan

1. Engine envelope — `surface_event.rs` schema v2: closed `SurfaceSourceApp`,
   `SurfaceEventSource`, typed `SurfaceEventAction`, public `correlation_id`,
   bounded queue run-id derivation.
2. Engine ack-first handoff — once-per-correlation admission in one LMDB write
   txn over the existing `AttemptQueue`/run-index APIs, durable status read, and
   the test-only worker leg behind `SurfaceEventDispatcher`.
3. Server surface — `api/surface_events.rs` domain module + mechanical `api.rs`
   registration for `POST /v1/core/surface-events` and
   `GET /v1/core/surface-events/{correlation_id}`.

## PACKET_AMEND (2 mechanical strays, both collision-checked)

Both are forced by the claimed `api.rs` route-table edit — neither is a design
choice, and each was checked against every live claim manifest in
`~/.claude-wave5/blueprints/` before touching.

1. **`crates/oneiron-server/tests/skills_pack.rs`** (+6 lines).
   `documented_route_set_matches_api_routes_exactly` parses the route table out
   of `api.rs` source and asserts exact set equality; its own failure message is
   "api.rs route table changed; update oneiron.skills.md and this contract test
   together". Any route added to `api.rs` mechanically reds it.
   *Collision check:* no live lane claims this file (full manifest scan).
   *Minimality:* the two routes go into the file's existing
   `API_PARITY_ROUTES_PENDING_SKILLS_PACK_DOCS` escape hatch (precedent:
   ONE-1214, ONE-1265), so **`oneiron.skills.md` stays untouched** — it is BK
   ONE-1819's sole A3 MODIFY surface. Same class the ONE-1191 panel already
   ruled amendable.

2. **`crates/oneiron-server/tests/fixtures/v1_core_openapi_contract.snapshot.json`**
   (+378 / -0, purely additive). Generated artifact of the claimed
   `api/tests.rs` contract constants; regenerated via the file's own
   `ONEIRON_UPDATE_TEST_FIXTURES=1` mechanism. No pre-existing line changed.

### Deliberate non-amendment

`crates/oneiron-server/src/api/openapi.rs` holds the protected-route list that
attaches `CoreBearer`. It is a **contested cross-lane file** (BK ONE-1819
MODIFY; CSTDY ONE-1902/1903; RETRIEVAL-API — with explicit "no concurrent PR"
rules) and is not in this ticket's claims. Instead both routes declare
`security(("CoreBearer" = []))` inline in the owned `api/surface_events.rs`;
utoipa emits an identical `security` block, and
`generated_openapi_has_descriptions_examples_and_defaults` passes. A later
legitimate writer of that file may fold the two rows in.

## Notes

- **`SurfaceSourceApp` wire spelling.** The blueprint's sketch pairs
  `rename_all = "snake_case"` with `IMessage` / `LinkedIn`, which serde splits
  into `i_message` / `link_ed_in` — those cannot round-trip the `imessage` /
  `linkedin` channel keys the same blueprint pins. Both variants carry an
  explicit `#[serde(rename)]`; a test asserts every ruled channel key equals its
  own wire spelling in both directions.

- **Status-path encoding.** Provider correlation ids are not URL-safe (`@`, `:`,
  `/` all occur in real ids), so the ack's `status_path` percent-encodes the id.
  An unencoded path would have addressed the wrong resource, or none.

- **Admission atomicity.** The run-index lookup and `enqueue_in_txn` share one
  write transaction; a read-txn lookup followed by a separate write would let a
  concurrent submitter slip in a second row. Proven by a real two-thread test
  (`concurrent_submissions_of_one_correlation_id_produce_one_attempt`) asserting
  one row and exactly one non-replayed ack — not merely by sequential calls.

- **Pre-existing reds, charged to no lane** (both verified against a clean
  `origin/main` worktree):
  - `oneiron-server` lib: `handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
    — websocket codec, `handler.rs`, untouched here.
  - `oneiron` lib: dead-code warning on `batch.rs::put_replicated`.

- **Scope held.** `attempt_queue.rs`, `store.rs`, and their tests are unmodified
  (consumed only); no MCP/gateway file, no `oneiron.skills.md`, no
  `api/openapi.rs`, no wave-4 surface. No production dispatcher or worker-loop
  wiring ships: `SurfaceEventDispatcher` is exercised only by a test fake.
