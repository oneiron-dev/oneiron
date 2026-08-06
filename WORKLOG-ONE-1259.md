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

## FIX ROUND 1 (Opus) — DONE · 2026-08-06

Round-1 verdict (K3, `wf_a08b6bd5-ea9`): 3 REAL P2s + 1 banked P3. All four
landed; the lib.rs PACKET_AMEND-GAP is orchestrator-side (`CLAIMS.md` ONE-1926
row) and was not touched here.

Commits: **`214fdc9`** (engine, +48/-14 src · +114/-1 tests) ·
**`863bd38`** (server, +134/-25 src · +93/-9 tests · +77/-1 generated snapshot).

### FIX 1 — source-classification · `crates/oneiron/src/surface_event.rs`

`InboundSurfaceEventInput::new` derived `source.app` with
`from_channel_key(...).unwrap_or(Web)`. `ChannelIdentity::validate` admits any
nonempty ≤64-byte channel string, so an ACTIVE identity on a key outside the
ruled nine was reachable — and stamped a plausible, wrong source app into a
durable envelope. (In-tree `own_app` home identities are exactly such a key; see
known holes below.)

The guard lives in `routed_receipt` — the single place a `SurfaceEvent` is
built — so every routed state (Active/Rotating/Released/Quarantine) inherits it
and any future routed state does too. It returns `Error::InvalidConfig` naming
the offending key: the existing taxonomy seat (`validate_non_blank` and the
typed kind-collision already use it), mapped by `core_engine_error` to `400`, so
the refusal propagates as a 4xx rather than a 202 or a 500. No new error
variant was minted. `new` stays infallible, so the email/Slack/LINE/mock and
LinkedIn constructors compile unchanged; its placeholder is now documented as
unreachable-by-construction rather than a silent default.

- Test: `unruled_channel_key_is_refused_before_a_source_app_is_stamped` —
  ACTIVE identity on `carrier-pigeon`, asserts the routing error names the
  channel key, that admission fails the same way with zero queued rows, and
  that an explicit `with_source` override does not buy admission.
- **Mutation-verified**: neutering the guard turns the test red, and the
  failure prints the exact defect —
  `source: SurfaceEventSource { app: Web, .. }` on `channel: "carrier-pigeon"`.

### FIX 2 — correlation-admission · `crates/oneiron/src/surface_event.rs`

`dedupe_key` was the raw provider correlation id, and `AttemptQueue` caps
dedupe keys at 512 bytes, so a >512-byte id 400'd at admission. The fix is at
the admission chokepoint, not the call sites: **one bounded derivation
(`surface_event_run_id`) now keys both queue indexes.** The public correlation
id stays verbatim on the envelope, the ack, the status snapshot, and the
downstream `dispatch_idempotency_key`.

*Spec note — the blueprint is UNDERDEFINED here, and the amendment is minimal.*
It pins both `dedupe_key = correlation_id` (Shape §4) and "admission never
rejects a provider id merely for exceeding the run-id cap" (§1, Done-means row
2); those contradict for ids over 512 bytes. The derivation is verbatim at or
under 128 bytes, so **the pinned equality still holds for every id that was
previously admissible** — only the ids the old code rejected outright change
key.

- Test: `correlation_id_beyond_the_dedupe_cap_is_admitted_and_replays_once` —
  609-byte id admitted queued, both indexes keyed by the `sha256:` derivation,
  raw id intact on the decoded payload, duplicate submission observes exactly
  one admission, status queryable by the raw public id.
- One existing assertion changed deliberately:
  `long_provider_correlation_id_is_admitted_under_a_digested_run_id` asserted
  `dedupe_key == raw id` for a 209-byte id; it now asserts both indexes carry
  the derived key. Mutation-verified (reverting the change reds both tests).

### FIX 3 — api-contract · `crates/oneiron-server/src/api/surface_events.rs`

`UnknownReceivingIdentity` / `NonAgentBoundIdentity` /
`InactiveReceivingIdentity` / `TombstonedReceivingIdentity` all flattened
through `rejection_error` into one generic `BAD_REQUEST` envelope carrying a
stringified reason — four distinct adapter-actionable verdicts collapsed onto
one body, with the resolved identity/agent refs dropped. POST now returns
**`422` with `SurfaceEventRejectionResponse`**, the pinned
`InboundSurfaceRouteReceipt` field for field, minus the `surface_event` a
rejection never carries. `rejection_error` is deleted; `400` documents
malformed input only.

Shape decision: admission and typed rejection are both engine verdicts, not
transport failures, so the handler returns
`Result<SurfaceEventSubmitOutcome, EnvelopedApiError>` and the outcome enum's
`IntoResponse` owns 202-vs-422. The two engine enums the body mirrors
(`InboundSurfaceRouteOutcome`, `InboundSurfaceRejectionReason`) and
`SurfaceCounterpartyStamp` are `#[non_exhaustive]`; the response therefore
carries the **engine values directly** under `#[schema(value_type = ...)]`
instead of a hand-mirrored enum, so no wildcard arm can invent a reason or
silently drop a future one. Counterparty points its schema at the existing
`SurfaceCounterpartyPayload` component (identical tagged shape).

- OpenAPI: 422 response added, 400 description narrowed,
  `SurfaceEventRejectionResponse` registered in `ApiDoc` and in the contract
  schema list. Snapshot regenerated via `ONEIRON_UPDATE_TEST_FIXTURES=1`;
  **still purely additive vs `origin/main` (454 insertions / 0 deletions)**, so
  the PACKET_AMEND's minimality claim is unchanged.
- Tests: `v1_core_surface_event_rejects_unroutable_identity_without_queueing`
  now asserts the exact status and every receipt field (and that no `error`
  envelope or `surface_event` key survives); new
  `v1_core_surface_event_rejection_receipt_names_which_identity_failed` drives a
  vault-bound identity and asserts a different reason with
  `receiving_identity_ref` stamped and `agent_ref` absent.

### P3 (banked, folded in) — `last_error` wire shape

Dropped `skip_serializing_if` and declared `#[schema(required = true)]`, so the
status body mirrors the engine envelope: `"last_error": null` when empty rather
than absent, and the schema now lists it as required with type
`["string","null"]`. A client no longer has to tell "no error" apart from
"field not in this build". The ack test pins present-and-null.

### Gates

- `cargo fmt --check`: clean.
- `cargo clippy -p oneiron --all-targets --all-features -- -D warnings`: clean.
- `cargo clippy -p oneiron-server --all-targets --all-features -- -D warnings`: clean.
- `cargo test -p oneiron --all-features --lib surface_event`: **23/23**.
- `cargo test -p oneiron-server --all-features --lib` surface-event slice: **10/10**.
- `cargo test -p oneiron-server --all-features --lib`: 380 passed, 1 failed —
  the pre-existing `handler::tests::the_real_codec_rows_run_the_same_codec_package_axum_resolves`
  (websocket codec, `handler.rs`, untouched; already charged to no lane above).
- `cargo test -p oneiron-server --all-features --tests --no-fail-fast`:
  `core_discover` 10/10, `skills_pack` 7/7, `ws_sync` 41/41.
- Adapter regression check (the guard's blast radius):
  `channel_identity` lib 33/33, `channel_identity_email_adapter_smoke` 16/16,
  `channel_identity_slack_adapter_smoke` 2/2, `linkedin_connector_adapter` 2/2.
  Every in-tree adapter uses a ruled key (`email`/`slack`/`line`/`linkedin`).
- Full `cargo test -p oneiron --all-features --lib`: **3167 passed, 0 failed,
  24 ignored** in 209s — 3165 baseline (3164 + the previously-flaking
  `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`,
  which passed this run) plus the 2 new engine regressions. Nothing red.

### Known hole (banked, needs owner)

`ChannelIdentity::own_app_home` mints identities on channel key `own_app`,
which is **not** one of the ruled nine. No in-tree path routes inbound surface
events on it today (every adapter is email/Slack/LINE/LinkedIn, and the napi leg
is email-only), so nothing regresses. But if the companion ever posts inbound on
the own-app home identity, admission will now refuse it rather than silently
stamping `Web`. Resolving that needs a ruling — extend the closed enum or map
`own_app` onto an existing variant — which is a blueprint change, not an
implementer call.

## SIMPLIFY (K3) — DONE

**Verdict: the deviation is honest.** The `#[serde(rename = "imessage")]`
/`"linkedin"` overrides are genuinely required, not a rationalization. Verified
by compiling a serde probe (serde 1.0.229): `rename_all = "snake_case"` on
`IMessage` yields `i_message` and on `LinkedIn` yields `linked_in`. Neither
round-trips the pinned channel keys `imessage`/`linkedin` (the blueprint's own
Shape section pins those keys and `from_channel_key` matches them), so the two
explicit renames are the only way to satisfy both the closed enum and the key
round-trip the blueprint demands. The departure is forced by the pin, not
worked around it.

**One factual correction landed.** Both the source doc comment and this
worklog's note above overstate the mangling as `link_ed_in`; real serde emits
`linked_in` (single underscore before the interior capital `I`). The rename
*decision* is unaffected — both `i_message` and `linked_in` differ from the
pinned keys — but the justification comment now states verified reality.

- Edit: `crates/oneiron/src/surface_event.rs` doc comment on `SurfaceSourceApp`
  corrected (`i_message` / `link_ed_in` → `i_message` / `linked_in`, plus a true
  description of the rule). Comment-only; no assertion, no public-API change.
- add/del: **+3 / -1** on the SIMPLIFY commit (`5d13250`).
- Untouched on purpose: `SurfaceEventHandoffState::as_str()` has zero callers
  (the `.state.as_str()` hits elsewhere are `AttemptState`/`ChannelIdentityState`,
  a different type) — but it is exported public API mirroring the used
  `InboundSurfaceRejectionReason::as_str`, so removal would be a public-API
  change outside polish scope. Flagged, not deleted.

**Cheap gates after the pass:**
- `cargo fmt --check`: clean.
- `cargo clippy -p oneiron --all-targets --all-features -- -D warnings`: clean.
- `cargo test -p oneiron --all-features --lib surface_event`: 21/21 green.
- Full `cargo test -p oneiron --all-features --lib`: 3164 passed, 1 failed —
  `batch::tests::authority_fold_backfills_legacy_missing_first_seen_sidecars_once`.
  This is a **pre-existing timing flake charged to no lane**: the file is
  outside this lane's claims, the assertion compares two `unix_seconds_now()`
  reads that invert under full parallel load (`observed_before` 1785948168 vs
  `migrated` 1785947831, a ~6-min straddle across the 320s suite), and it
  **passes in isolation** (`--test-threads=1` + exact filter). Unrelated to
  surface events and to this comment-only edit.
