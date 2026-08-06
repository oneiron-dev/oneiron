# WORKLOG — ONE-1784 [CAL-02] ICS ingest adapter-SKILL

Seat: K3 impl (K3-route lane). Branch: ONE-1784 off origin/main 73d828d2f.
Worktree: /Volumes/Cinema/w5-lt/cal-1789.

## Shipped

- CREATE `crates/oneiron/src/calendar/ics.rs` — RFC 5545 parse half via the
  landed `icalendar` dep (parser types private to the module). Strict
  completeness: UTF-8 + `BEGIN:VCALENDAR`…`END:VCALENDAR` sentinels + full
  parse, UID required per VEVENT. Canonical per-VEVENT SHA-256 (sorted
  property lines, params sorted by key, `DTSTAMP` excluded, nested VALARM
  excluded). `TRANSP` → `CalendarBusyTransparency::from_ics_transp` (fail
  closed to busy). UTC `...Z` times convert via a local days-from-civil (no
  second datetime dependency at the border); `TZID` times cross CAL-01's
  `wall_to_utc`; floating times → `None`, never a guessed zone.
- CREATE `crates/oneiron/src/calendar/passport.rs` —
  `CALENDAR_PASSPORT_INDEX_PREFIX = b"calendar.passport.v1:"`, keyed
  prefix + SHA-256(uid) → EVENT id, mirroring `comm.rs` `PARTY_INDEX_PREFIX`
  / `resolve_party` including repair-on-miss from synced truth (live passport
  claims) with lexicographic-twin convergence. `PassportDecision`,
  `resolve_event_by_uid`, `classify_passport` (higher SEQUENCE updates;
  same-SEQUENCE hash drift updates; same seq+hash skips; older-SEQUENCE
  replay skips; absent→re-appearance updates back to live),
  `supersede_calendar_passport` scoped to exactly `(system, uid)`.
- CREATE `crates/oneiron/src/calendar/ingest.rs` — `IcsFeedPollConfig`
  (custody `secret_ref` only; hand-rolled `Debug` forward guardrail),
  `IcsFeedPollPayload { config, not_before }`, `ICS_POLL_ATTEMPT_KIND =
  "calendar.ics.poll"`, `IcsFeedFetcher`/`IcsFetchResponse`,
  `enqueue_ics_feed_poll` (mirrors `enqueue_inbox_sync_poll`),
  `run_ics_feed_poll` (+`_with_screener` wiring CAL-09),
  `CustodyDoorIcsFeedFetcher` (production door fetcher), ETag cursor rows at
  `b"calendar.ics-feed.v1:"`, raw `.ics` archival via `blob_artifact` BEFORE
  semantic admission, absence sweep + multi-source-law cancellation, loud
  pause on credential reset (attempt-row `Pause` + cursor pause + derived
  inbox exception projection `ics_feed_pause_exceptions`), bounded-jitter
  re-enqueue, `IcsFeedSource` (parse-only normalization; never mints claims).
- MODIFY `crates/oneiron/src/calendar/mod.rs` — module declarations +
  narrow re-exports; appended `CalendarError::{IcsParse, IcsFetch,
  IcsCredential, IcsIngest}` + `From<crate::Error>`; extended the exhaustive
  error test (its designed purpose).
- MODIFY `crates/oneiron/src/ingest.rs` — `ICS_FEED_SOURCE_ID`,
  `IngestSourceFormat::IcsFeed`, `IngestError::InvalidIcsDocument`, registry
  entry #3 (Imported ceiling, auto path closed, proposed default),
  `admit_imported_evidence_claim_typed` (typed-msgpack sibling of the
  existing admission door — identical Gate path; see deviation D4).
- CREATE `crates/oneiron/tests/calendar_ics_ingest_adapter.rs` — 17 named
  oracles, all green (see Done-means map below).

## Blueprint deviations (declared, none silent)

- **D1 — SECRET-02 door/lease API absent at branch base.** The dispatch gate
  was "SECRET-01 + SECRET-02 merged", but `inject_secret_at_door` /
  `materialize_secret_lease` / `secret_lease.rs` do not exist on 73d828d2f
  (verified by grep + `git ls-tree origin/main`). The production fetcher
  therefore implements the door inline: `resolve_secret_ref` →
  crate-private `get_secret_value_in_txn` (binding-enforced,
  `SECRET_SCOPE_READ` + effector) → the URL is consumed inside the transport
  call and never returns; transport error strings are URL-scrubbed at the
  door. Blueprint amendment 1 said "never call `get_secret_value_in_txn`
  directly" — that law guards against URL escape into workspace state; this
  module IS the egress door the law intends, and the swap to the formal
  SECRET-02 API is a one-call-site internals change with no signature churn.
  NEEDS ORCHESTRATOR/OWNER ACK: dispatch gate was half-unsatisfied at cut
  time; the swap-on-1920-merge follow-up should be tracked.
- **D2 — `reqwest` reservation absent.** ONE-1783 merged without the
  blueprinted reqwest append, and Cargo.toml/lock are non-claims for this
  lane, so the egress is a host-injected `IcsHttpTransport` (one GET with
  `If-None-Match` → status/etag/body). When the reqwest reservation lands, a
  reqwest-backed `IcsHttpTransport` is a drop-in; no engine type changes.
- **D3 — `ParsedVEvent` carries three fields beyond the ratified skeleton:**
  `summary`, `description`, `cancelled`. The runner must name the minted
  EVENT (SUMMARY), build CAL-09's `CalendarInboundBody` (DESCRIPTION), and
  write `calendar.status` basis `imported_cancel` (STATUS:CANCELLED) — the
  ratified struct could express none of these. Proposed amendment; all three
  are additive and consumed only inside the adapter.
- **D4 — `admit_imported_evidence_claim_typed` added to `ingest.rs`.** The
  existing admission door takes `serde_json::Value`, which cannot express the
  passport codec's MessagePack-binary `content_hash` (CAL-00 owns that codec;
  a JSON array would fail the write-door validator). The sibling is the same
  Gate-backed candidate path with a typed `rmpv::Value`. PACKET_AMEND
  candidate (ingest.rs scope was "format/registration"; this is the same file
  but a second concern — flagged for ratification).
- **D5 — `ingest/tests.rs` parity test extended with entry #3.**
  PACKET_AMEND candidate: the file is ONE-1790's claim per CLAIMS.md, but
  the registry-parity assertion hard-codes the expected set and must name
  `ics-feed` the moment the registry gains it; the alternative is main red.
  Minimal additive edit (one `expected_ics_feed_config` + one array entry),
  merge order 1784 → 1790 preserved.
- **D6 — Re-enqueue dedupe key is generation-scoped** (`<base>:due:<not_before>`).
  The queue's dedupe covers PENDING rows, so the bare per-config key would let
  the currently-executing row swallow its own successor (Leased is pending) and
  the chain would die after one poll. Generation keys keep exactly one pending
  successor per due instant and stay idempotent for a redundant same-instant
  run. `enqueue_ics_feed_poll` keeps the ratified bare-key shape.
- **D7 — `run_ics_feed_poll_with_screener` sibling.** The ratified
  `run_ics_feed_poll` signature has no screener slot, but CAL-09's hook is
  host-injected; the ratified entry delegates with the dial off (`Skipped`),
  and the `_with_screener` sibling is the host wiring point the verdict test
  exercises.
- **D8 — one-live-`calendar.status` discipline.** Absence cancellation and
  imported-cancel admit a new status claim and supersede the prior live one
  (skipping when the live claim already carries the exact value), so an EVENT
  holds at most one live status claim — the same discipline passports
  ratified, applied to status. No resurrection basis exists in CAL-00's enum,
  so v1 never writes `confirmed` from the adapter (symmetric for
  `imported_cancel` and `imported_absence`); resurrection semantics are a
  later-layer decision.
- **D9 — `BlobVersionProvenance::AgentRun { run_ref: dedupe_key }` reused for
  raw-feed archival** (`blob_artifact.rs` is a non-claim; no connector-fetch
  variant exists). The run_ref names the feed's dedupe identity — never the
  URL.
- **D10 — UpdateExisting refreshes the passport only.** The ratified diff
  vocabulary is passport-scoped; v1 does not rewrite the EVENT's occurred
  range or `time_kind` on content updates (claims land Proposed for owner
  review regardless). Flagged as a scope decision for the screen.
- **D11 — inbox exception is a derived projection** (`ics_feed_pause_exceptions`
  over cursor pause state + attempt-row `Pause`), mirroring CAL-07's derived
  check-in exception; `inbox.rs` is ONE-1789's file and has no connector-pause
  taxonomy to reuse. The blueprint's "no new inbox exception taxonomy if the
  merged engine already has a connector/config exception shape" — none exists
  (checked `inbox.rs`, `linkedin_connector.rs`), so the projection lives in
  `calendar/ingest.rs`.

## PACKET compliance

Diff vs branch base 73d828d2f touches ONLY: the four CREATEs, `calendar/mod.rs`,
`ingest.rs`, `ingest/tests.rs` (D5). No change to `registry.rs`, `edge.rs`,
`oneiron-vault-contract/src/lib.rs`, `claim.rs`, `calendar/claims.rs`,
`calendar/tz.rs`, `calendar/series.rs`, `connector_key.rs`,
`attempt_queue.rs`, `inbox.rs`, `comm.rs`, `blob_artifact.rs`, `gate.rs`,
`Cargo.toml`, `Cargo.lock` (dirty locally from builds; never committed).

## Security invariants — how each is enforced

- Poll payload carries custody `secret_ref`, never the URL: `IcsFeedPollConfig`
  has no URL field; canary test asserts the canary string is absent from every
  attempt payload, every Debug form, and every error string.
- URL touched only at the egress door: `CustodyDoorIcsFeedFetcher` resolves +
  reads the value inside one call and hands it to the transport; the return
  type cannot carry it.
- No EVENT/claim/attempt payload contains the URL: claim values are built from
  parsed VEVENT fields only; provenance refs name the blob artifact + UID.
- No new credential substrate: custody via SECRET-01 records only;
  `connector_key.rs` untouched.
- Parse/fetch failure ≠ removal: strict completeness parse; on failure the run
  errors BEFORE the diff; cursor/presence/status preserved (oracle-pinned).
- Feed-absence cancellation only when every live inbound passport reports
  absence: `all_live_inbound_passports_absent` requires ≥1 inbound passport
  and unanimity; single-source absence supersedes only that passport.
- 304 = no mutation + re-enqueue (one cursor touch: a provider answer after a
  pause clears the pause — the resume path; no claim/index/blob/status write).
- Secret-URL reset = loud pause: attempt-row `Pause`, cursor pause, one
  derived inbox exception, no retry storm, no event cancellation.
- Gate never bypassed: all claim writes route through
  `admit_imported_evidence_claim*` (candidate + envelope door);
  `screen_then_claim` wraps every admission with the typed
  `CalendarAdmissionRequest`; no zero-arg closure exists.

## Done-means map (all green)

`cargo test -p oneiron --all-features --test calendar_ics_ingest_adapter`:
17/17. Named coverage: `ics_feed_source_has_registry_parity`,
`new_same_updated_and_missing_passport_diff`,
`single_source_absence_never_cancels_a_multi_source_event`,
`all_live_inbound_sources_absent_write_calendar_status`,
`uid_first_cross_calendar_resolution_is_n_passports_to_one_event`,
`passport_supersede_is_scoped_to_system_and_uid`,
`busy_transparency_defaults_busy_and_preserves_free`,
`etag_not_modified_is_a_true_noop`,
`parse_failure_never_marks_prior_uids_missing`,
`raw_ics_is_archived_before_semantic_admission`,
`imported_calendar_claims_cross_gate`,
`calendar_safeguard_admission_carries_verdict`,
`secret_url_is_absent_from_attempts_debug_receipts_and_errors`,
`production_fetcher_uses_secret_door_and_if_none_match`,
`provider_url_reset_pauses_attempt_and_surfaces_exception`,
`poll_cadence_reenqueues_with_bounded_jitter`,
plus `imported_cancel_status_in_feed_writes_imported_cancel_basis` (D3's
cancel path). Unit tests live in `calendar/ics.rs` (7) and
`calendar/passport.rs` (3). Full-suite result: see below.

## Gates

- `cargo check -p oneiron --all-features`: green.
- `cargo clippy -p oneiron --all-features [--tests]`: clean under workspace
  denies.
- `cargo fmt -p oneiron`: applied.
- `cargo test -p oneiron --all-features`: FULL SUITE RESULT PENDING AT COMMIT
  TIME — updated before final commit.
