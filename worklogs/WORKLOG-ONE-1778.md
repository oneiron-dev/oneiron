# WORKLOG — ONE-1778 [CA-07] SDK surface

Branch `ONE-1778`, cut from `origin/main` @ `8c4ed0753`.
Worktree `/Volumes/Cinema/w5-lt/ca-1773`.

## What landed

One `self.*` verb vocabulary over the CRM pack, reachable from two places that
share a single engine door.

| File | Kind | Content |
|---|---|---|
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/campaign/surface.rs` | CREATE | The ten `SELF_*` constants + `CAMPAIGN_SELF_VERBS` (verbatim from the blueprint skeleton), `CampaignSurfaceVerb`, `SurfaceCall`/`SurfaceReply`, the membership types, `invoke_campaign_surface`, `read_campaign_members`, `read_saved_query_members`, the CAMPAIGN record lifecycle, the JSON codec, and the in-crate membership-projection tests |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron-server/src/api/campaign.rs` | CREATE | Campaign router + the shared `dispatch` / `surface_actor` / `surface_error` plumbing |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron-server/src/api/saved_query.rs` | CREATE | Saved-query router, importing that plumbing |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron-server/tests/campaign_surface_oracle.rs` | CREATE | 11-row parity/contract oracle |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/campaign.rs` | MODIFY | `pub mod surface;` + doc, nothing else |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron/src/facade.rs` | MODIFY | Ten `self.*` verb methods on the existing `MemoryFacade`, nothing else |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron-server/src/api.rs` | MODIFY | Two `mod` declarations + two `.merge(...)` mounts, nothing else |
| `/Volumes/Cinema/w5-lt/ca-1773/crates/oneiron-server/src/api/discover.rs` | MODIFY | `self_verb_capabilities()` chained into the existing capabilities list |

`git diff --name-only 8c4ed0753..HEAD` is exactly those eight paths. No
`mcp.rs`, no `api/mcp_gateway.rs`, no `graph_fs.rs`, no `registry.rs`, no
`saved_query.rs`, no `Cargo.toml`. **`Cargo.lock` appears in no commit** (it is
dirty in the worktree because cargo regenerates it — see finding F3).

### Shape

The transport is as thin as it can be: an HTTP handler injects the path ref into
the JSON body, calls `invoke_campaign_surface`, and serializes the whole
`SurfaceReply`. Parity is therefore **structural, not asserted** — an HTTP
response and an in-process `invoke_campaign_surface` result are the same
document by construction, and `campaign_http_crud_matches_facade` compares them
byte-for-byte on a shared record.

## Blueprint deviations — declared, none silently absorbed

### D1 (material) — CA-00..CA-04 ship no CAMPAIGN record; CA-07 mints the minimal one

The blueprint reads "expose the **already-built** campaign and saved-query domain
APIs" and its Notes say "do not duplicate the domain model". Ground truth: there
is no campaign domain model to duplicate.

* `campaign.rs` (CA-00/ONE-1771) owns the short-id prefix, the pack id, and
  `register_campaign_kind` / `register_crm_pack`. That is all.
* Grep for `create_campaign|read_campaign|update_campaign|archive_campaign|CampaignRecord|CreateCampaignRequest|CampaignLifecycle` across `crates/oneiron/src/` returns nothing.
* `MemoryFacade::put_structural` cannot mint one either: it resolves kinds
  through the static `ENTITY_TYPE_REGISTRY`, and CAMPAIGN is a runtime-registered
  dynamic kind.

So `POST /campaigns` → `self.campaign.create` had nothing to delegate to. I minted
the minimal record in `campaign/surface.rs` (my own CREATE claim, inside the
engine, not the transport): `CampaignDefinition { schema_version, owner_actor,
name, definition_version, lifecycle }` + `CampaignRecord` + create/read/update/
archive, built as a **line-for-line mirror of CA-02's SavedQuery idiom** —
no owner field on the request types, owner bound at the write boundary,
single-transaction version CAS, archive-as-transition, storage through the same
`apply_ops` batch-put chokepoint.

Deliberately excluded: any stage/compliance/enrollment/send-hygiene field. A
campaign still stores no member list — CA-01's separation law holds.

**Ask:** confirm CA-07 is the right home, or route the record to a CA-00
follow-up and have CA-07 delegate.

### D2 — the blueprint's membership skeleton does not compile as written

`MembershipReadRequest` / `MembershipRow` / `MembershipPage` are pinned with
`#[derive(Serialize, Deserialize)]`, but all three carry `EntityId`, which has no
serde impl (`entity_id.rs` is a CA non-claim, and CA-02 documents the same
constraint on `SavedQueryDefinition`). Dropped the two serde derives; the wire
form goes through the module's hand-written JSON codec, exactly as CA-02 does.
`SurfaceCall`/`SurfaceReply` keep theirs (`String` + `Value` only). Field names,
types, and ordering are otherwise verbatim.

### D3 — the MCP arm cannot exist yet; CA-07 correctly adds nothing

Two done-means rows are unsatisfiable together as written:

* "`campaign_mcp_gateway_uses_existing_dialect` invokes all ten `self.*` verbs
  through the CAL-09-owned existing gateway envelope"
* the hard NON-CLAIM on `api/mcp_gateway.rs` and `mcp.rs`

`McpToolName` is a closed set of six — `nav`, `read`, `edit`, `ask`,
`ask_routed`, `calendar`. **There is no generic "dispatch a `self.*` verb" arm**,
so no gateway call can reach `invoke_campaign_surface` without editing
`api/mcp_gateway.rs`. CA-07's non-claim is the binding constraint and I honored
it: no gateway branch, no tool, no op enum.

What I pinned instead, both checkable and true:

* `campaign_adds_no_mcp_tool_name` — the catalog keeps `oneiron.calendar`, gains
  no campaign/saved-query tool, alias, or op discriminator.
* `campaign_surface_reaches_all_ten_verbs_through_one_engine_door` — all ten
  verbs dispatch through `invoke_campaign_surface` with no transport present.
  That is precisely the property a future gateway arm inherits: a dialect that
  builds a `SurfaceCall` gets the HTTP routes' exact behavior for free.

**Ask (`needs: owner`):** MCP reach for the ten verbs is **not delivered** and is
blocked on a generic self-verb arm in the CAL-09-owned dialect. Schedule it on
CAL-09 or ONE-1819, or grant CA-07 (or a follow-up) the `api/mcp_gateway.rs`
claim after 1819 lands.

### D4 — HTTP routes mounted at the ratified paths, un-prefixed

`POST /campaigns`, `GET /campaigns/{campaign_ref}`, … and `/saved-queries/...`,
exactly as the content-ratified resource matrix spells them — merged at the
router root, alongside `/mcp`, not nested under `/v1`. Flagged only because every
other recent resource lives under `/v1/core` or `/v1/companion`. Say the word and
they move.

### D5 — discovery rides the existing capabilities list, not a new key

First cut added a top-level `self_verbs` array to `DiscoverResponse`. That broke
`discover_requires_auth_and_returns_empty_contract` in
`crates/oneiron-server/tests/core_discover.rs`, which pins the exact key set —
**an out-of-packet file**. Rather than take a PACKET_AMEND for a cosmetic
choice, the ten verbs now chain into `feature_flags.capabilities`, derived from
`CAMPAIGN_SELF_VERBS` the same way `mcp_tool_capabilities()` is derived from
`McpToolName`. Each verb appears exactly once by construction, no discovery key
was added, and `core_discover.rs` is untouched and green. This is the better
shape anyway — the verb string IS the token an agent calls.

### D6 — membership-fold tests live in-crate, not in the server oracle

See finding F1: a `campaign.member` write is held at the gate in any
`Vault::open`ed vault, and the unseeded opener sits behind the `test-support`
feature, which `oneiron-server`'s dev-dependency does not enable (turning it on
means editing `crates/oneiron-server/Cargo.toml` — hard non-claim).

Split, so both halves are real rather than one being weak:

* **Fold semantics** — cursor stability across a page boundary, gap-free paging,
  cursor idempotence, `limit = 0` default, over-large-limit clamp, malformed-cursor
  rejection, bitemporal `at_epoch`, cause preservation, read-only fingerprint —
  live in `campaign/surface.rs`'s own `#[cfg(test)] mod tests`
  (`campaign_membership_reads_are_paginated_and_read_only`,
  `saved_query_membership_reads_preserve_causes`, both named per the done-means).
  Inline rather than a `surface/tests.rs` sibling, to stay inside the one claimed path.
* **Route wiring** — route shape, scope enforcement, query-string translation,
  clamping, cursor rejection, malformed-ref rejection, HTTP↔facade document
  equality, and a no-write fingerprint — live in the server oracle as
  `campaign_membership_routes_carry_the_engine_paging_contract`.

## Findings to return

### F1 — the CRM pack ships no policy-manifest axes, so `campaign.member` cannot auto-approve on a default-seeded vault

`gate.rs`'s default manifest declares axes for exactly four predicate prefixes:
`profile.`, `calendar.`, `booking.`, `affect.vad`. Its default for everything
else is `critical` (`axes_for_predicate(...).criticality.unwrap_or(Critical)`),
and `evaluate` pushes `PendingCriticalityFloor` for any `Critical` write with no
consent context. So on a `Vault::open`ed vault:

```
commit_membership_plan(...) -> Err(GateWriteRejected {
    outcome: "pending", reason_codes: ["gate.pending.criticality_floor"]
})
```

Every CRM predicate (`campaign.`, `crm.`, `comm.*` pack rows) is affected, not
just `campaign.member` — CA-02's oracle sidesteps it with the unseeded opener, so
it has stayed invisible. This means **CA-03's enrollment writer cannot land a
membership claim on a default-seeded vault** without a host manifest or a
consent context.

Not CA-07's to fix (`gate.rs`, `registry.rs`, and the manifest are all
non-claims), and CA-07 is unaffected — it only READS heads. Belongs to CA-01/CA-06
or a policy-pack ticket. **Route to the deviation board.**

### F2 — pre-existing red on clean main: `the_real_codec_rows_run_the_same_codec_package_axum_resolves`

`cargo test -p oneiron-server --lib` has one failure that is **not mine**:

```
left:  ...tokio-tungstenite@0.28.0   (the `production-ws-codec` dev-dep alias)
right: ...tokio-tungstenite@0.29.0   (what axum 0.8.9 resolves)
```

Proof it is pre-existing: the test reads `cargo metadata --locked` and compares
dependency EDGES — it never reads a `.rs` file, and my diff is eight `.rs` files
with zero manifest changes. The **committed** `Cargo.lock` at base `8c4ed0753`
already carries `axum 0.8.9 -> tokio-tungstenite 0.29.0` while
`crates/oneiron-server/Cargo.toml` pins `production-ws-codec = "0.28"`.

Fix is a one-line bump to `production-ws-codec = "0.29"` in
`crates/oneiron-server/Cargo.toml` — a hard non-claim here. **Charged to no lane;
route to the recipe-defect bucket.** Everything else in the server crate is green
(393 lib rows with that one skipped, plus every integration target).

### F3 — the committed `Cargo.lock` is stale relative to main's manifests

Any build regenerates it with 172 pure insertions (`icalendar`, `rrule`,
`chrono`, `chrono-tz`, `iso8601`, `phf`, …) — CAL's C4 dependency append landed
in `Cargo.toml` without a lock refresh. Expected under the never-commit-the-lock
law (regeneration happens at merge); noted so the merge audit is not surprised,
and because `--locked` cannot run in this worktree until the lock is refreshed.

### F4 — membership enumeration is a CLAIM-index scan, by necessity

`read_campaign_members` / `read_saved_query_members` walk
`entities_by_type(ENTITY_TYPE_CLAIM)` and filter live `campaign.member` heads —
the same shape `/api/core/discover` uses. The CRM pack registers no membership
index and `registry.rs` is a hard non-claim, so there is no cheaper door. Output
is bounded by the page limit; the scan is not. Documented at the function.
A membership index is the honest follow-up once cohorts get large.

## PACKET_AMEND candidates

**None taken.** The one near-miss (D5, `core_discover.rs`) was designed out
rather than amended.

## Design notes worth a screener's eye

* **Cursor is the `(entity, query, campaign)` triple, hex-encoded** (96 chars,
  opaque). An entity-only cursor could skip or repeat a row when one entity holds
  heads in several campaigns derived from one query.
* **`next_cursor` is emitted only when an unvisited head remains**, and it
  advances for every head the loop CONSUMED — including heads whose history folds
  to nothing, so a cohort of them cannot stall a pager.
* **`entered_*` always report the newest ENTRY**, even after an exit, so a caller
  can distinguish "left after a long membership" from "left immediately".
  `exited_*` populate only when the newest folded event is an exit — a re-entry
  supersedes a prior exit rather than leaving a stale end date on a live member.
* **`with_path_ref` overwrites, never merges.** The URL names the resource; a body
  key disagreeing with it is not a second opinion.
* **`surface_actor` refuses an un-narrowed root secret** (403) rather than
  defaulting to an ambient owner: the trust root is not a person, and records
  owned by a rotating secret would be unreachable after rotation.
* **Actor class is pinned to `Human`** because `principal_ref` is the third-party
  PERSON binding (OF-365 ILD-1). Deliberately NOT a server-side entity-type→class
  mapping: that would be a second spelling of `provenance::validate_actor_class`,
  and drift between the two is exactly the failure mode. The engine's
  `verify_actor_binding` stays the sole authority. Consequence: a MACHINE-class
  principal cannot own CRM records today. Say the word if that needs widening.
* **Payload parsing runs before the facade call**, so an unadmitted actor sending
  a malformed body gets `BAD_REQUEST`, not `FORBIDDEN`. No leak — payload
  validation is caller-side and reveals nothing about the vault — but the gate
  oracle passes complete bodies so admission is genuinely the verdict under test.
* **Filters route through `parse_filter_ast`**, CA-02's own door, so the ranked /
  global-relative rejection (`top_k`, `ppr_score`, …) is inherited rather than
  restated. Pinned on both transports in `saved_query_http_crud_matches_facade`.

## Gates

* `cargo clippy -p oneiron -p oneiron-server --all-features --all-targets` — clean, zero warnings.
* `cargo fmt` — applied.
* `cargo test -p oneiron --all-features` — green (~3950 lib rows + every integration target), incl. the two new in-crate membership rows.
* `cargo test -p oneiron-server` — green except F2's pre-existing dependency-resolution row.
  * `campaign_surface_oracle` — 11/11.
  * `core_discover` 10/10, `skills_pack` 7/7, `ws_sync` 41/41, `mcp_oracle` unchanged.
  * `--lib` with F2 skipped: 393/393.

## Done-means coverage

| Row | Where |
|---|---|
| `campaign_surface_verb_round_trip` | oracle — parses, round-trips, and rejects prefix/suffix/case/whitespace/family-crossed confusables |
| `campaign_http_crud_matches_facade` | oracle |
| `saved_query_http_crud_matches_facade` | oracle — incl. CA-02 filter-AST + CAS parity, pack id `oneiron-crm` |
| `saved_query_owner_actor_is_authenticated_principal` | oracle — four spoof spellings, plus foreign-principal read/update |
| `campaign_membership_reads_are_paginated_and_read_only` | `campaign/surface.rs` in-crate (D6) |
| `saved_query_membership_reads_preserve_causes` | `campaign/surface.rs` in-crate (D6) |
| `campaign_surface_write_uses_memory_facade_gate` | oracle |
| `campaign_server_handlers_use_sync_server_state` | oracle |
| `campaign_surface_error_parity` | oracle — not-found / invalid payload / archived lifecycle / gate-denied / rootless / anonymous / wrong-scope, plus no-hard-delete |
| `campaign_mcp_gateway_uses_existing_dialect` | **NOT DELIVERED — see D3** |
| `campaign_adds_no_mcp_tool_name` | oracle |
| `campaign_discovery_lists_self_verbs_once` | oracle — plus advertised-set-equals-dispatchable-set, and health parity |
| existing `/query`, `/context-pack`, `/memory/verbs/{verb}`, MCP gateway tests green | full server suite, modulo F2 |

## Simplify pass (K3) — NO EDIT WARRANTED

Deletion-biased review of the impl tip (`44b4f010a`) found nothing to cut:

* **No dead or single-use structure.** Every helper is used at least twice or is
  blueprint-pinned public API (`CampaignSurfaceVerb::ALL` / `is_write` are
  exercised by the oracle; `optional_record_json` serves both read verbs; the
  `parse_scope`/`parse_filter`/`parse_matcher`/`parse_eval` set serves both
  saved-query create and update).
* **No duplicated helpers.** The two server routers share one
  `dispatch`/`surface_actor`/`surface_error`/`with_path_ref`/`membership_body`
  set in `api/campaign.rs`; `api/saved_query.rs` is a pure consumer.
* **No defensive branches or speculative generality.** `surface_error` maps the
  facade's own codes and nothing else; cursor validation is one length+alphabet
  check; the membership fold is a single pass. The facade wrappers match the
  neighboring calendar legs' `Ok(engine(...)?)` idiom exactly.
* **Laws re-verified, not touched:** the ten `SELF_*` constants and
  `CAMPAIGN_SELF_VERBS` are verbatim; `invoke_campaign_surface` parses only the
  closed list; writes all route through `verify_actor_binding` +
  `MemoryFacade`; no request type carries an owner field; membership reads open
  no write transaction; transports define no shadow domain types.

Gates re-run on the unmodified tip: `cargo check -p oneiron --all-features` and
`-p oneiron-server` clean (one pre-existing `dead_code` warning in
`batch.rs` under default features — outside this lane's packet, left alone);
`cargo test -p oneiron --all-features campaign::surface` 2/2;
`cargo test -p oneiron-server --test campaign_surface_oracle` 11/11.

## VERDICT-FIX (Opus, post-simplify tip `1f44007e3`)

The finder returned five items; the verdict leg confirmed **three REAL** and
banked two. All three are fixed at their chokepoint, each mutation-verified
red-before / green-after. The two banked items are **not relitigated below**.

### V1 (P1, `authorization-bypass`) — membership verbs verified admission, then dropped the actor

`crates/oneiron/src/facade.rs` — `campaign_members` / `saved_query_members`.

The projections select on the CAMPAIGN or the QUERY, never on `owner_actor`:
`read_campaign_members(vault, req)` takes no principal, by the blueprint's own
pinned signature. The facade called `verify_actor_binding` and then passed only
the vault and a caller-controlled `owner_ref` through. Any admitted principal
holding `core:read` and a foreign campaign's id could therefore page its cohort —
member entity ids, states, epochs, and causes — while the RECORD reads on the
same facade were owner-filtered. Two doors to one resource, one of them open.

Fixed where the ownership fact already lives: each membership verb now performs
the same owner-filtered record read its sibling `*_read` verb performs, and
answers a non-owned or absent resource with the empty page — one answer for
absent-or-not-yours, so the projection leaks no existence signal either. The
skeleton signatures are unchanged; no principal is threaded into the projections.

* **RED** `membership_reads_are_scoped_to_the_owning_principal` (new, in-crate):
  panicked `a campaign's cohort must not page for a principal that does not own it`.
* **GREEN** after: owner pages 1 row on both axes, intruder pages 0 on both.

### V2 (P1, `cross-campaign-state-mixing`) — the fold read another campaign's events

`crates/oneiron/src/campaign/surface.rs` — `fold_membership_events`.

`membership_events` is keyed `(query, entity)` (`saved_query.rs` `event_prefix`),
while every `MembershipEvent` carries its own `campaign_ref` and the head model
explicitly supports one `(query, entity)` pair holding heads in several
campaigns. The fold consumed the whole shared history unfiltered, so campaign A's
row folded campaign B's later transitions: state, cause, and both bitemporal
pairs were wrong in a supported configuration, and the saved-query axis emitted
rows that were one campaign's state repeated rather than each campaign's own.

Fixed in the fold's own skip clause, next to the existing `at_epoch` ceiling:
the function now takes the `MembershipHead` and ignores every event whose
`campaign_ref` is not that head's. One predicate, at the single place the union
is consumed — no filtering scattered into the two public read functions.

* **RED** `membership_rows_fold_only_their_own_campaigns_events` (new, in-crate):
  campaign A (Entered @1) folded campaign B's Exited @3 — `left: "exited"`,
  `right: "entered"`.
* **GREEN** after: A reports `entered` / `data_change` / `entered_valid 100`;
  B reports `exited` / `definition_change` / `entered_valid 200` /
  `exited_valid 300`; the query axis pages both heads, `["entered", "exited"]`.

### V3 (P2, `scope-validation`) — a scalar `scope` silently widened the query

`crates/oneiron/src/campaign/surface.rs` — `parse_scope`.

`parse_scope` checked only absent-or-null. For any other non-object,
`raw.get("worlds")` and `raw.get("facets")` both return `None`, yielding empty
axes — and an empty axis in `QueryScope` means UNRESTRICTED. So
`{"scope": "sales", ...}` with an otherwise valid body was accepted as a saved
query targeting every world and every facet instead of being refused. Campaign
targeting semantics changed on a typo.

Fixed by requiring `scope` to be a JSON object when present; absent and null
still mean the documented default.

* **RED** `scope_must_be_an_object` (new, in-crate): `"sales"`, `7`, `["sales"]`,
  `true` all parsed. Also **RED** over HTTP in `campaign_surface_error_parity`
  (new rows): `POST /saved-queries` returned `200` with
  `"scope":{"worlds":[],"facets":[]}` — the widening, on the wire.
* **GREEN** after: all four malformed shapes are field errors; HTTP returns
  `400 BAD_REQUEST` for `"sales"`, `7`, and `["sales"]`.

### Not relitigated (verdict-banked, owner/postmortem)

* **Finder-1 (MCP transport)** — REJECTED as a lane defect by the verdict leg.
  The demanded dispatch hook can only live in `mcp.rs` / `api/mcp_gateway.rs`,
  both unconditional non-claims, and "CA-07 adds no MCP tool" is ratified. The
  blueprint's `campaign_mcp_gateway_uses_existing_dialect` done-means presumes a
  generic gateway verb arm that does not exist — a spec collision for the owner
  (strike as dialect-owner work, or schedule an MCP arm), already carried as D3.
* **Finder-4 (unbounded membership scan)** — REJECTED as blocking; posture item,
  already carried as F4. Forced by the `registry.rs` non-claim, documented
  in-code, same shape as the shipped `/api/core/discover`; responses stay
  cursor-bounded. Follow-up is a membership index or a server-layer rate limit.

### Packet + gates

Diff is `campaign/surface.rs`, `facade.rs` (inside the two `self.*` membership
verb methods only), and `tests/campaign_surface_oracle.rs`. No `Cargo.toml`,
no `Cargo.lock`, no `mcp.rs`, no `mcp_gateway.rs`, no `graph_fs.rs`, no
`registry.rs`. The ten `SELF_*` constants, `CAMPAIGN_SELF_VERBS`, the closed-list
parse, and every pinned skeleton signature are untouched.

* `cargo fmt --all` clean; `cargo clippy -p oneiron -p oneiron-server
  --all-features --all-targets` clean.
* `cargo test -p oneiron --all-features` — fully green (engine suite + doctests).
* `cargo test -p oneiron-server` — green except **F2**, the pre-existing
  `the_real_codec_rows_run_the_same_codec_package_axum_resolves` manifest-pin
  red. Re-confirmed base-red this pass: it fails identically on the stashed
  pre-fix tip and with the committed `Cargo.lock` restored, and the test reads
  only `cargo metadata` edges — no `.rs` input. Its fix is a one-line bump in
  `crates/oneiron-server/Cargo.toml`, a hard non-claim. Charged to no lane.
* `campaign::surface` in-crate: 5/5. `campaign_surface_oracle`: 11/11.
