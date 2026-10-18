import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Calendar and booking — public binding read at main
 * 1aec7a3c94647f7f2cb012aaa9e4e3c2ff3d7cd3.
 *
 * G01: every complete scenario below awaits a typed public prerequisite.
 * suite.todo registers a real Bun test.todo and a required BLOCKED report row.
 * None is passing coverage. Do not activate a partial flow under its full ID.
 * Names, ordered steps, authored inputs, expected facts and immutable source
 * hashes are in calendar-scenarios. Every corpus file is hash-pinned by the
 * calendar manifest, loaded by the shared preflight. No shared helper is edited.
 *
 * Binding evidence: scripts/sdk/agent-verbs.json, both generated SDK catalogs,
 * api/openapi_registry.rs, api/openapi/{booking_schemas,endpoints_merge}.rs,
 * api/booking{,/public,/front,/page_token}.rs, mcp/{surface,tool_catalog}.rs,
 * api/mcp_gateway/actor_dispatch.rs and cli.rs. Rust calendar DTOs explain the
 * intended shapes, NOT permission to call Rust or invent HTTP routes.
 *
 * Important drift: oneiron.skills.md still describes oneiron.book, but current
 * MCP registers setup/actions and generated verbs, not that retired tool.
 * api/tests/mcp_scoping.rs explicitly expects unknown_tool for oneiron.book
 * AND oneiron.calendar on both endpoints. Generated HTTP/native SDK catalogs
 * export neither calendar nor booking calls. Existing HTTP booking routes
 * really ARE present; their absence is not the blocker claimed here.
 *
 * Activation uses (await loadFixtures()).readJson("calendar-scenarios") and
 * readArchive(assetId), EngineFixture.start({ id, profile }) for EACH ID,
 * fixture.client/cli/mcp and ScriptedProviders for external protocols only.
 * Read matching authenticated OpenAPI as a binding diagnostic. Pair real
 * principals and establish owner policy, import consent and standing grants
 * through public calls. Preserve refusals/PENDING_ASK instead of retrying a
 * mutation. Await public receipts/status or external provider barriers, never
 * internal queues, private clocks, fixed sleeps or log wording.
 *
 * A generic EVENT/claim write cannot impersonate calendar_projector origin,
 * DerivedFrom evidence, an ICS source, invite consent or an outcome sensor.
 * Do not copy private page-token/config-hash derivations, seed records, inject
 * CalDavWire/OutboundResultSender, or use execute_code as a missing typed door.
 * Corpus labels bind to refs returned publicly; they are not invented ids.
 *
 * No engine defaults changed. Fixture-only declared policy: 30-minute slots,
 * 30-minute step, zero notice/buffers, seven-day booking window; 300-second
 * poll cadence; a one-second outcome grace ONLY through a supported owner row.
 * Read, do not shorten, default hold TTL 300s, outcome grace 1800s, prep lead
 * 2700s and 250-word ceiling. Booking expectations use a future UTC day from
 * the Linux host clock; DST imports use fixed historical dates. No fake clock.
 */

/* CALENDAR-01 — EVENT origins and time kinds should work.
 * Rows OF-004/OF-405; ARCH-0060 #treatment/#time; ARCH-0002 #ent-event.
 * Fixtures: calendar-origins and calendar-scenarios.
 *
 * Canon EVENT union (refs/frontiers must come from real public ingestion):
 *   { origin: "native", summary, occurredAt, recordedAt,
 *       evidenceTurnIds?: never, sourceFrontiers?: never }
 * | { origin: "imported", summary, occurredAt, recordedAt,
 *       importSource, externalId, evidenceTurnIds?: never,
 *       sourceFrontiers?: DocFrontier[] }
 * | { origin: "dreamer", summary, occurredAt, recordedAt,
 *       evidenceTurnIds: string[], sourceFrontiers: DocFrontier[],
 *       rrule?: never, calendarName?: never }
 * Required typed calendar.read/search shapes retained from domain DTOs:
 *   CalendarReadRequest { event_ref }
 *   CalendarSearchRequest { calendars: [{ system?: string }],
 *     range: { start, end } | null, text: string | null, limit: 200 }
 *     -> scoped { value: CalendarEventView[], narrowing: ScopedReadReceipt }
 *   CalendarEventView { origin, event_ref, name?, start_utc?, end_utc?,
 *     calendar_systems: string[], blocks_time: boolean }
 * Query ranges are INCLUSIVE UTC seconds, not booking's half-open slots.
 * Raw claims must additionally expose time_kind { kind, busy_transparency },
 * wall_time { y, mo, d, h, mi, s }, tz and recorded origin/provenance.
 *
 * Ingest native, imported four-time-kind ICS, and a separately sourced
 * extracted event. Query their UTC windows via HTTP and the real CLI API;
 * compare identical identities/origins and exact fixture instants, not two
 * outputs used as each other's oracle. Inspect the raw typed provenance:
 * dreamer has live TURN evidence/frontiers, native has none, imported names
 * the source/UID and Imported trust. No missing origin defaults to dreamer.
 * The 15:00 London fixture is 14:00Z; floating 09:30 remains unzoned; all-day
 * [24 Oct, 26 Oct) remains two dates with exclusive end, not UTC midnights.
 *
 * Delete only the imported source using its public source-erase door. Its
 * erased evidence must not remain live or leak through temporal reads. The
 * independent native/dreamer events keep their ids/origins. Source erasure is
 * distinct from a successful empty feed, which cancels (02), not erases.
 * Missing: typed origin writers, ICS ingestion and calendar read/search.
 * The CLI api transport exists; it cannot invent those underlying doors.
 */
suite.todo(test, "CALENDAR-01", "waits on typed HTTP/SDK calendar origin writers, ICS import and calendar.search/read — EVENT origins and time kinds should work");

/* CALENDAR-02 — Calendar passport rescan and cancellation should work.
 * Rows OF-405/OF-406; ARCH-0060 #passports/#treatment.
 * Fixtures: calendar-passport-{v0,v1,drift,absent}, calendar-protocol.
 *
 * Domain design, not a shipped HTTP call:
 *   IcsFeedPollConfig { secret_ref, system, cadence_min_seconds: 300,
 *     cadence_max_seconds: 300 }
 *   IcsFeedPollPayload { config, not_before }
 *   cursor -> { etag?, last_complete_at?, paused, last_screen_verdict? }
 *   calendar.passport -> { system, uid, last_sequence,
 *     content_hash: byte[32], direction: "inbound", last_seen_at,
 *     presence: "live" | "absent" }
 * Typed production configure/poll/status doors must bind these semantics;
 * do not enqueue/run IcsFeedPollPayload by calling engine internals.
 *
 * Drive five complete GET/200 responses over a local feed: v0, identical v0,
 * sequence 1 beta, sequence 1 gamma body drift, complete empty calendar.
 * Approve imported candidates through public consent, then await public
 * completion before each observation. A 304-only fixture would not test
 * semantic same-revision dedupe; this fixture deliberately repeats HTTP 200.
 * Require one EVENT id and one live (system, UID) passport throughout.
 * The second poll adds NO semantic revision; higher sequence updates; equal
 * sequence with changed body also updates. Compare fixture summaries and
 * sequence heads; compare hashes for equality/difference without copying the
 * engine's semantic hash algorithm. last_seen_at may change independently.
 *
 * On disappearance: passport absent and calendar.status
 * { status: "cancelled", basis: "imported_absence", recorded_at }.
 * There is only one inbound source, so all-inbound-absent applies. EVENT and
 * alpha/beta/gamma history survive; no duplicate, physical erase or no-show.
 * A failed/truncated fetch must never stand in for the complete empty feed.
 * Missing: typed feed setup/poll and public completion/passport observation.
 * Existing generic claims.history cannot run the calendar ingest adapter.
 */
suite.todo(test, "CALENDAR-02", "waits on typed HTTP/SDK ICS feed configure/poll and passport revision observation — Calendar passport rescan and cancellation should work");

/* CALENDAR-03 — Recurring meetings across DST should work.
 * Row OF-405; ARCH-0060 #time/#treatment.
 * Fixtures: calendar-dst-series, calendar-dst-series-moved.
 *
 * Preserve typed recurrence semantics, without inventing an endpoint:
 *   calendar.series_master { rrule, dtstart_utc, tz: "Europe/London" }
 *   calendar.series_exception { master_ref, uid, original_start_utc }
 *   bounded expansion input: the admitted master and UTC { start, end };
 *   output: ordered occurrence starts/identities inside that inclusive window.
 * An instance move names (UID, ORIGINAL occurrence start), new start/end;
 * it does not replace the series UID or mutate the original instance key.
 *
 * Import the four-Monday 09:00 London series with its existing November
 * exception. Expand 18 Oct–10 Nov 2026 and query around 25 Oct's transition.
 * Authored initial UTC starts, NOT calculated with engine/rrule/tz code:
 *   19 Oct 08:00Z, 26 Oct 09:00Z, 02 Nov 11:00Z, 09 Nov 09:00Z.
 * The Nov 2 exception replaces 09:00Z; it is not a fifth occurrence.
 * Move Oct 26 to 10:30Z through the typed instance-move door. Require only
 * that one occurrence to change; master, UID, original-start exception keys
 * and existing Nov 2 link remain. No instance remains at the old start.
 * Compare the exact sets/order with calendar-scenarios, not engine output.
 * Fetch the original archived ICS VERSION publicly and compare all bytes,
 * including X-FIXTURE-OPAQUE. The later resource must not overwrite it.
 * Missing: typed import/occurrence/instance-move bindings. expand_window and
 * expand_master_window are Rust functions, never public-surface substitutes.
 */
suite.todo(test, "CALENDAR-03", "waits on typed HTTP/SDK ICS import, bounded calendar occurrences and instance move — Recurring meetings across DST should work");

/* CALENDAR-04 — Invite and two-way echo suppression should work.
 * Row OF-406; ARCH-0060 #invites/#passports; ARCH-0063 #law.
 * Fixtures: calendar-invite-{request,update,acceptance,cancel},
 * calendar-caldav-echo, calendar-protocol. All addresses are .test fixtures.
 *
 * calendar.invite typed design (from CalendarInviteSurfaceInput):
 *   { method: "request" | "cancel", uid, sequence, ics_blob_ref, recipient,
 *     mention?: MentionProvenance } -> OutboundIntentReceipt.
 * No caller-supplied consent/hygiene flags or generic outbound draft.
 * Connector design: CalendarConnectorSeatConfig { seat_ref, secret_ref,
 *   system, calendar_ref, cadence_jitter_min_seconds,
 *   cadence_jitter_max_seconds }; sync observation returns cursor, applied,
 *   acknowledged, source_absences and status_cancellations, not fake commits.
 *
 * Before agreement/grant, attempt the invite and require an actual refusal
 * with ZERO iMIP sink deliveries. Establish real recipient agreement, house
 * primary calendar identity and standing invite grant publicly. Invite at
 * 17:00Z/sequence 0; update to 18:00Z/sequence 1 on the SAME UID. Observe one
 * gate/intent receipt per effect and exactly one sink delivery per intent.
 * A CalDAV sink records conditional PUT bytes/ETag. Return THOSE exact staged
 * bytes on the next pull; don't assume independently authored ICS is byte-
 * identical to the engine renderer. Exact echo changes no semantic heads and
 * creates no second EVENT. calendar-caldav-echo is the semantic oracle only.
 *
 * Receive ACCEPTED/sequence 1, then METHOD:CANCEL/sequence 2. Require the same
 * EVENT/UID, attendee soft state, cancelled status and retained history.
 * Acceptance is not attendance. No echo-triggered invite loop, no side-domain
 * sending identity, no send without live authority. Retry sends nothing twice.
 * Missing: typed invite and connector configure/sync doors plus public host
 * iMIP/CalDAV transport configuration. The protocol corpus is not a fake
 * engine; Rust trait injection and generic outbound.schedule are not allowed.
 */
suite.todo(test, "CALENDAR-04", "waits on typed HTTP/SDK calendar.invite and CalDAV seat configure/sync — Invite and two-way echo suppression should work");

/* CALENDAR-05 — Meeting prep and earned outcome should work.
 * Row OF-407; ARCH-0060 #prep/#seam/#outcomes.
 * Fixtures: calendar-meeting-transcript and calendar-scenarios.
 *
 * Canon prep: event ref -> fresh scoped PrepPack | no pack;
 *   { event_ref, built_at, sections: [{ kind, items: [{ text,
 *       source_refs: string[], observed_at }] }], word_count }.
 * Domain file-drop design: { source_blob_ref, decoded_text, arrived_at_ms }
 *   -> Session { session_ref, turn_refs, wake_turn_refs, extraction_enqueued }
 *    | RetryOpenSession { open_session_ref } | NoteFallback { note_ref }.
 * The public door must ingest the uploaded file, not trust asserted evidence.
 * calendar.event_outcome wire: { outcome: "held" | "no_show" |
 *   "cancelled_pre_start" | "unknown", basis: "machine" |
 *   "owner_attested", recorded_at }; canon's attended maps to wire held.
 * Check-in answers held/no_show/rescheduled; rescheduled routes to scheduling,
 * it is not a fifth outcome. No caller can assert machine provenance.
 *
 * Create meeting-class event, solo focus and all-day controls. Request prep
 * against the fixture's scoped commitment/thread and unrelated private dossier.
 * Require commitments first, <=250 words, only eligible source citations;
 * no useful evidence means deliberately no pack, not padding.
 * Use short real fixture end/grace times ONLY through a typed owner policy;
 * await a public due-check-in observation, never sleep or advance a clock.
 * Without evidence the meeting remains unknown and gets a check-in; neither
 * nonmeeting control gets an attendance question. Silence never means no_show
 * and sends no recovery email. Inspect default 30-minute metadata separately.
 *
 * Upload the two-speaker text via the public transcript door: SESSION + two ordered TURNs,
 * linked evidence and held/machine outcome. On a separate meeting WITHOUT a
 * transcript, answer as owner: held/owner_attested. An unrelated actor cannot
 * answer for the owner. Do not overwrite machine evidence to fake that case.
 * Missing: typed prep, transcript, outcome/check-in and owner grace/due doors.
 */
suite.todo(test, "CALENDAR-05", "waits on typed HTTP/SDK meeting prep, transcript file-drop and outcome/check-in — Meeting prep and earned outcome should work");

/* CALENDAR-06 — Booking disclosure and race should work.
 * Rows OF-411/OF-412; ARCH-0062 #disclosure/#lifecycle.
 * Fixture: calendar-scenarios.bookingFixture, independent future UTC day.
 *
 * EXISTING protected HTTP shapes, bound by OpenAPI Booking* components:
 *   GET /api/booking/{page_token}/agent-instructions
 *     -> { version: 1, page_token, event_types, constraint_schema_version,
 *          operations: [{ operation, method, path }] }.
 *   POST /api/booking/{page_token}/availability
 *     { event_type, window: { start, end }, visitor_tz, constraint, session_ref }
 *     -> { op: "availability", result: { slots: [{ start_utc, end_utc, rank }],
 *          flex_used } }.
 *   POST .../book { stage: "hold", input: { event_type, selected_slot,
 *     visitor_tz, constraint, session_ref, checkout_lease_token: null,
 *     idempotency_key } }
 *     -> { op: "book", result: { stage: "held", result: {
 *          hold_token, selected_slot, expires_at } } }
 *   POST .../book { stage: "confirm", input: { hold_token, booker_email,
 *     intake: [{ field_key, value }], session_ref, idempotency_key } }
 *     -> { op: "book", result: { stage: "confirmed", result: {
 *          reschedule_token, cancel_token } } }
 *      | { op: "book", result: { stage: "slot_taken",
 *          result: { alternatives: RankedSlot[] } } }.
 *
 * ANONYMOUS routes are /public/booking/{page_token}/availability and
 * /public/booking/{page_token}/verbs/{hold|confirm|reschedule|cancel}.
 * Public verbs require { op: "book", input: <stage/input union above> };
 * protected /api/booking routes take the inner input, NOT that outer union.
 * Use two fresh PublicHttpClient instances without credentials for visitors.
 * Read instructions as owner separately; that HTTP door is authenticated.
 *
 * Publicly set up the private 10:00 busy event and transparent 09:00 control.
 * Require no 10:00 overlap, but 09:00 and 11:00 independently valid slots.
 * Allowlist public fields; reject private title/body/attendee/location, internal
 * calendar/event refs, busy sources and raw busy intervals in every reply.
 * Instructions paths are relative/same-origin with the canonical four ops.
 *
 * Race distinct-session holds of 09:00 via Promise.all, then concurrently
 * confirm all actual live holders. Losing at hold is valid; never invent a
 * second hold token. Exactly one contender must settle in this free fixture;
 * at most one incompatible booking EVENT exists. Verify committed EVENT,
 * booking heads and receipts as owner, not only success-shaped responses.
 * Loser alternatives are offerable and private-data-free. TTL is server-owned.
 *
 * Blockers: calendar busy creation/read and owner page-token discovery.
 * claims.upsert CAN write booking.public_page, but its claim receipt returns
 * no opaque page token; private for_page/digest code is not a public helper.
 */
suite.todo(test, "CALENDAR-06", "waits on public owner booking page-token discovery and typed calendar busy-event setup/read — Booking disclosure and race should work");

/* CALENDAR-07 — Booking reschedule cancel and token scope should work.
 * Rows OF-411/OF-412; ARCH-0062 #lifecycle, ARCH-0060 #passports.
 * Fixture: calendar-scenarios; start from HTTP hold/confirm as in 06.
 *
 * Existing HTTP DTOs:
 *   POST /api/booking/{page_token}/reschedule
 *     { reschedule_token, selected_slot: { start_utc, end_utc }, visitor_tz,
 *       idempotency_key } -> { op: "reschedule", result: { reschedule_token } }
 *   POST .../cancel { cancel_token, idempotency_key }
 *     -> { op: "cancel", result: { cancel_token } }.
 * Public verbs wrap those as { op, input }. Canon MCP booking semantics use
 * the same BookingOperationRequest { op, input } plus opaque page_token;
 * a supported typed binding must exist before the MCP half is activated.
 * oneiron.book is RETIRED now; do not call it and accept unknown_tool as a pass,
 * route through execute_code, or guess another generated tool name/envelope.
 *
 * Save returned distinct opaque reschedule/cancel tokens privately. Try each
 * under the wrong operation, hold token as an amendment token, and valid token
 * on another page. Require refusal and unchanged EVENT/passport/receipts/sink.
 * Reschedule 09:00 to independently expected 11:00 over typed MCP, replay the
 * exact same key/body, then cancel over HTTP and replay that exact key/body.
 * After EACH step inspect EVENT identity, UID, slot/status, passport sequence
 * and semantic history: confirmed/seq0 -> moved/seq1 -> cancelled/seq2.
 * Replays add no semantic transition or second outbound effect, return the same
 * public result, and do not widen action scope. Order by public receipts/history,
 * not distinct-second timestamps. All prior revisions remain addressable.
 * Missing: supported typed MCP lifecycle, page-token discovery and typed
 * calendar event/passport observations. HTTP amendment routes ARE present.
 */
suite.todo(test, "CALENDAR-07", "waits on typed MCP booking lifecycle replacing retired oneiron.book and calendar passport reads — Booking reschedule cancel and token scope should work");

/* CALENDAR-08 — Booking needs an explicit choice should work.
 * Row OF-412; ARCH-0062 #agentfront/#lifecycle; ARCH-0036 #model-line.
 * Fixture: calendar-scenarios; external model uses ScriptedProviders ONLY.
 *
 * EXISTING anonymous HTTP POST
 * /public/booking/{page_token}/constraint-turn:
 *   { event_type, window: { start, end }, visitor_tz, free_text, session_ref }
 *   -> { outcome: "slots", card, flex_used,
 *        hold: { event_type, visitor_tz, constraint, session_ref } }
 *    | { outcome: "continue_by_email", continuation: {
 *        event_type, visitor_tz, constraint, session_ref } }
 *    | { outcome: "deflect", card }.
 * ConstraintObject { schema_version: 1, weekdays: [], local_time_windows:
 *   [{ start_minute, end_minute }], utc_window: null, allow_flex_pool: false }.
 * The HTTP front is implemented, but has no generated typed SDK binding.
 *
 * Configure the real parser/decision adapter and explicit inference policy
 * publicly; script typed evening then 11:00 constraints with declared usage.
 * Match role/model/protocol fields, never exact prompts. The model supplies
 * constraints only; it must NOT supply slots, availability or confirmations.
 * First ask after 20:00Z against 09:00–12:00 hours: continue_by_email with
 * canonical constraint, no private reason, raw sentence or calendar internals.
 * No EVENT or mutation receipt. Negotiate 11:00Z in the SAME session: require
 * solver-produced 11:00–11:30 slot controls and public-only HoldContext.
 * Inspect offers WITHOUT tapping: still no EVENT, hold or confirm mutation.
 *
 * Explicitly pick the real booking.select_slot control, check its args against
 * independently authored slotB, then hold using returned context. A hold still
 * is not a confirmed EVENT. Only an explicit authorised confirm with qualified
 * intake settles one EVENT/UID and its receipt. No prose-only booking at any
 * earlier step. Check privacy on no-fit AND offers, not just the final reply.
 * Missing: typed SDK constraint-turn and public owner page-token discovery;
 * calendar fixture setup/reads and decision-seat permission are prerequisites
 * too. Do not create a fake conversational scheduler or call a generic verb.
 */
suite.todo(test, "CALENDAR-08", "waits on typed SDK booking constraint-turn and public owner booking page-token discovery — Booking needs an explicit choice should work");
