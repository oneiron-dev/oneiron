import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Public binding readback: worktree head
 * 65529b62e07209d8faeb0c0fcde7812e3df9cc46, cut from origin/main.
 * Read the generated HTTP and Oneiron SDK catalogs, OpenAPI assembly/owner
 * paths, CLI, SurfaceEvent/campaign handlers and pack host doors. Source
 * digests and canon pins are in channels-scenarios, loaded by shared preflight.
 * Runtime OpenAPI is a binding diagnostic, never the expected-value oracle.
 *
 * Each registration below is a complete planned flow, not a partial smoke
 * test. G01 requires typed HTTP AND SDK calls for designed verbs. suite.todo
 * registers Bun test.todo and reports BLOCKED, so these cannot count as PASS.
 * Current HTTP-only owner connector routes are not missing HTTP routes; they
 * lack generated SDK rows and are not connector-pack qualification doors.
 * No guessed URL, FacadeVerb cast, generic batch/structural write, engine
 * import, execute_code escape hatch, fake vault or private clock fills a gap.
 *
 * Activation: one authenticated EngineFixture.start({ id, profile }) per
 * flow; loadFixtures().readJson("channels-scenarios") for authored inputs;
 * ScriptedProviders for loopback external protocols only. Actual connector,
 * gate, scheduler, storage and receipts remain the real server. Match protocol
 * fields, not prompts. Unexpected provider requests fail; never echo engine
 * output into the oracle. Observe public receipts/status and controlled
 * provider barriers, never fixed sleeps or an internal queue tick. Provider
 * acceptance is delivery-to-channel, never proof the counterparty read it.
 *
 * Fixture labels stand for refs obtained through future typed public setup;
 * they are not fabricated engine ids. Required contracts below preserve canon
 * vocabulary/data, not a proposed callable ABI. No shared helper is changed
 * or locally reimplemented. No process, typecheck or test ran on the Mac.
 */

/* CHANNELS-01 — Connector qualification and grant slate should work.
 * OF-188/189/435/519; ARCH-0053#r4b-hubs, ARCH-0072#slate and #mint,
 * ARCH-0040#mcp-actor-ceilings. Fixture case: CHANNELS-01.
 *
 * Present: vault.packs.put({files:[{path,text}]}) -> PackPutReceipt
 * {outcome,reason?,receipt?:PackInstallReceipt}. Its receipt can carry
 * content_hash, status, candidate_reason and connector_qualification.
 * HTTP owner catalog registration already takes {connector,summary,tools?};
 * setup returns {key,slate}; slate/accept takes {connector,revision,rows?,
 * facets?,all_manual?}; qualify takes {connector,kit}. These catalog-only
 * routes are not SDK rows or a typed qualification of the installed pack.
 * Built-in setup verification is not a substitute for a new untrusted pack.
 *
 * Needed: qualification and advisory results bound to the exact pack hash;
 * a resolved manifest and a readable, owner-stampable per-capability slate.
 * Canon row: capability identity (resolved tool name, including elicitation),
 * drafted disposition auto|always_allow|always_ask|never_allow, data class,
 * rationale and owner override. One stamp binds manifest-hash + grant-hash;
 * qualification remains an independent prerequisite. Advisory findings are
 * gate input, not a fixture-supplied qualification boolean.
 *
 * Install the fixture pack declaring fixture.read and fixture.send. Hold use
 * before qualification; inspect every drafted row and its rationale. Qualify
 * first: no owner stamp still means no use. Stamp once, then exercise both
 * declared rows via HTTP/MCP. An undeclared fixture.erase must never reach
 * the provider. Revoke only fixture.send at its row; read still works, send
 * does not. Inspect current authority and receipts, not only the UI slate.
 * Assert exactly the declared capability set, no implicit grant from auto,
 * source/manifest-bound qualification, one owner admission stamp, and no
 * provider effect before both prerequisites or after that row's revocation.
 */
suite.todo(test, "CHANNELS-01",
  "waits on typed connector-pack qualification/advisory and grant-slate admission HTTP and SDK calls");

/* CHANNELS-02 — Connector drift requires re-consent should work.
 * OF-189/213/277; ARCH-0053#r4b-hubs, ARCH-0040#mcp-actor-ceilings.
 * Fixture case: CHANNELS-02.
 *
 * Present: vault.packs.put replaces a source under its name. Catalog HTTP
 * /v1/owner/connectors/refresh takes {connector,tools?} and returns
 * {connector,changed,key,slate,reask,carried,dropped}. Catalog slate/accept
 * and qualify exist. They are not generated SDK rows, and they do not supply
 * a pack-source-bound update/advisory/qualification and delta-consent flow.
 * Do not claim refresh is absent or bypass G01 by wrapping it in raw HTTP.
 *
 * Needed typed update input: changed immutable pack source and resolved
 * permission/protocol declaration. Result: prior/current source identity,
 * pinned protocol revision, changed capability rows, qualification/advisory
 * evidence, carried/narrowed/removed rows and owner-stamped delta grant.
 * Canon: only expansions re-ask; a verb within the stored verb class is not
 * an expansion. A source alias or its mutable content is never authority.
 *
 * Admit v1, then publish v2 at the same alias: fixture.read stays unchanged,
 * fixture.send newly reaches a second recipient, and fixture.erase is new
 * and outside the old class. Publish a widening protocol revision too.
 * Before delta approval, attempts on the new reach must not hit the sink.
 * Inspect the changed-row proposal: unchanged/narrowed settings carry,
 * removed tools disappear, and only expanded reach asks again. Approve the
 * delta and requalify, then send inside its new bound. Inspect both source
 * identities, delta and call receipts. A stale v1 stamp must never authorize
 * v2's widened scope, budget, header set or protocol behaviour.
 */
suite.todo(test, "CHANNELS-02",
  "waits on typed connector-pack permission/protocol delta-consent HTTP and SDK calls");

/* CHANNELS-03 — Outbound delivery window and receipt should work.
 * OF-327/277/272; ARCH-0040#mcp-actor-ceilings, ARCH-0063#law.
 * Fixture case: CHANNELS-03.
 *
 * Present: connector.outbound.schedule({verb,channel,target,trigger,
 * trigger_ref,on_behalf_of?,content_ref?,idempotency_key?,dedupe_key?,...})
 * -> {intent_ref,outcome,gate_outcome?,gate_decision_ref?,gate_reason_codes,
 * deduped}. This is scheduling, not a transport-accepted delivery receipt.
 * GET /v1/core/outbound/capabilities/{connector}/verbs/{verb} discovers the
 * real contract. vault.receipts/get read receipts; no internal drain is used.
 *
 * Needed typed setup: live sending ChannelIdentity, an owner-authorized
 * grant with sends/rate/spend bound, and owner delivery_window policy rows.
 * Result must expose the intent's held/degraded/suppressed/delivered outcome,
 * reason, provenance, identity and delivery receipt. Declare the connector's
 * actual interruption_class, delivery_semantics and retry_class.
 *
 * Use two recipients and loopback sink. MCP sends an allowed interrupt-class
 * effect to A. A recipient-specific quiet-hours row holds B; an async write
 * and a supported low-interruption reaction must not be blocked merely for
 * being async during quiet hours. Prove B's sink count is zero while held.
 * Revoke B's grant before release and observe dispatch still holds: policy
 * lifting alone cannot bypass grant revalidation. Restore the explicit grant,
 * lift the restriction via owner rows, await public settlement, and replay the
 * same intent. Exactly one provider effect per distinct idempotent intent;
 * inspect original hold and terminal delivery provenance. Exercise a budget
 * exhausted before dispatch too: no effect and a visible reason. Never assert
 * that scheduling success or a sent receipt proves a human saw the message.
 */
suite.todo(test, "CHANNELS-03",
  "waits on typed channel-identity and delivery-window policy HTTP and SDK calls for dispatch setup");

/* CHANNELS-04 — Channel identity lifecycle and sticky thread should work.
 * OF-347/413/416; ARCH-0063#law (selection, shapes, threads, boundary).
 * Fixture case: CHANNELS-04.
 *
 * No generated HTTP/SDK call provisions/binds/rotates/releases a
 * ChannelIdentity, edits relationship selection rules or reads thread
 * passports. Built-in pack setup and vault.structural.put are not these
 * semantic doors. Internal lifecycle implementations are not public calls.
 *
 * Required typed identity: channel, address/handle, actor and facet binding,
 * dedicated_address|dedicated_handle|shared_presence|delegated_grant,
 * custody/lifecycle and outbound eligibility. Lifecycle returns a receipt,
 * outcome/reasons, owner-visible state, outbound_closed and identity_retiring.
 * Caller WHO and permission are server-authenticated, never payload booleans.
 * Passport: identity_ref, message_id, thread_ref, mask {identity_ref,actor_ref,
 * facet_ref}; ingest preserves References and In-Reply-To as thread evidence.
 * Rule writes must distinguish the authenticated owner's stamp from an
 * agent amendment. Dedicated addresses are engine-owned; delegated accounts
 * are not provisioned, rotated or silently owned by the product.
 *
 * Provision an agent address and bind the owner's delegated mailbox in the
 * loopback provider. The scheduling relationship rule picks the dedicated
 * address for message 1. Owner changes that default to the delegated mailbox.
 * A reply linked by Message-ID/References must retain the first identity AND
 * facet, while a new thread uses the changed default. Revoke the identity's
 * send authority: the old thread cannot send even with its valid passport.
 * Retire/release the dedicated address; attempt to reassign it to a second
 * agent and prove no silent recycling. Inspect retiring/tombstone state and
 * hold metadata without waiting the 90-day quarantine. Never rotate or retire
 * the owner's Gmail account as though it were an engine-owned address.
 */
suite.todo(test, "CHANNELS-04",
  "waits on typed channel-identity lifecycle, selection-rule and thread-passport HTTP and SDK calls");

/* CHANNELS-05 — Normalized inbound events and reactions should work.
 * OF-247/372/272; ARCH-0044#part-a, ARCH-0063#law.
 * Fixture case: CHANNELS-05.
 *
 * Existing POST /v1/core/surface-events input:
 * {event_id,channel,receiving_address_or_handle,counterparty,source?,action?,
 * correlation_id?,payload_ref?,workspace_ref?,received_at,foreign_inbound}.
 * source = {app,user_ref}; counterparty = {state:"unknown",counterparty_key}
 * or {state:"known",counterparty_ref}. action = {kind:"message"} or
 * {kind:"interaction",interaction:"reaction",target_ref?,reaction?:
 *   {glyph,external_id,occurred_at?,origin_ref?,removed?}}.
 * 202 -> {correlation_id,attempt_ref,state,replayed,accepted_at,status_path};
 * GET status_path -> {correlation_id,attempt_ref,state,attempt_count,
 * last_error,created_at,updated_at}. Identity refusal is a typed 422 receipt,
 * not an accepted event and not idempotency coverage.
 * vault.messages.react({message,by,glyph,occurred_at?,remove?,external?})
 * -> {id,event} exists. It writes a room reaction; it is NOT proof that an
 * external react verb is supported or was delivered. Read conversations via
 * the transcript/DAG/room public projections, not stored MessagePack bodies.
 *
 * Missing prerequisite: public provisioning/binding of receiving identities
 * for all three fake adapters, not SurfaceEvent submission or reaction write.
 * Use Slack, LINE and Telegram events, each with its own provider correlation
 * key replayed twice (do not dedup distinct providers against one another).
 * Assert original attempt ref, replayed=true, one normalized message, receiving
 * identity/source and untrusted provenance. Replay a reaction add, then remove:
 * it is a first-class conversation.reaction signal with toggle history, not a
 * new dialogue turn or an invented belief/acknowledgment claim. Submit an
 * invalid source/action and assert refusal with no conversation change.
 * Supported Slack/Telegram react reaches the sink once. LINE's unsupported
 * react must return a visible unsupported-capability result and produce no
 * effect, success receipt or fabricated read/ack evidence. Do not turn a glyph
 * alone into evidence of acknowledgment; interpretation belongs to extraction.
 */
suite.todo(test, "CHANNELS-05",
  "waits on typed receiving ChannelIdentity provisioning/binding HTTP and SDK calls");

/* CHANNELS-06 — Member email and LinkedIn consent should work.
 * OF-373/374; ARCH-0063#law, ARCH-0040#mcp-actor-ceilings.
 * Fixture case: CHANNELS-06.
 *
 * Existing connector.call({name,tool,arguments?,mutation?}) -> delivered |
 * held | refused | pending_delivery | awaiting_input; call_status reads a
 * held call. This generic catalog transport is not the absent typed member
 * Gmail send-as/draft or LinkedIn member-send consent operation. Gmail inbound
 * parsing and stock outbound manifests do not establish send-as functionality.
 *
 * Required typed send input binds the delegated member identity, thread,
 * content/proposal and durable intent/idempotency key. A press is a recorded
 * one-send approval by the authenticated holder, not a client approval flag.
 * Result preserves outcome/reasons, own-account identity, thread/passport,
 * intent and send/gate receipts. LinkedIn verification needs the created
 * message id plus a later own-seat transcript containing that id, not text
 * similarity. Ambiguous is not Delivered and must not trigger blind resend.
 *
 * Ingest Gmail and LinkedIn threads through each actual adapter at loopback
 * endpoints. Draft via MCP; sink stays empty. Attempt send without the press:
 * no provider mutation. The member presses through HTTP, then the same intent
 * may send. Replay through MCP and inspect exactly one delivery, unchanged
 * own-account sender/thread and receipts linked to that precise approval.
 * Approving intent 1 must not release intent 2. A grant selects press-per-send
 * for this fixture; do not assert a platform-wide permanent human-only wall.
 * Provider credentials remain host-side and no real account/browser is used.
 */
suite.todo(test, "CHANNELS-06",
  "waits on typed member-account send-as/draft and per-send consent HTTP and SDK calls");

/* CHANNELS-07 — Campaign membership and earned stages should work.
 * OF-402; ARCH-0059#membership, #stage and #sends.
 * Fixture case: CHANNELS-07.
 *
 * Present HTTP /v1/core/campaigns create/read/update/archive and read-only
 * /{campaign_ref}/members. Generated vault.campaign.program.* manages steps
 * {step_ref,channel,sender_ref,basis_evidence,outbound?}; program creation is
 * not enrollment, a stage projector invocation or unsubscribe.
 *
 * Canon membership is a claim on PERSON, not a CAMPAIGN-owned member array:
 * {campaign_ref,state:enrolled|paused|exited|suppressed,
 *  channels:[{channel,basis_evidence,sender_ref}],wake?}, with provenance.
 * Needed typed enrollment result must expose this evidence and sticky sender.
 * Stage input: {class,basis:machine|owner_attested,evidence_refs,recorded_at}
 * bound to person/campaign and a declared transition; result exposes stage,
 * evidence and receipt. Main's internal membership value calls its campaign
 * field `campaign`; that internal encoding is not a wire schema to seed.
 * Needed unsubscribe result: suppression and all affected member refs, without
 * a pending-delivery race. Do not forge projector-only crm.stage with upsert.
 *
 * Enroll two evidence-backed people; membership alone creates no crm.stage.
 * Record contact/send: still no earned stage. Attempt advancement with time
 * alone and with the wrong evidence class: neither advances. A positive-now
 * meaningful reply earns replied; EVENT + ICS evidence earns call_booked,
 * in that order, under two authored transition rules. Check evidence refs,
 * basis, provenance and absence of stage claims for the untouched person.
 * Unsubscribe before a queued next send dispatches; immediate membership
 * suppression must hold it with a visible receipt and zero additional sink
 * effects. This fixture grants no suppression override. No private projector
 * pass or elapsed-time fake may create earned evidence or settle the send.
 */
suite.todo(test, "CHANNELS-07",
  "waits on typed campaign enrollment, earned-stage evidence and unsubscribe HTTP and SDK calls");

/* CHANNELS-08 — Compliance strictness and stale rules should work.
 * OF-404; ARCH-0059#compliance/#sends, ARCH-0040#mcp-actor-ceilings.
 * Fixture case: CHANNELS-08.
 *
 * Missing: generated typed rule-pack install/amend/approve/verify and result
 * calls. Pack-file install is not the compliance amendment authority. Generic
 * claims.upsert cannot stand in for activation or forge verified timestamps.
 *
 * Canon rule row: {jurisdiction,channel,rule_kind,requirement,b2b_exemption,
 * source:{citation,url},verified_at,version,penalty_note}. rule_kind includes
 * consent_class, sender_id, physical_address, optout_mechanism,
 * optout_deadline, content_marking, records and source_hygiene. Amendment
 * input names prior version and cited new rows; result must expose effective
 * version, tightening vs loosening, proposal/owner stamp, notice and receipt.
 * Dispatch result identifies applied rows, stale rule and visible block reason.
 * Freshness bounds are declared owner policy, not a private accelerated clock.
 *
 * Use authored UK and EU/DE email rows with overlapping applicability. The
 * stricter opt-in row must block despite a permissive corporate-B2B row.
 * Supply consent evidence and observe a single accepted dispatch. Publish a
 * cited tightening (postal address now needed): it applies without a widening
 * stamp and blocks the next send. Supply the address and observe delivery.
 * Publish the loosening: it stays a proposal, and the old restriction still
 * applies until owner approval. Approve via its typed door; inspect version
 * and authority receipt. Install an explicitly stale verification row via
 * the declared public verification workflow (or await its public short TTL),
 * then send: BLOCK, exact stale-row reference and no sink mutation. Never
 * sleep through a long legal freshness default or infer law from engine output.
 */
suite.todo(test, "CHANNELS-08",
  "waits on typed compliance-pack amendment, owner approval and verification HTTP and SDK calls");

/* CHANNELS-09 — Outreach-fit skill proposes but does not send should work.
 * OF-517; ARCH-0053#r4-lifecycle, ARCH-0059#sends.
 * Fixture case: CHANNELS-09.
 *
 * Present: self.skills.save({id?,files,expected_version?}) saves skill text;
 * vault.graph.ask and vault.questions.* answer typed graph questions.
 * OutcomeBinding exists: {source:{kind:"stage",campaign},horizon,mapping,
 * noise_weight,linked_by?}. None supplies the complete workflow execution,
 * review-pick landing and later earned-stage settlement path. self.use is
 * SECRET use, not skill execution. A generic task/code program would hide the
 * missing typed contract; ten independent graph.ask calls are not this skill.
 *
 * Required workflow input: campaign, lead refs, variant refs, ten typed
 * questions, per-lead context recipe and earned-stage OutcomeBinding. Result:
 * per-(lead,variant,question) typed answer/evidence, campaign rollup and the
 * selected variant as a review proposal, never a dispatched message. The
 * proposed pick must cite its own question/evidence trail and stay editable.
 * Later labels bind question version + scored unit + binding to actual stage
 * evidence, not to a prediction, an approval click or elapsed horizon alone.
 *
 * Run an authored workflow over two leads and two message variants with the
 * ten fixture questions: hook, format, offer, CTA, buying signal, ICP fit,
 * intent, personalisation, prospect fit and reply odds. Script typed decisions
 * only; the engine builds evidence/rollup/proposal. Inspect fixture-authored
 * per-unit answers and each lead's distinct proposed pick, with zero connector
 * effects even after keeping the proposal. Sending remains outside the skill
 * under campaign consent, suppression and compliance. Record a later positive
 * reply/earned stage for one lead; only that scored unit receives the positive
 * outcome label. The unanswered lead remains unresolved, not invented failure.
 */
suite.todo(test, "CHANNELS-09",
  "waits on typed outreach workflow execution/proposal and earned-stage outcome settlement calls");
