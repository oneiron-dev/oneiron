import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Context and room surfaces — BOARD-01 through BOARD-09, in plan order.
 *
 * Binding inspected at main f6f16d4d906995dbc52826bb6c7a45f07301efee:
 * the OpenAPI route/schema registrations, generated HTTP and Oneiron SDKs,
 * shared harness contract, CLI, and the dedicated board/pack/result routes.
 * Source supplies current transport shapes, NEVER expected engine behavior.
 * The area manifest pins the inspected source bytes and canonical evidence.
 *
 * G01: a designed operation needs its typed HTTP AND SDK call. A run-only
 * verb in the engine catalog is not that call. Main's generated dispatch
 * explicitly refuses board/run verbs outside their bound context; neither
 * a cast to FacadeVerb, an opaque spec, nor execute_code closes that gap.
 * Each TODO below blocks the WHOLE journey. It is a real test.todo and a
 * BLOCKED report row, not a partial assertion presented as passing coverage.
 *
 * Independent fixtures:
 *   board-canonical-cases: cases[ID], symbolic roles and authored expectations.
 *   board-large-output-recipe: exact UTF-8 expansion, byte count, SHA-256,
 *     and a known tail; no megabyte of repeated text in the source tree.
 * loadFixtures verifies both assets even while these flows are blocked.
 * Symbolic names are NOT engine refs. Once a typed door lands, bind them
 * to refs returned by public setup on a fresh EngineFixture for that ID.
 * Pair only existing principals; do not forge an actor, grant or receipt.
 *
 * The signatures below preserve canonical design and current DTOs beside
 * the TODOs. Semantic signatures do not invent future route names or wire
 * encodings. Replace them with generated types when those doors land.
 * Runtime OpenAPI remains a diagnostic, not an oracle or an unblocking test.
 *
 * Arming contract: EngineFixture + loadFixtures + ScriptedProviders only;
 * HTTP, MCP and WS are real public clients of an owned real server. Inference
 * uses exact external protocol scripts with usage, role and model pins, not
 * prompt matching. Public reads/receipts/barriers replace sleeps or private
 * queue drains. Default harness deadlines, one slot, zero write retries.
 * No engine constants changed. Fixture budgets and corpus sizes are inputs,
 * not new product limits. No build, server, interpreter or test was launched.
 */

/**
 * BOARD-01 — Context Board frame and provenance should work.
 * Canon: ARCH-0067 #what/#keystone/#recipe; ARCH-0040
 * #memory-board-source-trust; OF-059, OF-238, OF-219.
 *
 * Current HTTP hydration:
 *   POST /v1/core/context-board
 *   {retrieval?: CoreContextPackRequest,
 *    memories?: {enabled?, slots?, shared_total?, pinned_refs: string[]},
 *    session?: {session_id?, branch?}, room?: {conversation_id},
 *    board_budget_tok?: number}
 *   -> {board: string, worlds: string[], tasks: string[], room?: string[],
 *       memories?: {rows: [{id, short_id, content_hash, claim_source,
 *         world, tier, snippet, ...}], ...}, cursor, board_budget, ...}
 * Source trust is typed provenance, not the row's retrieval-source enum
 * (result/neighbor). Canonical activation verbs are
 * self.focus.activate/deactivate/pin/unpin; describe(h) reads a handle.
 *
 * Deferred public journey, cases[BOARD-01]:
 * 1. Provision scoped actors, permitted workshop/guest worlds, an excluded
 *    world, activated memories, the own-task and a shared room through typed
 *    public doors. Pin the safety statement. Establish tool-first MCP for
 *    the SAME actor used by HTTP; retain the actual setup and read receipts.
 * 2. Hydrate and resolve the returned handles. Require fixture world/source
 *    facts on the structured rows; excluded world has no label or count.
 *    Visible core sections stay in canonical order; empty INBOX is hidden.
 *    ROOM reflects the admitted roster and its scope meet, never quote text.
 * 3. Put every hostile leaf into an admitted untrusted value and activate it
 *    through the typed operation. Hydrate again and describe its real handle.
 *    Exactly one engine frame remains; fake wrappers, world rows, speaker
 *    marks and verb strings stay escaped leaf data. Separate foreign fences
 *    must not be mistaken for a second first-party board block.
 * 4. The imported item stays imported/foreign when pinned or expanded. Its
 *    text cannot mint a ref, activate the excluded world, change a grant,
 *    stamp itself user_stated or author a WAKE. Check actual authority and
 *    scope against fixture-created sets, not a model's compliance.
 * 5. MCP actor-derived envelopes carry scope, engine refs and structured
 *    metadata; ttlMs=0 and cacheScope=private. No bare-data fallback.
 *
 * Main already has hydration, claim_source/world/tier fields and foreign
 * fencing. The missing operation is typed public activation/tier steering:
 * self.focus.activate/deactivate/pin/unpin are absent from the HTTP/SDK
 * catalog. Supplying pinned_refs in a hydration is not that full lifecycle.
 */
suite.todo(test, "BOARD-01",
  "waits on typed self.focus.activate/deactivate/pin/unpin HTTP and SDK calls — Context Board frame and provenance should work");

/**
 * BOARD-02 — Board history under current authority should work.
 * Canon: ARCH-0067 #tiers/#history-built/#board-per-turn;
 * ARCH-0004 #access; OF-082.
 *
 * Existing typed HTTP shapes:
 *   POST /v1/core/context-board {..., turn: {id: TurnRef}}
 *     -> {..., board_turn: {turn, source_revision_ref, changed_claims}}
 *   GET /v1/core/context-board/turns/{turn}
 *     -> {turn, owner, at, source_revision_ref,
 *         selection: {allowed, default_on, active, allowed_base,
 *           default_on_base, active_base, pinned, top_snippet},
 *         documents: Record<DocumentRef, Base64Body>}
 * The anchor identifies the head and frontier served at that turn, not a
 * guessed TURN revision-set field. Index-only rows do not persist selection.
 * Required compaction is the same session-log fold as BOARD-06, settled
 * through a typed public operation; it is not an owner-wide horizon setter.
 *
 * Deferred public journey, cases[BOARD-02]:
 * 1. Create two authored TURNs through live public conversation flow. Hydrate
 *    each with its turn id and the different fixture selections. Capture
 *    real board_turn receipts; do not insert anchors or selection claims.
 * 2. Edit the first backing document after its board was served. Read back
 *    both turns. The first selects safety+cedar and contains the old cedar
 *    text; the second selects safety+birch. Exact served revisions must
 *    survive later edits and selection changes. A repeated unchanged
 *    selection writes no new selection delta. Another author cannot record
 *    this speaker's board (409 board_turn_of_another_actor).
 * 3. Narrow a reader's live grant to withhold cedar. Reconstruct the first
 *    as that reader: 409 board_document_unreadable, no partial board or
 *    recovered old permission. Its still-readable second board stays exact.
 * 4. Drive real compaction of the recorded first turn, observe its public
 *    settlement and retained watermark, then retry as a reader whose current
 *    grant still admits the documents. Require 409 beyond_compaction_horizon,
 *    never the nearest board. This isolates retention from the scope refusal.
 *    A later uncompacted turn remains reconstructable. No invented window
 *    length, private clock, test-only epoch mint or internal horizon call.
 *
 * Hydration/history routes and live turn creation exist. G01 still blocks
 * the required public compaction call: self.compact is run-context-only and
 * omitted from both generated HTTP/SDK trees. An automatic host compactor
 * does not provide a typed caller operation or a deterministic settlement.
 */
suite.todo(test, "BOARD-02",
  "waits on typed run-bound compaction and its settlement HTTP/SDK call — Board history under current authority should work");

/**
 * BOARD-03 — Context receipts and cached summaries should work.
 * Canon: ARCH-0067 #what/#placement; ARCH-0040
 * #memory-board-source-trust; OF-236, OF-369, OF-538.
 *
 * Canonical emit-time fields on the existing receipt spine:
 *   {persona_compile_stamp: string, activated_memory_ids: MemoryRef[],
 *    board_state_ref: string, substrate_ref?: ModelRef, model?: string,
 *    reasoning_effort?: string, prompt_input_ref?, disclosure_stamp?}
 * The configured fixture supplies model/substrate/effort, so those joins
 * must be present. board_state_ref stamps the activated MEMORIES selection,
 * not a hash of the whole dynamic rendered board. No new receipt kind.
 * Existing pack.l2_base is {content_hash: string, body: string}; it is
 * score-free admitted claim data, ordered by claim id, not mandatory prose.
 * Existing lasting wire receipt: x-oneiron-receipt-ref: call:<id>, retrievable
 * through vault.receipts.get({receipt_ref}). It is NOT the context stamp.
 * Required semantic call: context-bearing reply generation from a scoped
 * conversation/reader and configured model -> reply plus receipt_refs.
 * Its concrete typed transport and result must come from the public catalog.
 *
 * Deferred public journey, cases[BOARD-03]:
 * 1. Publicly create the stable persona evidence and activated tray memory.
 *    Configure the real inference adapter to the authored three-reply script
 *    with explicit policy/egress. No native assembly helper or fake emit.
 * 2. Generate two replies with unchanged backing claims. Read each actual
 *    context receipt via receipt_refs. Require the persona compile, the
 *    fixture memory ids in served order, board frontier and configured
 *    model/substrate/effort that actually reached the provider.
 * 3. Observe equal L2 content_hash and byte-identical body across unchanged
 *    evidence; allow a fresh dynamic board/call receipt each time. Do not
 *    demand zero provider calls: L2 here is an evidence projection, not
 *    necessarily an LLM summary. The provider observes the actual context.
 * 4. Revise only the voice claim through the gate, await its receipt, and
 *    generate again. The new compile and evidence hash/body must invalidate
 *    the affected old inputs; the tray's source attribution does not change.
 *    Earlier emit receipts keep the old assembly, never recomputed history.
 * 5. Restart and read the lasting call and context receipts again. Reads
 *    receive their own receipt refs too. A request-id echo or an in-memory
 *    counter is not durable evidence. No summary becomes a memory claim.
 *
 * Main implements L2 pack output and lasting call receipts. It does not
 * expose a generated typed text-reply/context-receipt HTTP+SDK operation
 * for this assembled flow. ai.options and modality calls, raw model output,
 * generic consolidation.enqueue(input: unknown), or reading a pack alone
 * cannot stand in for an emit and its actual context stamp.
 */
suite.todo(test, "BOARD-03",
  "waits on typed context-bearing reply generation and emit context receipt HTTP/SDK calls — Context receipts and cached summaries should work");

/**
 * BOARD-04 — Standing blocks and private diary should work.
 * Canon: ARCH-0067 #what; ARCH-0032 #writers/#private-reads;
 * ARCH-0053 #r4-lifecycle; OF-217, OF-490, OF-042.
 *
 * Current hydration controls and result:
 *   standing: {world_ref?: WorldRef, token_budget: number, block_tokens?}
 *     -> standing: {handle, world_ref, compiled, reserved_tokens,
 *                   other_context_tokens, total_tokens, evicted_claims}
 * Current actor-bound calls (no caller-supplied author):
 *   self.memory.diary({content, kind?}) -> {entry_id, entry_ref, receipt_ref}
 *   self.memory.diary.query({agent, reason}) ->
 *     {state:"granted", read?, entries:[{id, learned_at, markdown}]} |
 *     {state:"pending_review", request} | {state:"declined", request} |
 *     {state:"not_covered"}
 *   self.focus.scratchpad.append({session_id, text, mark?, pin?})
 *   self.focus.scratchpad.recall({session_id, query})
 *     -> {pad?, sealed, matched, lines:[{index, mark?, pin, text}]}
 * Canonical standing handle keys (agent, world); edits are gated claims.
 * Canonical dreaming choice: own model | vault weaver model/window | off.
 * The typed configure/edit/self-dream calls are still prerequisites, not
 * permission to invent a settings key or a JSON claim body.
 *
 * Deferred public journey, cases[BOARD-04]:
 * 1. Provision two agent definitions/worlds and their standing claims via
 *    named public doors, then pair the actual actors. Configure each floor;
 *    read HTTP/MCP contexts as each actor and resolve its standing handle.
 *    Each compile contains only its fixture persona under current scope.
 * 2. Revise north's standing claim through its gate, never compiled text.
 *    Require a receipt and updated north compile, unchanged south evidence,
 *    and a reservation that optional retrieval cannot spend. Omission or
 *    a too-small requested block must not bypass the configured floor.
 * 3. Write both private diaries and run scratchpads as their real actors.
 *    North's request for south's diary without a read grant is not_covered,
 *    with no entries; its own context and scratchpad recall cannot leak
 *    south's sentinel. A new run gets a fresh pad, not the previous live pad.
 * 4. Exercise independent dreaming settings, then delegate both agents to
 *    the SAME model/window. Observe adapter routing and attributed diary
 *    writes. Shared inference never shares diary or scratchpad ownership.
 *    Turn dreaming off for one agent and require no inference for that act.
 * 5. Privacy is not a universal ban on authorised readers. An explicit
 *    owner/admin grant plus reason, logged access and review when enabled
 *    governs any permitted cross-read. Check the actual agent-visible log
 *    and reader list; pairing or sharing a model itself grants no read.
 *
 * Diary, review, scratchpad and standing hydration support already exist.
 * Main lacks typed HTTP/SDK standing-block registration/gated revision and
 * per-agent self-dream/model-choice operations. Existing diary writes are
 * not evidence that self-dreaming ran; private Rust setters are not setup.
 */
suite.todo(test, "BOARD-04",
  "waits on typed standing-block configure/edit and per-agent self-dream HTTP/SDK calls — Standing blocks and private diary should work");

/**
 * BOARD-05 — Own-task stream delivery should work.
 * Canon: ARCH-0067 #recipe/#stream-producer/#stream-narrowed-built;
 * ARCH-0004 #access; OF-386, OF-241.
 *
 * Current run/board-context normalized shapes, NOT facade calls:
 *   self.focus.refresh({frame_epoch?: number}) -> BoardVerbOutput
 *   self.focus.subscribe/unsubscribe({scopes: SubscriptionScope[]})
 *     -> BoardVerbOutput
 *   BoardStreamFrame {epoch, kind:
 *     {kind:"keyframe", payload:string} |
 *     {kind:"delta", payload:[{key:string, line:string}]}}
 * Canon default subscription: own tasks, own children, addressed consults.
 * CARRIER coalesces per key; WAKE is separate; memories/worlds/presence/counts
 * are ON-DEMAND. A subscription grants NO read. WS read cursors stay binary
 * and independent; use the actual app protocol, never a private sync window.
 *
 * Deferred public journey, cases[BOARD-05]:
 * 1. Pair north/south separately and establish their board keyframes and
 *    subscriptions through the typed public contract. Open two real WS
 *    clients with independent cursors; retain snapshot/end boundaries.
 * 2. Finish north's task, then change its done row before the next north
 *    carrier is consumed. Observe committed public task receipts, not an
 *    invented event-emission call. Next north tool result carries the last
 *    tasks:<id> row once; south's result carries no north own-task event.
 *    One client's cursor/ACK cannot advance or consume the other's delivery.
 * 3. Drain with another public tool response to prove no duplicate carrier.
 *    Distinguish a task-failed WAKE from next-response delivery and an idle
 *    adapter's wake. A quote saying WAKE is not an engine event. No claim
 *    that the existing in-memory wake registry is durable across restart.
 * 4. Queue another readable task delta, then narrow north's real grant so
 *    the task is no longer readable before delivery. Its next result and
 *    reconnect/keyframe must withhold it. Reconnect as south must not expose
 *    north's task either. Recheck at delivery, not only at publication.
 * 5. No memory/world/presence/count change is pushed as an own-task carrier.
 *    Explicit refresh is the resync floor. Verify actual WS cursors and
 *    receipt/EOSE boundaries; no sleeps or fabricated cursor strings.
 *
 * The own-task producer, MCP carriers and WS transport exist. However the
 * generated HTTP/SDK catalog omits focus.refresh/subscribe/unsubscribe, and
 * the facade explicitly refuses them as board-context-required. A WS RPC
 * to that facade is not a new door. The idle wake delivery leg also needs
 * its real public adapter; an internal drain_wakes call is not allowed.
 */
suite.todo(test, "BOARD-05",
  "waits on typed run-bound STREAM subscription/refresh and wake delivery HTTP/SDK calls — Own-task stream delivery should work");

/**
 * BOARD-06 — Folds and recoverable outputs should work.
 * Canon: ARCH-0067 #folds/#fold-result-handles; ARCH-0026
 * #run-tree/#context-economy; OF-190, OF-421, OF-597.
 *
 * Canonical positional fold call: self.fold([from, through], {note?});
 * main normalizes it to {from, through, note?} and replies
 *   {fold, from, through, pending:true} | {error:string}.
 * self.compact({note?}) -> {pending: FoldRef[], applies} | {error}
 * self.folds() -> {folds:[{fold,from,through}], pending, compact_asked}
 * describe({fold}) -> {fold,from,through,stub,source,ids,handles} | pending
 * self.unfold(f) -> {fold,from,through,unfolded_after_step} | {error}
 * Main's normalized unfold input is {fold:string}; host binds run/step.
 * These run-only shapes do NOT imply generated HTTP/SDK doors.
 * B++ result card: {handle, preview, bytes, kind, complete}; describe(r)
 * exposes slice/search/query/chunks facets. Summaries are derived, Generated
 * and source-attached, never promoted claims. A fold retains result handles.
 *
 * Deferred public journey, cases[BOARD-06] plus large-output recipe:
 * 1. Create the long transcript through public session/conversation flow
 *    and produce the exact scripted large code result. Bind real turn/step
 *    positions; fixture span numbers are ordinals, not fabricated turn ids.
 *    Keep its result card, full byte count and independently pinned digest.
 * 2. Mark both spans. self.folds shows them pending, and raw log remains
 *    unchanged. Compact ONCE; await its public settled boundary. Both marks
 *    fold in that batch, leaving cached-log stubs with their key facts and
 *    result refs. The live board lists handles/marks, not repeated summaries.
 * 3. Read describe(f) and raw public transcript evidence. Originals still
 *    exist, with source attribution; the system prompt and task intent were
 *    not compacted. Generated summaries do not appear as accepted claims.
 * 4. Unfold both spans. Raw turns append after the current tail, labelled
 *    with their source spans; they never replace earlier cached stubs.
 *    Both latch codes, bay and calibration equal the authored fixture facts.
 * 5. Read the result in bounded ranges/chunk refs. Assemble exactly the
 *    fixture UTF-8 bytes, length and SHA-256 including the known tail; use
 *    search/query as appropriate. A preview is not the complete result.
 *    Request a summary on demand; require source refs, not a new claim.
 *
 * Main implements run-local folds and result reading, including MCP
 * read_result and the MESSAGE-result HTTP route. That route still takes
 * an opaque facet input/result and is not a generated typed result API.
 * All four self.fold/compact/unfold/folds operations are excluded from the
 * HTTP/SDK trees and explicitly require a run. G01 forbids using code mode
 * or internal fold ledgers to replace those missing typed public calls.
 */
suite.todo(test, "BOARD-06",
  "waits on typed self.fold/compact/unfold/folds and result-facet HTTP/SDK calls — Folds and recoverable outputs should work");

/**
 * BOARD-07 — Plugin context sections are admitted should work.
 * Canon: ARCH-0067 #what/#recipe; ARCH-0053 #r4b-hubs;
 * OF-387, OF-250.
 *
 * Canonical typed section recipe, not arbitrary prompt text:
 *   SectionManifestEnvelope {schema_version, manifest: {
 *     section_id, name, state_family:{family,version}, verbs: VerbRef[],
 *     authority_lane: AuthorityLaneRef, budget_policy: BudgetPolicyRef,
 *     provenance:{pack_id,skill_id,skill_version,content_hash_hex}}}
 * State/verb/authority/budget are admitted references; the folder's actual
 * hash backs provenance. The semantic install/consent/revoke operations
 * must expose typed manifest and grant results. No made-up section field
 * is added to PACK.md or to a generic settings/claim call.
 * Existing vault.packs.put({files}) -> {outcome:"installed"|"candidate"|
 *   "blocked", reason?, receipt?} is pack installation, not a typed public
 * binding of that section recipe. Suggestions are attributed proposals.
 *
 * Deferred public journey, cases[BOARD-07]:
 * 1. Offer the workshop pack/section through the named manifest admission
 *    operation with no owner section permission. Hydrate HTTP and MCP:
 *    no WORKSHOP-NOTES, no execution of its verbs, no widening from its text.
 *    Malformed/unknown typed recipe refs must refuse, not become prose.
 * 2. Approve exactly the offered permission through the public grant flow.
 *    Hydrate again: one admitted, scoped section with its stated budget and
 *    real pack/skill provenance. It sees only the workshop data granted.
 *    A code-free object uses the same fit/install law as every other pack;
 *    do not impose a second installation gate merely because it has a section.
 * 3. Revoke the grant (and inspect inactive/removed backing skill where
 *    supported). Hydrate again: the section and its reachable verbs vanish.
 *    An old rendered card cannot retain the revoked read or permission.
 * 4. Execute the authored repeating workflow through live public operations
 *    and trigger the named suggestion pass. Inspect the resulting proposal
 *    and evidence. Repetition nominates a pack; it never installs or consents.
 *    Accept uses the same gated install, and disabling suggestions suppresses
 *    that pass. Do not inject suggestion rows as fixtures or tick a queue.
 *
 * Main has the engine SectionManifest schema and gated pack install/remove.
 * It has no generated HTTP/SDK section-manifest admission/grant/revoke or
 * typed workflow-to-suggestion trigger. The dedicated hydration does not
 * bind plugin manifests. A hook's timed pin in an existing core section is
 * not a new manifest-admitted plugin section, and is not a substitute.
 */
suite.todo(test, "BOARD-07",
  "waits on typed plugin-section manifest admission/grant/revoke and suggestion HTTP/SDK calls — Plugin context sections are admitted should work");

/**
 * BOARD-08 — Working-set budget and reader profile should work.
 * Canon: ARCH-0067 #what/#named-reader-built; ARCH-0004
 * #rrf-pipeline/#reader-budget; OF-183, OF-228, OF-309.
 *
 * Semantic working_set read: (scoped cursor, declared budget) -> bounded
 * items/handles plus continuation/end. Cursor and budget wire types await
 * the generated public contract; no fabricated endpoint or storage cursor.
 * Existing pack/board retrieval controls include:
 *   {query, limit?, budget?: {token_budget?, max_item_tokens?,
 *      max_field_chars?, retrieval?}, reader?: {definition, task_family?}}
 * Reader optional-memory setting: none | positive token budget with
 * view=summary|standard|full. none is NOT numeric zero (0 means unbounded
 * in the existing pack budget). Positive profile budgets meet the caller's
 * with min and narrower view, never grant more authority.
 * Skipped result: {state:{kind:"skipped",reason:"skipped_by_profile",...},
 *   results:[], neighbors:[], ...}; no L2, telemetry run or capability hits.
 * Mandatory pins and standing prefix remain under their own read checks.
 *
 * Deferred public journey, cases[BOARD-08]:
 * 1. Ingest the authored large allowed corpus and withheld control through
 *    public writes. Declare the small budget/item limit, reader definitions
 *    and mandatory pin. Do not access an unbounded whole-vault export or
 *    fabricate indexed embeddings as a stand-in for working_set.
 * 2. Request a working set and advance only its returned public cursors.
 *    Every batch respects the declared budget/limit and current read scope;
 *    handles open bounded further slices. Iteration has an explicit end,
 *    not a guessed empty cursor. No dump of all documents into agent context.
 * 3. Request the small reader profile, checking that it narrows the caller's
 *    request, then the none profile for the same task. A skipped pack has
 *    the exact skipped_by_profile reason, NOT weak_evidence/missing_data.
 *    Its board cursor still advances with no invented retrieval run/results;
 *    loaded skills/prefix can stay but no new found-skill/candidate rows.
 * 4. Generate the corresponding real reply against the scripted provider
 *    and inspect the actual provider context. The none path omits optional
 *    memory, L2 and withheld sentinels but keeps the standing/pinned safety
 *    material. Inspecting only a pack response cannot prove final placement.
 *    Budgets are ceilings, not targets or model-quality claims.
 *
 * Reader controls and typed skipped packs already exist in HTTP. Missing
 * are the cursor-incremental working_set HTTP/SDK call and the typed
 * context-bearing reply operation. Ordinary recall/limit or context-pack
 * pagination is not the OF-309 ingress contract and cannot replace it.
 */
suite.todo(test, "BOARD-08",
  "waits on typed working_set cursor paging and context-bearing reply HTTP/SDK calls — Working-set budget and reader profile should work");

/**
 * BOARD-09 — Incomplete large result never repeats committed effect should work.
 * Canon: ARCH-0019 #result-body-store; OF-597, OF-190.
 *
 * Canonical binding publishes {handle,preview,bytes,kind,complete:true} only
 * after the whole body exists. An interrupted occurrence stays explicitly
 * incomplete, never an empty success or a false complete card. The manifest
 * joins identity/run/step/effect, digest/length/kind/MIME/encoding, preview,
 * completion, source/taint refs and fence. Read facets are typed ranges.
 * Content deduplication shares bytes, NOT grants or occurrence authority.
 * Bodies over code_result_inline_bytes (canon default 1 MiB) use the body
 * store. The fixture expands to 1,224,051 UTF-8 bytes; no engine limit changes.
 * A typed public producing-run/effect status and recoverable result read
 * must identify this exact occurrence; do not guess a not-yet-published ref.
 *
 * Deferred public journey, cases[BOARD-09] plus large-output recipe:
 * 1. Configure the real adapter's stream with head and held-tail parts;
 *    declare its model/role/purpose/usage. Through typed public operations,
 *    commit the one connector effect with its isolated idempotency key.
 *    Observe both the sink's actual request and a durable ENGINE effect
 *    settlement receipt. A provider barrier alone proves no transaction.
 * 2. Start production of that effect's large result and await the external
 *    before-tail barrier. Read the public occurrence/progress if available;
 *    never accept complete while the tail is still withheld. SIGKILL only
 *    after the public settlement AND the controlled stream boundary.
 * 3. Restart this same vault. Inspect the already-known occurrence/result
 *    through its typed public status/read door, plus the unchanged sink log.
 *    A partial body is explicitly incomplete (or the producing occurrence
 *    says incomplete before a handle has published), not complete/empty.
 *    Recovery must not invoke the committed effect again. Reject extra
 *    provider/sink calls; do not hide them with a fake deduping engine.
 * 4. Request the unrelated cobalt notebook by normal public memory read:
 *    serving still works. If a subsequent authorised result read is complete,
 *    its ranges and tail must equal the fixture's full length/digest. It is
 *    valid to expose incomplete output; silently replaying the effect to
 *    regenerate that body is not valid. No private spill inspection.
 *
 * Main has result-body machinery, MCP read_result and a MESSAGE attachment
 * read route. The latter uses opaque facet input and Object output; there
 * is no generated typed HTTP/SDK producing-occurrence/result-facet/recovery
 * contract for this crash flow. Bare MCP execute_code/read_result or a raw
 * Object cast would bypass G01, not exercise the missing typed operation.
 */
suite.todo(test, "BOARD-09",
  "waits on typed effect-result occurrence/status/range recovery HTTP/SDK calls — Incomplete large result never repeats committed effect should work");
