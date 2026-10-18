import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Binding evidence: the checked-in generated catalog in
 * packages/oneiron-client/src/{facade,facade-types}.ts, the public Oneiron
 * TypeScript SDK, and the server's OpenAPI registration and route DTOs.
 * Canon and authored oracles are pinned by documents-scenarios in the area
 * manifest. Fixture labels are symbolic, not fabricated entity ids/cursors.
 *
 * Every complete flow below is blocked. suite.todo registers a real Bun
 * test.todo AND a mandatory BLOCKED row; none claims partial passing coverage.
 * G01 requires typed HTTP and SDK doors. No speculative URL, generic
 * consolidation input, raw entity-body decoder, Loro access or engine seed
 * substitutes for one. Existing note edits are not missing; their public
 * cursor/version reads and history/settlement doors are.
 *
 * On activation use EngineFixture.start({ id, profile }) per flow, authenticated
 * public setup, ScriptedProviders for external inference only, and loadFixtures
 * for documents-scenarios. Await public receipts/events, never private queue
 * ticks or fixed sleeps. Keep shared support and existing tests unchanged.
 */

/* DOCUMENTS-01 — Note kinds and cheap write should work. OF-002, OF-073.
 * Canon: ARCH-0032 #writers, #forks-proposals, #write-gate, #data-model.
 * Oracle: documents-scenarios / DOCUMENTS-01.
 *
 * Current typed calls:
 *   vault.notes.create({ kind: string, markdown: string })
 *     -> EntityRefReceipt { entity_ref, id_hex, receipt_ref, record? }
 *   vault.notes.defaults({ note_ref: string }) -> NoteDefaultsView
 *     { overrides, defaults: { pack, kind, extraction, context, retention,
 *                               archive_after_days? } }
 *   vault.notes.lifecycle({ note_ref: string }) -> { status, seal? }
 *   vault.notes.seal({ note_ref: string }) -> NoteSeal
 *
 * Hold the first classifier response at an external provider request barrier.
 * While it remains held, create all six notes and read their exact markdown;
 * each write receipt and live read must resolve without releasing the model.
 * Check the independently pinned kind defaults, not values learned from main.
 * Active scratchpad, handoff, research and reflection must not extract before
 * seal; diary must not produce ordinary claims. Seal eligible notes, release
 * the classifier, and await its public completion before inspecting claims.
 * Each note-derived claim must identify the note, indexed document frontier,
 * stable span and quote hash, using ARCH-0032's canonical EvidenceRef:
 *   { kind: EvidenceKind, entity: EntityRef, doc: DocId, at: Frontier,
 *     span: Option<CursorSpan>, quote_sha256: Option<[u8; 32]> }
 * Assert authored fact membership and exclude diary/private and premature
 * extraction. Do not assert exact generated prose, scores or a 100ms benchmark.
 *
 * Missing: typed live NOTE text reads (with reasoned private-note access), a
 * named note-classification trigger/result, and typed note evidence on claim
 * reads. vault.get's opaque body and consolidation.enqueue's unknown input
 * are not these contracts. No classifier response wire DTO is invented here.
 */
suite.todo(test, "DOCUMENTS-01", "waits on typed NOTE live reads and note-classification trigger/result with evidence refs");

/* DOCUMENTS-02 — Concurrent anchored edits should work. OF-472, OF-473, OF-233.
 * Canon: ARCH-0032 #writers. Oracle: DOCUMENTS-02.
 * Surface: the installed Oneiron TypeScript SDK in owned real Node processes,
 * never in-process native bindings or an HTTP-only substitute for this flow.
 * Pair two distinct existing writers and install automatic grants publicly.
 *
 * Current SDK input: memory.vault.notes.edit(EditNoteRequest), where
 *   EditNoteRequest = { note_ref: string, edit: NoteEdit }
 *   NoteAnchor = { note: string, head: string, cursor: number[] }
 *   NoteEdit =
 *     { kind: "replace_span", start: NoteAnchor, end: NoteAnchor, text: string }
 *     | { kind: "insert_after", anchor: NoteAnchor, text: string }
 *     | { kind: "append_to_section", end: NoteAnchor, text: string } | ...
 *   NoteEditOutcome = { outcome: "edited", head: EntityId }
 *     | { outcome: "rewrite_fork" | "proposed_fork", fork: EntityId }
 *     | { outcome: "review_required", receipt: CommitReceipt }
 *
 * Obtain stable anchors for the original "blue" span and Actions section from
 * a public read. Both writers retain that same version. Insert the human
 * preface before the span, then replace using the older anchors; append the
 * agent item to the section. This stale-anchor interleaving is deterministic
 * and checks concurrent work without depending on HTTP arrival races.
 * Assert the exact fixture result, both changes surviving, and history naming
 * the authenticated actor for each operation (not a client-supplied byline).
 * Read the note through the same public live-text surface the editor uses.
 *
 * Missing: typed stable-cursor acquisition and attributed NOTE operation
 * history, not the edit verbs themselves. Never manufacture cursor bytes or
 * use numeric offsets in place of stable anchors. The shared SDK driver only
 * covers four quickstart verbs; an owned broader SDK journey belongs here
 * when these doors exist, not in modified shared helpers.
 */
suite.todo(test, "DOCUMENTS-02", "waits on typed NOTE stable-cursor/version reads and attributed operation history");

/* DOCUMENTS-03 — Whole-text update preserves concurrent work should work.
 * Rows: OF-473, OF-478. Canon: ARCH-0032 #writers (newer than the registry's
 * older 'refuse while live' prose: a declared rewrite opens a fork).
 * Oracle: DOCUMENTS-03.
 *
 * Existing HTTP facade request: vault.notes.edit({ note_ref, edit }) with
 *   NoteVersion = { note: string, head: string, frontier: number[] }
 *   edit = { kind: "whole_text", text: string, timeout_ms: number,
 *            base?: NoteVersion | null }
 *     | { kind: "rewrite", text: string }
 * Result is NoteEditOutcome, as above. The fixture's timeout_ms is a caller
 * diff budget, never an engine default or a timing assertion.
 *
 * Read a public base version. Agent prepares whole_text from that base;
 * human inserts the preface before it is submitted. Submit with the original
 * base, then assert the preface and agent change both survive as small,
 * actor-attributed ops. Keep the human's live editor subscription open.
 * Submit the declared rewrite and require rewrite_fork, a different fork id,
 * unchanged live text/head, and a fork holding all of the rewrite output.
 * Read history to distinguish a diff from an overwrite. A whole-text diff
 * timeout likewise must retain output on a fork, never silently discard it.
 *
 * Missing: public base-version/live text/history reads, typed editor-presence
 * binding and fork inspection. Do not use a seal as a live-version surrogate
 * (sealing changes edit semantics), or treat an opaque EntityView body as a
 * typed NoteVersion. No private scheduling barrier is allowed.
 */
suite.todo(test, "DOCUMENTS-03", "waits on typed NOTE base-version/live/history reads, live editor binding and rewrite-fork inspection");

/* DOCUMENTS-04 — Proposal merge switch and rejection should work.
 * Rows: OF-474, OF-211, OF-062. Canon: ARCH-0032 #forks-proposals.
 * Oracle: DOCUMENTS-04.
 *
 * Canon design, NOT a route or SDK verb currently in the catalog:
 *   fork_at(head: DocId, frontier: Frontier) -> fork document
 * The fork retains parent document and frontier and joins an explicit proposal
 * id when opened. A proposal is a set of forks, never an author/time bucket.
 * Accept takes that set by merge (import ops) or switch (move head); reject
 * drops the pending fork. The head-move receipt and original history remain.
 * Canon does not freeze their HTTP DTO spelling: wait for those typed DTOs.
 *
 * Create two notes; open three distinct two-note proposal sets. On the first,
 * make a concurrent human head insertion, then accept once by merge and assert
 * both fork edits plus the head insertion survive. Accept the second set by
 * explicit switch; both heads must name the chosen forks and each move must
 * have a receipt. Reject the third set once; neither live head changes, rejected
 * text never appears live, and birth/head history stays inspectable.
 * Inspect the version tree's parent/frontier links, set membership, verdicts
 * and head-move receipts. Verify one verdict settles both members, not just
 * the first file; include the review bundle's explainer referencing its forks.
 *
 * Missing: NOTE fork/proposal open, merge/switch/reject and version-tree reads.
 * vault.artifacts.body.* forks are Office bodies, not entity NOTE documents.
 * Session-tagged proposed-claim review under OF-062 is not a text fork either.
 */
suite.todo(test, "DOCUMENTS-04", "waits on typed NOTE proposal-set fork/open, merge/switch/reject and version-tree doors");

/* DOCUMENTS-05 — Live indexed and pinned reads should work. OF-476, OF-472.
 * Canon: ARCH-0032 #writers, #pins, #retrieval; ARCH-0004 #rrf-pipeline,
 * #read-frontier. Oracle: DOCUMENTS-05.
 *
 * Canon requires three distinct read selectors:
 *   live: current document; indexed: last materialized Frontier;
 *   pinned: a past time or citation identifying a Frontier and CursorSpan.
 * A citation identifies { doc: DocId, at: Frontier, span: CursorSpan,
 *                         quote_sha256: [u8; 32] } and retains its quote.
 * These are semantic types, not invented JSON routes/opaque cursor encodings.
 *
 * Await the original indexed frontier, cite its original sentence, then hold
 * publication at a publicly acknowledged indexing boundary. An external
 * embedder barrier alone does not prove an index transaction is held.
 * After the live edit, read live=new and indexed=old and assert search quotes
 * old text AT the indexed frontier, not live text labeled with the old version.
 * Release the provider; await a public indexed-frontier change and assert
 * indexed/search=new. Resolve the original citation: pinned text stays old,
 * with the original document, frontier, span and quote hash.
 * Do not require scores/ranks or use a sleep to guess an idle boundary. Read
 * the public idle-debounce manifest row without changing its default.
 *
 * Missing: typed three-frontier NOTE reads, pin/resolve, and indexed-frontier
 * publication observation/control. Generic recall's as_of is query time, not
 * a pinned NOTE body read; the atomic witness/receipt is not an index barrier.
 */
suite.todo(test, "DOCUMENTS-05", "waits on typed NOTE live/indexed/pinned reads, citation pins and indexed-frontier observation");

/* DOCUMENTS-06 — Citation pins and owner-opened history purge should work.
 * Row: OF-477. Canon: ARCH-0032 #pins; ARCH-0038 #archive-delete-erase.
 * Oracle: DOCUMENTS-06.
 *
 * Use the same typed citation shape as DOCUMENTS-05. Canon's purge takes an
 * owner-opened request over one document's history and returns a receipt
 * identifying the retained frontier/pins. No current public request/result
 * DTO exists. Do not invent a purge floor field from engine internals.
 *
 * Pin the old sentence at one operation, append and pin a later still-live
 * sentence at another, then delete the old cited span. An ordinary writer
 * who otherwise has an automatic edit grant must be refused history purge
 * with no destructive effect. Owner purge is explicit, manual and receipted.
 * Assert its retained boundary respects the oldest cited OPERATION and the
 * cited span's deletion frontier, not merely the two citation versions.
 * Resolve both citations: the still-present span maps and its quote/hash
 * stays fixed; deleted text keeps its stored quote. If its cursor no longer
 * maps, resolution must explicitly report drift, never change/drop the quote.
 * Inspect the purge receipt and repeat citation reads after fixture.restart().
 * Do not require every deletion to drift: CRDT cursor mapping may survive.
 *
 * Missing: typed citation creation/resolution and owner-only history purge
 * with a retained-boundary receipt. An ordinary note edit grant cannot name
 * history erasure; vault.records.erase_confirm erases records, not edit history.
 */
suite.todo(test, "DOCUMENTS-06", "waits on typed NOTE citation pin/resolve and owner-only history-purge request/receipt");

/* DOCUMENTS-07 — Summary scope and keep memo should work. OF-028.
 * Canon: ARCH-0032 #writers, #forks-proposals, #summaries; ARCH-0026 #run-tree.
 * Oracle: DOCUMENTS-07.
 *
 * Existing typed HTTP shape:
 *   POST /v1/core/conversations/{conversation_id}/summaries
 *   { scope: { path: "canonical" | { branch: string }
 *       | { branch_span: { after: string, through: string } }
 *       | { sub_session: string }, include_forks?: boolean, session?: string },
 *     purpose?: string, actor: { entity_ref: string,
 *       actor_class: "human" | "agent" | "system" },
 *     land_on?: string, as_record?: boolean }
 *     -> 202 { attempt: string, status: string, coalesced: boolean }
 *   GET /v1/core/summary-attempts/{attempt}
 *     -> { attempt, current_attempt, state, result?: { summary, claim?, record? },
 *          failure?, retry_at?, updated_at }
 *   GET /v1/core/summaries/{summary_id}/covers -> { covers: string[] }
 *   GET /v1/core/summaries/{summary_id}/derivation -> { metadata: ... }
 *   POST /v1/core/summaries/{summary_id}/rederive
 *     { actor: { entity_ref, actor_class } } -> same queued response
 *
 * Build the fixture topology publicly: trunk and branch share only a textless
 * root, and the sub-session is spawned off trunk-two. Request each declared
 * scope with no caller-composed summary body; scripted Dreamer text is the
 * external model response, not public SUMMARY seeding. Await the returned
 * status and check exact authored source sets: exclude the other scopes,
 * empty-text records and earlier summary replies that Dreamer did not read.
 * The summary document's meta.keep memo guides the scripted update. Add a
 * human edit, then the single new fact. A Dreamer patch must preserve that
 * human op and cite the new fact in its receipt. A full regeneration reads
 * keep too, opens a fork, and leaves head unchanged until explicit switch.
 * Check fork provenance/covers before and after switch, not prose quality.
 *
 * Missing: typed SUMMARY document/keep edit/read, anchored Dreamer patch versus
 * regeneration-fork request/results, and switch. Existing rederive has no
 * patch/regenerate selector and cannot stand in for this whole lifecycle.
 */
suite.todo(test, "DOCUMENTS-07", "waits on typed SUMMARY keep-memo/edit, anchored patch, regeneration-fork and switch doors");

/* DOCUMENTS-08 — Streaming message finalization should work. OF-030, OF-136.
 * Canon: ARCH-0032 #writers, #birth-rule; ARCH-0026 #run-tree;
 * ARCH-0002 #streaming, #interrupted-reply. Owner rulings G01=A and G03=A
 * are settled, not unanswered questions. Oracle: DOCUMENTS-08.
 *
 * Canon's typed DESIGN (not currently a public HTTP/SDK lifecycle):
 *   commitMessage(messageId: string, content: string,
 *                 options?: { register?: string }): Promise<ReceiptId>
 *   beginMessageStream(messageId: string,
 *     options: { mode?: MessageWriteMode, register?: string })
 *       : Promise<MessageStreamHandle>
 *   appendToStream(handle: MessageStreamHandle, delta: string): Promise<void>
 *   flushStream(handle: MessageStreamHandle): Promise<void>
 *   finalizeStream(handle: MessageStreamHandle): Promise<ReceiptId>
 *   cancelStream(handle: MessageStreamHandle, reason: StreamCancelReason)
 *       : Promise<ReceiptId>
 *   MessageWriteMode = { kind: "atomic" } | { kind: "streamed",
 *     syncVisibility: StreamSyncVisibility, cadence: StreamCadence }
 *   StreamCancelReason = "user_interrupted" | "agent_aborted"
 *     | "external_signal" | { kind: "custom", description: string }
 *
 * Main DOES have POST /v1/ai/chat { conversation_ref, text, history?,
 * agent_ref?, stream?: boolean }, whole ChatReply with incomplete, and NDJSON
 * accepted/delta/done/saved/error. It also has typed Continue and Retry:
 *   vault.conversations.turn.continue / vault.conversations.turn.retry
 *   { turn_id: string } -> { action, turn_id, message_id, attempt_id }.
 * Do not report those as absent. Closing an HTTP subscriber is not cancel:
 * the producer continues. Model finish_reason is not a caller finalize verb.
 *
 * Atomic write is default. For an opt-in stream append both authored chunks,
 * observe ephemeral partials, and finalize once; exactly the final text and
 * one terminal receipt persist, with no durable delta edit operations and no
 * document until a later edit. Cancel a second stream: its same addressable
 * message stays incomplete, with cancelled finality and explicit reason.
 * For a third, first commit the authored prefix publicly, then open a stream
 * on that same message. Observe a public ACK/receipt plus an external barrier,
 * then kill the owned server and restart only its vault. Require the same
 * addressable message marked incomplete/partial, process_crash_recovery and
 * an explicit ephemeral_text_lost receipt, never a false final. Previously
 * committed text survives; the uncommitted tail is not an expected durable
 * quote. Continue resumes the same saved message; Retry retains old history.
 * Distinguish all three terminal outcomes through public reads and receipts.
 *
 * Missing: typed caller-controlled MESSAGE lifecycle HTTP and SDK calls and
 * a public durability/op-history read. Engine stream methods, raw WS tags,
 * presence bytes or a model stub must not substitute for G01's typed doors.
 */
suite.todo(test, "DOCUMENTS-08", "waits on typed MESSAGE commit/begin/append/flush/finalize/cancel HTTP and SDK calls plus durability history");
