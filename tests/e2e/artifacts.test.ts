import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Artifacts and document organs. Each TODO is a required BLOCKED report row,
 * not passing coverage. G01 requires a typed HTTP and SDK call for a designed
 * operation; execute_code, arbitrary claims and engine helpers are not substitutes.
 *
 * Binding readback: origin/main and this writer's base were both
 * 6315e0e42bfe530f6a4be73d3e77cc16e0a6ffe4. Inspected the server OpenAPI
 * registration, api/{blob_artifacts,artifacts,esign}.rs, cli.rs, the generated
 * HTTP facade/types, and packages/oneiron/src/index.ts. The shared harness's
 * c716fa9921692224fe46114b283993d5d81f6c8c snapshot is older. No shared pin is
 * changed here. Code readback determines available bindings, never expected truth.
 *
 * Fixture: artifacts-scenarios in fixtures/artifacts/manifest.json. It pins the
 * canon, independent authored content/arithmetic, missing calls and asset needs.
 * It is a scenario specification, NOT an Office oracle capture or a fake organ.
 * Licensed independent DOCX/XLSX/PPTX oracle packages, retained part hashes and
 * build-pinned real organs must arrive before the blocked flows can be activated.
 * Do not substitute the synthetic retained.* packages for an Office oracle.
 *
 * Activation uses a fresh EngineFixture.start({id, profile}) per complete flow,
 * loadFixtures(), authenticated public setup and explicit grants. HTTP/WS/MCP
 * use the shared real clients. External inference alone may use ScriptedProviders.
 * Keep organ processes real; await public receipts/ACKs or external barriers,
 * never private queue ticks, guessed delays or made-up document frontiers.
 */

/* ARTIFACTS-01 — Artifact version proposal and anchored comment should work.
 * Rows OF-368, OF-511. ARCH-0078 #contract; ARCH-0075 #body.
 *
 * Existing typed family calls:
 *   vault.artifacts.create({name, media_type, content_base64, run_ref?, made_by?})
 *     -> ArtifactView | null {artifact_id, kind, head, versions}
 *   vault.artifacts.view({artifact_ref}) -> ArtifactView | null
 *   ArtifactVersionView = {version, content_hash, parent_version?,
 *     fork_of_version?, provenance, run_ref?, created_at, export_name,
 *     export_media_type, made_by, born_from}
 *   vault.artifacts.proposals({artifact_ref}) -> PendingProposalView[]
 *   vault.artifacts.keep/discard({artifact_ref, proposal_ref, brief_ref?, reason?})
 *   vault.artifacts.export({artifact_ref, version?, travel?, why?})
 *     -> {version, content_hash, content_base64, born_with, ...} | null
 *
 * Canon's review primitive is Anchor(artifact, version, locator), an append-only
 * thread, then assignment into a task brief retaining that anchor. Locators are
 * a sheet/range, paragraph span, slide/shape, or code-document cursor span.
 * The HTTP family routes expose unattached/reattach offers, but there is no
 * typed thread-create/comment/read/assign lifecycle in the HTTP/SDK catalog.
 * An arbitrary annotation.* claim is not that lifecycle. Kind enum membership
 * alone also does not prove a usable image/canvas/code-family adapter.
 *
 * For every publicly supported kind: pin a unit, comment, assign its edit task,
 * generate a retained fork and compare against the pin. Before settlement both
 * live head and exported original stay unchanged. Refuse proposer/self-lineage
 * acceptance; an independent authorized holder keeps one proposal and rejects
 * another. Keep consumes once, rejection never replaces head. Export the kept
 * version and inspect parent, made_by inputs/prompt, trigger and born_from.
 * Read the comment after settlement: same unit/quote or explicit drift, never
 * silent reattachment. The authored content and unit facts are in the fixture.
 */
suite.todo(test, "ARTIFACTS-01", "waits on typed artifact anchored-thread create/comment/read/assign calls and supported-kind unit inspection");

/* ARTIFACTS-02 — Shared Office bodies preserve concurrent edits should work.
 * Rows OF-505, OF-510. ARCH-0075 #body; ARCH-0077 multiplayer.
 *
 * All three body formats have typed calls; these are NOT missing:
 *   vault.artifacts.body.import({artifact_ref, version?, made_by?})
 *     -> OfficeBodyHead {artifact, kind, source_version, source_hash,
 *                        import_frontier, frontier, commits}
 *   .read({artifact_ref, at?}) -> {format: "docx"|"xlsx"|"pptx", body}
 *   .edit({artifact_ref, base?, ops: OfficeBodyOps, made_by?})
 *     -> {frontier, minted, receipt: TextCommitReceipt, effects}
 *   .commits({artifact_ref, actor_ref?}) -> {actor?, receipt?, reason?}[]
 *   .fork.open({artifact_ref, run_root_ref?, proposal_ref?}) -> OfficeBodyFork
 *   .fork.edit({artifact_ref, fork_ref, ops, made_by?}) -> OfficeBodyEdit
 *   .fork.diff({artifact_ref, fork_ref}) -> {base, head, fork_head, conflicts, ...}
 *   .fork.merge({artifact_ref, fork_ref, reviewed_head, reviewed_fork})
 *   .proposal.settle({artifact_ref, proposal_ref, verdict, scope?,
 *                    reviewed_head, reviewed: [{fork_ref, reviewed_fork}], reason?})
 * Deck forks instead use .body.deck.review, .deck.merge and .deck.export.
 * Generic .body.export returns {frontier, record?}; a deck's export can wait
 * as a proposal while its independently qualified export profile is closed.
 * Never manufacture an oracle receipt to open .body.deck.oracle.
 *
 * Pair two real human editors and a distinct machine proposer. People list/get
 * are reads; shape actor ceiling rows do not create a human/agent principal.
 * EngineFixture.pairActor pairs existing principals and never creates them.
 * This complete flow waits on named typed principal-authoring setup, not an
 * invented identity or a client-controlled made_by.actor. WS facade RPC can
 * carry the already-typed body calls; it is not a missing edit verb.
 *
 * Both human editors read one base and submit disjoint fixture ops over HTTP
 * and WS before either learns the other's result. Read exact merged content
 * and receipts naming both authenticated actors. Machine work edits a fork;
 * live content is unchanged until preflight/independent settlement. Preserve
 * both human edits after merge, read each actor's commit history, then export
 * all three formats. Export is a numbered blob projection, not the new body
 * base: its source version and editable frontier stay intact. Check exported
 * values against the independent fixture, not a second engine rendering.
 */
suite.todo(test, "ARTIFACTS-02", "waits on typed creation of distinct human editors and a machine principal for shared Office-body setup");

/* ARTIFACTS-03 — DOCX focused edit preserves unrelated content should work.
 * Rows OF-503, OF-368. ARCH-0075 #body; ARCH-0078 #contract.
 *
 * Existing OfficeBodyOps docx variant:
 *   {format: "docx", ops: [{op: "set_text", block, text}]}
 *   {format: "docx", ops: [{op: "move", block, after?}]}
 * A read returns blocks with stable id, text, runs, kind, imported and locked.
 * Export takes {artifact_ref, run_ref, author?, made_by?,
 *               utc_offset_minutes?, iana_timezone?} and returns a blob-version
 * record. These typed body edits/export must not be reported as absent.
 *
 * Canon still needs a public anchored paragraph/comment read returning its
 * version, locator, stored quote and explicit mapped/drift disposition. The
 * family's unattached listing alone cannot create or read a still-attached
 * comment, and a body block id is not a fabricated annotation-thread id.
 * The wire spelling of that missing read must be published, not invented here.
 *
 * Import the independently Word-authored fixture, locate its named paragraph
 * through public inspection, pin/comment, and edit just the authored phrase.
 * Export; compare accepted user text with the golden and SHA-256 of every
 * independently pinned unrelated package part, including comments and opaque
 * bytes. Compare edited text semantically (tracked revisions are allowed),
 * never require the edited document.xml to be byte-identical. Move the block,
 * then resolve the original anchor: exact quote/unit or explicit drift retaining
 * the quote. Do not guess success from matching text at a nearby paragraph.
 */
suite.todo(test, "ARTIFACTS-03", "waits on typed DOCX paragraph/comment anchor pin and resolution with explicit drift");

/* ARTIFACTS-04 — Spreadsheet recalculation and refused formula should work.
 * Row OF-503. ARCH-0075 #body and #calc.
 *
 * Existing calls are typed through HTTP and Oneiron SDK:
 *   .body.edit({artifact_ref, base?, ops: {format: "xlsx", ops: [
 *     {op: "set_value", sheet: "Inputs", cell: "A1", value: {number: 8}}
 *   ]}}) -> OfficeBodyEdit
 *   .body.preview({artifact_ref, utc_offset_minutes: 0, iana_timezone: "UTC"})
 *     -> XlsxPreview {frontier, book, recalc?: string | null}
 *   .body.export({artifact_ref, run_ref, utc_offset_minutes: 0,
 *                 iana_timezone: "UTC"}) -> {frontier, record?}
 *   OfficeBodyExportRecord has version, source_version, frontier, recalc?,
 *   effects, actor and author; .artifacts.export retrieves that exact version.
 *
 * Missing field: a typed recalculation disposition/refusal with affected cells
 * and reason. Null recalc is not a distinction between unsupported, unresolved
 * and not attempted. Current office_body::recalc_xlsx discards the failure and
 * mark_full_calc sets fullCalcOnLoad without removing stale cached values.
 * A full-calc flag alone must never pass the fixture's unsupported-result check.
 * This waits for the typed result, not an internal calculator or a fallback app.
 *
 * With the independent golden workbook, change Inputs!A1 from 4 to 8. Check
 * stored exported caches and preview against authored B1=11, B2=22, C1=33,
 * C2=8.25 and Rates-dependent D1=16.5. Require the native calculator's version
 * stamp. Parse the exported package independently; reading only the live body's
 * stale value fields is not proof of recalculation. In the separate linked
 * fixture, [1]!Rate is unresolved/unsupported, with a deliberately false cache.
 * Require a named refusal/unresolved result, no stale number advertised as a
 * computed answer, and original bytes preserved. Never copy fallback output
 * or formula-engine answers into the golden. No universal coverage claim.
 */
suite.todo(test, "ARTIFACTS-04", "waits on typed spreadsheet recalculation and unsupported/unresolved-formula result fields");

/* ARTIFACTS-05 — PowerPoint safe editing and judgment comments should work.
 * Rows OF-507, OF-508. ARCH-0077 #routes, #edit-target-choice,
 * #review-route-built; ARCH-0078 #contract.
 *
 * Current named calls exist, but their decisive leaves are opaque:
 *   vault.artifacts.propose_deck({artifact_ref, transaction: unknown,
 *                                run_ref, context?, made_by?})
 *     -> {proposed?: PendingProposalView, rejected?: unknown}
 *   .review_slides({artifact_ref, run_ref, units: [{target: unknown,
 *     review_image?, review_image_ref?, renderer}], question: unknown,
 *     author: unknown, labels: unknown, reversibility?, evidence_refs?, ...})
 *     -> {proposed?, abstained: unknown[], refused: [{target, reason, offer?}]}
 * These names are not licenses to cast a private transaction into a typed call.
 *
 * Current target law: (slide package part, native p:cNvPr id, expected content
 * fingerprint). Crate Target is {slide: &str, shape: u32, expected: [u8;32]}.
 * Do not replace this with NodeId-only live-body ops, creationId-only lookup,
 * a name, or a global native-id search. The fixture repeats native id 7 in
 * different slide parts and has another fixture with an in-part duplicate.
 * Public inspect must return the actual fingerprint; never reproduce it here.
 *
 * Edit the named shape, then refuse its old fingerprint as TargetChanged and
 * the duplicate as AmbiguousAnchor, with no proposal/head change on refusal.
 * Run the declared system_one -> escalation -> big route, first/ceiling both
 * bound, enforced fixture band. At most two measurements per unit; an eligible
 * first result advances to escalation, not a third measurement at big. Retain
 * calibrated pairs bound to measuring pins and the precise judged version.
 * Independent Keep consumes one comment proposal; repeated settlement refuses.
 * Modern 2018 comments retain judgment/severity words and selected author;
 * receipts retain asker/answerer independently of the exported byline. Hash all
 * independently pinned unrelated parts. No thumbnails prove PowerPoint fit.
 */
suite.todo(test, "ARTIFACTS-05", "waits on typed deck target inspection/transactions and slide-review policy, paired readings and comment result schemas");

/* ARTIFACTS-06 — Deck creation requires kept brief should work.
 * Row OF-509. ARCH-0077 #routes; ARCH-0078 #contract.
 *
 * Canon's typed stages (semantic shapes, NOT frozen HTTP DTO names):
 *   Outline: audience/outcome/message, ordered page jobs, evidence pins
 *     (document, version, cursor span, quote hash), qualifications, data with
 *     units/missing meaning/sources, priority, split permission, accessibility.
 *   KeptBrief: brief NOTE version + content hash, frozen by the person's Keep.
 *   DesignPlan: kept input, template/profile/layout by capability, theme/tokens,
 *     block-to-slide/shape assignments, assets/data, fit/overflow, expected
 *     package parts/relationships and source trace for every output unit.
 *   Emission: candidate deck + report naming kept brief/template as born_from.
 * A note create with kind "brief", NativeOutputRequest bytes, or the existing
 * propose_deck edit transaction does not implement this staged creation route.
 * No named typed outline keep/decline -> design -> emission HTTP/SDK call exists.
 * The same absent operation also waits on its MCP tool, not execute_code.
 *
 * Propose outline one through HTTP; decline it through the real public surface.
 * Attempt final creation via MCP: no kept brief means refusal/no final artifact.
 * Keep outline two, bind its exact hash/version and three separate design
 * alternatives, then create once. Later brief edits make that run stale.
 * Unsupported filter-bearing SVG must refuse or take a declared typed fallback
 * (compatible shapes, permitted split, supported composition, or Ask). Never
 * silently rasterize; an explicit raster choice requires its own derivation.
 * Check claims/data/images/source hashes, licensed asset/font versions,
 * qualifications, missing != zero and every source block's output mapping.
 */
suite.todo(test, "ARTIFACTS-06", "waits on typed outline keep/decline, validated deck DesignPlan and creation HTTP/SDK/MCP calls");

/* ARTIFACTS-07 — Organ crash is contained and recoverable should work.
 * Row OF-575. ARCH-0075 #body, #organ-host; ARCH-0026 #run-tree.
 *
 * Existing .artifacts.waits({artifact_ref}) -> OrganWaitView[] includes
 * {artifact_id, run_ref, organ, verb, held_by, held_at, reason, tries,
 *  last_try_at, failed?}; .release_wait is a Discard-like release, NOT a retry.
 * Pack installation and the server's host exist. They do not make the current
 * in-process DOCX/XLSX body edits an out-of-process document-organ operation.
 *
 * Canon requires a typed hosted document-edit call/result carrying the existing
 * durable intent, grant and public run/receipt status, not a private host call.
 * Need an observable in-flight operation/receipt and ownership-bound organ
 * process identity before this flow can kill precisely that real organ. Do not
 * replace it with engine.kill(), a stub that crashes, or a private queue drain.
 * Do not invent retry DTOs: wait for the operation's public typed retry binding.
 *
 * Import the original, start the edit and await its public intent/ACK boundary.
 * Terminate only the owned organ PID. Engine health/read remain available; the
 * pending result reports explicit failure/wait, original export and head remain
 * unchanged and no partial edit appears. Restart the real organ, then explicitly
 * retry under the SAME intent and grant. Resume at the safe checkpoint, consume
 * once and inspect the final result/receipt. One version/effect, not two tasks
 * with the same prose. Keep machine output a proposal until authorized Keep.
 */
suite.todo(test, "ARTIFACTS-07", "waits on typed hosted document-organ edit/retry and public in-flight intent/process/result observation");

/* ARTIFACTS-08 — E-sign request through public signing should work.
 * Row OF-415. ARCH-0064 #seal; ARCH-0040 #mcp-actor-ceilings;
 * ARCH-0078 #contract.
 *
 * Existing typed facade/SDK calls:
 *   vault.esign.create({document_ref, draft: EsignDocument}) -> EsignDraftView
 *   EsignDocument: {schema_version, kind, title, sequential, expires_at,
 *     items: [{artifact_ref, original_version}], recipients: [{id, email, name,
 *       role, order, expires_at, principal_ref?, automated, natural_person?}],
 *     fields: [{id, item, recipient, required, geometry, meta}],
 *     full_trail_appendix, lifecycle?, project?}
 *   .links.issue({document_ref, rotate?}) -> {issued, unchanged, ...}
 *   .send_for_signature({document_ref, recipient_count, on_behalf_of?,
 *                        idempotency_key?}) -> {intent_ref, outcome, ...}
 *   .get({document_ref}) -> {status, document, recipients, signatures,
 *                          sealed_sha256, audit, awaits_owner_answer, ...}
 * Sending, link issue, ceremony and async seal worker ARE implemented on main.
 *
 * Recipient HTTP implementation: GET /sign loads the shell; the capability is
 * /sign#token, scrubbed and thereafter ONLY in POST bodies. /sign/action takes
 * {token, action: {action: "load" | "save_field" | "complete" | "reject", ...}}.
 * Complete has consent and next; SaveField has field and typed FieldValue.
 * SigningOutcome includes page, not_your_turn, awaiting_seal, held_for_owner,
 * consent_required and terminal. POST /sign/pdf takes {token, item}.
 * These ceremony DTOs lack generated typed HTTP/SDK calls/OpenAPI schemas.
 * Do not hand-roll them as an escape from G01, or inherit the owner's signed
 * PublicHttpClient for the recipient. Bearer recipient access is its authority;
 * presenting an agent credential makes Complete an automated act, not a person.
 *
 * With a pinned tiny PDF, local test-only certificate/trust, real seal organ
 * and independent verifier: freeze the exact item version, send under explicit
 * grant, open as recipient, refuse a different/invalid capability without any
 * field mutation, sign with consent and await awaiting_seal -> public terminal
 * task/receipt. Audit/certificate pages must precede sealing and be covered.
 * Inspect atomic version/status/audit publication, SealJob provenance and the
 * send + recipient authority; no extra Keep after signing. Download the exact
 * sealed version, verify trust/digests/covered audit pages independently, then
 * change a covered content byte and require failure. Preserve the pristine
 * original. Engine self-verify alone, a new random CA or bytes after EOF are
 * not the independent verification/tamper check. Redact capabilities first.
 */
suite.todo(test, "ARTIFACTS-08", "waits on typed public signing-ceremony HTTP/SDK calls and seal-task receipt observation");

/* ARTIFACTS-09 — Published pin and private live preview should work.
 * Rows OF-356, OF-555. ARCH-0078 #contract; ARCH-0050 #tested-pointer.
 *
 * Existing public GET serving routes are /a/{artifact}/... . Published and
 * static-preview selectors are /_s/c/published/ and /_s/c/preview/; immutable
 * versions use /_s/f/{forkHash}/ or /_s/b/{blobVersion}/. Optional /_t/{token}/
 * is serving authority, never an owner API credential. API health reports the
 * separate artifact_port. Serving is built; do not report GET /a as missing.
 *
 * Canon publication input: one artifact's exact immutable export (code tested
 * snapshot OR numbered blob version), pointer channel and explicit audience/
 * grant. A public tier needs that artifact's explicit owner authorization.
 * Canon live-preview input: session manifest's declared process/port and lease,
 * owner-private audience, widening only by a sharing URL or named invitation.
 * Result is a draft-labelled, lease-bound endpoint, not a published snapshot.
 * Current catalog has no typed publish/repoint/unpublish or private live-port
 * register/read/close calls. Internal ArtifactPublishVerbRequest/PrivatePreview
 * types and static GET preview selectors are not those public calls.
 *
 * Register the pinned code and blob fixtures publicly. Without public grant,
 * refuse anonymous publish; with a specific grant publish each allowed export.
 * Advance each draft, fetch the published URLs over HTTP and compare exact
 * independently authored v1 bytes, not current draft v2. Read the receipt/pin.
 * Start the declared local backend, open its preview as owner, refuse uninvited
 * guest, and check draft/private metadata. End its lease; old endpoint cannot
 * serve. Recheck the published pin survives draft and lease changes. Never use
 * a public preview or a generic task/claim write to manufacture these pointers.
 */
suite.todo(test, "ARTIFACTS-09", "waits on typed artifact publish/repoint/unpublish and lease-bound private live-port preview calls");
