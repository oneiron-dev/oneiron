import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/* Voice and media: required IDs in plan order, not passing partial coverage.
 * Binding readback: main 1aec7a3c94647f7f2cb012aaa9e4e3c2ff3d7cd3.
 * Read api/mod.rs, api/openapi_registry.rs, api/ai/{mod,media,voices}.rs,
 * api/vad.rs, cli.rs, the generated @oneiron/client catalog/DTOs and SDK docs.
 * Canon/registry pins and independent oracles: voice-scenarios in the area
 * manifest. G01 requires typed HTTP AND SDK calls, not a generic escape hatch.
 * These TODOs use the shared reporter's real test.todo/BLOCKED registration.
 * No private UDS, vault seeding, engine imports, or fake engine is substituted.
 *
 * When doors land, use EngineFixture for each fresh authenticated real server,
 * loadFixtures for these pins, ScriptedProviders for external inference only,
 * and the shared HTTP/WS clients for calls/receipts. Keep the image organ real.
 * Do not turn a subset of a flow into a passing test under its full planned ID.
 * The synthetic PCM is transport data, NOT licensed recorded human speech or
 * evidence of ASR/voice quality. Missing speech assets are on the FIX-LIST.
 */

/* VOICE-01 — Meeting file to attributed session should work. OF-408.
 * Canon: ARCH-0061 #pipeline/#twoway; ARCH-0060 #treatment, section 8.
 * Oracle: voice-scenarios.meeting; fixture need: licensed two-speaker recording
 * with an independently aligned transcript, including an uncertain span.
 *
 * Current typed doors, not substitutes for this producer:
 *   vault.artifacts.create({name, media_type, content_base64, run_ref?, made_by?})
 *   ai.transcribe(AiCallRequest) -> AiAnswer {model, parts, usage}
 *   AiCallRequest = {model?, prompt?, input?: AiPart[], references?: AiPart[],
 *                    params?: Record<string, unknown>, voice?: AiVoice}
 *   AiPart audio = {kind:"audio", media_type:string, data:string (base64)}
 * The transcription answer is text/audio parts, not a produced SESSION with
 * raw/provisional/corrected revisions or a speaker-resolution receipt.
 *
 * Upload the recording publicly, run its producer, await the public completion
 * receipt, then inspect all three transcript revisions and the SESSION/TURNs.
 * Require original source bytes/spans and ordered timestamps throughout; no
 * invented words in the uncertain span and no guessed principal for speaker B.
 * Preserve source labels separately from user/assistant roles and identity.
 * Have the paired owner resolve speaker B, citing the recorded span; require
 * that explicit decision's actor/evidence and the resulting attributed turns.
 * The raw transcript and source remain unchanged after resolution/cleanup.
 *
 * Canon requires source span -> transcript revision -> SESSION/TURN lineage
 * and owner-attributed resolution; it does not freeze a public producer DTO.
 * Wait for that typed request/result rather than inventing a URL or submitting
 * pre-written TURNs through witness. The private calendar_transcript.rs helper
 * supplies no permitted ingestion door and must not be copied into this suite.
 */
suite.todo(test, "VOICE-01", "waits on typed meeting-file producer, transcript-revision/SESSION lineage and owner speaker-resolution HTTP/SDK calls (Meeting file to attributed session should work)");

/* VOICE-02 — Voice identity survives provider change should work. OF-410.
 * Canon: ARCH-0061 #serving/#identity-privacy/#twoway.
 * Oracle: voice-scenarios.identity; two isolated TTS protocol origins A and B.
 *
 * Already implemented HTTP shapes (do not claim these routes are absent):
 *   POST /v1/ai/voices/{voice_id}/packs
 *     {pack_id, owner, origin:{kind:"captured", consent_event_ref},
 *      clips:[{register, media_type, audio (base64), transcript}]}
 *   POST /v1/ai/voices/{voice_id}/render_consent
 *     {event_id, subject, recorded_by, occurred_at, reach, basis, state}
 *     -> {voice_id, state, reach, revision, evicted}
 *   POST /v1/ai/voices/{voice_id}/targets/{target} {include_generated?, language?}
 *     -> {voice_id, target, vendor_voice_id, cloned_at, revision}
 *   DELETE the same target -> {voice_id, target, evicted, vendor}
 *   ai.speech({prompt, model?, voice:{kind:"bank", voice_id,
 *                                  include_generated?:boolean}}) -> AiAnswer
 * A stock voice is {kind:"stock", name}; it is NOT the banked-identity oracle.
 *
 * Record the subject's render grant, bank the captured ref under that event,
 * provision A, render, provision authorized B, and evict A. Render the SAME
 * banked voice again with the new target; assert provider requests use each
 * fixture vendor ID but identity, source pack and grant stay owner-controlled.
 * Inspect current target/consent and public lineage/receipts, not sonic quality
 * or equal PCM across vendors. Recognition consent must not grant rendering.
 * Deny an ungranted reference and a target beyond the grant's reach before
 * any provider call; neither may silently choose a stock voice or new identity.
 * Withdraw the render grant and require subsequent banked renders to refuse.
 *
 * Missing: generated typed SDK provisioning/consent calls and a typed bank
 * identity/source-pack/current-target inspection. The HTTP write responses
 * alone do not expose that full inspection. The voice-bank routes are also
 * absent from the OpenAPI registration read above. G01 forbids replacing those
 * designed SDK calls with raw HTTP merely because the handlers already exist.
 */
suite.todo(test, "VOICE-02", "waits on typed voice-bank provisioning/consent SDK calls and identity/source-pack/target inspection (Voice identity survives provider change should work)");

/* VOICE-03 — Barge-in cancels old generation should work. OF-139.
 * Canon: ARCH-0061 #twoway; OF-139 generation-epoch cancellation.
 * Oracle: voice-scenarios.bargeIn; voice-old-pcm, voice-new-pcm, voice-user-pcm.
 *
 * Current public text stream: POST /v1/ai/chat
 *   {conversation_ref, text, history?, agent_ref?, stream?:boolean}
 *   -> NDJSON accepted/delta/done/saved/error. Disconnecting its subscriber
 * does NOT cancel its producer. The public /ws is not the private voice UDS.
 * Voice currently has private sibling inputs pcm/cut/speaking and outputs
 * pcm/generation_end/flush/playout_stop; those are NOT callable public doors.
 *
 * Start a real streamed voice reply; the loopback consumer acknowledges old
 * audio queued/playing before a provider barrier holds the remaining tail.
 * Feed the fixture's 160ms sustained user speech via the public media session,
 * not a stop button, session end, disconnected HTTP request or private signal.
 * Observe generation retirement, LLM cancellation, TTS cancel, queued-PCM flush
 * and playout_stop for the same old epoch. Only then release old text/PCM.
 * Require a public processing/terminal boundary before asserting absence of
 * late old-epoch playout; an empty queue or elapsed sleep proves nothing.
 * Start the next epoch and require its distinct PCM to play, proving that the
 * consumer was not just closed. Settle the interrupted attempt exactly once
 * with declared actual usage and unused reservation released, not full spend.
 *
 * The required typed contract links session + utterance + generation to media,
 * cancellation, playout acknowledgment and terminal usage. No public HTTP/SDK
 * media-session or WS playout contract exists in this binding. Do not expose
 * UDS DTOs as invented HTTP/WS messages. 160ms is fixture duration above canon's
 * 100–150ms sustained-speech range, not a changed threshold or latency bench.
 */
suite.todo(test, "VOICE-03", "waits on typed public live-voice media session, epoch/playout-stop acknowledgment and interrupted-usage settlement (Barge-in cancels old generation should work)");

/* VOICE-04 — Tainted voice safeguard should work. OF-078.
 * Canon: ARCH-0061 #twoway; ARCH-0040 #mcp-actor-ceilings.
 * Oracle: voice-scenarios.safeguard; harmless scripted injection, no real secret.
 *
 * Return the external/tool-derived sentence through its real public result
 * boundary, preserving taint. Start TTS while the blocking safeguard response
 * is held at an external provider barrier. Observe the first PCM before that
 * verdict is released: the check must race TTS, not add a pre-speech gate.
 * Release the blocking verdict, require the SAME epoch-retirement/flush/
 * playout_stop path as VOICE-03, then release late audio for the retired epoch.
 * At a public completion/ack boundary, require no further blocked PCM playout,
 * an attributed safeguard notice/receipt, and settled actual usage once.
 *
 * In a separate first-party-safe turn, require the authored safe sentence to
 * play normally and no safeguard provider request for exempt memory/diary
 * material. A catch-all fake must not conceal an unexpected safeguard call.
 * Do not relabel fetched text as first-party, submit the model's verdict as a
 * privileged user mutation, or call an internal safeguard function directly.
 *
 * Canon specifies taint -> per-sentence parallel verdict -> shared epoch stop
 * -> public notice/receipt. The typed live HTTP/SDK/WS contract carrying those
 * links and its public completion observation are missing, as in VOICE-03.
 */
suite.todo(test, "VOICE-04", "waits on typed public tainted live-voice sentence/safeguard, epoch playout and notice/receipt contract (Tainted voice safeguard should work)");

/* VOICE-05 — Speculative ASR recall reuse should work. OF-108.
 * Canon: ARCH-0061 #twoway/#recall-in-call; ARCH-0004 #rrf-pipeline.
 * Oracle: voice-scenarios.speculation. Four hypotheses; initial signature,
 * cosmetic-only second, then TWO anchor changes: fires at [1,3,4], not [1,2,3,4].
 * Scripted enrichment supplies those independently authored entity/term sets.
 *
 * Publicly seed permitted and out-of-scope decoy memories in a fresh server.
 * Stream all four hypotheses under ONE utterance, retaining public per-fire
 * receipts. Require only meaningful signature changes to trigger recall and
 * at most four fires in that utterance. Do not infer the count from embedder
 * calls, cache timing or prompt text. Await the latest compatible fire before
 * submitting the compatible final. Require promotion/reuse of that result,
 * no extra full recall, and receipt linkage to the final transcript and scope.
 * The hidden decoy must never enter prepared/final candidates or citations.
 * Keep call-mode deadline/partial reporting honest; do not require model scores
 * or turn this small flow into the 10k/100k latency benchmark.
 *
 * Already public: vault.recall({query, effort:"call", scope?, deadline_ms?})
 * -> MemoryPack. It has no ASR utterance/hypothesis/finalize handle, signature
 * change decision, or speculative-fire/reuse receipt. Repeating recall three
 * times in test code would implement the behavior this test must observe.
 * Canon's partial/final session and RetrievalAction::Speculative are required
 * semantics, not invented facade verb names or private counters to read.
 */
suite.todo(test, "VOICE-05", "waits on typed ASR hypothesis/finalize HTTP/SDK session and speculative-fire/final-reuse scoped receipts (Speculative ASR recall reuse should work)");

/* VOICE-06 — Image generation and reference edit should work. OF-328, OF-329.
 * Canon: ARCH-0078 #contract/#image-built; ARCH-0036 #model-line.
 * Oracle: voice-scenarios.images; voice-image-base and voice-image-edited.
 *
 * Already typed: ai.image(AiCallRequest) -> AiAnswer with image parts
 *   {kind:"image", media_type, data (base64)}; references are AiPart[].
 * This raw inference answer carries no artifact ref/version/parent/made_by.
 * vault.artifacts.create accepts bytes and made_by; manually wrapping a model
 * answer there would manufacture the generation lineage being tested.
 * OfficeBodyKind/Ops are docx/xlsx/pptx, not a public image-organ adapter.
 *
 * Generate through provider A; require a traceable persisted artifact/version,
 * prompt input and producer receipt, then edit that referenced version through
 * authorized B. Assert the independently authored output bytes/pixels and a
 * NEW version with the original version as parent, source refs, prompt/trigger
 * and provider/process attribution. Read the original pinned version again.
 * Open/crop/export the image via public artifact calls invoking the REAL small
 * oneiron-image-organ process, never a fake organ or direct organ invocation.
 * Require its version/provenance/export receipt as the artifact contract says.
 *
 * An actor with an unrelated grant must be refused the reference and its text,
 * thumbnail/handle and full pixels, before either provider receives that ref.
 * A text-only modality route and a provider swap cannot widen the grant. When
 * a fallback form is served, inspect the served-form receipt, not prose hints.
 *
 * Missing: typed generation/reference-edit -> image artifact lineage/landing
 * and the production image-kind organ adapter. The six organ verbs exist in
 * the separate binary; calling them privately or mocking them is not this E2E.
 * ai.image's inline reference bytes do not establish access to a vault ref.
 */
suite.todo(test, "VOICE-06", "waits on typed generated/reference-edited image artifact lineage/landing and public image-organ calls (Image generation and reference edit should work)");

/* VOICE-07 — Affect outcomes without rewriting truth should work.
 * Rows: OF-010, OF-032, OF-335. Canon: ARCH-0003 #claim-type;
 * ARCH-0036 #model-line. G11=B is SETTLED: configured routing and its receipt,
 * not a universal wellness/model-score cutoff. Oracle: voice-scenarios.affect.
 *
 * Already public HTTP/OpenAPI:
 *   POST /v1/core/turns/annotate
 *     {turn_id, message_id?, vad:{valence,arousal,dominance},
 *      source:"model_inference"|"user_self_report", annotated_at?}
 *     -> {turn_id, message_id, vad, source, annotated_at}
 *   GET same path ?turn_id=...&message_id=... -> same annotation.
 * Those VAD annotations are NOT a coping-outcome aggregate/wellness projection.
 *
 * Install the companion/wellness PACK's coping vocabulary publicly, witness
 * person A's before/after turns and a neutral user-stated fact, then annotate
 * the two turns with the independent VAD values. Record an authorized strategy
 * outcome linked to BOTH turns, the person, scope and attribution evidence.
 * Read per-person aggregate and derive the configured non-clinical wellness
 * projection. Require policy-routed mode plus receipt/source refs, not any
 * invented numeric wellness formula, improvement cutoff or disease label.
 * Person B with no outcome must not inherit A's result. Re-read the neutral
 * fact, its value/source/status/history and citations before and after derive:
 * VAD/outcomes remain separate evidence, never a silent supersession of truth.
 * A generated contradiction stays Proposed beside a user-stated head.
 *
 * Missing: typed pack-installed coping outcome/aggregate and wellness derive/
 * projection HTTP+SDK calls. Generic claim upsert cannot be used to precompute
 * the ledger/derived answer in the test. G11 is not an open owner blocker.
 */
suite.todo(test, "VOICE-07", "waits on typed coping-outcome/aggregate and per-person wellness projection HTTP/SDK calls (Affect outcomes without rewriting truth should work)");

/* VOICE-08 — Captured-session ingestion and device revocation should work.
 * Row: OF-409. Canon: ARCH-0061 #producers/#twoway/R2;
 * identity #authority-log. G12=B is SETTLED, no native capture/perms in this suite.
 * Oracle: voice-scenarios.capture; voice-capture-mic and voice-capture-process.
 *
 * Pair a capture producer through real public pairing and obtain its bound
 * device credential. Submit ONE bounded recording/session with separate mic
 * and process sources, stream IDs, timestamps, rates and source digests.
 * Await home-node custody/ingestion acknowledgment through HTTP+WS. Inspect
 * the produced transcript's spans: each cites the right distinct stream and
 * original blob, never a collapsed source or invented speaker confidence.
 * Use the owner to revoke that producer's capability slip (current HTTP:
 * POST /v1/core/slips/revoke {slip_id:number[32]} -> {revoked:true}).
 * Send the NEXT recording through a fresh holder proof on that revoked slip.
 * Require rejection before any upload/session/transcript addition, plus a
 * public completion boundary/read demonstrating the prior home-custody data
 * and its lineage still exist unchanged. Do not revoke the vault owner.
 *
 * Capture=device; custody=home; processing=routed setting; scope=vault. A
 * server receiving a blob alone proves neither native capture nor home sync.
 * A local replica needs two slots; this one-slot flow is a synthetic remote
 * producer to one real home server, not a second embedded writer or peer.
 * No microphone/process tap, AEC, OS permission dialog or Mac app is exercised.
 *
 * Missing: typed public captured-session upload/ingestion with distinct-source
 * and home-custody receipts, and transcript lineage read. Pairing/revocation
 * already exist; legacy device-key ceremonies and native app Tauri commands
 * are not replacements. G12 is not an unanswered question or reason to skip.
 */
suite.todo(test, "VOICE-08", "waits on typed captured-session ingestion/home-custody acknowledgment and multi-source transcript lineage (Captured-session ingestion and device revocation should work)");
