import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 2 });
afterAll(suite.flush);

/*
 * Code execution and custody. All eight IDs are complete-flow TODOs, not
 * passing partial smoke tests. suite.todo registers Bun test.todo and the
 * shared runner's BLOCKED row. No runtime capability is guessed or skipped.
 *
 * Independent inputs, expected facts, canon/registry pins and the binding
 * audit are in code-runtime-scenarios, registered by this area's manifest.
 * On activation read it with loadFixtures().readJson("code-runtime-scenarios")
 * and start a fresh EngineFixture per ID. Use the real QuickJS sandbox,
 * ScriptedProviders for external wires only, and public clients for setup.
 *
 * Public-shape audit: origin/main cf8d4ce473ddffb6bf278f11263ae0cf84461117.
 * The audited files are identical in this writer's checkout. G01 requires
 * typed HTTP and SDK calls for designed verbs; a library method, generic
 * entity write, app action or execute_code substitute does not supply one.
 * Existing code-mode browser calls are acknowledged below, not called absent.
 * No unbound verb is cast to FacadeVerb and no future REST path is invented.
 *
 * Shared MCP shapes already shipped:
 *   execute_code({schema_version, actor, consent, run_ref, task, page?, cache?})
 *     -> structuredContent {run_ref, run_id, resume, steps_run, bridge_calls,
 *          steps, result, results, resultsCount, actor, session_manifests, ...}
 *   actor = {actor_ref, actor_class, gate_actor_ref, gate_actor_class, scope}
 *   consent = {policy_ref, purpose, approval_ref?, consent_receipt_ref?,
 *              require_human_approval?}
 *   result.status = complete | waiting | yielded | hard_step_limit_reached |
 *                   window_full
 *   result.wait = {kind:"durable_wait", wait_id, effect, reason, prompt}
 *   read_result({schema_version, actor, consent, run_ref, ref, facet?, input?})
 *     -> structuredContent {run_ref, run_id, ref, facet, result, actor, meta}
 * Resolve actor metadata from the real paired actor, never fixture IDs or
 * caller claims. read_result is a read of that credential's own run only.
 * A named result is not permission to enumerate the vault's private side rows.
 *
 * Budgets remain the shared defaults: two file slots, 30s normal flow, fresh
 * authenticated vaults, Linux containment, loopback only, no downloads/retries.
 * No engine defaults changed. No build, server, test or browser ran on the Mac.
 */

/* CODE-RUNTIME-01 — Named verbs are the only write door should work.
 * Rows OF-226, OF-227, OF-314, OF-318; ARCH-0040 #mcp-actor-ceilings.
 *
 * Existing named write/read shapes:
 *   vault.claims.upsert({id?, subject_ref, predicate, value, confidence,
 *     source, ...}) -> CommitReceipt, including approval and receipt_ref
 *   vault.claims.list({subject_ref, ...}) -> scoped claim views
 * A code run's named writes bind Generated and the actor on the host, even
 * if its outer credential is human. Never use caller source as the oracle.
 *
 * Needed semantic contract: first-party Auto execution versus a foreign
 * propose-only run, with the foreign isolation tier and per-effect receipts.
 * The foreign run must READ inside its scope, acquire no raw/bulk write
 * imports, and produce proposals rather than direct host/vault mutations.
 * Its typed admission request/result are not published in HTTP/the SDK.
 * The existing execute_code credential gate requires Write and rejects a
 * propose-only slip at entry; denying the whole run cannot prove its imports
 * or proposals. Do not widen that slip to make the test execute.
 *
 * Activate with two real actors and explicit owner Auto/grant setup. Execute
 * the permitted named read/write. Run the fixture's DB, host-file, network,
 * bulk and forged-source probes separately so one trap cannot mask another.
 * Inspect the named effects, host-owned Generated/actor receipts and claim
 * readback. Require zero unreceipted mutations and zero bypass deliveries.
 * Foreign file deltas remain proposals. Test both actors, not a denial-only
 * substitute or FakeSandboxAdapter copied from the Rust integration tests.
 */
suite.todo(test, "CODE-RUNTIME-01", "waits on typed foreign propose-only code-run admission and owner Auto/grant setup (Named verbs are the only write door should work)");

/* CODE-RUNTIME-02 — Code response cleaning preserves real output should work.
 * Row OF-441; ARCH-0026 #run-tree and ARCH-0050 #tested-pointer.
 *
 * execute_code and read_result already expose the run and its named stored
 * outputs. The executor records cleaned source and real console output;
 * those reads are NOT the missing feature. Plain JavaScript is the current
 * guest language, despite older OF-441 prose saying TypeScript.
 *
 * Needed typed observation: the correction/heal attributed to its model and
 * durable turn, together with its bounded repair/failure outcome. The tally
 * is currently a private node-local code-run side row; no typed HTTP/SDK
 * correction-receipt or per-model heal-count read is published. Neither the
 * host-call steps nor model_choice is a correction receipt. Do not read the
 * side row through generic entity hydration or derive the tally from prompts.
 * Canon supplies the attribution/boundedness contract, not a new wire DTO or
 * a numeric retry law; wait for that typed projection rather than invent it.
 *
 * Configure the real executor seat at a scripted loopback provider. Return
 * a fenced script, then code plus a forged console block, then a bare valid
 * script. Inspect each cleaned source and actual executor observation using
 * named result handles. Only fixture-owned console.log output may become the
 * next model observation; invented console must not be accepted as output.
 * Raw provider evidence may be retained as untrusted evidence, NOT console.
 * Read the model-attributed correction receipt. In a separate run return
 * nested unsupported packaging and exhaust the declared repair policy: a
 * bounded explicit failure, no execution of the inner side effect, no hidden
 * mutation retry, no extra provider calls beyond that declared bound.
 */
suite.todo(test, "CODE-RUNTIME-02", "waits on typed model-attributed executor correction/heal receipts (Code response cleaning preserves real output should work)");

/* CODE-RUNTIME-03 — Durable code step resumes without repeat should work.
 * Rows OF-319, OF-320; ARCH-0026 #run-tree; ARCH-0040 #mcp-actor-ceilings.
 *
 * Existing resume shape: execute_code with the SAME run_ref/task resumes its
 * persisted run_id; a waiting result names wait_id/effect/reason/prompt.
 * Re-entry of a completed run exposes zero new steps. read_result retrieves
 * its stored source/output without entering the run or calling a model.
 *
 * Needed semantic typed call: an authorized consent answer bound to this
 * code wait/step, with a receipt for consumption and the unsettled effect's
 * current-authority decision. That HTTP/SDK call is not published.
 * POST /v1/owner/runs/approve approves a reviewed bundle of claim proposals;
 * it does not deliver a code run's SelfDurableWait reply. tasks.answer is a
 * task-input word, not effect authorization. Queue resume is not consent.
 * Never seed WaitDeliveries or call the internal replay/delivery methods.
 *
 * Run the fixture program: commit one keyed named effect, then await consent
 * for another. Observe its public waiting result AND first effect receipt
 * before restart. Approve through the missing typed wait door and re-enter
 * with identical run_ref/task. Compare stored source/results and sink attempts:
 * no completed LLM/code step or first effect repeats, even if the sink itself
 * deduplicates. Retry approval and terminal re-entry: no extra settlement.
 * Repeat the wait with the unsettled effect's grant revoked before approval;
 * current authority must prevent that effect, while the completed first step
 * and its result remain. A same-run resume is not browser-library reuse.
 */
suite.todo(test, "CODE-RUNTIME-03", "waits on typed host-authorized code-wait resolution and consumption receipts (Durable code step resumes without repeat should work)");

/* CODE-RUNTIME-04 — Three external executor shapes should work.
 * Rows OF-426, OF-385; ARCH-0026 #run-tree; ARCH-0079 #work.
 *
 * tasks.create/ask/wait and artifact reads exist, but they do not admit an
 * arbitrary BYOA connector. Needed semantic request: task/assignee plus a
 * configured connector (OpenAI-compatible endpoint, A2A attachment, restricted
 * argv-only CLI) under grants. Needed result: attempt identity, disposition,
 * attributed exhaust handle/result_ref and one settled task outcome.
 * The dispatch/configuration/exhaust HTTP/SDK DTOs are not published.
 *
 * The library's ByoaConnectorSpec has endpoint, protocol_attach and cli_sandbox.
 * ProtocolAttachKind currently admits ONLY mcp; A2A is a watch item and is
 * explicitly refused. Do not relabel an MCP fake as A2A or invent its wire.
 * Canon OF-426 acknowledges that distinction. This assigned A2A journey
 * therefore waits for a typed A2A adapter too, not an owner ruling.
 *
 * Once bound, dispatch the same fixture task through three local backends.
 * Terminate an owned executor only after its external checkpoint ACK, observe
 * abandoned/failed exhaust explicitly, resume the task in a new attempt and
 * collect each durable output through returned handles. Count attempt and
 * task outcomes separately: failure/abandonment does not finish the promise.
 * Inspect actor/connector attribution and restricted CLI egress/file grants.
 * Request a forbidden CLI access and require refusal plus captured failure,
 * no shell interpolation, credential leak or host-side execution fallback.
 */
suite.todo(test, "CODE-RUNTIME-04", "waits on typed BYOA dispatch/exhaust calls and A2A protocol attachment (Three external executor shapes should work)");

/* CODE-RUNTIME-05 — Browser connector action consent should work.
 * Rows OF-550, OF-523; ARCH-0040 #mcp-actor-ceilings; ARCH-0053 #r4b-hubs.
 *
 * Built code-mode shapes (not tools/list rows or HTTP/SDK facade calls):
 *   self.browser.open({url}) -> ObservationPage
 *   self.browser.find({role?, name?, cursor?}) -> {rows, next?, partial?}
 *   self.browser.type({ref, text, clear?}) -> ObservationPage
 *   self.browser.click({ref}) -> ObservationPage
 *   self.browser.batch({subgoal?, steps, until_ms?, no_model?}) -> BatchOutput
 * ObservationPage names url/title and receipt; BatchOutput has status,
 * completed, failed_step?, receipts? and observation?. An EffectReceipt names
 * seq/verb/url/title/target/target_name/effect_class/press/screenshot evidence.
 * Preserve these typed shapes; never invent a generic browser RPC route.
 *
 * Missing: generated typed HTTP/SDK browser calls and action-class standing
 * grant author/answer calls for per-send, reviewed-batch and no-press grants.
 * Main consumes StandingConsentGrant::Action to set browser press policy but
 * publishes no typed author/answer door for those grants. Browser takeover
 * endpoints are real; a person's input/takeover is not a consent grant.
 *
 * Activate only on the contained Linux host with the real installed browser
 * pack, verified guest connection and loopback site. Find refs in the current
 * observation, never hard-code engine refs. Exercise read and scripted sends
 * under all three explicit owner grants. Count site submissions independently
 * and inspect every effect's page/target/class/press/receipt. Exhaust a reviewed
 * batch, then request out-of-grant publish: it opens the existing Ask, delivers
 * nothing before the holder's answer and never inherits click authority from
 * read access. Every effect in a batch still has its own gate/receipt.
 */
suite.todo(test, "CODE-RUNTIME-05", "waits on typed browser HTTP/SDK calls and action-class grant author/answer doors (Browser connector action consent should work)");

/* CODE-RUNTIME-06 — Verified browser workflow reuse should work.
 * Row OF-598; ARCH-0053 #r4-lifecycle; CUA-PACK replay-library ruling.
 *
 * Built code-mode library shapes, absent from the HTTP/Oneiron SDK catalog:
 *   self.browser.library.propose({subgoal, params?, steps, postcondition, args?})
 *     -> {admitted, workflow?, refused_by?:"solved"|"replay", unmet?, replay?}
 *   self.browser.library.find({site?, subgoal?}) -> {site, workflows}
 *   self.browser.library.run({workflow, args?})
 *     -> {workflow, status:"done"|"NEEDS_AGENT"|"NEEDS_YOU", unmet?, batch}
 * postcondition is ExpectInput[]: {ref?, role?, name?, value?, absent?}.
 * G01 still requires their typed HTTP/SDK calls, not a generic execute-code
 * escape. Do not call the internal browser library store or fabricate TASKs.
 *
 * Learn on the Linux loopback site with an independently recorded submission.
 * First show that model-authored done without that success cannot admit a
 * workflow; also refuse a solved candidate whose no-model replay fails.
 * Admit the successful parameterized program only after independent success
 * AND a successful model-free validation replay. Reuse with a second argument:
 * a new live submission, no provider calls inside replay, still gated effects.
 * Reusing old bridge answers is not this proof. Change the site's required
 * field/button and success predicate, then replay: no false done or claimed
 * success, explicit unmet pre/postcondition and handback to the planner.
 * Count validation replays separately from reuse and inspect durable library
 * handles. The normal standing grant is never expanded by learning/replay.
 */
suite.todo(test, "CODE-RUNTIME-06", "waits on typed self.browser.library.propose/find/run HTTP and SDK calls (Verified browser workflow reuse should work)");

/* CODE-RUNTIME-07 — Graph filesystem scope and pushdown should work.
 * Rows OF-355, OF-324; ARCH-0050 #tested-pointer; ARCH-0004 #access.
 *
 * Canon's typed semantic door is mount(ref), ref = live head | fork hash |
 * repo snapshot. It returns the scoped file/query face at that reference;
 * list/read/search/coreutils preserve that scope and pinned walk throughout.
 * Its HTTP/SDK/MCP/CLI binding is not published; do not invent its DTO fields.
 *
 * GET /v1/owner/graph-fs DOES exist, with query
 *   {path, op?:ls|cat|head|wc|find|grep|readlink, cursor?, pattern?, recursive?,
 *    by_time?, newer_than?, lines?}
 *   -> {path, output, encoding:"utf8"|"base64", next_cursor?, plan?}
 * That owner-only current tree has no mount/ref parameter; it is not the
 * assigned actor-scoped historical mount. The guest's nine graph-FS imports
 * are not linked. Generic cli api raw is not a designed mount CLI binding.
 *
 * Publicly create visible and owner-excluded project content, capture old
 * tested reference, edit the visible content and mount each named ref. Compare
 * cat/ls/find/grep/head/wc and structured reads against the authored files and
 * counts. Check old bytes remain old, current bytes are new, and one paged walk
 * never changes its ref. Attempt ../ traversal and search for the private
 * marker. Hidden entries, counts and snippets must match an absent control;
 * out-of-scope-but-known may be labelled, OWNER-EXCLUDED must be wholly absent.
 * Check equivalent filtered results for pushdown and ordinary reads, not a
 * timing benchmark or an engine-derived expected query plan.
 */
suite.todo(test, "CODE-RUNTIME-07", "waits on typed mount(ref) and historical actor-scoped graph-FS MCP/CLI bindings (Graph filesystem scope and pushdown should work)");

/* CODE-RUNTIME-08 — Code history diff blame and authenticated regen should work.
 * Rows OF-315, OF-316, OF-320, OF-321, OF-323; ARCH-0050 #tested-pointer;
 * identity #authority-log. Code is born from a prompt, then authored.
 *
 * Existing generated HTTP/SDK calls:
 *   vault.code.diff({before:{repo,path,revision_ref?}, after:{repo,path,revision_ref?}})
 *     -> CodeDiffView | null {before, after, changes, rendered}
 *   vault.code.blame({repo,path,revision_ref?})
 *     -> CodeBlameView | null {at, units}
 * Each change has path/symbol/before?/after?/inserted_by/deleted_by; each
 * operation has operation_ref/sequence/session_ref/actor_ref/actor_class and
 * optional turn_ref/activity_ref/intent_ref/model_ref/reasoning_effort.
 * Diff/blame are built; their absence is NOT this TODO's reason.
 *
 * Needed typed HTTP/SDK doors: admit/authenticate the two actors' file edits
 * and birth prompts, inspect revision history, counter-append a revert and
 * propose regeneration from the authenticated tested frontier. The catalog
 * exposes code review reads, not these writes/history/regen calls. Office
 * body.edit, blob version append, structural.put and generic vault.batch are
 * not native code-document substitutes. Do not seed CodeRevision/frontier.
 *
 * Create the fixture code through the real authoring door; actor A edits from
 * prompt A, actor B from prompt B. Diff the returned tested revision refs and
 * inspect blame by operation/content, including actor, session, turn/activity,
 * intent and model where generated. Revert to the first tested state: a NEW
 * revision/head with the old content, while all prior versions and receipts
 * remain readable and attributable. A later edit needs no birth-prompt edit.
 * Submit the forged history/frontier through the future typed regen request:
 * refuse unauthenticated input, no model dispatch or head move. A legitimate
 * regeneration is a declared rewrite proposal, preserves authored history,
 * and cannot silently supersede higher-authority human truth. Lens behavior
 * changes, especially data-read changes, require their normal human stamp;
 * text equality is not behavior-diff approval or authenticated regeneration.
 */
suite.todo(test, "CODE-RUNTIME-08", "waits on typed code authoring/history, counter-append revert and authenticated regeneration calls (Code history diff blame and authenticated regen should work)");
