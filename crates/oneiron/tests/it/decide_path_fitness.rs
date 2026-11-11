//! DECIDE-PATH (owner, 2026-10-16): `decide()` under `crates/oneiron/src/llm/decision/` is the one
//! required path for typed model decisions, as Grant/Scope is for permissions. A typed decision is
//! a model answer the code reads as a choice from closed labels, a yes/no or a score on a fixed
//! scale, and then acts on. Generation (free text, extraction, agent loops) stays out.
//!
//! No mechanical signal tells the two apart at a call site (`generate` and `call_as_step` serve
//! both), so every model call outside `llm/decision/` is pinned here with what it does.
//! [`BYPASSES`] are typed decisions made another way; the list only shrinks as surfaces move into
//! `decide()`. [`OUTSIDE`] is everything else, which stays out. A host seam that a model can sit
//! behind (a `*Judge`, `*Classifier`, `*Scorer`, `*Checker`, `*Critic` or `*Grader` trait, or one
//! named in [`SEAM_TRAITS`] / [`SEAM_STRUCTS`]) is pinned by its declaration the same way.
//!
//! Pins match the call's trimmed line text, as OF-060 F2 does, so unrelated edits above a call do
//! not move them; a line that occurs twice is pinned twice. A failure prints each hit's `file:line`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::common::source_scan::{
    SourceTree, is_ident_byte, is_ident_start, normalized, production_source,
};

/// Methods that reach a model, called as `x.name(` or through a raw-seam trait path
/// (`LlmBackend::generate(`): the raw seam, the server's offer ladder and the BEAM transport.
const MODEL_METHODS: &[&str] = &["generate", "generate_while", "stream", "invoke_with_lease"];
/// Free fns that reach a model, under any path: the durable-step wrappers and the
/// interface-bench transport.
const MODEL_FNS: &[&str] = &[
    "call_as_step",
    "call_as_step_checked",
    "call_as_step_with_fallbacks",
    "call_openrouter",
];
/// Methods that reach a model only inside one tree: BEAM's model session.
const SCOPED_METHODS: &[(&str, &str)] = &[
    ("invoke", "crates/oneiron-bench/src/beam/"),
    ("invoke_capped", "crates/oneiron-bench/src/beam/"),
];

const SEAM_SUFFIXES: &[&str] = &[
    "Judge",
    "Classifier",
    "Scorer",
    "Checker",
    "Critic",
    "Grader",
];
const SEAM_TRAITS: &[&str] = &[
    "ReviewNotes",
    "AttributionNotes",
    "SeatNotes",
    "DescriptionNotes",
    "AutoCheckNotes",
    "HeldOutReplayNotes",
];
const SEAM_STRUCTS: &[&str] = &[];

/// The one path every typed decision takes.
const DECIDE_DIR: &str = "crates/oneiron/src/llm/decision/";
/// Adapter crates implement the raw seam; they never choose what to ask.
const ADAPTER_PREFIX: &str = "crates/oneiron-llm-";

/// The length of [`BYPASSES`]. Lower it as a surface moves into `decide()`; never raise it.
const BYPASS_CEILING: usize = 0;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Edge {
    path: String,
    needle: String,
    line: String,
}

struct Pin {
    path: &'static str,
    needle: &'static str,
    line: &'static str,
    what: &'static str,
}

const fn pin(
    path: &'static str,
    needle: &'static str,
    line: &'static str,
    what: &'static str,
) -> Pin {
    Pin {
        path,
        needle,
        line,
        what,
    }
}

/// Typed decisions made outside `decide()`. Each one leaves this list when its surface moves.
const BYPASSES: &[Pin] = &[];

/// Model calls and seams that are not typed decisions. They stay outside `decide()`.
const OUTSIDE: &[Pin] = &[
    pin(
        "crates/oneiron-bench/src/beam/llm_judge.rs",
        "invoke_with_lease",
        "let (answer, cost) = session.invoke_with_lease(",
        "eval judge: fixed model for comparability (BEAM answer 0, 0.5 or 1 against gold)",
    ),
    pin(
        "crates/oneiron-bench/src/interface_bench/wire_and_scoring.rs",
        "call_openrouter",
        "let response = call_openrouter(",
        "eval judge: fixed model for comparability (interface-bench browse grades, 1 to 5)",
    ),
    pin(
        "crates/oneiron-bench/src/beam/llm_host.rs",
        "generate",
        ".block_on(self.backend.generate(request, &lease))",
        "BEAM transport under both the judge and answer generation",
    ),
    pin(
        "crates/oneiron-bench/src/beam/llm_host.rs",
        "invoke_with_lease",
        "self.invoke_with_lease(pin, purpose, system, user, None)",
        "BEAM invoke, the answer-generation entry",
    ),
    pin(
        "crates/oneiron-bench/src/beam/model_scaffold.rs",
        "invoke_capped",
        "session.invoke_capped(pin, CallPurpose::AnswerGen, prompt, &input)",
        "BEAM benchmark answer",
    ),
    pin(
        "crates/oneiron-bench/src/beam/model_scaffold/context.rs",
        "invoke_capped",
        "session.invoke_capped(pin, CallPurpose::AnswerGen, prompt, &input)?;",
        "BEAM trajectory-only arm: the reader's own working step",
    ),
    pin(
        "crates/oneiron-bench/src/beam/model_scaffold.rs",
        "invoke",
        "let (query, cost) = session.invoke(",
        "BEAM agentic retrieval query",
    ),
    pin(
        "crates/oneiron-bench/src/beam/scorer.rs",
        "trait BeamScorer",
        "pub(super) trait BeamScorer {",
        "BEAM fixed metric scorer, no model",
    ),
    pin(
        "crates/oneiron-ffi/build.rs",
        "generate",
        ".generate()?",
        "bindings generator in a build script, no model",
    ),
    pin(
        "crates/oneiron-model/src/llm/image.rs",
        "generate",
        "None if row.generate => adapter.generate(intent, lease).await?,",
        "image generation",
    ),
    pin(
        "crates/oneiron-server/src/models/declared.rs",
        "generate",
        ".generate(&self.admission, request, Some(selector))",
        "declared run: the offer ladder under a caller",
    ),
    pin(
        "crates/oneiron-server/src/models/run_backend.rs",
        "generate",
        "Box::pin(self.ladder.generate(&self.run, request, None))",
        "run backend forwarding to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/models/run_backend.rs",
        "stream",
        "self.ladder.stream(&self.run, request, None)",
        "run backend stream forwarding to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/voice_host/extraction.rs",
        "generate",
        ".generate(request, lease.lease.as_ref().ok_or(HostError::Stopped)?),",
        "voice entity labels and salient terms (extraction)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs",
        "call_as_step",
        "let outcome = call_as_step(step_ctx, call.backend, self.guard, request).await;",
        "consolidation merged value: the claim value a decided merge or supersede writes (generation)",
    ),
    pin(
        "crates/oneiron/src/ingest/docs_import.rs",
        "trait DocsInjectionClassifier",
        "pub trait DocsInjectionClassifier {",
        "docs import: an injection annotation stored as data, never read as a label",
    ),
    pin(
        "crates/oneiron/src/llm/run_admission/admission.rs",
        "generate",
        "match gated.generate(call.request.clone(), permit.lease()).await {",
        "run admission: the gated call under a run's permit",
    ),
    pin(
        "crates/oneiron/src/llm/step/execute.rs",
        "call_as_step_with_fallbacks",
        "call_as_step_with_fallbacks(",
        "durable step: call_as_step is the form with no fallbacks",
    ),
    pin(
        "crates/oneiron/src/llm/tagger.rs",
        "call_as_step",
        "Some(super::call_as_step(ctx, backend, guard, request).await?)",
        "tagger render (extraction)",
    ),
    pin(
        "crates/oneiron/src/saved_query/decisions.rs",
        "generate",
        ".generate(request, binding.lease)",
        "saved-query membership note: the why a decided verdict keeps (generation)",
    ),
    pin(
        "crates/oneiron/src/critic/review/questions.rs",
        "trait ReviewNotes",
        "pub trait ReviewNotes {",
        "critic notes: evidence refs and a suggested edit beside a decided review (generation)",
    ),
    pin(
        "crates/oneiron/src/skill_attribution/judge.rs",
        "trait AttributionNotes",
        "pub trait AttributionNotes {",
        "attribution notes: why a doubtful hunk is unclear, beside a decided attribution (generation)",
    ),
    pin(
        "crates/oneiron/src/llm/seat/decisions.rs",
        "trait SeatNotes",
        "pub trait SeatNotes: Send + Sync {",
        "seat notes: the receipt's why beside a decided seat pick (generation)",
    ),
    pin(
        "crates/oneiron/src/llm/routing/decisions.rs",
        "trait DescriptionNotes",
        "pub trait DescriptionNotes {",
        "route notes: a routed seat's receipt reason beside its decided grade (generation)",
    ),
    pin(
        "crates/oneiron/src/skill_optimize/gate/basis.rs",
        "trait HeldOutReplayNotes",
        "pub trait HeldOutReplayNotes {",
        "skill replay notes: replays, response pairs, objectives and metered person-time beside decided scores, preferences, findings and tradeoffs (evidence)",
    ),
    pin(
        "crates/oneiron-agent-runtime/src/code_sandbox/wasmtime_runtime/wire.rs",
        "stream",
        "if !admitted(cancel, || host.write_output(target.stream(), &frame))? {",
        "sandbox output frame target: a console/file stream tag for host.write_output, no model",
    ),
    pin(
        "crates/oneiron-bench/src/infer/measure.rs",
        "stream",
        ".stream(request, lease)",
        "infer bench timing harness: streams the caller request to Done and records timings",
    ),
    pin(
        "crates/oneiron-bench/src/infer/native.rs",
        "generate",
        ".generate(id, &transport.epoch, transport.shape(body))",
        "infer bench native arm: the generate op over codec v1 to an external EXL3 worker",
    ),
    pin(
        "crates/oneiron-bench/src/interface_bench/eval_run.rs",
        "call_openrouter",
        "let response = call_openrouter(api_key, &messages, 900, &row.request_nonce, settings)?;",
        "interface-bench answer generation",
    ),
    pin(
        "crates/oneiron-broker/src/serve.rs",
        "stream",
        ".stream(",
        "credential broker: streams the checked provider reply for a streaming shape",
    ),
    pin(
        "crates/oneiron-model/src/llm/backend.rs",
        "generate",
        "self.generate(request, lease)",
        "raw seam defaults: generate_sourced and generate_bound forward to generate",
    ),
    pin(
        "crates/oneiron-model/src/llm/backend.rs",
        "generate",
        "self.generate(request, lease)",
        "raw seam defaults: generate_sourced and generate_bound forward to generate",
    ),
    pin(
        "crates/oneiron-model/src/llm/backend.rs",
        "stream",
        "self.stream(request, lease)",
        "raw seam default: stream_bound forwards to stream",
    ),
    pin(
        "crates/oneiron-model/src/llm/media/backend.rs",
        "generate",
        "self.0.generate(intent, lease).await?",
        "image generation through the image backend for a reference-less media call",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/coach_health.rs",
        "generate",
        ".block_on(call.ladder.generate(&run, call.request, None))",
        "Coach agent-health draft: diagnosis, route and proposal filed on the card for owner approval",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/coach_host/weave_digest_settings.rs",
        "generate",
        "let answer = models.generate(",
        "Coach digest settings draft through the hub skill; the rule decides on refusal",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/compaction/serve.rs",
        "generate",
        ".block_on(call.ladder.generate(&run, call.request, None))",
        "compaction summary and handoff",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer/request_sources.rs",
        "generate",
        "Box::pin(self.ladder.generate(&self.run, request, None))",
        "Dreamer sourced route: generate forwarding to the ladder on the call run",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer/request_sources.rs",
        "stream",
        "self.ladder.stream(&self.run, request, None)",
        "Dreamer sourced routes: stream forwarding to the ladder on the call or role run",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer/request_sources.rs",
        "stream",
        "self.ladder.stream(&self.run, request, None)",
        "Dreamer sourced routes: stream forwarding to the ladder on the call or role run",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer/request_sources.rs",
        "stream",
        "self.realization.ladder.stream(&self.run, request, None)",
        "Dreamer realization call: stream forwarding on the run bound to its rows",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer_thing/profile.rs",
        "generate",
        "let generated = self.inner.generate(request, lease).await;",
        "served agent generation: counted generate forwarding to the route backend",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/dreamer_thing/profile.rs",
        "stream",
        "let inner = self.inner.stream(request, lease)?;",
        "served agent generation: counted stream forwarding to the route backend",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/eval_measurement.rs",
        "generate",
        "let (answer, served, serving_offer) = match arms.generate(",
        "paired eval leg: the arm answer text, scored blind afterwards",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/eval_measurement.rs",
        "generate",
        "match arms.generate(self.server, self.judge, &self.run, arm, task, &self.clock) {",
        "seat-native eval leg: embedder/tagger inference or ladder Choice, fixed-code scored",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/hook_regen.rs",
        "generate",
        ".generate(",
        "hook regen: the new body.js drafted on the Coach seat",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/skill_author.rs",
        "generate",
        ".generate(",
        "Coach repair drafts (environment, prompt, producer fix): a proposal or a decline",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/skill_author.rs",
        "generate",
        ".generate(",
        "Coach repair drafts (environment, prompt, producer fix): a proposal or a decline",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/skill_author.rs",
        "generate",
        ".generate(",
        "Coach repair drafts (environment, prompt, producer fix): a proposal or a decline",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/turn_program_host.rs",
        "generate",
        "self.0.backend().generate(request, lease)",
        "turn program backend: generate forwarding to the provider backend",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/turn_program_host.rs",
        "stream",
        "self.0.backend().stream(request, lease)",
        "turn program backend: stream forwarding to the provider backend",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/waves.rs",
        "generate",
        ".generate(",
        "wave plan: task list JSON cut by the planner agent definition",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/weave_lens.rs",
        "generate",
        ".generate(&run, step.clone(), None)",
        "live weave lens render through the weave-report skill",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat/compaction/seeds.rs",
        "stream",
        "return recorder.stream(run, admitted);",
        "chat reply stream without a live prefix: the admitted call alone",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat/compaction/seeds.rs",
        "stream",
        "return recorder.stream(today_run, today);",
        "chat reply stream with no headroom: today call alone",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat/compaction/seeds.rs",
        "stream",
        "match recorder.stream(run, admitted) {",
        "chat reply stream: the captured rung first, today call behind it",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat/compaction/seeds.rs",
        "stream",
        "recorder.stream(today_run, today)",
        "chat reply stream: today call after the captured rung gave way",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat/compaction/seeds.rs",
        "stream",
        "match recorder.stream(&run, today) {",
        "chat reply stream: today leg after the live leg failed silent",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/vision.rs",
        "generate",
        ".generate(&run, admitted.request, None)",
        "ask_image free-text answer on the Local-vision seat; Box/Point uses the ladder",
    ),
    pin(
        "crates/oneiron-server/src/api/anonymous_chat.rs",
        "generate",
        "match backend.generate(request.clone(), permit.lease()).await {",
        "anonymous chat: one gated attempt on a private meter, fallback on proved fault",
    ),
    pin(
        "crates/oneiron-server/src/api/booking/free_text.rs",
        "generate",
        ".generate(&self.run, admitted.request, None)",
        "booking parse seat: the role call forwarded under the off-topic decide",
    ),
    pin(
        "crates/oneiron-server/src/api/facade/content_policy_doors.rs",
        "generate_while",
        ".generate_while(&run, call.request, None, &|| {",
        "policy Checker seat: the role call forwarded while the credential stays live",
    ),
    pin(
        "crates/oneiron-server/src/api/facade/model_stream_doors.rs",
        "stream",
        "let source = match ladder.stream(&run, input.request, None) {",
        "model stream door: the admitted raw stream opened for subscribers",
    ),
    pin(
        "crates/oneiron-server/src/api/memory_reason/host/call.rs",
        "generate",
        "self.generate(role, request, pins, budget, None)",
        "memory reason JSON call: caller-schema request through the generate helper",
    ),
    pin(
        "crates/oneiron-server/src/api/memory_reason/host/call.rs",
        "generate",
        "let response = backend.generate(request, permit.lease()).await?;",
        "memory reason anonymous leg: the gated offer call on its own permit",
    ),
    pin(
        "crates/oneiron-server/src/api/memory_reason/host/mod.rs",
        "generate",
        "self.generate(ModelRole::Reranker, request, pins, token_budget, Some(line))?;",
        "memory reason rerank scores: retrieval ranking, not a typed question",
    ),
    pin(
        "crates/oneiron-server/src/api/openai_proxy/choices.rs",
        "generate",
        "return ladder.generate(run, request, None).await;",
        "openai proxy: one choice with no deadline, straight to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/api/openai_proxy/choices.rs",
        "generate",
        "let first = clock.generate(ladder, run, request.clone()).await?;",
        "openai proxy: first choice, its own admitted call on the run",
    ),
    pin(
        "crates/oneiron-server/src/api/openai_proxy/choices.rs",
        "generate",
        "rest.push(clock.generate(ladder, run, request.clone()).await?);",
        "openai proxy: each later choice, its own admitted call on the run",
    ),
    pin(
        "crates/oneiron-server/src/commands/hook_regen.rs",
        "generate_while",
        "response = call.ladder.generate_while(&run, call.request, None, &may_send) =>",
        "hook regeneration body text from the configured wording and binding",
    ),
    pin(
        "crates/oneiron-server/src/mcp/live_lease_backend.rs",
        "generate",
        "let generated = self.inner.generate(request, lease);",
        "live lease backend: generate after the leases look, booked again after",
    ),
    pin(
        "crates/oneiron-server/src/mcp/live_lease_backend.rs",
        "stream",
        "self.inner.stream(request, lease)",
        "live lease backend stream: the leases look, then the inner stream",
    ),
    pin(
        "crates/oneiron-server/src/models/broker_responses.rs",
        "generate",
        "self.0.generate(request, lease)",
        "buffered chat generate forwarding to the broker chat backend",
    ),
    pin(
        "crates/oneiron-server/src/models/broker_responses.rs",
        "generate",
        "let response = self.0.generate(request, lease).await?;",
        "buffered chat stream: one chat generate buffered as a single Done",
    ),
    pin(
        "crates/oneiron-server/src/models/broker_responses.rs",
        "generate",
        "return self.chat.generate(request, lease).await;",
        "broker responses generate fallback to chat when Responses cannot carry",
    ),
    pin(
        "crates/oneiron-server/src/models/broker_responses.rs",
        "generate",
        "let response = chat.generate(request, lease).await?;",
        "broker responses stream fallback: buffered chat generate as one Done",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder/cache_warmth.rs",
        "generate",
        "match gate.generate(bound, permit.lease()).await {",
        "live fork warm send: one gated attempt on the picked rung while warm",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder/generation.rs",
        "generate_while",
        "self.generate_while(run, request, selector, &|| true).await",
        "offer ladder: generate is generate_while with no stop",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder/sends.rs",
        "stream",
        "super::streamed_generation::response(gate.stream(bound, permit.lease())?).await",
        "offer ladder: one gated stream collected as the generated reply",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder/sends.rs",
        "generate",
        "gate.generate(bound, permit.lease()).await",
        "offer ladder: one gated generate in the rung send",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder/sends.rs",
        "stream",
        "let ended = match gate.stream(call, permit.lease()) {",
        "offer ladder: one gated stream",
    ),
    pin(
        "crates/oneiron-server/src/models/native_exl3/mod.rs",
        "stream",
        "Ok(self.shaping.stream(route, request, lease))",
        "native stream over the supervised channel, shaped as HTTP would send",
    ),
    pin(
        "crates/oneiron-server/src/models/native_exl3/mod.rs",
        "stream",
        "Ok(self.shaping.stream(route, request, lease))",
        "native stream over the supervised channel, shaped as HTTP would send",
    ),
    pin(
        "crates/oneiron-server/src/models/raw.rs",
        "generate",
        "return ladder.generate(&run, request, None).await;",
        "injected runs: raw backend forwarding to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/models/raw.rs",
        "stream",
        "return ladder.stream(&run, request, None);",
        "injected runs: raw stream forwarding to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/models/responses_socket.rs",
        "generate",
        ".generate(request, lease)",
        "responses sockets: chat generate fallback when no socket carries the call",
    ),
    pin(
        "crates/oneiron-server/src/models/responses_socket.rs",
        "generate",
        ".generate(request, lease)",
        "responses sockets: chat generate fallback when no socket carries the call",
    ),
    pin(
        "crates/oneiron-server/src/models/responses_socket.rs",
        "stream",
        "return self.chat.stream(request, lease).map(chat_stream_metadata);",
        "responses sockets: chat stream when Responses cannot carry",
    ),
    pin(
        "crates/oneiron-server/src/models/responses_socket.rs",
        "stream",
        "None => self.chat.stream(request, lease).map(chat_stream_metadata),",
        "responses sockets: chat stream fallback when no socket opens",
    ),
    pin(
        "crates/oneiron-server/src/runtime/seat_login.rs",
        "stream",
        "stdout: stdout.stream(deadline)?,",
        "official seat stdout drain to a spooled stream, no model",
    ),
    pin(
        "crates/oneiron-server/src/runtime/seat_login.rs",
        "stream",
        "stderr: stderr.stream(deadline)?,",
        "official seat stderr drain to a spooled stream, no model",
    ),
    pin(
        "crates/oneiron-server/src/saved_query_sweep.rs",
        "generate",
        "Ok(request) => self.inner.generate(request, lease),",
        "saved query judge: admitted generate on the run backend under decide",
    ),
    pin(
        "crates/oneiron-server/src/saved_query_sweep.rs",
        "stream",
        "self.inner.stream(self.admit(request)?, lease)",
        "saved query judge: admitted stream on the run backend under decide",
    ),
    pin(
        "crates/oneiron-server/src/server/live_runs/model_request.rs",
        "generate",
        "let answer = backend.generate(request, provider.lease()).await;",
        "live run repo model call: the attached callers messages on native backend",
    ),
    pin(
        "crates/oneiron-server/src/server/reader_runner/child.rs",
        "generate",
        "backend.generate(request, lease),",
        "reader summary: one generate of member texts, stored as the finding",
    ),
    pin(
        "crates/oneiron-server/src/server/recall_rerank.rs",
        "generate_while",
        "ladder.generate_while(&run, call.request, None, &may_send),",
        "paid recall rerank scores: retrieval ranking, not a typed question",
    ),
    pin(
        "crates/oneiron-server/src/server/resident_pump/pattern_launch.rs",
        "generate",
        ".block_on(self.backend.generate(request, &self.lease))",
        "pattern team start: leader and member briefings plus axis from skill",
    ),
    pin(
        "crates/oneiron-server/src/server/space_move.rs",
        "generate",
        ".block_on(call.ladder.generate(&run, call.request, None))",
        "space probe query: one short retrieval query for the candidate check",
    ),
    pin(
        "crates/oneiron-server/src/server/space_move/repo_index_derivation.rs",
        "generate",
        ".block_on(call.ladder.generate(&run, call.request, None))",
        "derived index caption: one or two sentences from masked sources",
    ),
    pin(
        "crates/oneiron-server/src/voice_host/backend.rs",
        "generate",
        "ladder.generate(&self.run, request, None).await",
        "voice call backend generate forwarding to the serving ladder",
    ),
    pin(
        "crates/oneiron-server/src/voice_host/backend.rs",
        "stream",
        "ladder.stream(&self.run, request, None)",
        "voice call backend stream forwarding to the serving ladder",
    ),
    pin(
        "crates/oneiron/src/autoreason_campaign/archive.rs",
        "trait ArchiveCellJudge",
        "pub trait ArchiveCellJudge {",
        "autoreason archive: cell-placement seam; the only impl replays a receipted judgment, no model",
    ),
    pin(
        "crates/oneiron/src/booking/constraint/parse.rs",
        "generate",
        ".generate(",
        "booking front: the schedule extraction for a turn the off-topic question kept (generation)",
    ),
    pin(
        "crates/oneiron/src/claim_check.rs",
        "trait AutoCheckNotes",
        "pub trait AutoCheckNotes: Send + Sync {",
        "auto-check notes: a decided hold's receipt reasons (generation)",
    ),
    pin(
        "crates/oneiron/src/code_run/contribution.rs",
        "trait ContributionForkScorer",
        "pub trait ContributionForkScorer {",
        "contribution replay: host scorer seam; the pass bool is the replay judge's ladder answer, or undecided",
    ),
    pin(
        "crates/oneiron/src/code_run/contribution/generation.rs",
        "generate",
        "let Some(response) = self.model.generate(request, &rung, self.clock)? else {",
        "contribution replay: one fork's answer from the capsule's own model, kept as a receipt before scoring",
    ),
    pin(
        "crates/oneiron/src/dispatch_byoa/dispatcher.rs",
        "generate",
        "let response = backend.generate(request, lease).await.map_err(|error| {",
        "foreign-agent transcript for a dispatched run",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/follower_attempt/mod.rs",
        "call_as_step_checked",
        "let (response, memoized) = match call_as_step_checked(",
        "follower suffix readings: each asked span linked to one of its entity candidates (extraction)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/follower_attempt/mod.rs",
        "call_as_step_checked",
        "match call_as_step_checked(&step, leg.call.backend, self.guard, request, &check).await {",
        "follower keyframe fold: one partial summary over a group of parts (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/nightly_merge.rs",
        "call_as_step_checked",
        "let (response, binding) = match call_as_step_checked(",
        "nightly narrative: the merge's arc summary text over child proposals (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/note_review.rs",
        "call_as_step_checked",
        "let response = match call_as_step_checked(",
        "note review extraction: beliefs, people, a topic key and a 0-1 importance kept on the review record (extraction)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/person_about.rs",
        "call_as_step_checked",
        "let (response, binding) = match call_as_step_checked(",
        "person about: the one-line person summary from live facts (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/resident_dream.rs",
        "call_as_step_checked",
        "let (response, binding) = match call_as_step_checked(",
        "resident dreaming: one diary entry plus optional craft notes (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/resident_for_human.rs",
        "call_as_step",
        "let response = match call_as_step(&step_ctx, model.backend, model.guard, request).await {",
        "free time for human: suggestion, note and own-time choice from the agent's records (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt.rs",
        "call_as_step_checked",
        "let response = match call_as_step_checked(",
        "scope summary: one sitting's summary body under the host instruction (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_compose.rs",
        "call_as_step_checked",
        "call_as_step_checked(&step_ctx, self.backend, self.guard, request, &check).await;",
        "arc composition: cited summary lines over sittings, reopening turns it names (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_open_backend.rs",
        "generate",
        "self.inner.generate(request, lease).await",
        "arc openings probe: freshness-observing forward to the inner backend",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_open_backend.rs",
        "stream",
        "self.inner.stream(request, lease)",
        "arc openings probe: stream forwarding to the inner backend",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/arc_review.rs",
        "call_as_step_checked",
        "call_as_step_checked(step_ctx, self.backend, self.guard, request, &check).await;",
        "arc parts: one compose or review call over a part's lines and cells (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt/chunks.rs",
        "call_as_step_checked",
        "call_as_step_checked(&step_ctx, self.backend, self.guard, request, &check).await;",
        "paged sitting: one page's summary lines over raw turn text (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/sieve_attempt/audit.rs",
        "call_as_step_checked",
        "match call_as_step_checked(&step, call.backend, self.guard, request, &check).await {",
        "sieve window audit: dates and names spotted in an unflagged range (extraction)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/task_realize.rs",
        "call_as_step_checked",
        "let (response, binding) = match call_as_step_checked(",
        "task realization: a Dreamer-lane TASK answered as a research NOTE (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/weave_lens.rs",
        "call_as_step",
        "match call_as_step(step_ctx, backend, model.guard, request).await {",
        "weave lens: one period render step under the weave-report skill (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_runner/maintenance/compaction_check.rs",
        "call_as_step",
        "let outcome = call_as_step(&step_ctx, model.backend, model.guard, request).await;",
        "compaction check diagnostic: conflicts and reason; the ladder types the verdict when the host lends decisions",
    ),
    pin(
        "crates/oneiron/src/dreamer_wake/program.rs",
        "call_as_step",
        "slot = Some(call_as_step(&ctx, self.inner, self.meter, request).await);",
        "turn program: the executor's model calls run as durable steps on the program meter",
    ),
    pin(
        "crates/oneiron/src/entity_doc/review_explainer/run.rs",
        "generate",
        "let response = route.backend.generate(request, &lease).await?;",
        "review explainer: per-fork explanations plus a diagram over the pending set (generation)",
    ),
    pin(
        "crates/oneiron/src/llm/step/retry.rs",
        "generate",
        "match backend.generate(request.clone(), lease).await {",
        "durable step: the raw call under every step, with its transport retries",
    ),
    pin(
        "crates/oneiron/src/policy_model/decide/checked.rs",
        "generate",
        "let reply = self.backend.generate(request, lease).await;",
        "safeguard reads: reply-checking forward to the decision backend",
    ),
    pin(
        "crates/oneiron/src/policy_model/decide/checked.rs",
        "stream",
        "self.backend.stream(request, lease)",
        "safeguard reads: stream forwarding to the decision backend",
    ),
    pin(
        "crates/oneiron/src/policy_model/notes.rs",
        "generate",
        "let response = match tokio::time::timeout(left, backend.generate(request, lease)).await {",
        "policy rationale notes: rule ids, confidence and rationale beside a decided policy read (generation)",
    ),
    pin(
        "crates/oneiron/src/recovery/checkpoint/artifact/sink.rs",
        "stream",
        "let image = sink.stream(IMAGE_STREAM, &mut &image[..])?;",
        "checkpoint writer: byte stream sealed into the artifact, no model",
    ),
    pin(
        "crates/oneiron/src/recovery/checkpoint/artifact/sink.rs",
        "stream",
        "let entry = sink.stream(stream, &mut open_body(index)?)?;",
        "checkpoint writer: byte stream sealed into the artifact, no model",
    ),
    pin(
        "crates/oneiron/src/recovery/checkpoint/artifact/sink.rs",
        "stream",
        "payload_streams.push(sink.stream(stream, &mut bytes.as_slice())?);",
        "checkpoint writer: byte stream sealed into the artifact, no model",
    ),
    pin(
        "crates/oneiron/src/recovery/checkpoint/payload/restore.rs",
        "stream",
        "let bytes = sealed.stream(stream)?;",
        "checkpoint restore: byte stream read back from the sealed payload, no model",
    ),
    pin(
        "crates/oneiron/src/recovery/checkpoint/payload/restore.rs",
        "stream",
        "let bytes = sealed.stream(stream)?;",
        "checkpoint restore: byte stream read back from the sealed payload, no model",
    ),
    pin(
        "crates/oneiron/src/test_doors/wake_d1_park_release.rs",
        "call_as_step",
        "let outcome = crate::llm::call_as_step(&ctx, backend, &guard, request)",
        "test door: a supplied backend run through the production paid-step writer (test-only)",
    ),
    pin(
        "crates/oneiron/src/test_doors/wake_d1_park_release.rs",
        "call_as_step",
        "let outcome = crate::llm::call_as_step(&ctx, backend, &guard, request)",
        "test door: a supplied backend run through the production paid-step writer (test-only)",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate lives under crates/oneiron")
        .to_path_buf()
}

fn scanned(rel: &str) -> bool {
    !rel.starts_with(DECIDE_DIR) && !rel.starts_with(ADAPTER_PREFIX) && !rel.contains("/vendor/")
}

fn line_of(source: &str, at: usize) -> usize {
    source.as_bytes()[..at]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn seam_name(keyword: &str, name: &str) -> bool {
    match keyword {
        "trait" => {
            SEAM_TRAITS.contains(&name) || SEAM_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
        }
        "struct" => SEAM_STRUCTS.contains(&name),
        _ => false,
    }
}

/// Whether the identifier at `start..end` calls a model: a method call, a raw-seam trait path
/// call or a wrapper fn call, never a declaration or `SigningKey::generate(`.
fn model_call(rel: &str, masked: &str, start: usize, end: usize) -> bool {
    let name = &masked[start..end];
    let method = MODEL_METHODS.contains(&name)
        || SCOPED_METHODS
            .iter()
            .any(|(scoped, tree)| *scoped == name && rel.starts_with(*tree));
    let free = MODEL_FNS.contains(&name);
    if !(method || free) || !masked[end..].trim_start().starts_with('(') {
        return false;
    }
    let before = masked[..start].trim_end();
    if before.ends_with('.') {
        method
    } else if let Some(path) = before.strip_suffix("::") {
        let qualifier = path.trim_end().trim_end_matches('>');
        free || (method && trailing_ident(qualifier).ends_with("Backend"))
    } else {
        free && trailing_ident(before) != "fn"
    }
}

fn trailing_ident(text: &str) -> &str {
    let start = text
        .char_indices()
        .rev()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(0, |(at, c)| at + c.len_utf8());
    &text[start..]
}

/// Every model call and seam declaration in one file, with its 1-based line.
fn file_edges(rel: &str, source: &str) -> Vec<(Edge, usize)> {
    let masked = production_source(source);
    let lines = source.lines().collect::<Vec<_>>();
    let edge = |needle: &str, at: usize| {
        // Offsets match the masked text, but its literal stripping can drop a newline after a
        // `\` string continuation, so lines are counted in the original.
        let line = line_of(source, at);
        let text = lines.get(line - 1).copied().unwrap_or_default().trim();
        (
            Edge {
                path: rel.to_owned(),
                needle: needle.to_owned(),
                line: text.to_owned(),
            },
            line,
        )
    };
    let bytes = masked.as_bytes();
    let mut edges = Vec::new();
    let mut i = 0;
    let mut previous = "";
    while i < bytes.len() {
        if !is_ident_start(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_ident_byte(bytes[i]) {
            i += 1;
        }
        let ident = &masked[start..i];
        if model_call(rel, &masked, start, i) {
            edges.push(edge(ident, start));
        } else if seam_name(previous, ident) {
            edges.push(edge(&format!("{previous} {ident}"), start));
        }
        previous = ident;
    }
    edges
}

/// The hit map the gate checks, with every hit's line for the failure message.
fn actual_edges(
    sources: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<Edge, Vec<String>> {
    let mut actual = BTreeMap::<Edge, Vec<String>>::new();
    for (rel, source) in sources {
        if !scanned(&rel) {
            continue;
        }
        for (edge, line) in file_edges(&rel, &source) {
            let at = format!("{}:{line}", edge.path);
            actual.entry(edge).or_default().push(at);
        }
    }
    actual
}

/// Each pinned edge with how many times it is pinned, its list and what it does.
fn pinned() -> BTreeMap<Edge, (usize, &'static str, &'static str)> {
    let mut map = BTreeMap::<Edge, (usize, &'static str, &'static str)>::new();
    for (list, pins) in [("BYPASSES", BYPASSES), ("OUTSIDE", OUTSIDE)] {
        for pin in pins {
            let edge = Edge {
                path: pin.path.to_owned(),
                needle: pin.needle.to_owned(),
                line: pin.line.to_owned(),
            };
            let entry = map.entry(edge).or_insert((0, list, pin.what));
            assert_eq!(
                entry.1, list,
                "DECIDE-PATH: {}: `{}` is pinned in both lists",
                pin.path, pin.line
            );
            entry.0 += 1;
        }
    }
    map
}

fn tree_pairs(repo: &Path) -> Vec<(String, String)> {
    let tree = SourceTree::read(&repo.join("crates"));
    tree.production_sources()
        .map(|(path, source)| {
            let rel = normalized(path.strip_prefix(repo).unwrap_or(path));
            (rel, source.to_owned())
        })
        .collect()
}

/// What differs between the tree and the pins, one line each; empty when they agree.
fn drift(actual: &BTreeMap<Edge, Vec<String>>) -> Vec<String> {
    let pins = pinned();
    let mut out = Vec::new();
    for (edge, sites) in actual {
        let count = pins.get(edge).map_or(0, |pin| pin.0);
        if sites.len() > count {
            out.push(format!(
                "NEW {} `{}` at {}: a typed decision goes through decide() in {DECIDE_DIR}; \
                 anything else joins OUTSIDE with one line on what it does",
                edge.needle,
                edge.line,
                sites.join(", ")
            ));
        }
    }
    for (edge, (count, list, what)) in &pins {
        let found = actual.get(edge).map_or(0, Vec::len);
        if found < *count {
            out.push(format!(
                "GONE {}: {} `{}` ({what}; {found} of {count} left): remove it from {list}{}",
                edge.path,
                edge.needle,
                edge.line,
                if *list == "BYPASSES" {
                    " and lower BYPASS_CEILING"
                } else {
                    ""
                }
            ));
        }
    }
    out
}

#[test]
fn decide_path_typed_decisions_outside_decide_are_pinned() {
    let repo = repo_root();
    assert_eq!(
        BYPASSES.len(),
        BYPASS_CEILING,
        "DECIDE-PATH: BYPASSES holds {} pins but BYPASS_CEILING says {BYPASS_CEILING}; \
         the list only shrinks, so lower the ceiling with it and never raise it",
        BYPASSES.len()
    );

    let drift = drift(&actual_edges(tree_pairs(&repo)));
    assert!(
        drift.is_empty(),
        "DECIDE-PATH: model calls outside {DECIDE_DIR} changed:\n{}",
        drift.join("\n")
    );
}

#[test]
fn decide_path_new_judge_call_and_dropped_bypass_both_fail() {
    let repo = repo_root();
    let pairs = tree_pairs(&repo);
    assert!(drift(&actual_edges(pairs.clone())).is_empty());

    // A new model call anywhere outside decision/ is unpinned, however it is spelled.
    let judge = "crates/oneiron/src/curation/new_judge.rs";
    let call = "let verdict = backend.generate(request, lease).await?;\n";
    for (rel, line, needle) in [
        (judge, call, "generate"),
        (
            judge,
            "let verdict = LlmBackend::generate(&*backend, request, lease).await?;\n",
            "generate",
        ),
        (
            judge,
            "let verdict = backend.stream (request, lease)?;\n",
            "stream",
        ),
        (
            "crates/oneiron-bench/src/beam/grade_judge.rs",
            "let (grade, cost) = session.invoke(pin, purpose, system, user)?;\n",
            "invoke",
        ),
    ] {
        let with_new = pairs
            .iter()
            .cloned()
            .chain([(rel.to_owned(), line.to_owned())]);
        let drift_new = drift(&actual_edges(with_new));
        assert_eq!(drift_new.len(), 1, "{drift_new:?}");
        assert!(
            drift_new[0].starts_with(&format!("NEW {needle} ")),
            "{drift_new:?}"
        );
    }
    // Key generation shares a method name with the raw seam and is not a model call.
    let keygen = "let key = SigningKey::generate(&mut rng);\n";
    let with_keygen = pairs
        .iter()
        .cloned()
        .chain([(judge.to_owned(), keygen.to_owned())]);
    assert!(drift(&actual_edges(with_keygen)).is_empty());

    // So is a new judge seam a host's model could sit behind.
    let seam = "pub trait MergeJudge {\n    fn judge(&self) -> bool;\n}\n";
    let with_seam = pairs
        .iter()
        .cloned()
        .chain([(judge.to_owned(), seam.to_owned())]);
    let drift_seam = drift(&actual_edges(with_seam));
    assert_eq!(drift_seam.len(), 1, "{drift_seam:?}");
    assert!(
        drift_seam[0].starts_with("NEW trait MergeJudge"),
        "{drift_seam:?}"
    );

    // The same call inside decision/ is the required path, not a bypass.
    let inside = format!("{DECIDE_DIR}new_rung.rs");
    let with_inside = pairs.iter().cloned().chain([(inside, call.to_owned())]);
    assert!(drift(&actual_edges(with_inside)).is_empty());

    // A pin whose seam is renamed away without leaving the list fails until it is removed.
    let seat = "crates/oneiron/src/llm/seat/decisions.rs";
    let without = pairs.iter().map(|(rel, source)| {
        let source = if rel == seat {
            source.replace(
                "pub trait SeatNotes: Send + Sync {",
                "pub trait SeatWords: Send + Sync {",
            )
        } else {
            source.clone()
        };
        (rel.clone(), source)
    });
    let drift_gone = drift(&actual_edges(without));
    assert_eq!(drift_gone.len(), 1, "{drift_gone:?}");
    assert!(
        drift_gone[0].starts_with("GONE crates/oneiron/src/llm/seat/decisions.rs"),
        "{drift_gone:?}"
    );
}
