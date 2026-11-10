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
        "crates/oneiron-bench/src/interface_bench/eval_run.rs",
        "call_openrouter",
        "let response = call_openrouter(api_key, &messages, 900, &request_nonce, settings)?;",
        "interface-bench answer generation",
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
        "crates/oneiron-server/src/ai_host/code_mode.rs",
        "generate",
        "call.ladder.generate(&run, call.request, None).await",
        "code-mode agent generation",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/compaction.rs",
        "generate",
        ".block_on(call.ladder.generate(&run, call.request, None));",
        "compaction summary and handoff",
    ),
    pin(
        "crates/oneiron-server/src/ai_host/step.rs",
        "generate",
        "let response = match runtime.block_on(call.ladder.generate(&run, request, None)) {",
        "saved-workflow step text",
    ),
    pin(
        "crates/oneiron-server/src/api/ai/chat.rs",
        "stream",
        ".stream(&run, admitted.request, None)",
        "streaming chat answer",
    ),
    pin(
        "crates/oneiron-server/src/api/llm.rs",
        "generate",
        "match ladder.generate(&run, request, None).await {",
        "raw inference route: the caller's request passed through",
    ),
    pin(
        "crates/oneiron-server/src/api/llm.rs",
        "stream",
        "let mut source = match ladder.stream(&run, request, None) {",
        "raw inference route, streamed",
    ),
    pin(
        "crates/oneiron-server/src/models/declared.rs",
        "generate",
        ".generate(&self.admission, request, Some(selector))",
        "declared run: the offer ladder under a caller",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder.rs",
        "generate",
        "match gate.generate(bound, permit.lease()).await {",
        "offer ladder: one gated attempt",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder.rs",
        "generate_while",
        "self.generate_while(run, request, selector, &|| true).await",
        "offer ladder: generate is generate_while with no stop",
    ),
    pin(
        "crates/oneiron-server/src/models/ladder.rs",
        "stream",
        "let ended = match gate.stream(call, permit.lease()) {",
        "offer ladder: one gated stream",
    ),
    pin(
        "crates/oneiron-server/src/models/raw.rs",
        "generate",
        "ladder.generate(&run, request, None).await",
        "injected runs: raw backend forwarding to the ladder",
    ),
    pin(
        "crates/oneiron-server/src/models/raw.rs",
        "stream",
        "ladder.stream(&run, request, None)",
        "injected runs: raw stream forwarding to the ladder",
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
        "crates/oneiron-server/src/server/recall_rerank.rs",
        "generate_while",
        ".generate_while(&run, call.request, None, &may_send);",
        "paid recall rerank scores: retrieval ranking, not a typed question",
    ),
    pin(
        "crates/oneiron-server/src/voice_host/extraction.rs",
        "generate",
        ".generate(request, lease.lease.as_ref().ok_or(HostError::Stopped)?),",
        "voice entity labels and salient terms (extraction)",
    ),
    pin(
        "crates/oneiron/src/dispatch_byoa/dispatcher.rs",
        "generate",
        ".generate(request, lease)",
        "foreign-agent transcript for a dispatched run",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/parallel.rs",
        "call_as_step_checked",
        "call_as_step_checked(",
        "Dreamer extraction, one child per slice: candidates, values, people and evidence (the claim each corrects is decided after it)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs",
        "call_as_step",
        "let outcome = call_as_step(step_ctx, call.backend, self.guard, request).await;",
        "consolidation merged value: the claim value a decided merge or supersede writes (generation)",
    ),
    pin(
        "crates/oneiron/src/dreamer_consolidation/scope_summary_attempt.rs",
        "call_as_step",
        "let response = match call_as_step(&step_ctx, self.backend, self.guard, request).await {",
        "scope summary text",
    ),
    pin(
        "crates/oneiron/src/engine_executor/repl.rs",
        "generate",
        "let response = self.backend.generate(request, self.lease).await?;",
        "code-mode agent loop",
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
        "crates/oneiron/src/llm/run_admission/gate.rs",
        "generate",
        "let result = self.inner.generate(request, lease).await;",
        "run gate forwarding to the inner backend",
    ),
    pin(
        "crates/oneiron/src/llm/run_admission/gate.rs",
        "stream",
        "let inner = self.inner.stream(request, lease)?;",
        "run gate stream forwarding to the inner backend",
    ),
    pin(
        "crates/oneiron/src/llm/step/execute.rs",
        "generate",
        "match backend.generate(request.clone(), lease).await {",
        "durable step: the raw call under every step",
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
        "crates/oneiron/src/policy_model/notes.rs",
        "generate",
        "let response = backend.generate(request, lease).await;",
        "policy rationale notes: rule ids, confidence and rationale beside a decided policy read (generation)",
    ),
    pin(
        "crates/oneiron/src/saved_query/decisions.rs",
        "generate",
        ".generate(request, binding.lease)",
        "saved-query membership note: the why a decided verdict keeps (generation)",
    ),
    pin(
        "crates/oneiron/src/booking/constraint.rs",
        "generate",
        ".generate(",
        "booking front: the schedule extraction for a turn the off-topic question kept (generation)",
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
        "crates/oneiron/src/llm/autocheck.rs",
        "trait AutoCheckNotes",
        "pub trait AutoCheckNotes: Send + Sync {",
        "auto-check notes: a decided hold's receipt reasons (generation)",
    ),
    pin(
        "crates/oneiron/src/llm/routing.rs",
        "call_as_step",
        "call_as_step(",
        "routed verdict: a caller's arbitrary schema call through the description route (generation); a typed decision a future caller makes with it is that caller's row",
    ),
    pin(
        "crates/oneiron/src/skill_optimize/gate/basis.rs",
        "trait HeldOutReplayNotes",
        "pub trait HeldOutReplayNotes {",
        "skill replay notes: replays, response pairs, objectives and metered person-time beside decided scores, preferences, findings and tradeoffs (evidence)",
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

    // A bypass that moves into decide() without leaving the list fails until it is removed.
    let seat = "crates/oneiron/src/llm/seat.rs";
    let without = pairs.iter().map(|(rel, source)| {
        let source = if rel == seat {
            source.replace(
                "pub trait SeatJudge: Send + Sync {",
                "pub trait SeatPick: Send + Sync {",
            )
        } else {
            source.clone()
        };
        (rel.clone(), source)
    });
    let drift_gone = drift(&actual_edges(without));
    assert_eq!(drift_gone.len(), 1, "{drift_gone:?}");
    assert!(
        drift_gone[0].starts_with("GONE crates/oneiron/src/llm/seat.rs"),
        "{drift_gone:?}"
    );
}
