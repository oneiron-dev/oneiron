//! The hook sandbox's input bound ([SKILL-POST-HOOK-INPUT-BODY-CHANNEL]):
//! a hook input is held only to the guest's memory, never to the 1 MiB
//! body cap or to a fixed wire size. Run with: `cargo test --locked -p
//! oneiron --all-features --test hook_sandbox_input_bound`.
#![cfg(feature = "code-sandbox-wasmtime")]

use oneiron::runtime_hooks::HookBodyUsage;
use oneiron::runtime_hooks::HookRunContext;
use oneiron::runtime_hooks::sandbox::{HookSandbox, hook_component_bytes};

/// The Redact body every bound test runs: it judges the input whole.
const REDACT_TITLE_BODY: &str = "return {kind: \"redact\", paths: [\"/title\"]};";
/// The hook body cap (`ComponentBudget::message_bytes`).
const BODY_CAP_BYTES: usize = 1024 * 1024;
/// The fixed wire-size input cap the measured limit replaced (REVIEW-9805).
const FIXED_INPUT_CAP_BYTES: usize = 8 * 1024 * 1024;
/// The NUL characters of the escape-heavy input: each is six bytes on the
/// wire (`\u0000`), one in the interpreter's string.
const ESCAPED_NULS: usize = 1_572_864;
/// The hook's guest memory (components/code-run-quickjs/build.py
/// `--max-memory=33554432`).
const GUEST_MEMORY_BYTES: usize = 32 * 1024 * 1024;

/// A sandbox over the pinned checked-in hook component.
fn hook_sandbox() -> HookSandbox {
    let (bytes, pin) = hook_component_bytes();
    HookSandbox::from_component(bytes, pin).expect("the pinned hook component loads")
}

/// A hook input carrying a `pad` of `len` bytes of `b`.
fn padded_input(len: usize) -> String {
    format!(
        "{{\"now\":1700000000000,\"title\":\"t\",\"pad\":\"{}\"}}",
        "b".repeat(len)
    )
}

/// A hook input of exactly `total` bytes, padded as [`padded_input`].
fn input_of_length(total: usize) -> String {
    let input = padded_input(total - padded_input(0).len());
    assert_eq!(input.len(), total, "the padded input has its length");
    input
}

/// A hook input carrying `count` empty arrays: about three bytes each on
/// the wire, far more each in the interpreter's heap.
fn object_heavy_input(count: usize) -> String {
    let mut input = String::from("{\"now\":1700000000000,\"rows\":[");
    for _ in 1..count {
        input.push_str("[],");
    }
    input.push_str("[]]}");
    input
}

/// A read answering Err, as a body that reads nothing is given.
fn refusing_read(_: &str) -> std::result::Result<String, String> {
    Err("test_read_refused".to_owned())
}

/// Asserts the run ended typed as an input the guest never took, never a
/// trap or the body's own failure.
fn assert_not_taken(error: &oneiron::Error, context: &HookRunContext) {
    assert!(
        error
            .to_string()
            .contains("hook input exceeds the guest memory"),
        "the run ends typed as not taken: {error}",
    );
    assert!(
        context.input_not_taken(),
        "the untaken input is reported never taken",
    );
}

/// The input limit is the guest's own memory: past the fixed 8 MiB wire
/// cap, and within the 32 MiB guest less the body cap it reserves.
#[test]
fn the_input_limit_is_measured_from_the_guest_memory() {
    let limit = hook_sandbox().input_limit();
    assert!(
        limit > FIXED_INPUT_CAP_BYTES && limit <= GUEST_MEMORY_BYTES - BODY_CAP_BYTES,
        "the input limit is the guest's room: {limit} bytes",
    );
}

/// A 2 MiB hook input runs its body: past the 1 MiB body cap, under the
/// guest's input limit, the Redact body judges the whole input. Red where
/// the input kept the 1 MiB cap: refused before the start.
#[test]
fn a_two_mib_hook_input_runs_its_body() {
    let sandbox = hook_sandbox();
    let input = padded_input(2_097_152);
    assert!(
        input.len() > BODY_CAP_BYTES && input.len() < sandbox.input_limit(),
        "the input sits between the body cap and the input limit: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let run = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect("a 2 MiB input runs its body");
    assert_eq!(
        run.outcome_json, r#"{"kind":"redact","paths":["/title"]}"#,
        "the body redacts the title",
    );
    assert!(!context.input_not_taken(), "the guest took the input");
}

/// An escape-heavy input past 8 MiB on the wire runs its body (REVIEW-9805
/// P1 mod.rs:202): its 1.5 million NUL characters are 9 MiB of `\u0000`
/// escapes but a 1.5 MiB string in the interpreter, which the guest holds,
/// so the body reads the whole string and redacts. Red at the fixed 8 MiB
/// wire cap (584c37bc487): refused before the start as never taken.
#[test]
fn an_escape_heavy_input_past_eight_mib_on_the_wire_runs_its_body() {
    let sandbox = hook_sandbox();
    let input = format!(
        "{{\"now\":1700000000000,\"title\":\"t\",\"pad\":\"{}\"}}",
        "\\u0000".repeat(ESCAPED_NULS)
    );
    assert!(
        input.len() > FIXED_INPUT_CAP_BYTES,
        "the input passes the fixed wire cap: {} bytes",
        input.len(),
    );
    let body = format!(
        "return input.pad.length === {ESCAPED_NULS} && input.pad.charCodeAt(0) === 0 \
         ? {{kind: \"redact\", paths: [\"/title\"]}} : {{kind: \"skip\", reason: \"pad\"}};"
    );
    let mut context = HookRunContext::new(5_000);
    let run = sandbox
        .run_hook(&body, &input, &mut context, &mut refusing_read)
        .expect("an escape-heavy input the guest holds runs its body");
    assert_eq!(
        run.outcome_json, r#"{"kind":"redact","paths":["/title"]}"#,
        "the body read the whole string and redacts the title",
    );
    assert!(!context.input_not_taken(), "the guest took the input");
}

/// A hook input past the input limit is refused before the start: the host
/// never lowers it into the guest, reports the input never taken, and the
/// run used nothing. Green where the input kept the 1 MiB cap or the fixed
/// 8 MiB cap too: refused before the start all the same.
#[test]
fn a_hook_input_past_the_input_limit_is_refused_before_the_start() {
    let sandbox = hook_sandbox();
    let input = input_of_length(sandbox.input_limit() + 1);
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input past the input limit is refused before the start");
    assert_not_taken(&error, &context);
    assert_eq!(
        context.usage(),
        HookBodyUsage::NOT_RUN,
        "a run refused before its worker starts used nothing",
    );
}

/// An input past the input limit is reported never taken whatever else the
/// hook gets wrong (REVIEW-9805 P1 mod.rs:198): a body past the 1 MiB cap,
/// or a budget out of bounds, beside it still ends typed as not taken, so
/// a skill answer's post chain refuses the call. Red where the body or
/// budget check ran first (584c37bc487): the run ends on the body's or the
/// budget's refusal, the input reported taken.
#[test]
fn an_untaken_input_is_reported_never_taken_whatever_the_hook() {
    let sandbox = hook_sandbox();
    let input = input_of_length(sandbox.input_limit() + 1);
    let oversized_body = format!("{REDACT_TITLE_BODY}\n//{}", "a".repeat(BODY_CAP_BYTES));
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(&oversized_body, &input, &mut context, &mut refusing_read)
        .expect_err("an untaken input beside an oversized body is refused");
    assert_not_taken(&error, &context);
    let mut context = HookRunContext::new(0);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an untaken input beside an out-of-bounds budget is refused");
    assert_not_taken(&error, &context);
}

/// An input of exactly the input limit, beside a body of exactly the body
/// cap, lowers and ends typed as not taken, never a trap: the limit leaves
/// both lowerings their room, and the guest, holding no room to parse the
/// input, answers `hook_input_not_taken`. Red where the limit overstates
/// the guest's room: the lowering aborts the guest and the run ends
/// "hook body trapped", reported taken.
#[test]
fn an_input_at_the_input_limit_beside_a_full_body_never_traps() {
    let sandbox = hook_sandbox();
    let input = input_of_length(sandbox.input_limit());
    let head = format!("{REDACT_TITLE_BODY}\n//");
    let full_body = format!("{head}{}", "a".repeat(BODY_CAP_BYTES - head.len()));
    assert_eq!(full_body.len(), BODY_CAP_BYTES, "the body fills its cap");
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(&full_body, &input, &mut context, &mut refusing_read)
        .expect_err("an input the guest cannot parse is not taken");
    assert_not_taken(&error, &context);
}

/// A hook input past the interpreter heap is not taken: one million empty
/// arrays parse to far more than the 24 MiB heap, so the guest answers
/// `hook_input_not_taken` and the body never starts.
#[test]
fn a_hook_input_past_the_interpreter_heap_is_not_taken() {
    let sandbox = hook_sandbox();
    let input = object_heavy_input(1_000_000);
    assert!(
        input.len() > BODY_CAP_BYTES && input.len() < sandbox.input_limit(),
        "the input passes the host's limit so the guest judges it: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input past the interpreter heap is not taken");
    assert_not_taken(&error, &context);
}

/// An object-heavy input of about 8 MB is not taken, never a trap: its
/// lowered copy and the guest's copy of it leave the interpreter's heap
/// less than its 24 MiB of the 32 MiB linear memory, so the parse meets a
/// failed memory growth before the heap limit. That growth fails the
/// allocation, which QuickJS throws as out of memory, so the guest answers
/// `hook_input_not_taken`. Red where a failed growth traps the store: the
/// run ends "hook body trapped", which a skill answer's post chain records
/// as an ordinary failure on an answer its body never judged.
#[test]
fn an_object_heavy_input_under_the_bound_is_not_taken_never_trapped() {
    let sandbox = hook_sandbox();
    let input = object_heavy_input(2_700_000);
    assert!(
        input.len() > 7 * 1024 * 1024 && input.len() < sandbox.input_limit(),
        "the input sits under the input limit: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input the guest cannot hold is not taken");
    assert_not_taken(&error, &context);
}
