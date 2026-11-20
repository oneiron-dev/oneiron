//! The hook sandbox's input bound ([SKILL-POST-HOOK-INPUT-BODY-CHANNEL]):
//! a hook input is held only to the guest's memory, never to the 1 MiB
//! body cap. Run with: `cargo test --locked -p oneiron --all-features
//! --test hook_sandbox_input_bound`.
#![cfg(feature = "code-sandbox-wasmtime")]

use oneiron::runtime_hooks::HookBodyUsage;
use oneiron::runtime_hooks::HookRunContext;
use oneiron::runtime_hooks::sandbox::{HookSandbox, hook_component_bytes};

/// The Redact body every bound test runs: it judges the input whole.
const REDACT_TITLE_BODY: &str = "return {kind: \"redact\", paths: [\"/title\"]};";
/// The host's input bound: the guest's memory, past the 1 MiB body cap.
const INPUT_BOUND_BYTES: usize = 8 * 1024 * 1024;

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

/// A 2 MiB hook input runs its body: past the 1 MiB body cap, under the
/// 8 MiB guest-memory bound, the Redact body judges the whole input.
/// Red where the input kept the 1 MiB cap: refused before the start.
#[test]
fn a_two_mib_hook_input_runs_its_body() {
    let sandbox = hook_sandbox();
    let input = padded_input(2_097_152);
    assert!(
        input.len() > 1024 * 1024 && input.len() < INPUT_BOUND_BYTES,
        "the input sits between the body cap and the guest-memory bound: {} bytes",
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

/// A hook input past 8 MiB is refused before the start: the host never
/// lowers it into the guest, reports the input never taken, and the run
/// used nothing. Green where the input kept the 1 MiB cap too: refused
/// before the start all the same.
#[test]
fn a_hook_input_past_eight_mib_is_refused_before_the_start() {
    let sandbox = hook_sandbox();
    let input = padded_input(INPUT_BOUND_BYTES);
    assert!(
        input.len() > INPUT_BOUND_BYTES,
        "the input passes the guest-memory bound: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input past 8 MiB is refused before the start");
    assert!(
        error
            .to_string()
            .contains("hook input exceeds the guest memory"),
        "the refusal names the guest-memory bound: {error}",
    );
    assert!(
        context.input_not_taken(),
        "the refused input is reported never taken",
    );
    assert_eq!(
        context.usage(),
        HookBodyUsage::NOT_RUN,
        "a run refused before its worker starts used nothing",
    );
}

/// A hook input past the interpreter heap is not taken: one million empty
/// arrays parse to far more than the 24 MiB heap, so the guest answers
/// `hook_input_not_taken` and the body never starts.
#[test]
fn a_hook_input_past_the_interpreter_heap_is_not_taken() {
    let sandbox = hook_sandbox();
    let input = object_heavy_input(1_000_000);
    assert!(
        input.len() > 1024 * 1024 && input.len() < INPUT_BOUND_BYTES,
        "the input passes the host bound check so the guest judges it: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input past the interpreter heap is not taken");
    assert!(
        error
            .to_string()
            .contains("hook input exceeds the guest memory"),
        "the refusal names the guest-memory bound: {error}",
    );
    assert!(
        context.input_not_taken(),
        "the untaken input is reported never taken",
    );
}

/// An object-heavy input just under the bound is not taken, never a trap:
/// its lowered copy and the guest's copy of it leave the interpreter's heap
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
        input.len() > 7 * 1024 * 1024 && input.len() < INPUT_BOUND_BYTES,
        "the input sits just under the guest-memory bound: {} bytes",
        input.len(),
    );
    let mut context = HookRunContext::new(5_000);
    let error = sandbox
        .run_hook(REDACT_TITLE_BODY, &input, &mut context, &mut refusing_read)
        .expect_err("an input the guest cannot hold is not taken");
    assert!(
        error
            .to_string()
            .contains("hook input exceeds the guest memory"),
        "the run ends typed as not taken, never trapped: {error}",
    );
    assert!(
        context.input_not_taken(),
        "the untaken input is reported never taken",
    );
}
