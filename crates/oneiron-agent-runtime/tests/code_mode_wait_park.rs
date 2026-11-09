//! ENGINE CALL CODE-SANDBOX-WAIT-RESPONSE-FIELD: a code-mode call whose row
//! output holds a park, answered with the wait its run parks on, resolves with
//! that output, as every verb call resolves with its row's output:
//! - the bare `wait` on an ask still pending, `TaskAskWait::Park` (the `output`
//!   of `scripts/sdk/verbs/wait.json`);
//! - `tasks.wait` on a world-privacy request still pending, the untagged
//!   `TaskWaitOutput::WorldPrivacy(TaskAskWait::Park)` (FIX 4706).
//!
//! Before the fix the bridge answered a park as a bare `{waitId}`, in which
//! the verb-table import (`wasmtime_runtime/typed.rs` `self.verbs.call`)
//! finds no `output`, so the guest's call rejected with
//! `missing_host_response_field`.
//!
//! The guest is the pinned first-party QuickJS component, over the real typed
//! imports and bridge (`wasmtime_runtime/typed.rs`, `wire.rs`). The host
//! answers each wait as the engine's dispatcher answers one still pending: a
//! durable wait (`code_run/dispatcher/coordination.rs` `dispatch_tasks_wait`,
//! `code_run/dispatcher/world_privacy_wait.rs`).
//!
//! `cargo test --locked -p oneiron-agent-runtime --all-features --test code_mode_wait_park`
#![cfg(feature = "code-sandbox-wasmtime")]

#[path = "wait_park/fixture.rs"]
mod fixture;

use fixture::{WaitHost, first_party_factory, pending_ask_park};
use oneiron::EntityId;
use oneiron::code_run::{
    CodeRunDeterminism, SelfCall, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    TaskWaitOutput, TaskWaitSetCall,
};
use oneiron::code_sandbox::{SandboxBoundaryContract, SandboxGuestTier};
use oneiron::engine_executor::{JsCodeModeRuntime, JsCodeModeStep};
use oneiron::task_verb::{TaskAskHandle, TaskAskWait};
use serde_json::{Value, json};

/// The key both waits are made under.
const STEP_KEY: &str = "sdk.wait";

/// What the guest's `expression` came to: `{resolved}` with its value, or
/// `{rejected}` with what it threw.
fn guest_reads(expression: &str, host: &mut WaitHost) -> Value {
    let script = format!(
        "let waited; \
         try {{ waited = {{resolved: await {expression}}}; }} \
         catch (error) {{ waited = {{rejected: String(error)}}; }} \
         finish(JSON.stringify(waited));"
    );
    let mut runtime = first_party_factory().runtime().expect("a guest runtime");
    let outcome = runtime
        .run_step(
            JsCodeModeStep {
                run_id: EntityId::from_bytes([0x5B; 16]).expect("run id"),
                seq: 0,
                script: &script,
                boundary: SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer),
                determinism: CodeRunDeterminism::new(1_700_000_000_000, [0x5C; 32]),
            },
            host,
        )
        .expect("the guest's step runs");
    assert!(outcome.done, "the guest finished: {}", outcome.observation);
    serde_json::from_str(&outcome.observation).expect("the guest finished with JSON")
}

#[test]
fn a_parked_wait_resolves_with_its_rows_park() {
    let handle = TaskAskHandle {
        group_ref: EntityId::from_bytes([0x5A; 16]).expect("ask group id"),
    };
    let park = pending_ask_park(handle.group_ref);
    let mut host = WaitHost::parking(park.clone());
    let handle_json = serde_json::to_string(&handle).expect("handle JSON");
    let waited = guest_reads(
        &format!("wait({{handle: {handle_json}, step_key: '{STEP_KEY}'}})"),
        &mut host,
    );
    assert_eq!(
        host.calls,
        [SelfCall::TasksWait(handle)],
        "the guest's one host call is its wait on the ask"
    );
    let expected = serde_json::to_value(TaskAskWait::Park(park)).expect("the park as JSON");
    assert_eq!(
        waited,
        json!({ "resolved": expected }),
        "a parked wait resolves with its row's output, `TaskAskWait::Park`, \
         and does not reject with missing_host_response_field"
    );
}

#[test]
fn a_parked_world_privacy_tasks_wait_resolves_with_its_rows_park() {
    let request = EntityId::from_bytes([0x5D; 16])
        .expect("request id")
        .to_hex();
    // The park the engine makes for a world-privacy request still pending
    // (`task_verb/world_privacy_wait.rs` `request_park`).
    let park = SelfDurableWait {
        wait_id: EntityId::from_hex(&request).expect("request id"),
        effect: SelfEffect::TasksWait,
        reason: SelfDurableWaitReason::HumanInput,
        prompt: None,
    };
    let mut host = WaitHost::parking(park.clone());
    let waited = guest_reads(
        &format!("tasks.wait({{request: '{request}', step_key: '{STEP_KEY}'}})"),
        &mut host,
    );
    assert_eq!(
        host.calls,
        [SelfCall::TasksWaitSet(TaskWaitSetCall {
            tasks: Vec::new(),
            all: None,
            n_of: None,
            until: None,
            step_key: STEP_KEY.to_owned(),
            request: Some(request),
        })],
        "the guest's one host call is its wait on the request"
    );
    let expected = serde_json::to_value(TaskWaitOutput::WorldPrivacy(TaskAskWait::Park(park)))
        .expect("the park as JSON");
    assert_eq!(
        waited,
        json!({ "resolved": expected }),
        "a parked world-privacy tasks.wait resolves with its row's output, \
         `TaskWaitOutput::WorldPrivacy(TaskAskWait::Park)`, and does not reject with \
         missing_host_response_field"
    );
}
