//! The shared fixture of `code_mode_wait_park.rs` and `callable_wait_park.rs`
//! (ENGINE CALL CODE-SANDBOX-WAIT-RESPONSE-FIELD, SANDBOX-WAIT-PARK-SEMANTICS):
//! the pinned first-party QuickJS component, and a host that answers each
//! wait the guest makes with one outcome.
#![allow(dead_code)]

use std::path::PathBuf;

use oneiron::code_run::{SelfCall, SelfDispatchOutcome, SelfDurableWait, SelfEffect};
use oneiron::engine_executor::{JsCodeModeHost, SelfDispatchResponse};
use oneiron::{Error, Result};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_agent_runtime::code_sandbox::wasmtime_runtime::ComponentBudget;
use sha2::{Digest, Sha256};

/// The pinned first-party QuickJS component, past its readiness probe.
pub(crate) fn first_party_factory() -> QuickJsRuntimeFactory {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm"))
        .expect("the pinned QuickJS component; see components/code-run-quickjs/README.md");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())
        .expect("the first-party component passes its readiness probe")
}

/// The park the engine makes for a `wait` on an ask still pending, waited on
/// with no step key, as code mode waits (`tasks_wait_observing`): the ask's
/// group is the wait.
pub(crate) fn pending_ask_park(group_ref: oneiron::EntityId) -> SelfDurableWait {
    let mut park = oneiron::code_run::peer_result_wait(group_ref);
    park.effect = SelfEffect::TasksWait;
    park
}

/// Answers each wait the guest makes, the bare `wait` and `tasks.wait`, with
/// `answer`, as the engine's dispatcher would, and keeps the calls. It
/// answers no other call.
pub(crate) struct WaitHost {
    pub(crate) answer: SelfDispatchOutcome,
    pub(crate) calls: Vec<SelfCall>,
}

impl WaitHost {
    /// A host whose waits park the run on `park`.
    pub(crate) fn parking(park: SelfDurableWait) -> Self {
        Self {
            answer: SelfDispatchOutcome::DurableWait(park),
            calls: Vec::new(),
        }
    }
}

impl JsCodeModeHost for WaitHost {
    fn dispatch_self(&mut self, call: SelfCall) -> Result<SelfDispatchResponse> {
        let waits = matches!(call, SelfCall::TasksWait(_) | SelfCall::TasksWaitSet(_));
        self.calls.push(call);
        if !waits {
            return Err(Error::InvalidConfig(
                "this guest makes only its wait call".into(),
            ));
        }
        Ok(SelfDispatchResponse {
            outcome: self.answer.clone(),
            budget: None,
            view: None,
        })
    }
}
