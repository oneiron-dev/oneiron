//! The host's program runs for the Coach's contribution forks (FIX 3607,
//! FIX 3028). Each engine step's fork's answer runs on a fresh runtime of
//! the checked-in QuickJS component, the one pin both forks of every pair
//! run on, with the same component budget. Each fork gets a scratch arm
//! store of its own in the shadow runner's arm registry, and the store is
//! released before the run returns. The store is held by the source run's
//! actor and masks each write under the source vault's custody, as a shadow
//! arm's store does (FIX 5718). Nothing here dispatches, writes, sends or
//! resolves a credential: the program reaches the captured step's recorded
//! calls alone. In the `Executed` mode the judge reads what the program did
//! ([`executed_evidence`]) after the answer's text, never in its place. A
//! server with no runtime of the component says so, a reason a retry may
//! clear: its pairs wait for one retry, then fall back to the `Text` mode.
//! A callable's pair runs its caller step's two branches the same way, each
//! on a fresh runtime and in a scratch store of its own (FIX 3608).

use std::sync::{Arc, OnceLock};

use oneiron::code_run::shadow_runner::{
    PreparedShadowStep, ShadowArmLease, ShadowBodyStore, ShadowUnavailable,
    ShadowUnavailableReason as Reason,
};
use oneiron::code_run::{
    CallableBranch, ContributionForkProgram, ExecutedFork, ExecutedForkView,
    execute_callable_branch, execute_contribution_fork,
};
use oneiron::engine_executor::{JsCodeModeRuntime, StepCancellation};
use oneiron::{Error, LlmResponse, Vault};
use serde_json::json;

use crate::ai_host::shadow_runner::{ArmRegistry, CheckedInRuntimes, source_hold};
use crate::server::SyncServer;

/// The runtime and the scratch stores one wake pass lends its forks'
/// programs.
#[derive(Default)]
pub(super) struct ProgramLending {
    runtimes: CheckedInRuntimes,
    /// The pass's scratch stores, opened at its first program.
    arms: OnceLock<ArmRegistry>,
}

impl ProgramLending {
    /// The pass's arm registry, opened now when it is not yet.
    fn arms(&self) -> oneiron::Result<&ArmRegistry> {
        if let Some(arms) = self.arms.get() {
            return Ok(arms);
        }
        let opened = ArmRegistry::open()?;
        Ok(self.arms.get_or_init(|| opened))
    }
}

/// The program run a fork makes, on the server's vault, which is the vault
/// the pass runs on.
pub(super) struct LentProgram<'a> {
    pub(super) server: &'a SyncServer,
    pub(super) vault: &'a Vault,
    pub(super) lending: &'a ProgramLending,
}

impl ContributionForkProgram for LentProgram<'_> {
    fn runtime_pin(&self) -> oneiron::Result<Result<[u8; 32], ShadowUnavailable>> {
        Ok(self.lending.runtimes.pin().ok_or_else(no_runtime))
    }

    fn execute(
        &self,
        step: &PreparedShadowStep,
        response: &LlmResponse,
    ) -> oneiron::Result<Result<ExecutedFork, ShadowUnavailable>> {
        self.in_arm(step, |runtime, runtime_pin, store, cancel| {
            execute_contribution_fork(step, response, runtime, runtime_pin, store, cancel)
        })
    }

    fn execute_branch(
        &self,
        step: &PreparedShadowStep,
        branch: &CallableBranch,
    ) -> oneiron::Result<Result<ExecutedFork, ShadowUnavailable>> {
        self.in_arm(step, |runtime, runtime_pin, store, cancel| {
            execute_callable_branch(step, branch, runtime, runtime_pin, store, cancel)
        })
    }
}

impl LentProgram<'_> {
    /// `run` on a fresh runtime of the checked-in component, its pin and a
    /// scratch arm store of its own, released once `run` returns.
    fn in_arm(
        &self,
        step: &PreparedShadowStep,
        run: impl FnOnce(
            &mut dyn JsCodeModeRuntime,
            [u8; 32],
            &ShadowBodyStore,
            &StepCancellation,
        ) -> oneiron::Result<Result<ExecutedFork, ShadowUnavailable>>,
    ) -> oneiron::Result<Result<ExecutedFork, ShadowUnavailable>> {
        let vault = self.server.vault();
        // The scratch store's hold and custody are the server vault's: the
        // pass must run on it.
        if !std::ptr::eq(Arc::as_ptr(vault), self.vault) {
            return Err(Error::InvalidConfig(
                "contribution forks: the pass's vault is not the server's".to_owned(),
            ));
        }
        let (Some(runtime_pin), Ok(mut runtime)) =
            (self.lending.runtimes.pin(), self.lending.runtimes.runtime())
        else {
            return Ok(Err(no_runtime()));
        };
        let arms = self.lending.arms()?;
        let lease = ShadowArmLease::mint();
        let actor = step.source_actor();
        let source = (actor, step.step().run);
        let hold = source_hold(vault, actor);
        let arm = arms.open_arm(lease, source, hold, step.release_source(), vault)?;
        let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
        let cancel = StepCancellation::new();
        let ran = run(runtime, runtime_pin, arm.store(), &cancel);
        // The fork keeps only what was read back: its scratch bodies go now.
        arms.release(&lease);
        ran
    }
}

/// No runtime of the checked-in component now.
fn no_runtime() -> ShadowUnavailable {
    let resource = Reason::ResourceUnavailable {
        resource: "js_runtime".to_owned(),
    };
    ShadowUnavailable::new(resource, "runtime")
}

/// What a fork's program did, as the judge reads it after the answer's text
/// in the `Executed` mode (FIX 3607): how its step ended, its provenance
/// (it ran against the captured step's recorded calls, and how many of them
/// it matched), and each observation, file and stored result, whole, by its
/// path. Never the program's source or its own claim of success.
pub(super) fn executed_evidence(executed: &ExecutedForkView) -> String {
    let pin = &executed.pin;
    let outputs: Vec<_> = executed
        .outputs
        .iter()
        .map(|output| {
            json!({
                "path": output.path,
                "complete": output.complete,
                "text": String::from_utf8_lossy(&output.bytes),
            })
        })
        .collect();
    json!({
        "executed_program": {
            "status": executed.status,
            "provenance": {
                "ran_against": "captured_step_recorded_calls",
                "recorded_calls_in_step": pin.bridge_end.saturating_sub(pin.bridge_start),
                "recorded_calls_matched": executed.consumed.saturating_sub(pin.bridge_start),
            },
            "outputs": outputs,
        },
    })
    .to_string()
}
