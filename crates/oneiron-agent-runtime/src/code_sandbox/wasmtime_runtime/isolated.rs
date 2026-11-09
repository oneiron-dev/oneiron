//! Finite foreign steps use the selected backend, never an engine worker.
use super::*;
use crate::code_sandbox::{
    SandboxMountTable, foreign::execute_foreign_code_on, microvm::MicroVmBackend,
};

/// Runs one foreign step through the shared isolated launch. Cancellation
/// drops its result and proposals before they reach the host collector.
/// `step.script` is what `prepared` executes: a failed program's own error
/// is masked by `host` and names its TypeScript position (FIX 9209).
pub(super) fn run(
    runtime: &mut WasmtimeComponentRuntime,
    step: JsCodeModeStep<'_>,
    prepared: &PreparedSource<'_>,
    backend: Box<dyn MicroVmBackend>,
    cancel: &StepCancellation,
    host: &mut dyn JsCodeModeHost,
) -> Result<JsCodeModeStepOutcome> {
    let relay = runtime
        .foreign_egress
        .as_ref()
        .cloned()
        .ok_or(failure("foreign engine egress proxy unbound"))?;
    let workspace = tempfile::tempdir()?;
    let mounts = SandboxMountTable::new(
        workspace.path(),
        workspace.path(),
        workspace.path(),
        workspace.path(),
    );
    let mut held = HeldOutput::default();
    let mut output = |stream: JsCodeModeStream<'_>, frame: Vec<u8>| {
        let target = match stream {
            JsCodeModeStream::Console => StreamTarget::Console,
            JsCodeModeStream::Finish { start } => StreamTarget::Finish { start },
            JsCodeModeStream::Store { start } => StreamTarget::Store { start },
            JsCodeModeStream::File(path) => StreamTarget::File(path.to_owned()),
        };
        wire::output_frame(
            host,
            &mut held,
            runtime.budget.message_bytes,
            cancel,
            target,
            frame,
        )
        .map(|_| ())
    };
    let outcome = execute_foreign_code_on(
        step.script,
        step.boundary.tier(),
        mounts,
        &runtime.component_bytes,
        backend,
        relay,
        runtime.proposal_spool.clone(),
        runtime.budget.foreign_budget,
        cancel,
        &mut output,
    )?
    .map_err(|failed| failed.into_error(prepared, 0, |body| host.mask_guest_error(body)))?;
    for proposal in outcome.proposals {
        cancel.check()?;
        runtime
            .adapter
            .as_mut()
            .ok_or(failure("foreign proposal collector unbound"))?
            .propose_write(proposal.write().clone())?;
    }
    cancel.check()?;
    held.into_outcome(wire::decode_output(
        &outcome.result_json,
        runtime.budget.message_bytes,
    )?)
}
