//! Finite foreign steps use the selected backend, never an engine worker.
use super::*;
use crate::code_sandbox::{
    SandboxMountTable,
    microvm::{
        CredentialAllowlist, CredentialDestination, CredentialResolver, GuestImage, MicroVmBackend,
        MicroVmSandboxAdapter,
    },
};
use std::sync::Arc;

struct NoCredentials;
impl CredentialResolver for NoCredentials {
    fn resolve_for(
        &self,
        _: &crate::code_sandbox::SandboxCredentialHandle,
        _: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        Err(failure("foreign credential service unbound"))
    }
}
/// Runs one foreign step on `backend`. A cancel ends the backend's own
/// guest (its process group or container, never another's), and the
/// cancelled run's result and proposals are dropped before admission; the
/// session's manifest is recorded either way (FIX 600).
pub(super) fn run(
    runtime: &mut WasmtimeComponentRuntime,
    step: JsCodeModeStep<'_>,
    mut backend: Box<dyn MicroVmBackend>,
    cancel: &StepCancellation,
) -> Result<JsCodeModeStepOutcome> {
    cancel.check()?;
    let relay = runtime
        .foreign_egress
        .as_ref()
        .cloned()
        .ok_or(failure("foreign engine egress proxy unbound"))?;
    backend.set_egress(Arc::clone(&relay));
    let image_ref = std::env::var("ONEIRON_CODE_GUEST_IMAGE")
        .map_err(|_| failure("pinned OCI code guest image unconfigured"))?;
    let source = tempfile::tempdir()?;
    let component = source.path().join("component.wasm");
    std::fs::write(&component, &runtime.component_bytes)?;
    let image = GuestImage::new("", "", component)
        .with_oci(&image_ref)?
        .with_source(step.script);
    let workspace = tempfile::tempdir()?;
    let mounts = SandboxMountTable::new(
        workspace.path(),
        workspace.path(),
        workspace.path(),
        workspace.path(),
    );
    let mut adapter = MicroVmSandboxAdapter::new(
        step.boundary.tier(),
        mounts,
        backend,
        Arc::new(NoCredentials),
        CredentialAllowlist::new(),
    )?;
    let budget = runtime.budget.foreign_budget;
    let result = adapter.run_cancellable(&image, budget, cancel);
    let recorded = match adapter.session_manifest() {
        Some(manifest) => relay
            .record_session(&manifest)
            .map_err(|e| Error::InvalidConfig(e.to_string())),
        None => Ok(()),
    };
    // A cancelled run is dropped here, whatever it returned: nothing it
    // proposed reaches the host.
    cancel.check()?;
    recorded?;
    let exit = result?;
    if exit.status != 0 {
        return Err(failure("foreign step failed in isolated backend"));
    }
    let proposals = adapter.collect_overlay_proposals()?;
    for proposal in proposals {
        cancel.check()?;
        runtime
            .adapter
            .as_mut()
            .ok_or(failure("foreign proposal collector unbound"))?
            .propose_write(proposal.write().clone())?;
    }
    cancel.check()?;
    let output = exit
        .result_json
        .ok_or(failure("isolated guest returned no step result"))?;
    wire::decode_output(&output, runtime.budget.message_bytes)
}
