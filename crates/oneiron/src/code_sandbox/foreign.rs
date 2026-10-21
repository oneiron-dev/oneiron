//! A finite foreign program on the existing propose-only isolation lane.
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver, ExecutionBudget, GuestImage,
    MicroVmBackend, MicroVmSandboxAdapter, select_backend_for_tier,
};
use super::{
    ProposalSpoolFloor, SandboxCredentialHandle, SandboxGuestTier, SandboxMountTable,
    SandboxProposalDelta,
};
use crate::engine_executor::StepCancellation;
use crate::{Error, Result};

/// Host-selected interpreter bytes and their reviewed SHA-256, never a wire input.
pub struct ForeignCodeArtifact<'a> {
    pub component: &'a [u8],
    pub sha256: [u8; 32],
}

pub struct ForeignCodeOutcome {
    pub result_json: String,
    pub proposals: Vec<SandboxProposalDelta>,
    pub manifest: Option<oneiron_container::SessionManifest>,
}

/// The adapter owns the only write exit: every file delta remains a proposal.
/// The workspace is a caller-scoped snapshot supplied by the admitting door.
/// No host credential or network authority is lent to a foreign program.
/// Its proposed files spool on `spool`, the host's measured disk floor
/// (FIX 7650).
pub fn execute_foreign_code(
    source: &str,
    mounts: SandboxMountTable,
    artifact: ForeignCodeArtifact<'_>,
    budget: ExecutionBudget,
    spool: Arc<dyn ProposalSpoolFloor>,
) -> Result<ForeignCodeOutcome> {
    if !artifact.component.starts_with(b"\0asm\x0d\0\x01\0")
        || <[u8; 32]>::from(Sha256::digest(artifact.component)) != artifact.sha256
    {
        return Err(invalid("foreign QuickJS component pin mismatch"));
    }
    let backend = select_backend_for_tier(SandboxGuestTier::Foreign)?
        .ok_or_else(|| invalid("foreign execution requires isolation"))?;
    execute_foreign_code_on(
        source,
        SandboxGuestTier::Foreign,
        mounts,
        artifact.component,
        backend,
        Arc::new(NoEgress),
        Some(spool),
        budget,
        &StepCancellation::never(),
    )
}

/// The finite foreign runtime and the public admission share one launch,
/// cancellation, manifest and proposal path. Only their host-owned workspace,
/// egress authority and proposal spool differ: a host that lent no spool
/// spools proposed files as before (FIX 7650).
#[expect(
    clippy::too_many_arguments,
    reason = "the host supplies each isolated execution axis"
)]
pub(crate) fn execute_foreign_code_on(
    source: &str,
    tier: SandboxGuestTier,
    mounts: SandboxMountTable,
    component_bytes: &[u8],
    mut backend: Box<dyn MicroVmBackend>,
    relay: Arc<dyn oneiron_container::EgressRelay>,
    spool: Option<Arc<dyn ProposalSpoolFloor>>,
    budget: ExecutionBudget,
    cancel: &StepCancellation,
) -> Result<ForeignCodeOutcome> {
    cancel.check()?;
    backend.set_egress(Arc::clone(&relay));
    if let Some(spool) = spool {
        backend.set_proposal_spool(spool);
    }
    let component_dir = tempfile::tempdir()?;
    let component = component_dir.path().join("component.wasm");
    std::fs::write(&component, component_bytes)?;
    let image = std::env::var("ONEIRON_CODE_GUEST_IMAGE")
        .map_err(|_| invalid("pinned foreign code guest image unconfigured"))?;
    let image = GuestImage::new("", "", component)
        .with_oci(&image)?
        .with_source(source);
    let mut adapter = MicroVmSandboxAdapter::new(
        tier,
        mounts,
        backend,
        Arc::new(NoCredentials),
        CredentialAllowlist::new(),
    )?;
    let result = adapter.run_cancellable(&image, budget, cancel);
    let manifest = adapter.session_manifest();
    let recorded = manifest
        .as_ref()
        .map(|manifest| relay.record_session(manifest))
        .transpose()
        .map_err(Error::from);
    cancel.check()?;
    recorded?;
    let exit = result?;
    if exit.status != 0 {
        return Err(invalid("foreign program failed in isolated backend"));
    }
    let proposals = adapter.collect_overlay_proposals()?;
    cancel.check()?;
    Ok(ForeignCodeOutcome {
        result_json: exit
            .result_json
            .ok_or_else(|| invalid("foreign execution returned no step result"))?,
        proposals,
        manifest,
    })
}

struct NoCredentials;
impl CredentialResolver for NoCredentials {
    fn resolve_for(
        &self,
        _: &SandboxCredentialHandle,
        _: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        Err(invalid("foreign code has no credential service"))
    }
}

/// A scoped snapshot is not an outbound grant. Network calls fail at the
/// existing backend relay, before any socket or delivery is opened.
struct NoEgress;
fn network_refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "foreign code has no network grant",
    )
}
impl oneiron_container::EgressRelay for NoEgress {
    fn connect(&self, _: SocketAddr) -> io::Result<TcpStream> {
        Err(network_refused())
    }
    fn authorize_datagram(&self, _: SocketAddr) -> io::Result<()> {
        Err(network_refused())
    }
    fn datagram(&self, _: SocketAddr, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(network_refused())
    }
    fn fetch(
        &self,
        _: oneiron_container::HttpRequest,
    ) -> io::Result<oneiron_container::HttpResponse> {
        Err(network_refused())
    }
    fn record_session(&self, _: &oneiron_container::SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn record_abandoned(&self, _: &oneiron_container::SessionManifest) -> io::Result<()> {
        Ok(())
    }
    fn transferred(&self, _: SocketAddr, _: [u8; 32], _: u64) {}
    /// Every relay is refused at once; no host floor is lent here.
    fn host_net_floor(&self) -> &dyn oneiron_container::HostNetFloor {
        &oneiron_container::UnmeteredFloor
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
