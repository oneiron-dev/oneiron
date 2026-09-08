//! The boundary-adapter trait and the in-memory double that pins it.

use std::{collections::BTreeMap, fmt};

use super::{
    contract::{SandboxBoundaryContract, SandboxGuestTier},
    credential::{
        SandboxCredentialCall, SandboxCredentialOutcome, SandboxFileRead, SandboxReadFile,
    },
    paths::{SandboxMountTable, SandboxVirtualPath},
    proposal::{SandboxProposalDelta, SandboxProposalWrite},
};
use crate::{Error, Result};

/// Boundary adapter used by a sandbox runtime.
pub trait SandboxBoundaryAdapter {
    /// Reads one file through the virtual `/mnt` ABI.
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead>;

    /// Calls one credential-backed operation by opaque handle.
    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome>;

    /// Emits one proposal delta for a foreign/untrusted write intent.
    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta>;
}

/// In-memory adapter used to pin the boundary contract before production runtime work.
pub struct FakeSandboxAdapter {
    tier: SandboxGuestTier,
    mounts: SandboxMountTable,
    files: BTreeMap<SandboxVirtualPath, Vec<u8>>,
    credential_calls: Vec<SandboxCredentialCall>,
    proposal_deltas: Vec<SandboxProposalDelta>,
}

impl FakeSandboxAdapter {
    #[must_use]
    pub fn new(tier: SandboxGuestTier, mounts: SandboxMountTable) -> Self {
        Self {
            tier,
            mounts,
            files: BTreeMap::new(),
            credential_calls: Vec::new(),
            proposal_deltas: Vec::new(),
        }
    }

    #[must_use]
    pub const fn tier(&self) -> SandboxGuestTier {
        self.tier
    }

    #[must_use]
    pub fn guest_mount_roots(&self) -> [&'static str; 4] {
        self.mounts.guest_mount_roots()
    }

    pub fn stage_file(&mut self, path: SandboxVirtualPath, bytes: impl Into<Vec<u8>>) {
        self.files.insert(path, bytes.into());
    }

    #[must_use]
    pub fn credential_calls(&self) -> &[SandboxCredentialCall] {
        &self.credential_calls
    }

    #[must_use]
    pub fn proposal_deltas(&self) -> &[SandboxProposalDelta] {
        &self.proposal_deltas
    }
}

impl SandboxBoundaryAdapter for FakeSandboxAdapter {
    fn read_file(&self, call: SandboxReadFile) -> Result<SandboxFileRead> {
        let _host_path = self.mounts.resolve_host_path(&call.path);
        let bytes = self
            .files
            .get(&call.path)
            .ok_or(Error::EntityNotFound)?
            .clone();
        Ok(SandboxFileRead {
            path: call.path,
            bytes,
        })
    }

    fn call_credential(&mut self, call: SandboxCredentialCall) -> Result<SandboxCredentialOutcome> {
        self.credential_calls.push(call.clone());
        Ok(SandboxCredentialOutcome {
            operation: call.operation,
            credential: call.credential,
        })
    }

    fn propose_write(&mut self, write: SandboxProposalWrite) -> Result<SandboxProposalDelta> {
        let contract = SandboxBoundaryContract::for_tier(self.tier);
        if !contract.has_proposal_delta_channel() {
            return Err(Error::InvalidClaimBody(
                "sandbox tier does not expose proposal deltas",
            ));
        }

        let delta = SandboxProposalDelta::new(self.tier, write)?;
        self.proposal_deltas.push(delta.clone());
        Ok(delta)
    }
}

impl fmt::Debug for FakeSandboxAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeSandboxAdapter")
            .field("tier", &self.tier)
            .field("mounts", &self.mounts)
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .field("credential_calls", &self.credential_calls)
            .field("proposal_deltas", &self.proposal_deltas)
            .finish()
    }
}
