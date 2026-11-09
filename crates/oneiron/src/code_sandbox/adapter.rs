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

