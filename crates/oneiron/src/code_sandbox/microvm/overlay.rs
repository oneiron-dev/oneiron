//! The host-side scratch root and the checked overlay walk that turns guest writes into proposals.

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use crate::code_sandbox::{
    SANDBOX_WORKSPACE_ROOT, SandboxBoundaryContract, SandboxDirectoryOpaqueProposal,
    SandboxFileDeleteProposal, SandboxFileWriteProposal, SandboxMount, SandboxMountTable,
    SandboxProposalBody, SandboxProposalWrite, SandboxVirtualPath,
};
use crate::{EntityId, Error, Result};

use super::backend::backend_error;
use super::handle::MicroVmHandle;
use crate::error::CodeError;

pub fn overlay_error(detail: impl Into<String>) -> Error {
    Error::Code(CodeError::MicroVmOverlayError {
        detail: detail.into(),
    })
}

