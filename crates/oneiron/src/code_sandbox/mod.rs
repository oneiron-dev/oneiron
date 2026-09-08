//! Sandbox boundary contract for code-mode execution.
//!
//! This module does not start a sandbox or link a production adapter. It pins
//! the host/guest ABI that future runners must obey: plain JavaScript runs
//! inside a QuickJS-class interpreter embedded as a WASM component in the
//! existing Wasmtime/WIT boundary, guests target stable `/mnt` virtual paths,
//! clock/random are deterministic host imports, credential use is handle-only,
//! first-party writes are linked as typed traps, and foreign writes leave the
//! sandbox as reviewable proposal deltas rather than commit authority.

mod adapter;
mod contract;
mod credential;
mod paths;
mod proposal;

/// Firecracker-backed microVM lane (Linux; feature-gated).
#[cfg(feature = "microvm-firecracker")]
pub mod firecracker;
/// MicroVM execution lane for foreign and ingested guest code.
pub mod microvm;

pub use self::adapter::{FakeSandboxAdapter, SandboxBoundaryAdapter};
pub use self::contract::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_JS_COMPONENT_NAME, SANDBOX_WIT_WORLD_NAME,
    SandboxBoundaryContract, SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestRuntime,
    SandboxGuestTier, SandboxImportClass, SandboxLinkedImport,
};
pub use self::credential::{
    SandboxCredentialCall, SandboxCredentialEffect, SandboxCredentialHandle,
    SandboxCredentialOperation, SandboxCredentialOutcome, SandboxFileRead, SandboxReadFile,
};
pub use self::paths::{
    SANDBOX_MNT_ROOT, SANDBOX_OUTPUTS_ROOT, SANDBOX_SKILLS_ROOT, SANDBOX_UPLOADS_ROOT,
    SANDBOX_WORKSPACE_ROOT, SandboxMount, SandboxMountTable, SandboxVirtualPath,
};
pub use self::proposal::{
    SandboxClaimProposal, SandboxFileWriteProposal, SandboxProposalDelta, SandboxProposalKind,
    SandboxProposalWrite,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::{ClaimApprovalStatus, ClaimCandidate, Result, code_run::SelfEffect};
#[cfg(test)]
use std::path::Path;
