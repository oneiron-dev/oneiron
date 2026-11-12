//! Sandbox boundary contract for code-mode execution.
//!
//! The optional `code-sandbox-wasmtime` boundary instantiates a fresh sandbox. It pins
//! the host/guest ABI that future runners must obey: plain JavaScript runs
//! inside a QuickJS-class interpreter embedded as a WASM component in the
//! existing Wasmtime/WIT boundary, guests target stable `/mnt` virtual paths,
//! clock/random are deterministic host imports, credential use is handle-only,
//! first-party writes are linked as typed traps, and foreign writes leave the
//! sandbox as reviewable proposal deltas rather than commit authority.

//! The backends themselves (the Wasmtime/QuickJS runtime, the Firecracker
//! microVM and the OCI fenced container) live in the `oneiron-agent-runtime`
//! crate, behind [`microvm::SandboxBackends`] and
//! `engine_executor::JsCodeModeRuntime`.

mod adapter;
/// Per-step ceilings of a Wasmtime component run.
#[cfg(feature = "code-sandbox-wasmtime")]
mod component_budget;
mod contract;
mod credential;
/// Engine-owned open-web relay and owner-local receipts.
pub mod egress;
pub mod foreign;
/// A guest program's own error text, masked before it leaves the host (FIX 9209).
mod paths;
mod proposal;
/// Host-side preparation of a code-mode program: TypeScript stripped by Oxc
/// in process, JavaScript passed through byte for byte (FIX 8276).
pub use oneiron_code_source::source;

/// MicroVM execution lane for foreign and ingested guest code.
pub mod microvm;

pub use self::adapter::{FakeSandboxAdapter, SandboxBoundaryAdapter};
#[cfg(feature = "code-sandbox-wasmtime")]
pub use self::component_budget::ComponentBudget;
pub use self::contract::{
    PLAIN_JS_HOST_VERB_DTS, SANDBOX_JS_COMPONENT_NAME, SANDBOX_WIT_WORLD_NAME,
    SandboxBoundaryContract, SandboxComponentBoundary, SandboxGuestLanguage, SandboxGuestRuntime,
    SandboxGuestTier, SandboxImportClass, SandboxLinkedImport, SandboxLinkedImportEffects,
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
    ProposalSpoolClaim, ProposalSpoolFloor, SandboxClaimProposal, SandboxDirectoryOpaqueProposal,
    SandboxFileDeleteProposal, SandboxFileEdit, SandboxFileEditProposal, SandboxFileRenameProposal,
    SandboxFileWriteProposal, SandboxProposalBody, SandboxProposalBodyReader,
    SandboxProposalBodyWriter, SandboxProposalDelta, SandboxProposalKind, SandboxProposalText,
    SandboxProposalWrite, SpoolAtFloor, SpoolFloorRefusal,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
use crate::{ClaimApprovalStatus, Result};
#[cfg(test)]
use std::path::Path;
