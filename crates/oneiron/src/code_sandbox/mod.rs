//! Sandbox boundary contract for code-mode execution.
//!
//! The optional `code-sandbox-wasmtime` boundary instantiates a fresh sandbox. It pins
//! the host/guest ABI that future runners must obey: plain JavaScript runs
//! inside a QuickJS-class interpreter embedded as a WASM component in the
//! existing Wasmtime/WIT boundary, guests target stable `/mnt` virtual paths,
//! clock/random are deterministic host imports, credential use is handle-only,
//! first-party writes are linked as typed traps, and foreign writes leave the
//! sandbox as reviewable proposal deltas rather than commit authority.

/// Host-pinned production QuickJS artifact loader and runtime factory.
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod quickjs;
/// Fuel-limited Component Model request boundary (no WASI).
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod wasmtime_boundary;
/// Typed Component Model adapter shared with the canonical CODE host boundary.
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod wasmtime_runtime;

#[doc(hidden)]
pub mod adapter;
/// Engine-owned open-web relay and owner-local receipts.
pub mod egress;
pub mod foreign;
/// A guest program's own error text, masked before it leaves the host (FIX 9209).
pub mod guest_error;
#[doc(hidden)]
pub mod proposal;
/// Host-side preparation of a code-mode program: TypeScript stripped by Oxc
/// in process, JavaScript passed through byte for byte (FIX 8276).
pub use oneiron_code_source::source;

/// Firecracker-backed microVM lane (Linux; feature-gated).
#[cfg(feature = "microvm-firecracker")]
pub mod firecracker;
/// MicroVM execution lane for foreign and ingested guest code.
pub mod microvm;

pub use self::adapter::SandboxBoundaryAdapter;
pub use self::contract::PLAIN_JS_HOST_VERB_DTS;
pub use self::contract::SANDBOX_JS_COMPONENT_NAME;
pub use self::contract::SANDBOX_WIT_WORLD_NAME;
pub use self::contract::SandboxBoundaryContract;
pub use self::contract::SandboxComponentBoundary;
pub use self::contract::SandboxGuestLanguage;
pub use self::contract::SandboxGuestRuntime;
pub use self::contract::SandboxGuestTier;
pub use self::contract::SandboxImportClass;
pub use self::contract::SandboxLinkedImport;
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
