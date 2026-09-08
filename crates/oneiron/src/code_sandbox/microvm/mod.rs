//! MicroVM execution lane for foreign and ingested guest code.
//!
//! The parent module pins the boundary *contract*; this module lands the first
//! *executing* backend seam behind the same [`SandboxBoundaryAdapter`] trait.
//! Two guarantees move from in-process convention to backend enforcement:
//!
//! * **Overlay writes are proposals.** The guest's writable mount is an overlay
//!   upper directory; the base mount is read-only from the host side and the
//!   adapter exposes no commit verb. The only way a guest write leaves the
//!   sandbox is as a [`SandboxProposalDelta`].
//! * **Credentials are resolved at the network boundary.** The guest addresses
//!   an egress request by [`SandboxCredentialHandle`]. The host-side proxy
//!   checks the handle's destination allowlist *before* resolving, measures and
//!   scrubs the material, and returns a receipt that carries no secret bytes.
//!   Outbound transport lands with SECRET-02; the guest-visible outcome stays
//!   handle-only.
//!
//! Backend routing lives in `select_backend_for_tier` and nowhere else;
//! [`SandboxBoundaryContract::for_tier`] stays a pure value constructor.

mod adapter;
mod backend;
mod credential;
mod handle;
mod overlay;

pub use self::adapter::MicroVmSandboxAdapter;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
pub use self::backend::DevProcessBackend;
pub use self::backend::{
    DEV_BACKEND_NAME, MicroVmBackend, dev_backend_compiled, firecracker_backend_compiled,
    select_backend_for_tier,
};
pub use self::credential::{
    CredentialAllowlist, CredentialDestination, CredentialEgressProxy, CredentialInjection,
    CredentialResolver, EGRESS_PROXY_NAME, SANDBOX_EGRESS_ABI_KEY_HOST,
    SANDBOX_EGRESS_ABI_KEY_SCHEME, egress_destination_from_args,
};
pub use self::handle::{ExecutionBudget, GuestImage, MicroVmExit, MicroVmHandle};
pub use self::overlay::{collect_overlay_writes, prepare_overlay_handle};

// Re-anchors the `super::firecracker` path inside `backend.rs`: the flat
// microvm.rs resolved `super` to the parent `code_sandbox` module, while the
// split child resolves it to this module. The alias keeps the moved body
// byte-identical.
#[cfg(feature = "microvm-firecracker")]
use super::firecracker;

#[cfg(test)]
mod tests;

// The flat microvm.rs module used to provide these names to the sibling test
// module through `use super::*`: every microvm-internal item the tests name
// bare, plus the private crate/std imports they rely on. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::{backend::*, overlay::*};
#[cfg(test)]
use crate::Result;
#[cfg(test)]
use crate::code_sandbox::{
    SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxCredentialHandle, SandboxGuestTier,
    SandboxMount, SandboxMountTable, SandboxProposalWrite, SandboxReadFile, SandboxVirtualPath,
};
#[cfg(test)]
use std::collections::BTreeMap;
#[cfg(test)]
use std::{fs, path::Path, sync::Arc};
