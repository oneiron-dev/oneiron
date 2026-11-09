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
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::microvm::*;

#[doc(hidden)]
pub mod adapter;
#[cfg(target_os = "linux")]
mod container;
#[doc(hidden)]
pub mod backend;
#[doc(hidden)]
pub mod credential;
#[doc(hidden)]
pub mod handle;
#[doc(hidden)]
pub mod output;
#[doc(hidden)]
pub mod overlay;
#[doc(hidden)]
pub mod scratch;

#[cfg(target_os = "linux")]
pub use container::CONTAINER_BACKEND_NAME;
pub use container::ContainerBackend;
#[cfg(any(test, debug_assertions, feature = "microvm-dev"))]
pub use self::backend::DevProcessBackend;
pub use self::backend::DEV_BACKEND_NAME;
pub use self::backend::dev_backend_compiled;
pub use self::backend::firecracker_backend_compiled;
pub use self::backend::select_backend_for_session;
pub use self::output::MicroVmOutputBodies;
#[cfg(all(unix, feature = "microvm-firecracker"))]
pub(in crate::code_sandbox) use self::overlay::reap_overlay_scratch;
pub use self::overlay::collect_overlay_writes;
pub use self::overlay::prepare_overlay_handle;
pub use adapter::CodeSandboxMicrovmAdapterMicroVmSandboxAdapterExt;
pub use credential::CodeSandboxMicrovmCredentialCredentialDestinationExt;
pub use credential::CodeSandboxMicrovmCredentialCredentialAllowlistExt;
pub use credential::CodeSandboxMicrovmCredentialCredentialInjectionExt;
pub use credential::CodeSandboxMicrovmCredentialCredentialEgressProxyExt;
pub use handle::CodeSandboxMicrovmHandleGuestImageExt;
pub use handle::CodeSandboxMicrovmHandleMicroVmHandleExt;
pub use handle::CodeSandboxMicrovmHandleExecutionBudgetExt;
pub use output::CodeSandboxMicrovmOutputMicroVmOutputSpoolExt;
