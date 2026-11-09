//! The engine's open egress proxy. No guest network or credential proxy is
//! used as a transport. The owner allowlist is an optional narrowing dial.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::egress::*;

#[doc(hidden)]
pub mod fixture;
#[doc(hidden)]
pub mod floor;
#[doc(hidden)]
pub mod name_gate;
#[doc(hidden)]
pub mod receipt;

pub use floor::guest_network_permits;
pub use fixture::CodeSandboxEgressFixtureFixtureForwardExt;
pub use floor::CodeSandboxEgressFloorGuestPermitsExt;
pub use floor::CodeSandboxEgressFloorVaultExt;
pub use name_gate::CodeSandboxEgressNameGateEgressNameRefusalExt;
pub use name_gate::CodeSandboxEgressNameGateFieldsExt;
pub use receipt::CodeSandboxEgressReceiptVaultExt;
