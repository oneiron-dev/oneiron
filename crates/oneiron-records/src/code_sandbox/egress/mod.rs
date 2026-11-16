//! Moved from `crates/oneiron/src/code_sandbox/egress/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_sandbox::egress::receipt::EgressReceipt;

/// The transport a [`RawEndpointGrant`] admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawProtocol {
    Tcp,
    Udp,
}
pub mod receipt;
