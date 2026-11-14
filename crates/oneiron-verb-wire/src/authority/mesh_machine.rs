//! Moved from `crates/oneiron/src/authority/mesh_machine.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::mesh_machine::doors::MeshAlpnGrant;
pub use crate::authority::mesh_machine::doors::MeshBindingIdentity;
pub use crate::authority::mesh_machine::doors::MeshMachineBinding;
use serde::Deserialize;
use serde::Serialize;
use std::net::SocketAddr;

/// Address hints. This structure has no authority by itself.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineAddress {
    pub endpoint_key: [u8; 32],
    pub direct_addrs: Vec<SocketAddr>,
    pub relay_url: Option<String>,
}
pub mod doors;
