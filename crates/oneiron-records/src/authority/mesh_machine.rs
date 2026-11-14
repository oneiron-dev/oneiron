//! Moved from `crates/oneiron/src/authority/mesh_machine.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signature;
pub use oneiron_verb_wire::authority::mesh_machine::MeshMachineAddress;
pub use oneiron_verb_wire::authority::mesh_machine::doors::MeshAlpnGrant;
pub use oneiron_verb_wire::authority::mesh_machine::doors::MeshBindingIdentity;
pub use oneiron_verb_wire::authority::mesh_machine::doors::MeshMachineBinding;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineAddressEnvelope {
    pub domain: String,
    pub version: u8,
    pub address: MeshMachineAddress,
}

impl MeshMachineAddressEnvelope {
    pub const DOMAIN: &'static str = DOMAIN;

    pub fn new(address: MeshMachineAddress) -> Self {
        Self {
            domain: DOMAIN.into(),
            version: 1,
            address,
        }
    }
}
