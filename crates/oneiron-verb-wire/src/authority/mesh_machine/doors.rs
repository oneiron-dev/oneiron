//! Moved from `crates/oneiron/src/authority/mesh_machine/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::mesh_machine::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A paired MACHINE's address and proofs of both keys over its binding.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshMachineBinding {
    pub machine: EntityId,
    pub address: MeshMachineAddress,
    pub device_key: [u8; 32],
    pub pairing_slip_id: [u8; 32],
    /// Ed25519 signature by the key that paired.
    pub device_proof: Vec<u8>,
    /// Ed25519 signature by the derived transport key, on the same transcript.
    pub transport_proof: Vec<u8>,
}

/// Allow or revoke exactly one ALPN for a bound MACHINE and endpoint key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshAlpnGrant {
    pub machine: EntityId,
    pub endpoint_key: [u8; 32],
    pub alpn: Vec<u8>,
    pub allow: bool,
}

/// Public install identity and possession proofs; never either signing seed.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MeshBindingIdentity {
    pub machine: EntityId,
    pub device_key: [u8; 32],
    pub endpoint_key: [u8; 32],
    pub device_proof: Vec<u8>,
    pub transport_proof: Vec<u8>,
}
