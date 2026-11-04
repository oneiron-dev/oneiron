//! A project's depth birth record, as a POLICY_MANIFEST contribution carries
//! it. Encoding, signing and verification stay in the engine.

use serde::{Deserialize, Serialize};

use oneiron_contracts::entity_id::EntityId;

/// The first bytes of every project-depth contribution id.
pub const PROJECT_DEPTH_ID_PREFIX: &[u8; 4] = &[0xD5, 0x9A, 0x3C, 0x7E];

/// The immutable birth of one project identity: its depth and the manifest
/// it was born from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDepthBirth {
    /// The record's grammar version.
    pub version: u8,
    /// The project's entity ref.
    pub project_ref: String,
    /// The project's depth.
    pub depth: u64,
    /// The manifest the birth was taken from.
    pub source_manifest: String,
    /// The hash of that manifest's body.
    pub source_hash: [u8; 32],
    /// The owner's signature over the birth, if signed.
    pub owner: Option<ProjectBirthOwnerProof>,
}

/// The owner's signature over a project's depth birth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBirthOwnerProof {
    /// The vault the owner signed in.
    pub vault_id: [u8; 32],
    /// The signing owner's actor ref.
    pub actor_ref: String,
    /// The authority frontier the signature was made at.
    pub frontier: [u8; 32],
    /// The signature suite.
    pub suite: String,
    /// The signing public key.
    pub public_key: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// Whether `id` lies in the project-depth contribution id range.
#[must_use]
pub fn is_project_depth_id(id: &EntityId) -> bool {
    id.as_bytes().starts_with(PROJECT_DEPTH_ID_PREFIX)
}

/// Whether `bytes` carry a project-depth contribution's tagged envelope.
#[must_use]
pub fn is_project_depth_contribution(bytes: &[u8]) -> bool {
    // Distinct tagged envelope. A malformed candidate must never downgrade
    // to an ordinary locally trusted policy pack.
    rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
        .ok()
        .is_some_and(|value| {
            value.as_map().is_some_and(|entries| {
                entries.iter().any(|(key, value)| {
                    key.as_str() == Some("kind")
                        && matches!(
                            value.as_str(),
                            Some("default" | "default_edit" | "birth" | "edit")
                        )
                })
            })
        })
}
