//! Moved from `crates/oneiron/src/memory/campaign_records/program.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A program's audience on the wire: the saved query whose entries enroll,
/// and the step of this program they enroll at.
///
/// The query must be the campaign owner's. A Manual or inactive query may be
/// bound: it gets no automatic intake, and the record's `automatic_intake`
/// says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramAudienceSpec {
    /// The saved query whose entries enroll.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub query_ref: EntityId,
    /// The step an entry enrolls at; one of this program's `steps`.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub entry_step_ref: EntityId,
}

/// `vault.campaign.program.read`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignProgramReadRequest {
    /// The program's campaign.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// The program.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub program_ref: EntityId,
}

/// `vault.campaign.program.archive`'s input. Archive keeps the program, its
/// steps and its audience readable; it enrolls no one afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCampaignProgramRequest {
    /// The program's campaign.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub campaign_ref: EntityId,
    /// The program.
    #[schemars(with = "String")]
    #[serde(with = "oneiron_contracts::entity_id::serde_hex")]
    pub program_ref: EntityId,
    /// Version the caller believes is current.
    pub expected_definition_version: u64,
}

/// Decodes a lowercase-hex payload.
pub fn payload_from_hex(hex: &str) -> Result<Vec<u8>> {
    let not_hex = || invalid("a step's outbound payload must be lowercase hex");
    if !hex.len().is_multiple_of(2) {
        return Err(not_hex());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| match (hex_nibble(pair[0]), hex_nibble(pair[1])) {
            (Some(high), Some(low)) => Ok((high << 4) | low),
            _ => Err(not_hex()),
        })
        .collect()
}

pub const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}
