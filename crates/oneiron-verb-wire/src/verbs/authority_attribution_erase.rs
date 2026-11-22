//! Wire types for the owner's erase of one subject's authority attribution.
//! `oneiron` re-exports each item at its verb path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.authority.attribution.erase`'s input: the subject whose authority
/// attribution the Owner erases on this vault.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAttributionEraseRequest {
    /// The subject, 32 hex.
    pub subject: EntityId,
    /// An asker's approved check-in for this erase, 32 hex
    /// (`authority_attribution_erase_effect_digest`): the Owner applies it
    /// on their own proof, and the answer names its asker.
    #[serde(default)]
    pub check_in_ref: Option<String>,
}

/// `vault.authority.attribution.erase`'s answer: the overlays deleted here
/// and when the subject's erasure first stood here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AuthorityAttributionErased {
    /// How many overlay rows of the subject this erase deleted here.
    pub rows_erased: u64,
    /// When the subject's erasure first stood here (recording clock): this
    /// erase's time, or an earlier erase's.
    pub at: u64,
    /// The check-in decision the act ran on.
    pub check_in: crate::check_in::CheckInDecision,
}
