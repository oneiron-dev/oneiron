//! Moved from `crates/oneiron/src/consent/bundle_projection.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::gate_decision::types::GateDecisionId;
use serde::Deserialize;
use serde::Serialize;

/// The two owner actions over one run's consent bundle. Partial member
/// selection is deliberately not a variant: the bundle resolves as a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateConsentBundleAction {
    Approve,
    Decline,
}

impl GateConsentBundleAction {
    /// The stable token for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Decline => "decline",
        }
    }
}

/// One still-pending consent row projected into a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConsentBundleMember {
    pub decision_id: GateDecisionId,
    #[serde(with = "entity_id_hex")]
    pub claim_id: EntityId,
    pub created_at: u64,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    pub reason_codes: Vec<String>,
}

/// One run's pending consent rows as a single named, content-bound unit.
///
/// This is a PROJECTION over the durable pending-consent, claim, and attempt
/// rows: it is not persisted, owns no database, and mints no entity. Identity
/// is `bundle_id`; `name` and `agent_label` are presentation metadata a UI may
/// skin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConsentBundle {
    pub schema_version: u8,
    pub bundle_id: [u8; 32],
    pub name: String,
    pub dreamer_run_id: String,
    pub agent_label: Option<String>,
    pub members: Vec<GateConsentBundleMember>,
}

/// Typed view of the ONE durable gate-decision row a bundle resolution
/// appends. The row itself stays an ordinary `GateDecisionRecord` in the
/// existing ledger; this carries the bundle-shaped fields its schema has no
/// slot for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConsentBundleReceipt {
    pub schema_version: u8,
    pub receipt_id: GateDecisionId,
    pub bundle_id: [u8; 32],
    pub dreamer_run_id: String,
    pub action: GateConsentBundleAction,
    #[serde(with = "entity_id_hex_seq")]
    pub member_claim_ids: Vec<EntityId>,
    pub created_at: u64,
}

/// [`EntityId`] carries no serde impl, so bundle wire rows spell claim ids as
/// the same lowercase hex the rest of this module's surface uses.
mod entity_id_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    use oneiron_contracts::entity_id::EntityId;

    pub(super) fn serialize<S>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&id.to_hex())
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<EntityId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

/// [`entity_id_hex`] over a sequence.
mod entity_id_hex_seq {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use oneiron_contracts::entity_id::EntityId;

    pub(super) fn serialize<S>(ids: &[EntityId], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<EntityId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|hex| EntityId::from_hex(hex).map_err(serde::de::Error::custom))
            .collect()
    }
}
