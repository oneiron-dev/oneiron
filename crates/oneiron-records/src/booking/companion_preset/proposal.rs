//! Moved from `crates/oneiron/src/booking/companion_preset/proposal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use oneiron_verb_wire::booking::constraint::RankedSlot;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

// -------------------------------------------------------------------------
// Proposal state
// -------------------------------------------------------------------------
/// Opaque proposal identity: 32 unguessable bytes, minted from the CSPRNG and
/// domain-tagged so it cannot collide with any other digest booking persists.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ProposalId(pub [u8; 32]);

/// Index of a choice within one proposal's shortlist.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ChoiceId(pub u16);

/// One tappable choice. The slot is the oracle's, verbatim — nothing here
/// rounds, widens, or invents a time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProposalChoice {
    pub id: ChoiceId,
    pub slot: RankedSlot,
    pub label: String,
}

/// The ephemeral proposal. It stores participant token HASHES, never the raw
/// tokens: the raw values exist once, in the creation return value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionProposal {
    pub id: ProposalId,
    #[serde(with = "entity_ref_serde")]
    pub owner_ref: EntityId,
    pub preset_id: String,
    /// The configuration key the shortlist was solved under. Stored so confirm
    /// rebuilds its re-solve from the ROW and not from a caller argument.
    pub event_type: EventTypeKey,
    /// The visitor zone the shortlist was solved in, stored for the same
    /// reason.
    pub visitor_tz: String,
    pub choices: Vec<ProposalChoice>,
    pub participant_token_hashes: BTreeSet<[u8; 32]>,
    pub expires_at: u64,
}

/// One recorded tap. This is the stored form: `(participant, choice)` is unique
/// within a proposal, so the tap log is bounded by participants x choices and
/// a re-tap is idempotent rather than growth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposalTap {
    pub proposal_id: ProposalId,
    pub participant_token_hash: [u8; 32],
    pub choice_id: ChoiceId,
    pub tapped_at: u64,
}

/// The folded view of a proposal's taps, keyed by participant.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TapAggregate {
    pub choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>>,
}

impl TapAggregate {
    /// Folds a tap log. Taps from a hash the proposal never issued are dropped
    /// here as well as refused on the write path, so a row that somehow carried
    /// one could still not influence an intersection.
    pub fn fold(proposal: &CompanionProposal, taps: &[ProposalTap]) -> Self {
        let mut choices_by_participant: BTreeMap<[u8; 32], BTreeSet<ChoiceId>> = BTreeMap::new();
        for tap in taps {
            if !proposal
                .participant_token_hashes
                .contains(&tap.participant_token_hash)
            {
                continue;
            }
            choices_by_participant
                .entry(tap.participant_token_hash)
                .or_default()
                .insert(tap.choice_id);
        }
        Self {
            choices_by_participant,
        }
    }
}

/// The terminal artifact: the companion committed to one choice, softly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionSoftConfirmation {
    pub proposal_id: ProposalId,
    pub selected: ProposalChoice,
    #[serde(with = "entity_ref_serde")]
    pub confirmed_by_companion: EntityId,
    pub confirmed_at: u64,
}

/// Hex spelling for the one `EntityId` field each stored shape carries. The
/// booking module keeps this adapter per file rather than sharing one, matching
/// `config.rs`, `disclosure_rung.rs`, and `lifecycle.rs`.
pub mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}
