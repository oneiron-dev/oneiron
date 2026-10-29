//! Evidence-citing user-voice plans. A plan is saved at once for the owner's
//! send review (OF-023), or held in the run tray where the Gate parks it.
//! Only the owner's own approval arms OF-327; the Dreamer never sends.
mod approval;
mod context;
mod proposal;
#[cfg(test)]
mod tests;

use rmpv::Value;

use crate::compaction::output::OutputRef;
use crate::{EntityId, Error, Result};
pub use approval::{
    ApprovedRepresentation, RepresentationReview, schedule_approved_representation,
};
pub use context::{DestinationContext, RepresentationContext, RepresentationSource};
pub use proposal::{PrematerializedDraft, RepresentationDraft, RepresentationPlanner};
use serde::{Deserialize, Serialize};

pub const REPRESENTATION_FACET: &str = "dreamer.representation";
const PREDICATE: &str = "dreamer.representation.proposal";
const CONTENT_PREFIX: &str = "representation:";
/// The prefix of an approved representation's content ref, for the served
/// sink's content resolver (FIX 1469).
pub(crate) const REPRESENTATION_CONTENT_PREFIX: &str = CONTENT_PREFIX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationKind {
    FollowUp,
    Reply,
    Introduction,
    Post,
}

/// The host selects a bounded source set, never a new read grant. Both sets
/// are read under the vault's Dreamer principal and current scoped-read policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationRequest {
    #[serde(with = "crate::serialize::entity_ref")]
    pub owner: EntityId,
    pub kind: RepresentationKind,
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub evidence: Vec<RepresentationSourceRef>,
    pub voice: Vec<RepresentationSourceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepresentationSourceRef {
    #[serde(with = "crate::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub claim: EntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationCitation {
    #[serde(with = "crate::serialize::entity_ref")]
    pub claim: EntityId,
    pub revision: [u8; 32],
    pub quote: String,
}
impl RepresentationCitation {
    /// A stable in-text marker. The quote is validated against the cited
    /// claim's exact revision, not accepted as a planner assertion.
    pub fn marker(&self) -> String {
        format!(
            "[{}@{}]",
            self.claim.to_hex(),
            crate::entity_id::bytes_to_hex_lower(&self.revision)
        )
    }
}

/// A request as its packet keeps it: everything but the owner, so neither
/// the packet's hash nor the claim it lands as names them (FIX 4512). The
/// owner stands in the plan's envelope, which an erase scrubs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PacketRequest {
    kind: RepresentationKind,
    verb: String,
    channel: String,
    target: String,
    evidence: Vec<RepresentationSourceRef>,
    voice: Vec<RepresentationSourceRef>,
}
impl RepresentationRequest {
    fn packet(&self) -> PacketRequest {
        PacketRequest {
            kind: self.kind,
            verb: self.verb.clone(),
            channel: self.channel.clone(),
            target: self.target.clone(),
            evidence: self.evidence.clone(),
            voice: self.voice.clone(),
        }
    }
}
impl PacketRequest {
    /// The request again, for the live `owner` its envelope names.
    fn with_owner(&self, owner: EntityId) -> RepresentationRequest {
        RepresentationRequest {
            owner,
            kind: self.kind,
            verb: self.verb.clone(),
            channel: self.channel.clone(),
            target: self.target.clone(),
            evidence: self.evidence.clone(),
            voice: self.voice.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    request: PacketRequest,
    content: OutputRef,
    evidence: Vec<RepresentationCitation>,
    voice: Vec<RepresentationCitation>,
    /// The stewardship reach-out a follow-up drafts: the plan lands, is
    /// reviewed and sends only while that reach-out stands at this pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reach_out: Option<ReachOutPin>,
}

/// A reach-out and the revision a follow-up was drafted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReachOutPin {
    #[serde(with = "crate::serialize::entity_ref")]
    claim: EntityId,
    revision: [u8; 32],
}
impl Packet {
    fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid())
    }
    fn id(&self) -> Result<EntityId> {
        crate::codebase::entity_id_from_hash_material(
            b"oneiron:dreamer-representation:v1",
            &[&self.bytes()?],
        )
    }
    fn content_ref(&self) -> Result<String> {
        Ok(format!(
            "{CONTENT_PREFIX}{}:{}:{}",
            self.id()?.to_hex(),
            crate::entity_id::bytes_to_hex_lower(&self.content.hash),
            self.content.byte_len
        ))
    }
    fn trigger_ref(&self) -> Result<String> {
        Ok(format!("{CONTENT_PREFIX}{}", self.id()?.to_hex()))
    }
}
fn invalid() -> Error {
    Error::InvalidClaimBody("invalid or stale representation proposal")
}

/// Every entity row a queued plan's input names: its packet's requested
/// evidence and voice sources, its validated citations, and the reach-out a
/// follow-up drafts from. The owner is not among them: they stand in the
/// plan's envelope, never in the queue (FIX 4512).
pub(crate) fn packet_claims(input: &Value) -> Result<Vec<EntityId>> {
    let packet: Packet =
        serde_json::from_str(input.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let mut claims = Vec::new();
    claims.extend(packet.request.evidence.iter().map(|source| source.claim));
    claims.extend(packet.request.voice.iter().map(|source| source.claim));
    claims.extend(packet.evidence.iter().map(|citation| citation.claim));
    claims.extend(packet.voice.iter().map(|citation| citation.claim));
    claims.extend(packet.reach_out.map(|pin| pin.claim));
    Ok(claims)
}

pub(crate) use approval::{
    erase_approval_actor_in_txn, representation_approval_is_live_in_txn, validate_dispatch,
};
pub(crate) use proposal::erase_proposal_actor_in_txn;
pub(super) use proposal::{review_revision, run, withdraw_follow_ups_in_txn};
