//! Evidence-citing user-voice proposals. Only owner resolution can arm OF-327.
mod approval;
mod context;
mod proposal;
#[cfg(test)]
mod tests;

use crate::compaction::output::OutputRef;
use crate::{EntityId, Error, Result};
pub use approval::{
    ApprovedRepresentation, RepresentationReview, schedule_approved_representation,
};
pub use context::{RepresentationContext, RepresentationSource};
pub use proposal::{RepresentationDraft, RepresentationPlanner};
use serde::{Deserialize, Serialize};

pub const REPRESENTATION_FACET: &str = "dreamer.representation";
const PREDICATE: &str = "dreamer.representation.proposal";
const RECORD_PREFIX: &[u8] = b"dreamer:representation:v1:proposal:";
const APPROVAL_PREFIX: &[u8] = b"dreamer:representation:v1:approval:";
const CONTENT_PREFIX: &str = "representation:";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationSourceRef {
    #[serde(with = "crate::serialize::entity_ref")]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    request: RepresentationRequest,
    content: OutputRef,
    evidence: Vec<RepresentationCitation>,
    voice: Vec<RepresentationCitation>,
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
fn key(prefix: &[u8], id: &EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}

pub(crate) use approval::validate_dispatch;
pub(super) use proposal::run;
