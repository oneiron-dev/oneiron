use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::dreamer_runner::maintenance::representation::RepresentationSourceRef;
use serde::Deserialize;
use serde::Serialize;

pub mod approval;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentationKind {
    FollowUp,
    Reply,
    Introduction,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationCitation {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
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
            oneiron_contracts::entity_id::bytes_to_hex_lower(&self.revision)
        )
    }
}

pub fn invalid() -> Error {
    Error::InvalidClaimBody("invalid or stale representation proposal")
}
