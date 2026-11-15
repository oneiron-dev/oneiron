//! Moved from `crates/oneiron/src/office_body/consent.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::typed_body::body_actor::BodyActor;
pub use oneiron_verb_wire::office_body::consent::SettleVerdict;
use serde::Deserialize;
use serde::Serialize;

/// Who opened a proposal, in which run, and when. A proposal opened by a
/// fork with no named proposal takes that fork's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalHeader {
    pub proposal: EntityId,
    pub artifact: EntityId,
    pub opener: BodyActor,
    pub run_root: Option<EntityId>,
    pub opened_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberVerdict {
    Waiting,
    Landed,
    Rejected,
    /// Its opener discarded it unsettled.
    LetGo,
}

/// What answered one member: a person's word, or a standing grant with the
/// gate decision that recorded its use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnsweringAuthority {
    Word { person: BodyActor },
    Grant { grant_ref: String, decision: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAnswer {
    pub by: AnsweringAuthority,
    /// Who called the settlement; under a grant, possibly the opener.
    pub caller: BodyActor,
    /// The live head and the fork head the review read.
    pub head: Vec<u8>,
    pub fork_head: Vec<u8>,
    /// The body head the landing left; `None` for a rejection.
    pub landed: Option<Vec<u8>>,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalMember {
    /// The artifact this fork edits; the proposal's home need not be its own.
    pub artifact: EntityId,
    pub fork: EntityId,
    pub opener: BodyActor,
    /// The run its opener named when it opened the fork: a label, never
    /// what a scope matches (FIX 3551).
    pub run_root: Option<EntityId>,
    /// The try the fork was opened from, which the host bound the opening
    /// surface to and the opening transaction proved live (FIX 3551): what a
    /// run-and-children scope names. `None` for an owner's or a direct
    /// opening, which belongs to no run.
    #[serde(default)]
    pub origin: Option<AttemptId>,
    pub verdict: MemberVerdict,
    pub answer: Option<MemberAnswer>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleVerdict {
    Landed,
    Rejected,
    Mixed,
    LetGo,
}

/// The holder ask raised for the members a settlement left waiting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAsk {
    /// The member artifact whose holders were asked.
    pub artifact: EntityId,
    /// The ask group its TASKs share.
    pub ask: EntityId,
    /// The waiting forks it asks about, in member order.
    pub forks: Vec<EntityId>,
    pub at: u64,
}

/// A holder ask the ask admission refused, kept until an ask is raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAskRefusal {
    /// The member artifact whose ask admission refused.
    pub artifact: EntityId,
    /// The waiting forks no holder was asked about, in member order.
    pub forks: Vec<EntityId>,
    /// The ask admission's refusal.
    pub reason: String,
    pub at: u64,
}

/// The one receipt that closes a proposal once no member waits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSettlement {
    pub verdict: BundleVerdict,
    pub at: u64,
    pub reason: Option<String>,
}
