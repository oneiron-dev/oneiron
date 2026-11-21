//! Display-edit proposals as typed rows (FIX [SECRETS-LABEL-PURPOSE-VERBS],
//! [DEVICE-DISPLAY-NAME]; Engine RULING DISPLAY-EDIT-PROPOSAL-SCOPE = A):
//! `self.display_edits.propose`, an agent's proposal of a secret's label or
//! purpose or a machine's name; `vault.display_edits.list`, `.accept` and
//! `.decline`, the owner's answers. Each owner row runs the engine read or
//! door its `/v1/owner/display-edits` route runs ([`Vault::display_edit_proposals`],
//! [`Vault::accept_display_edit`], [`Vault::decline_display_edit`]) under the
//! owner's proof, with the same reply fields.
//!
//! The agent row is the agent's request only: it grants nothing and edits
//! nothing, and the agent is the host's binding, never a field it sends. An
//! accept runs the owner's own door, so the Gate record names the owner.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
pub use crate::display_edits::DisplayEditTarget;
use crate::display_edits::{DisplayEditProposal, DisplayEditProposer};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding,
};
use crate::task_verb::task_create_origin_in_txn;
use oneiron_verb_wire::verbs::secret_custody::entity_id;

/// `self.display_edits.propose`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditProposeRequest {
    /// The edit: `secret_label`, `secret_purpose` or `machine_name`.
    pub target: DisplayEditTarget,
    /// What it edits: a secret's handle, or a machine's 32 hex.
    pub subject: String,
    /// The proposed one-line text; `null` or blank proposes clearing it.
    #[serde(default)]
    pub value: Option<String>,
    /// Why, in one line of at most 512 bytes.
    pub why: String,
}

/// One open proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditItem {
    /// The proposal, 32 hex: what `vault.display_edits.accept` and
    /// `.decline` take as `id`.
    pub id: String,
    /// The edit it asks for.
    pub target: DisplayEditTarget,
    /// What it edits: a secret's bare handle, or a machine's 32 hex.
    pub subject: String,
    /// The proposed text; null asks the owner to clear it.
    pub value: Option<String>,
    /// The agent's why.
    pub why: String,
    /// The proposing agent, 32 hex.
    pub proposer: String,
    /// When it was filed, in recording seconds.
    pub proposed_at: u64,
}

/// `vault.display_edits.list`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditListReply {
    /// Every open proposal, newest first.
    pub proposals: Vec<DisplayEditItem>,
}

/// `vault.display_edits.accept`'s and `.decline`'s input: the body `POST
/// /v1/owner/display-edits/accept` and `/decline` take.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditAnswerRequest {
    /// The proposal, 32 hex.
    pub id: String,
}

/// An accepted proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditAcceptReply {
    /// The proposal, closed now.
    pub proposal: DisplayEditItem,
    /// The Gate receipt of the owner's act it ran.
    pub receipt: String,
}

/// A declined proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayEditDeclineReply {
    /// The proposal, closed now; nothing it names changed.
    pub proposal: DisplayEditItem,
}

/// `self.display_edits.propose`: the calling agent proposes a display edit
/// for the owner to accept or decline.
///
/// # Errors
/// `FORBIDDEN` for a caller that is no agent, or an anonymous off-record
/// session; every refusal of the engine's proposal door.
pub fn propose_display_edit_as_caller(
    memory: &Memory<'_>,
    input: DisplayEditProposeRequest,
) -> MemoryResult<DisplayEditItem> {
    let proposer = display_edit_proposer(memory)?;
    let proposal = memory.vault().propose_display_edit(
        &proposer,
        input.target,
        &input.subject,
        input.value.as_deref(),
        &input.why,
    )?;
    Ok(proposal.into())
}

/// `vault.display_edits.list`: every open proposal, newest first.
///
/// # Errors
/// Every refusal of [`Vault::display_edit_proposals`].
pub fn list_display_edits_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<DisplayEditListReply> {
    Ok(DisplayEditListReply {
        proposals: vault
            .display_edit_proposals(owner)?
            .into_iter()
            .map(DisplayEditItem::from)
            .collect(),
    })
}

/// `vault.display_edits.accept`: the owner's door makes the proposed edit as
/// his own act, and the proposal closes.
///
/// # Errors
/// An `id` that is not 32 hex; every refusal of
/// [`Vault::accept_display_edit`].
pub fn accept_display_edit_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: DisplayEditAnswerRequest,
) -> MemoryResult<DisplayEditAcceptReply> {
    let id = entity_id("id", &input.id)?;
    let accepted = vault.accept_display_edit(owner, id)?;
    Ok(DisplayEditAcceptReply {
        proposal: accepted.proposal.into(),
        receipt: accepted.receipt,
    })
}

/// `vault.display_edits.decline`: the proposal closes, and nothing it names
/// changes.
///
/// # Errors
/// An `id` that is not 32 hex; every refusal of
/// [`Vault::decline_display_edit`].
pub fn decline_display_edit_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: DisplayEditAnswerRequest,
) -> MemoryResult<DisplayEditDeclineReply> {
    let id = entity_id("id", &input.id)?;
    Ok(DisplayEditDeclineReply {
        proposal: vault.decline_display_edit(owner, id)?.into(),
    })
}

/// The proposer of a display edit: the calling agent, and the leased try its
/// host bound. Only an agent proposes; a proposal is a record, so an
/// anonymous off-record session cannot file one.
fn display_edit_proposer(memory: &Memory<'_>) -> MemoryResult<DisplayEditProposer> {
    verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "only an agent proposes a display edit",
            &[
                "The owner makes the edit at its own door: a secret's label or purpose, or POST /v1/owner/machines/name.",
            ],
        ));
    }
    if memory.keeps_no_record() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a display-edit proposal is a record, and an anonymous off-record session keeps none",
            &["Propose outside the anonymous session."],
        ));
    }
    let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
    let origin = task_create_origin_in_txn(memory, &txn, memory.task_host())?;
    drop(txn);
    Ok(DisplayEditProposer {
        agent: memory.actor(),
        attempt: origin.and_then(|origin| origin.parent_attempt()),
    })
}

impl From<DisplayEditProposal> for DisplayEditItem {
    fn from(proposal: DisplayEditProposal) -> Self {
        Self {
            id: proposal.id.to_hex(),
            target: proposal.target,
            subject: proposal.subject,
            value: proposal.value,
            why: proposal.why,
            proposer: proposal.proposer.to_hex(),
            proposed_at: proposal.proposed_at,
        }
    }
}
