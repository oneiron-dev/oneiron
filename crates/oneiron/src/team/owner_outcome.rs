//! OF-540: the owner's verdict on a team's deliverable settles the team.
//!
//! When the host puts a team's deliverable up for the owner's review, it
//! binds that review to the team: the team, its leader and the TASK it ran,
//! the output revision under review, the reviewed claim and its canonical
//! fingerprint, and that the review asks the owner to accept the deliverable.
//! Permission to run a write is not such a review.
//!
//! The owner's inbox decision on that exact claim is then an `OwnerVerdict`
//! anchor for the team ([ARCH-0079 #scoring]): an untouched approval settles
//! it a success, a rejection a failure. An amended approval accepts other
//! content than the team delivered, so it settles nothing. The outcome rests
//! on the decision's own receipt, in the decision's transaction. A team
//! already settled keeps its first outcome: one run is one observation.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ClaimBody;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::learning::Anchor;
use crate::side_table::{self, Named, SideTable};
use crate::store::GateDecisionRecord;

use super::receipt::{TeamOutcome, TeamReceipt, settle_team_outcome_in_txn, team_receipt_in_txn};
use super::run_binding::team_run_binding_in_txn;

/// Deliverable reviews bound to a team. Key: id16 (the reviewed claim).
const TEAM_DELIVERABLE: SideTable<[u8; 16], TeamDeliverableBinding, Named> =
    SideTable::new(&side_table::TEAM_DELIVERABLE);

/// Longest output revision kept.
const MAX_REVISION_BYTES: usize = 256;

/// What a bound review asks the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverableReview {
    /// Whether the team's deliverable, as pinned, is accepted.
    Acceptance,
}

/// One review of a team's deliverable. Host-only: never guest input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeamDeliverableBinding {
    pub team_ref: String,
    /// The team's leader, whose work the deliverable is.
    pub leader: AttemptId,
    /// The TASK the leader ran, as its queue row names it. The writer fills
    /// it from that row.
    pub root_task: Option<String>,
    /// The revision of the output under review, as the host pinned it.
    pub output_revision: String,
    pub claim: EntityId,
    /// The reviewed claim's canonical inbox fingerprint, hex.
    pub fingerprint: String,
    pub review: DeliverableReview,
    pub at: u64,
}

impl TeamDeliverableBinding {
    /// A review asking acceptance of `team_ref`'s deliverable, the reviewed
    /// claim `claim` with body `reviewed`.
    ///
    /// # Errors
    ///
    /// The fingerprint's encoding errors.
    pub fn acceptance(
        team_ref: impl Into<String>,
        leader: AttemptId,
        output_revision: impl Into<String>,
        claim: EntityId,
        reviewed: &ClaimBody,
        at: u64,
    ) -> Result<Self> {
        Ok(Self {
            team_ref: team_ref.into(),
            leader,
            root_task: None,
            output_revision: output_revision.into(),
            claim,
            fingerprint: bytes_to_hex_lower(&crate::inbox::inbox_claim_hash(reviewed)?),
            review: DeliverableReview::Acceptance,
            at,
        })
    }
}

/// Binds a deliverable review to its team. The team's receipt comes first: a
/// deliverable is reviewed once its team's work is recorded. Binding the
/// same review again is a no-op; a claim keeps the review it was bound to.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] for an unrecorded team, a leader that did not
/// start it, a malformed revision, or a claim bound to another review;
/// [`Error::EntityNotFound`] for an unknown leader; storage errors.
pub fn bind_team_deliverable(vault: &Vault, binding: &TeamDeliverableBinding) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| bind_team_deliverable_in_txn(vault, wtxn, binding))
}

/// [`bind_team_deliverable`] in the caller's transaction, beside the review
/// it binds.
///
/// # Errors
///
/// As [`bind_team_deliverable`].
pub fn bind_team_deliverable_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    binding: &TeamDeliverableBinding,
) -> Result<()> {
    if binding.output_revision.is_empty()
        || binding.output_revision.len() > MAX_REVISION_BYTES
        || binding.output_revision.contains('\0')
    {
        return Err(Error::InvalidClaimBody(
            "an output revision is 1..=256 bytes without NUL",
        ));
    }
    if team_receipt_in_txn(vault, txn, &binding.team_ref)?.is_none() {
        return Err(Error::InvalidClaimBody(
            "a team deliverable is bound after its team's receipt",
        ));
    }
    if !binding
        .team_ref
        .starts_with(&super::run::led_team_ref(binding.leader, ""))
        && team_run_binding_in_txn(vault, txn, binding.leader, &binding.team_ref)?.is_none()
    {
        return Err(Error::InvalidClaimBody(
            "a team deliverable names the leader that started the team",
        ));
    }
    let leader = AttemptQueue::new(vault)
        .get_in_txn(txn, binding.leader)?
        .ok_or(Error::EntityNotFound)?;
    let mut row = binding.clone();
    row.root_task = leader.task_ref;
    let key = *binding.claim.as_bytes();
    match TEAM_DELIVERABLE.get(&vault.store, txn, &key)? {
        Some(existing) if existing == row => Ok(()),
        Some(_) => Err(Error::InvalidClaimBody(
            "a reviewed claim keeps the deliverable it was bound to",
        )),
        None => TEAM_DELIVERABLE.put(&vault.store, txn, &key, &row),
    }
}

/// Settles the team whose deliverable `decision` reviewed, inside the
/// decision's transaction. `reviewed` is the claim as the owner reviewed it.
/// The caller passes only a decision its host authenticated as the owner's.
/// `None`: the decision reviewed no bound deliverable, accepted other
/// content, or the team was already settled.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for a bound team with no receipt; the
/// settlement's errors; storage errors.
pub(crate) fn settle_team_owner_verdict_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    decision: &GateDecisionRecord,
    reviewed: &ClaimBody,
) -> Result<Option<TeamReceipt>> {
    let Some(claim) = decision.claim_id else {
        return Ok(None);
    };
    let Some(binding) = TEAM_DELIVERABLE.get(&vault.store, txn, &claim)? else {
        return Ok(None);
    };
    let success = match (binding.review, decision.outcome.as_str()) {
        (DeliverableReview::Acceptance, "approved") => true,
        (DeliverableReview::Acceptance, "rejected") => false,
        _ => return Ok(None),
    };
    if binding.fingerprint != bytes_to_hex_lower(&crate::inbox::inbox_claim_hash(reviewed)?) {
        return Ok(None);
    }
    let receipt = team_receipt_in_txn(vault, txn, &binding.team_ref)?.ok_or(
        Error::CorruptedIndex("team deliverable without its receipt"),
    )?;
    let outcome = TeamOutcome {
        receipt: crate::receipt::gate_decision_receipt(decision).receipt_id,
        anchor: Anchor::OwnerVerdict,
        success,
        at: decision.created_at,
    };
    match &receipt.outcome {
        Some(existing) if *existing == outcome => Ok(Some(receipt)),
        Some(_) => Ok(None),
        None => settle_team_outcome_in_txn(vault, txn, &binding.team_ref, &outcome).map(Some),
    }
}
