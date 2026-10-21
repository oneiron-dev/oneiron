//! A Keep the Gate holds (FIX 5753): the responder's approval of the exact
//! retained alternative its Keep selected, in the settlement's own commit.
//!
//! A Keep of a retained alternative lands it Auto under the current Gate, as
//! the Dreamer's claim from its round ([`KeepAs::Auto`]); that path is
//! unchanged. When the Gate holds exactly that landing for review, on reasons
//! that are all in [`KEEP_APPROVABLE_PENDING_REASONS`], the landing notes it
//! and the settlement still aborts whole. The responder's door
//! (`Memory::settle_conflict`) may then retry once, in a fresh write
//! transaction ([`KeepAs::Approved`]): the same alternative is born Proposed,
//! with the same source, provenance and signed MACHINE birth, and the
//! responder's gated, signed Approve transition approves it there, through
//! the machinery a reviewed proposal is approved by. The supersession and the
//! answer follow in that same transaction. The Keep is the yes: nothing asks
//! again, no standing permit or ceiling changes, and no retry is queued.

use std::cell::Cell;

use crate::claim::ClaimApprovalStatus;
use crate::consent::OwnerAuthoredWrite;
use crate::error::{Error, GateDenialOutcome, GateDenialReason, Result};
use crate::run_tree::GateConsentBundleAction;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The Gate holds a responder's Keep approves (Engine 10-21 18:3x): the
/// actor, source and criticality ceilings, a missing signed policy authority,
/// the automatic checker's hold or silence, the Dreamer's persona and
/// mirroring isolation, and a forward claim's low confidence. Every reason of
/// the hold must be one of these; a Deny, an external-effect hold or a reason
/// the typed taxonomy does not know never is.
pub(crate) const KEEP_APPROVABLE_PENDING_REASONS: [GateDenialReason; 9] = [
    GateDenialReason::PendingActorCeiling,
    GateDenialReason::PendingSourceTrust,
    GateDenialReason::PendingCriticalityFloor,
    GateDenialReason::PendingPolicyManifestAuthority,
    GateDenialReason::PendingChecker,
    GateDenialReason::PendingCheckerUnavailable,
    GateDenialReason::PendingPersonaIsolation,
    GateDenialReason::PendingMirroringIsolation,
    GateDenialReason::PendingCarryForwardConfidence,
];

/// How a Keep lands the retained alternative it selected.
#[derive(Clone, Copy)]
pub(crate) enum KeepAs<'a> {
    /// Auto under the current Gate, as every Keep lands it first. A hold of
    /// that landing on [`KEEP_APPROVABLE_PENDING_REASONS`] alone sets the
    /// flag; the refusal itself is returned unchanged.
    Auto(&'a Cell<bool>),
    /// Born Proposed and approved by the responder in the same transaction.
    Approved(&'a KeepApproval),
}

/// A responder's approval of its held Keep, as its door rechecked the
/// responder in the retry's own transaction.
pub(crate) struct KeepApproval {
    /// The responder, approving as its own actor.
    actor: WriteActor,
    /// The owner-tier proof that answers the claim's owner-answer
    /// obligation: an Owner's alone, never a delegate's.
    owner_answer: Option<OwnerAuthoredWrite>,
    approved: Cell<Option<ApprovedKeep>>,
}

/// The landing a [`KeepApproval`] approved.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ApprovedKeep {
    pub(crate) claim: EntityId,
    /// Whether its approval consolidates VAD once the transaction commits.
    pub(crate) dreamer_run: bool,
}

impl KeepApproval {
    pub(crate) fn new(actor: WriteActor, owner_answer: Option<OwnerAuthoredWrite>) -> Self {
        Self {
            actor,
            owner_answer,
            approved: Cell::new(None),
        }
    }

    /// The landing this approval approved, once it has.
    pub(crate) fn approved(&self) -> Option<ApprovedKeep> {
        self.approved.get()
    }
}

impl KeepAs<'_> {
    /// The status the landing asks the Gate for.
    pub(crate) const fn requested(self) -> ClaimApprovalStatus {
        match self {
            Self::Auto(_) => ClaimApprovalStatus::Auto,
            Self::Approved(_) => ClaimApprovalStatus::Proposed,
        }
    }

    /// The status the landing must stand at once it is written.
    pub(crate) const fn landed(self) -> ClaimApprovalStatus {
        match self {
            Self::Auto(_) => ClaimApprovalStatus::Auto,
            Self::Approved(_) => ClaimApprovalStatus::Approved,
        }
    }

    /// Notes `error`, the Gate's refusal of an Auto landing, when it is a
    /// typed hold the responder may approve.
    pub(crate) fn note_refusal(self, error: &Error) {
        if let Self::Auto(held) = self
            && approvable_hold(error)
        {
            held.set(true);
        }
    }

    /// Approves `claim`, the landing just born Proposed, as the responder,
    /// through the claim settlement's own Gate, tray closure and signed
    /// Approve event. An Auto landing approves nothing.
    pub(crate) fn approve_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        claim: EntityId,
        now: u64,
    ) -> Result<()> {
        let Self::Approved(approval) = self else {
            return Ok(());
        };
        let settled = vault.settle_proposed_claim_in_txn(
            txn,
            claim,
            GateConsentBundleAction::Approve,
            approval.actor,
            approval.owner_answer.as_ref(),
            now,
        )?;
        approval.approved.set(Some(ApprovedKeep {
            claim,
            dreamer_run: settled.dreamer_run,
        }));
        Ok(())
    }
}

/// Whether `error` is a typed Gate hold whose every reason a responder's
/// Keep approves. Read from the typed taxonomy only, never from its text.
fn approvable_hold(error: &Error) -> bool {
    error.gate_denial().is_some_and(|denial| {
        denial.outcome() == GateDenialOutcome::Pending
            && !denial.reason_codes().is_empty()
            && denial
                .reason_codes()
                .iter()
                .all(|reason| KEEP_APPROVABLE_PENDING_REASONS.contains(reason))
    })
}
