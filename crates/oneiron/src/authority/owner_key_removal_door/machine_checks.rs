//! The machine removal door's checks before its first write, written once:
//! the door runs them on a read before it asks and again inside its write.

use super::*;
use crate::authority::machine_answers::AnswerAct;

/// What the caller of the machine removal door asked for.
pub(super) struct MachineRemovalRequest {
    pub(super) surface: ActSurface,
    pub(super) machine: EntityId,
    pub(super) seen: Option<[u8; 32]>,
    pub(super) confirmation: LastDeviceKeyConfirmation,
}

/// Where the checks run. A key under a device PIN proves only inside the
/// window the ask opens, so "no owner key proves now" is no answer before
/// the ask; in the write it means the removal ends no key.
pub(super) enum MachineRemovalCheckPhase {
    /// On the door's read: with no proving key the checks stop there.
    BeforeAsk,
    /// In the door's write: with no proving key the removal ends no key.
    BeforeWrite,
}

/// What a removal that passed its checks does: the owner keys it would end,
/// and which of the door's two writes it takes.
pub(super) struct MachineRemovalPlan {
    pub(super) ending: Vec<EnrolledOwnerKey>,
    pub(super) action: MachineRemovalAction,
}

/// The door's two writes.
pub(super) enum MachineRemovalAction {
    /// The fold already holds the machine removed and live owner keys still
    /// name it: the door ends them and writes no second removal.
    EndKeys,
    /// The removal is written as the owner's answer.
    Answer(AnswerAct),
}

impl Vault {
    /// The machine removal's checks before its first write, in the door's
    /// order: the owner's proof, the fold, the keys the removal would end,
    /// the last-device-key question, then either the second removal's `seen`
    /// check or the answer's checks before the signature. On the read, with
    /// no proving key, they stop at [`RemovalCheck::NoProvingKey`] and the
    /// door asks; in the write they go on and the removal ends no key.
    pub(super) fn machine_removal_checks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        request: &MachineRemovalRequest,
        phase: MachineRemovalCheckPhase,
    ) -> Result<RemovalCheck<MachineRemovalPlan>> {
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let ending = match self.proving_owner_keys_ending_with_machine_in_txn(
            txn,
            &fold,
            request.machine,
        )? {
            Some(ending) => ending,
            None if matches!(phase, MachineRemovalCheckPhase::BeforeAsk) => {
                return Ok(RemovalCheck::NoProvingKey);
            }
            None => Vec::new(),
        };
        if request.confirmation == LastDeviceKeyConfirmation::NotGiven && !ending.is_empty() {
            let remaining = self.owner_keys_remaining_in_txn(txn, &fold, &ending)?;
            if remaining.needs_recovery() {
                return Ok(RemovalCheck::LastDeviceKey(remaining));
            }
        }
        // Removed in a head the machine stands under here, the roster's or
        // the pinned anchor's, as `set_machine_role` reads it: the mark of an
        // anchor this install does not pin removes nothing here.
        let pin = fold.pinned_root.as_ref();
        let removed = fold.machine(request.machine).filter(|folded| {
            folded
                .standing_heads(pin)
                .into_iter()
                .any(|head| head.removed)
        });
        if let Some(standing) = removed
            && !ending.is_empty()
        {
            check_removed_machine_revision(standing, pin, request.seen)?;
            return Ok(RemovalCheck::Ready(
                fold,
                MachineRemovalPlan {
                    ending,
                    action: MachineRemovalAction::EndKeys,
                },
            ));
        }
        let proves_joins = owner.proves_joins_in_txn(self, txn)?;
        let mut answer = AnswerAct::by_owner(
            (actor, proves_joins),
            request.surface,
            MachineRole::Removed,
            request.seen,
        );
        answer.last_device_key = request.confirmation;
        let ending = self.machine_removal_ending_in_txn(txn, &fold, &answer, request.machine)?;
        Ok(RemovalCheck::Ready(
            fold,
            MachineRemovalPlan {
                ending,
                action: MachineRemovalAction::Answer(answer),
            },
        ))
    }
}
