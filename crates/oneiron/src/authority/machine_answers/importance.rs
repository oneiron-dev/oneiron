//! The importance of an owner's machine answer from the value in force.
//!
//! A door derives the importance on a read before it asks, and its writer
//! derives again inside the write. The read uses the writer's checks
//! before any signature to derive the importance.

use ed25519_dalek::SigningKey;

use crate::error::{Error, Result};
use crate::world_keys::OwnerActImportance;
use crate::{EntityId, Vault};

use super::*;

/// What the writer's checks before the signature answered: the carrier and
/// its key, the owner keys the answer would end, the machine's current
/// answer revision, and the importance from the value in force.
pub(super) struct OwnerAnswerChecks {
    /// This install as the carrier of the owner's act: its machine.
    pub(super) carrier: EntityId,
    /// The carrier's install key.
    pub(super) key: SigningKey,
    /// The owner keys a removal that stands would end on this install.
    pub(super) ending: Vec<EnrolledOwnerKey>,
    /// The machine's answer revision as the deciding surface showed it.
    current: [u8; 32],
    /// The act's importance from the value in force.
    pub(super) importance: OwnerActImportance,
}

/// The importance of the machine answer `profile` would write on `fold`,
/// with `ending` the owner keys it would end.
///
/// An answer that ends an owner key is an identity act, so it is important
/// whatever its direction. One with no standing head puts a key on the
/// roster, so it is important. One in any role but `Removed` that changes
/// the machine's keys or class is important, because the comparator knows
/// roles only. Any other answer is important exactly when its role change
/// widens.
fn machine_answer_importance(
    fold: &AuthorityFold,
    profile: &MachineProfile,
    ending: &[EnrolledOwnerKey],
) -> OwnerActImportance {
    if !ending.is_empty() {
        return OwnerActImportance::Important;
    }
    let Some(folded) = fold.machine(profile.machine) else {
        return OwnerActImportance::Important;
    };
    let heads = folded.standing_heads(fold.pinned_root.as_ref());
    if heads.is_empty() {
        return OwnerActImportance::Important;
    }
    if profile.role != MachineRole::Removed
        && heads.iter().any(|head| {
            head.profile.machine_key != profile.machine_key
                || head.profile.encryption_key != profile.encryption_key
                || head.profile.device_class != profile.device_class
        })
    {
        return OwnerActImportance::Important;
    }
    let standing = if heads.iter().any(|head| head.conflicted) {
        None
    } else {
        let mut roles = heads.iter().map(|head| head.profile.role);
        match roles.next() {
            None => None,
            Some(first) => {
                if roles.all(|role| role == first) {
                    Some(first)
                } else {
                    None
                }
            }
        }
    };
    OwnerActImportance::of_direction(profile.role.direction_from(standing))
}

/// The profile the owner's answer `role` about `machine` would write on
/// `fold` for `owner`: the next revision above the heads the machine stands
/// under, copying the newest head's identity.
pub(super) fn role_answer_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    machine: EntityId,
    role: MachineRole,
) -> Result<MachineProfile> {
    let folded = fold.machine(machine).ok_or_else(invalid_authority)?;
    // The machine's identity as the newest head it stands under names
    // it, the roster's or the pinned anchor's; the next revision tops
    // both.
    let mut heads = folded.standing_heads(fold.pinned_root.as_ref());
    heads.sort_by_key(|head| head.profile.revision);
    let current = heads.last().ok_or_else(invalid_authority)?;
    if heads.iter().any(|head| head.removed) {
        return Err(invalid_authority());
    }
    Ok(MachineProfile {
        owner,
        role,
        revision: current
            .profile
            .revision
            .checked_add(1)
            .ok_or_else(invalid_authority)?,
        carrier: None,
        act: None,
        ..current.profile.clone()
    })
}

/// The profile the enrolment of `request` in `role` would write on `fold`
/// for `owner`: a joining profile for a machine the roster never held, else
/// the class-only revision of the machine the roster already holds.
pub(super) fn enrolment_profile(
    fold: &AuthorityFold,
    owner: EntityId,
    request: &MachineEnrolmentRequest,
    role: MachineRole,
) -> Result<MachineProfile> {
    // A machine the roster holds never joins again; only its class is
    // revised here (FIX 3835).
    if fold
        .machine(request.machine)
        .is_some_and(|folded| folded.roster.is_some())
    {
        super::class_revision_profile(fold, owner, request, role)
    } else {
        super::joining_profile(fold, owner, request, role)
    }
}

impl Vault {
    /// The writer's checks before the signature, on a read transaction, in
    /// the order the write makes them today: the carrier, the owner keys a
    /// removal would end, the last device key's confirmation, the machine's
    /// current revision, and the `seen` check. Answers what the write needs
    /// and the importance from the value in force.
    pub(super) fn owner_answer_checks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        answer: &AnswerAct,
        profile: &MachineProfile,
    ) -> Result<OwnerAnswerChecks> {
        let (carrier, key) = self.carrier_in_txn(txn, fold)?;
        let ending = if profile.role == MachineRole::Removed {
            self.owner_keys_ending_with_machine_in_txn(txn, fold, profile.machine)?
        } else {
            Vec::new()
        };
        self.refuse_unconfirmed_last_device_key_in_txn(txn, fold, &ending, answer.last_device_key)?;
        let target = fold.machine(profile.machine);
        let current = target.map_or([0; 32], |target| {
            target.answer_revision(fold.pinned_root.as_ref())
        });
        // Revision integrity (contract §4): the owner decided on what the
        // surface showed him.
        if answer.seen.is_some_and(|seen| seen != current) {
            return Err(Error::ConcurrentWrite(
                "the machine's answer changed since it was read",
            ));
        }
        let importance = machine_answer_importance(fold, profile, &ending);
        Ok(OwnerAnswerChecks {
            carrier,
            key,
            ending,
            current,
            importance,
        })
    }

    /// Runs the answer checks and validates the carried profile before the
    /// door asks. A frontier within the parent limit needs no join, so its
    /// carrier sequence can also be checked here.
    pub(in crate::authority) fn owner_answer_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        answer: &AnswerAct,
        profile: MachineProfile,
    ) -> Result<OwnerActImportance> {
        let checks = self.owner_answer_checks_in_txn(txn, fold, answer, &profile)?;
        self.checked_owner_answer_profile_in_txn(txn, fold, answer, profile, &checks)?;
        if fold.append_heads.len() <= MAX_PARENTS {
            let signer = AuthorityKey::Ed25519(checks.key.verifying_key().to_bytes());
            next_sequence(fold, &signer)?;
        }
        Ok(checks.importance)
    }

    /// Builds and validates the carried profile without signing any row.
    pub(super) fn checked_owner_answer_profile_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        answer: &AnswerAct,
        mut profile: MachineProfile,
        checks: &OwnerAnswerChecks,
    ) -> Result<MachineProfile> {
        profile.seen_world_edits = crate::authority::act_standing::acknowledged_by_in_txn(
            &self.store,
            txn,
            fold,
            profile.machine,
        )?;
        // A removal names, beside those, each TASK fact the machine carried that this install
        // counts: past the removal its signature proves no other (lead ruling
        // REMOVED-CARRIER-NEW-FACTS = A).
        if profile.role == MachineRole::Removed {
            profile
                .seen_world_edits
                .extend(crate::task_authority::carried_fact_acts_in_txn(
                    self,
                    txn,
                    profile.machine,
                )?);
        }
        profile.carrier = Some(checks.carrier);
        profile.act = Some(OwnerAct {
            owner: answer.owner,
            by: answer.by,
            surface: answer.surface,
            act: answer.kind,
            target: profile.machine,
            seen: checks.current,
            answer: None,
        });
        profile.validate()?;
        Ok(profile)
    }
}
