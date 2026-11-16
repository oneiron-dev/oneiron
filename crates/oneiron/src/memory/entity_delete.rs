//! Owner-bound preview and one-call unshare-before-delete confirmation, and
//! the delete a non-owner's role or Grant admits (ARCH-0043 DEL-2), judged
//! by check-in first (ROLES-CHECKIN 2k5).

use super::support::{verify_actor_binding_in_txn, verify_deletion_authority_in_txn};
use super::{
    DeleteReceipt, DeleteRequestState, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_OWNER_BINDING_REQUIRED,
    Memory, MemoryError, MemoryResult, SafeDeleteReason,
};
use crate::check_in::{
    ActClass, CheckInDecision, CheckInMode, CheckInScope, DoorAct, DoorCheckIn, RolePreset,
};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    AdmittedDeleteDoor, DeleteEntityOptions, DeleteEntityPreview, DeleteReason,
    DeletionGateContext, GuestRevokeAuthority,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::federation::{
    ArchiveDeleteRole, DeleteAuthority, DeleteCaller, DeleteRefusal, DeleteTarget,
};
use crate::secret_custody::EraseOwnerAct;
use crate::write_envelope::WriteActor;
use crate::{Vault, check_in};

/// The saved verb a delete by reason is: the verb its check-in names (2k5).
const DELETE_VERB: &str = "vault.delete";

/// What a delete by role does once its check-in is judged (2k5).
pub(super) enum RoleDeleteCheckIn {
    /// The delete runs under the authority the judge read; its receipt
    /// records the decision, none for an agent's.
    Go {
        authority: DeleteAuthority,
        decision: Option<CheckInDecision>,
    },
    /// The delete waits on this pending check-in, committed alone.
    Waits(EntityId),
}

impl Memory<'_> {
    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): the vault's owner deletes anything, on the
    /// owner path below, unchanged: a VERIFIED `human`-class actor
    /// (`Self::verified_actor_class`: the asserted actor must exist and be a
    /// PERSON — asserted class strings are never trusted) holding the owner
    /// binding. A caller that owner predicate refuses is judged by the
    /// delete authority instead (ARCH-0043 DEL-2, owner 9 Oct): a Member
    /// deletes the NOTE or TASK it owns, an Admin what its live grant holds,
    /// and an agent under one live Grant that names `delete`
    /// (`federation::require_delete_authority_in_txn`). A caller with no
    /// role in this vault keeps the owner predicate's refusal; any other
    /// refusal is FORBIDDEN and leads with its reason.
    ///
    /// The owner gate is evaluated before deletion TXN1. Sync-enabled deletes
    /// durably stage an authority-required marker + request-keyed recovery
    /// sidecar before the tombstone can commit; TXN3 consumes that sidecar
    /// with `append_gate_decision_in_txn` alongside the purge and distinct
    /// REDACTION_AUDIT execution receipt. Sync-disabled builds append directly
    /// on their first local scrub/purge.
    ///
    /// The delete checks in first, and its receipt records the decision
    /// ([`Self::safe_delete_with_check_in`] with no `check_in_ref`).
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_with_check_in(entity_ref, reason, None)
    }

    /// `vault.delete`: [`Self::safe_delete`], judged by check-in first
    /// (ROLES-CHECKIN 2k5; ARCH-0082 "Delete items"; P25-SHAPE Q1 = A). The
    /// owner's delete goes on their own proof, and so does another Owner's
    /// by role. A person the delete authority admits by role is judged under
    /// their membership role, in a writer of its own before the delete's
    /// rail: a Deputy's delete goes as `sure`, an Admin's and a Member's
    /// never ask, a Steward's delete of its own NOTE or TASK goes as
    /// `own_item`, and a Steward's delete of another's item in scope always
    /// asks (Engine ruling STEWARD-DELETE-WAIT = B: no role has less than a
    /// Member's "go, own items"). A delete that asks commits
    /// its pending check-in alone, deletes nothing and answers
    /// `CHECK_IN_PENDING` naming it; once it is approved, the call that names
    /// it as `check_in_ref` spends it in that writer and deletes, and a
    /// refusal by the rail after leaves it spent. An agent's delete under its
    /// Grant is not judged at this door: PR 3's act gate judges agents. The
    /// receipt records the decision, none for an agent's.
    ///
    /// # Errors
    ///
    /// As [`Self::safe_delete`]; `BAD_REQUEST` for a `check_in_ref` that is
    /// no check-in id, or that an Owner's or an agent's delete names;
    /// `CHECK_IN_PENDING` while the delete waits; a check-in that does not
    /// apply; `FORBIDDEN` when the role or Grant the judge read changed
    /// before the delete committed.
    pub fn safe_delete_with_check_in(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check_in_ref: Option<&str>,
    ) -> MemoryResult<DeleteReceipt> {
        let check_in_ref = check_in_ref
            .map(|hex| {
                EntityId::from_hex(hex)
                    .map_err(|_| MemoryError::bad_request("check_in_ref is not a check-in id"))
            })
            .transpose()?;
        let gate = match self.evaluate_deletion_gate() {
            Ok(gate) => gate,
            Err(refusal)
                if refusal.code == MEMORY_CODE_OWNER_BINDING_REQUIRED
                    || refusal.code == MEMORY_CODE_FORBIDDEN =>
            {
                return self.safe_delete_by_role(
                    entity_ref,
                    reason.delete_reason(),
                    refusal,
                    check_in_ref.as_ref(),
                );
            }
            Err(error) => return Err(error),
        };
        if check_in_ref.is_some() {
            return Err(spends_no_check_in());
        }
        let mut receipt = self.safe_delete_owner_gated(
            gate,
            entity_ref,
            reason.delete_reason(),
            |_| Ok(()),
            false,
            None,
        )?;
        receipt.check_in = Some(check_in::owner_own_proof_decision(ActClass::Delete));
        Ok(receipt)
    }

    /// The delete of `entity_ref` by a caller the owner predicate refused
    /// with `owner_refusal` (ARCH-0043 DEL-2): the delete authority is read
    /// in the gate's snapshot and again in each write before publication,
    /// and must find the same role and Grant. A caller whose actor binding
    /// fails is no one here and keeps `owner_refusal`. Withdrawing a Connect
    /// guest's grants and mirroring an erase are the owner's own acts, so
    /// neither happens here. The delete checks in first, with
    /// `check_in_ref` spending an approved ask ([`Self::role_delete_check_in`]);
    /// each write of the rail then must find the authority the judge read.
    fn safe_delete_by_role(
        &self,
        entity_ref: &str,
        reason: DeleteReason,
        owner_refusal: MemoryError,
        check_in_ref: Option<&EntityId>,
    ) -> MemoryResult<DeleteReceipt> {
        {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            if verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class).is_err()
            {
                return Err(owner_refusal);
            }
        }
        let id = self.resolve_ref(entity_ref)?;
        let caller = DeleteCaller {
            actor: self.actor,
            class: self.actor_class,
            credential: self.presented_credential(),
        };
        // The scrub retires the record's facts before the tombstone's publish
        // re-reads this authority; the target keeps its last live read.
        let target = DeleteTarget::new(id);
        let authority = |txn: &heed::RoTxn<'_>| -> MemoryResult<DeleteAuthority> {
            crate::federation::require_delete_authority_in_txn(self.vault, txn, caller, &target)?
                .map_err(|refusal| role_delete_refusal(refusal, &owner_refusal))
        };
        let (judged, decision) = match self.role_delete_check_in(
            &target,
            reason,
            DELETE_VERB,
            &authority,
            check_in_ref,
        )? {
            RoleDeleteCheckIn::Go {
                authority: judged,
                decision,
            } => (judged, decision),
            RoleDeleteCheckIn::Waits(check_in) => {
                return Err(Error::CheckInPending(check_in.to_hex()).into());
            }
        };
        let (mut receipt, _) =
            self.safe_delete_admitted(id, reason, AdmittedDeleteDoor::Record, &authority, |txn| {
                if authority(txn)? == judged {
                    Ok(())
                } else {
                    Err(authority_changed(AdmittedDeleteDoor::Record))
                }
            })?;
        receipt.check_in = decision;
        Ok(receipt)
    }

    /// The check-in `self.actor`'s delete of `target` by role through the
    /// saved verb `verb` runs on, judged in a writer of its own before the
    /// delete's rail (2k5; P25-SHAPE Q1 = A): `authority` read there, then
    /// the Owner on their own proof, an agent unjudged (PR 3's act gate),
    /// and a person under their membership role
    /// ([`check_in::person_door_check_in_in_txn`]), which opens or finds the
    /// pending check-in when the delete waits and spends `check_in_ref` when
    /// it names an approved one.
    ///
    /// # Errors
    ///
    /// `authority`'s refusal; `BAD_REQUEST` for a `check_in_ref` an Owner's
    /// or an agent's delete names; a person with no membership grant; as
    /// [`check_in::person_door_check_in_in_txn`].
    pub(super) fn role_delete_check_in(
        &self,
        target: &DeleteTarget,
        reason: DeleteReason,
        verb: &str,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> MemoryResult<DeleteAuthority>,
        check_in_ref: Option<&EntityId>,
    ) -> MemoryResult<RoleDeleteCheckIn> {
        self.vault.try_with_write_txn_grouped(|txn| {
            let judged = authority(txn)?;
            let decision = match judged.role() {
                ArchiveDeleteRole::Owner | ArchiveDeleteRole::Agent if check_in_ref.is_some() => {
                    return Err(spends_no_check_in());
                }
                ArchiveDeleteRole::Owner => {
                    Some(check_in::owner_own_proof_decision(ActClass::Delete))
                }
                ArchiveDeleteRole::Agent => None,
                ArchiveDeleteRole::Admin
                | ArchiveDeleteRole::Steward
                | ArchiveDeleteRole::Member => {
                    match person_delete_check_in_in_txn(
                        self.vault,
                        txn,
                        self.actor,
                        target,
                        reason,
                        verb,
                        check_in_ref,
                    )? {
                        DoorCheckIn::Go(decision) => Some(decision),
                        DoorCheckIn::Wait(check_in) => {
                            return Ok(RoleDeleteCheckIn::Waits(check_in));
                        }
                    }
                }
            };
            Ok(RoleDeleteCheckIn::Go {
                authority: judged,
                decision,
            })
        })
    }

    /// The owner's own delete of `entity_ref`, `owner`'s proof re-proved in
    /// each of its writes before publication beside the delete's own
    /// authority (FIX 9781, 9784). A hold refuses it as it refuses any
    /// delete.
    pub(crate) fn safe_delete_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        entity_ref: &str,
        reason: DeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(
            entity_ref,
            reason,
            |txn| {
                owner.revalidate_in_txn(self.vault, txn)?;
                Ok(())
            },
            false,
            None,
        )
    }

    pub(super) fn safe_delete_checked(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(entity_ref, reason.delete_reason(), check, false, None)
    }

    /// As [`Self::safe_delete_checked`], making `claim` in the delete's
    /// linearizing write.
    pub(super) fn safe_delete_claimed(
        &self,
        entity_ref: &str,
        reason: DeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        if claim.is_some() && reason != DeleteReason::OwnerErase {
            return Err(Error::InvariantViolation("a claimed delete is an owner erase").into());
        }
        self.safe_delete_checked_in_phase(entity_ref, reason, check, false, claim)
    }

    /// A confirmed impact preview is valid only while the original body is
    /// live. After this call's own soft scrub commits, publication still
    /// rechecks owner authority but must not compare the shell to that body.
    pub(super) fn safe_delete_preview_checked(
        &self,
        entity_ref: &str,
        reason: DeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(entity_ref, reason, check, true, None)
    }

    fn safe_delete_checked_in_phase(
        &self,
        entity_ref: &str,
        reason: DeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        self.safe_delete_owner_gated(
            gate,
            entity_ref,
            reason,
            check,
            stop_check_after_soft_scrub,
            claim,
        )
    }

    /// The owner's delete of `entity_ref` once `gate`, the owner predicate's
    /// decision record, admitted it.
    fn safe_delete_owner_gated(
        &self,
        gate: DeletionGateContext,
        entity_ref: &str,
        reason: DeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        let id = self.resolve_ref(entity_ref)?;
        // The owner deleting in person on a host that bound its slip issuer
        // withdraws a Connect guest PERSON's grants with it (FIX 3875).
        let guest_revoke = self
            .owner_authorship()
            .zip(self.host_slip_issuer)
            .map(|(owner, issuer)| GuestRevokeAuthority { owner, issuer });
        // The owner deleting in person carries out his own act: each custody
        // record his erase revokes goes to his other machines too (FIX 11883).
        let owner_act = self
            .owner_authorship()
            .map(|owner| EraseOwnerAct::new(owner, self.owner_surface()));
        let deleted = self.safe_delete_gated(
            &id,
            reason,
            gate,
            &|txn| verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class),
            check,
            stop_check_after_soft_scrub,
            claim,
            guest_revoke,
            owner_act.as_ref(),
        );
        if let Some(act) = owner_act.as_ref().filter(|_| deleted.is_ok()) {
            act.mirror_after_commit(self.vault);
        }
        deleted
    }

    /// The checked execution of a delete the delete authority admits
    /// (ARCH-0043 DEL-2; the archive door, OF-449 L4): a delete of `id` for
    /// `reason` under the caller's `authority`, never the owner predicate.
    /// The gate records the role and Grant `authority` admitted in its own
    /// snapshot and the `door`, and each write before publication reads it
    /// again and must find the same ones, else this record is refused as
    /// changed; `check` is rechecked there too. Withdrawing a Connect guest's
    /// grants is the owner's own delete, so none is withdrawn here.
    pub(super) fn safe_delete_admitted(
        &self,
        id: EntityId,
        reason: DeleteReason,
        door: AdmittedDeleteDoor,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> MemoryResult<DeleteAuthority>,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<(DeleteReceipt, DeleteAuthority)> {
        let (gate, admitted) = self.evaluate_admitted_delete_gate(authority, door)?;
        let same = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
            if authority(txn)? == admitted {
                return Ok(());
            }
            Err(authority_changed(door))
        };
        let receipt =
            self.safe_delete_gated(&id, reason, gate, &same, check, false, None, None, None)?;
        Ok((receipt, admitted))
    }

    /// The gated delete both doors share: `authority` and `check` rerun in
    /// each write before publication, `check` only until the soft scrub
    /// when `stop_check_after_soft_scrub`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one gated deletion tail for the owner's door and the admitted doors"
    )]
    fn safe_delete_gated(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: DeletionGateContext,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
        guest_revoke: Option<GuestRevokeAuthority<'_>>,
        owner_act: Option<&EraseOwnerAct<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        // Keep the exact binding-layer refusal while the engine sees a typed
        // concurrent-write stand-in. Both callbacks are invoked only under
        // the deletion rail's writer transaction.
        let refusal: std::cell::RefCell<Option<MemoryError>> = std::cell::RefCell::new(None);
        let map_refusal = |err| {
            *refusal.borrow_mut() = Some(err);
            Error::ConcurrentWrite("deletion authority or preview changed before commit")
        };
        let reverify =
            |txn: &heed::RoTxn<'_>| -> Result<(), Error> { authority(txn).map_err(map_refusal) };
        let recheck =
            |txn: &heed::RoTxn<'_>| -> Result<(), Error> { check(txn).map_err(map_refusal) };
        let both = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            reverify(txn)?;
            recheck(txn)
        };
        let revokes_guests = guest_revoke.is_some();
        // The code run that asks the delete, from its own write origin: the
        // write that commits the delete joins that run's change journal
        // (ARCH-0040 #revert-run).
        let run = self.host_run_ref();
        let gated = if stop_check_after_soft_scrub {
            crate::deletion::GatedDeletion::with_pre_scrub_check(gate, &reverify, &recheck)
        } else {
            crate::deletion::GatedDeletion::new(gate, &both)
        }
        .with_claim(claim)
        .with_guest_revoke(guest_revoke)
        .with_owner_act(owner_act)
        .with_run(run.as_deref());
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(id, reason, gated);
        // FIX 11743: a Connect guest's slips its delete revoked in one of
        // its writes; once they have committed, every stream judging a
        // credential judges again, as after a slip revoke. The notice says
        // only "judge again", so a delete that revoked none sends a spare one.
        if revokes_guests {
            self.vault.store.notify_credential_revocations();
        }
        let outcome =
            outcome.map_err(|err| refusal.take().unwrap_or_else(|| MemoryError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
            state: DeleteRequestState::Applied,
            check_in: None,
        })
    }

    /// Preview the exact record and live, directly attributed brief recipients.
    /// This read is owner-checked; it reveals no body or unverifiable peer list.
    pub fn preview_entity_delete(&self, id: &EntityId) -> MemoryResult<DeleteEntityPreview> {
        self.preview_entity_delete_in_snapshot(id, || {})
    }

    #[cfg(test)]
    pub(crate) fn preview_entity_delete_with_after_authority_hook(
        &self,
        id: &EntityId,
        hook: impl FnOnce(),
    ) -> MemoryResult<DeleteEntityPreview> {
        self.preview_entity_delete_in_snapshot(id, hook)
    }

    fn preview_entity_delete_in_snapshot(
        &self,
        id: &EntityId,
        after_authority: impl FnOnce(),
    ) -> MemoryResult<DeleteEntityPreview> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        // One snapshot binds owner authority, content and recipients. The
        // test hook can commit a revocation on another thread at this seam.
        after_authority();
        let preview = self.vault.preview_entity_delete_in_txn(&txn, id)?;
        // The preview is derived from the record, each live grant it revokes
        // and that grant's recipient, and every other record or owner its
        // bytes are shared with (DEC-0005).
        self.produced_from(std::iter::once(preview.entity()));
        self.produced_from(
            preview
                .shared_with()
                .iter()
                .flat_map(|(grant, recipient)| [*grant, *recipient]),
        );
        self.produced_from(
            preview
                .held_bytes()
                .iter()
                .flat_map(|row| row.other_holders().iter().copied()),
        );
        self.produced_from(
            preview
                .lfs_chunks()
                .iter()
                .flat_map(|row| row.other_owners().iter().copied()),
        );
        Ok(preview)
    }

    /// A single owner action revokes the previewed brief grants, publishes a
    /// CRDT tombstone (hard purge retracts incident edges with it), then erases
    /// the active body only when `purge` is set. The named delete gate rechecks
    /// owner authority and the preview in its linearizing write transactions.
    /// If a later step fails, already-revoked grants stay revoked; retry with
    /// a fresh preview. Remote recipients may still retain delivered copies.
    pub fn confirm_entity_delete(
        &self,
        preview: &DeleteEntityPreview,
        options: DeleteEntityOptions,
    ) -> MemoryResult<DeleteReceipt> {
        {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
            preview.check_before_unshare(self.vault, &txn)?;
        }
        let actor = WriteActor::new(self.actor, self.actor_class);
        for (share_id, _) in preview.shared_with() {
            self.vault
                .revoke_share(share_id, &actor, self.vault.store.clock.now_recorded_at())?;
        }
        let reason = if options.purge {
            DeleteReason::UserHardDelete
        } else {
            DeleteReason::UserDelete
        };
        self.safe_delete_preview_checked(&preview.entity().to_hex(), reason, |txn| {
            preview
                .check_after_unshare(self.vault, txn)
                .map_err(Into::into)
        })
    }
}

/// The refusal of a delete whose role or Grant changed between the read
/// that admitted it and a write of its rail.
pub(super) fn authority_changed(door: AdmittedDeleteDoor) -> MemoryError {
    match door {
        AdmittedDeleteDoor::Archive => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "archive_delete_changed: the role or Grant that admitted this delete \
             changed before it committed",
            &["Preview the archived record again, then confirm it."],
        ),
        AdmittedDeleteDoor::Record => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "delete_authority_changed: the role or Grant that admitted this delete \
             changed before it committed",
            &["Delete the record again; its role or Grant is read afresh."],
        ),
    }
}

/// The refusal of a `check_in_ref` an Owner's or an agent's delete names:
/// neither waits on a check-in at a delete door (2k5).
pub(super) fn spends_no_check_in() -> MemoryError {
    MemoryError::bad_request(
        "check_in_ref names a person's waiting delete; an Owner's or an agent's delete waits on \
         none",
    )
}

/// `person`'s delete of `target` for `reason` through the saved verb
/// `verb`, judged under their membership role in `txn`, the judge's writer
/// (2k5; P25-SHAPE Q1 = A): the digest of the exact delete, the grant their
/// pending check-in climbs from, and `check_in_ref` when they name an
/// approved one. A Steward's delete of its own NOTE or TASK goes at once as
/// `own_item`, as a Member's does (Engine ruling STEWARD-DELETE-WAIT = B).
///
/// # Errors
///
/// A person with no membership grant on the shared vault; as
/// [`check_in::person_door_check_in_in_txn`].
fn person_delete_check_in_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    person: EntityId,
    target: &DeleteTarget,
    reason: DeleteReason,
    verb: &str,
    check_in_ref: Option<&EntityId>,
) -> crate::Result<DoorCheckIn> {
    let not_member =
        || Error::InvalidConfig("a delete by role needs the person's membership grant".into());
    let creation = vault
        .shared_vault_creation_in_txn(txn)?
        .ok_or_else(not_member)?;
    let (grant, role) = vault
        .member_grant_in_txn(txn, creation.vault_id, person)?
        .ok_or_else(not_member)?;
    let role = RolePreset::of_grant_role(role);
    if role == RolePreset::Steward && target.owned_by_in(vault, txn, person)? {
        return Ok(DoorCheckIn::Go(CheckInDecision {
            act_class: ActClass::Delete.as_str().to_owned(),
            role: role.as_str().to_owned(),
            mode: Some(CheckInMode::NeverAsk.as_str().to_owned()),
            basis: "own_item".to_owned(),
            check_in: None,
            requester: None,
        }));
    }
    let act = DoorAct {
        person,
        role,
        grant,
        verb,
        act: ActClass::Delete,
        scope: CheckInScope::default(),
        effect_digest: check_in::record_delete_effect_digest(&target.id(), reason),
    };
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    check_in::person_door_check_in_in_txn(vault, txn, &act, check_in_ref, now)
}

/// A non-owner's delete refusal (ARCH-0043 DEL-2). A person with no live
/// binding or no role in this vault keeps `owner_refusal`, the owner
/// predicate's refusal it got before; every other refusal is FORBIDDEN and
/// leads with its reason.
fn role_delete_refusal(refusal: DeleteRefusal, owner_refusal: &MemoryError) -> MemoryError {
    match refusal {
        DeleteRefusal::Unbound | DeleteRefusal::NoStanding => owner_refusal.clone(),
        DeleteRefusal::NotOwnerOfItem
        | DeleteRefusal::OutOfAdminScope
        | DeleteRefusal::NoDeleteGrant
        | DeleteRefusal::CredentialBounds
        | DeleteRefusal::Unreadable(_) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            refusal.message(),
            &[
                "The vault's Owner deletes anything; a Member deletes the NOTE or TASK it owns, \
                 an Admin what its live grant holds, and an agent under one live Grant that \
                 names delete.",
            ],
        ),
    }
}
