//! Owner-bound preview and one-call unshare-before-delete confirmation.

use super::support::verify_deletion_authority_in_txn;
use super::{DeleteReceipt, DeleteRequestState, Memory, MemoryError, MemoryResult, SafeDeleteReason};
use crate::consent::AuthenticatedOwner;
use crate::deletion::{
    DeleteEntityOptions, DeleteEntityPreview, DeletionGateContext, GuestRevokeAuthority,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::federation::ArchiveDeleteAuthority;
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    /// Deletes an entity under a NAMED reason (S7). `user_delete` is the
    /// tombstone path; the other three run the redaction-audit machinery.
    ///
    /// Authority (fail-closed): deletion is an OWNER verb — the named
    /// reasons are `user_*`/compliance erasures. Only a VERIFIED
    /// `human`-class actor may delete (`Self::verified_actor_class`:
    /// the asserted actor must exist and be a PERSON — asserted class
    /// strings are never trusted); `agent`/`system` actors get a typed
    /// denial (agents withdraw their own claims via
    /// [`Self::claim_retract`]).
    ///
    /// The owner gate is evaluated before deletion TXN1. Sync-enabled deletes
    /// durably stage an authority-required marker + request-keyed recovery
    /// sidecar before the tombstone can commit; TXN3 consumes that sidecar
    /// with `append_gate_decision_in_txn` alongside the purge and distinct
    /// REDACTION_AUDIT execution receipt. Sync-disabled builds append directly
    /// on their first local scrub/purge.
    ///
    /// The proven owner's own delete of a record only secret orders keep is
    /// accepted, not refused: its receipt reads completion pending, and the
    /// delete runs under its own reason once nothing holds the record (FIX
    /// 1465). Every other hold refuses it as before.
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        if let Some(owner) = self.owner_authorship() {
            let id = self.resolve_ref(entity_ref)?;
            // The exact binding-layer refusal, as the rail keeps it.
            let refusal: std::cell::RefCell<Option<MemoryError>> = std::cell::RefCell::new(None);
            let authority = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
                verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)
                    .map_err(|err| {
                        *refusal.borrow_mut() = Some(err);
                        Error::ConcurrentWrite("deletion authority changed before commit")
                    })
            };
            let queued = self
                .vault
                .owner_pending_delete_checked(owner, &id, reason.delete_reason(), &authority)
                .map_err(|err| refusal.take().unwrap_or_else(|| MemoryError::from(err)))?;
            if queued {
                return Ok(DeleteReceipt {
                    existed: true,
                    reason: reason.as_str().to_owned(),
                    receipt_ref: None,
                    state: DeleteRequestState::CompletionPending,
                });
            }
        }
        self.safe_delete_checked(entity_ref, reason, |_| Ok(()))
    }

    /// The owner's own delete of `entity_ref`, `owner`'s proof re-proved in
    /// each of its writes before publication beside the delete's own
    /// authority (FIX 9781, 9784). A hold refuses it as it refuses any
    /// delete.
    pub(crate) fn safe_delete_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked(entity_ref, reason, |txn| {
            owner.revalidate_in_txn(self.vault, txn)?;
            Ok(())
        })
    }

    pub(super) fn safe_delete_checked(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(entity_ref, reason, check, false, None)
    }

    /// As [`Self::safe_delete_checked`], making `claim` in the delete's
    /// linearizing write.
    pub(super) fn safe_delete_claimed(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        if claim.is_some() && reason != SafeDeleteReason::UserHardDelete {
            return Err(Error::InvariantViolation("a claimed delete is a user hard delete").into());
        }
        self.safe_delete_checked_in_phase(entity_ref, reason, check, false, claim)
    }

    /// A confirmed impact preview is valid only while the original body is
    /// live. After this call's own soft scrub commits, publication still
    /// rechecks owner authority but must not compare the shell to that body.
    pub(super) fn safe_delete_preview_checked(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(entity_ref, reason, check, true, None)
    }

    fn safe_delete_checked_in_phase(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
    ) -> MemoryResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        let id = self.resolve_ref(entity_ref)?;
        // The owner deleting in person on a host that bound its slip issuer
        // withdraws a Connect guest PERSON's grants with it (FIX 3875).
        let guest_revoke = self
            .owner_authorship()
            .zip(self.host_slip_issuer)
            .map(|(owner, issuer)| GuestRevokeAuthority { owner, issuer });
        self.safe_delete_gated(
            &id,
            reason,
            gate,
            &|txn| verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class),
            check,
            stop_check_after_soft_scrub,
            claim,
            guest_revoke,
        )
    }

    /// The archive delete's checked execution (OF-449 L4): a user hard
    /// delete of `id` under the caller's archive-delete `authority`, never
    /// the owner predicate. The gate records the role and Grant `authority`
    /// admitted in its own snapshot, and each write before publication reads
    /// it again and must find the same ones, else this record is refused as
    /// changed; `check` is rechecked there too. Withdrawing a Connect guest's
    /// grants is the owner's own delete, so none is withdrawn here.
    pub(super) fn safe_delete_archive_checked(
        &self,
        id: EntityId,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> MemoryResult<ArchiveDeleteAuthority>,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<(DeleteReceipt, ArchiveDeleteAuthority)> {
        let (gate, admitted) = self.evaluate_archive_delete_gate(authority)?;
        let same = |txn: &heed::RoTxn<'_>| -> MemoryResult<()> {
            if authority(txn)? == admitted {
                return Ok(());
            }
            Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "archive_delete_changed: the role or Grant that admitted this delete changed \
                 before it committed",
                &["Preview the archived record again, then confirm it."],
            ))
        };
        let receipt = self.safe_delete_gated(
            &id,
            SafeDeleteReason::UserHardDelete,
            gate,
            &same,
            check,
            false,
            None,
            None,
        )?;
        Ok((receipt, admitted))
    }

    /// The gated delete both doors share: `authority` and `check` rerun in
    /// each write before publication, `check` only until the soft scrub
    /// when `stop_check_after_soft_scrub`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one gated deletion tail for the owner's and the archive's doors"
    )]
    fn safe_delete_gated(
        &self,
        id: &EntityId,
        reason: SafeDeleteReason,
        gate: DeletionGateContext,
        authority: &dyn Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
        claim: Option<crate::deletion::DeletionClaim<'_>>,
        guest_revoke: Option<GuestRevokeAuthority<'_>>,
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
            |txn: &heed::RoTxn<'_>| -> Result<(), Error> { authority(txn).map_err(&map_refusal) };
        let recheck =
            |txn: &heed::RoTxn<'_>| -> Result<(), Error> { check(txn).map_err(&map_refusal) };
        let both = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            reverify(txn)?;
            recheck(txn)
        };
        let gated = if stop_check_after_soft_scrub {
            crate::deletion::GatedDeletion::with_pre_scrub_check(gate, &reverify, &recheck)
        } else {
            crate::deletion::GatedDeletion::new(gate, &both)
        }
        .with_claim(claim)
        .with_guest_revoke(guest_revoke);
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(id, reason.delete_reason(), gated)
            .map_err(|err| refusal.take().unwrap_or_else(|| MemoryError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
            state: DeleteRequestState::Applied,
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
            SafeDeleteReason::UserHardDelete
        } else {
            SafeDeleteReason::UserDelete
        };
        self.safe_delete_preview_checked(&preview.entity().to_hex(), reason, |txn| {
            preview
                .check_after_unshare(self.vault, txn)
                .map_err(Into::into)
        })
    }
}
