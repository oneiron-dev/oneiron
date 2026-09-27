//! Owner-bound preview and one-call unshare-before-delete confirmation.

use super::support::verify_deletion_authority_in_txn;
use super::{DeleteReceipt, Memory, MemoryError, MemoryResult, SafeDeleteReason};
use crate::deletion::{DeleteEntityOptions, DeleteEntityPreview};
use crate::entity_id::EntityId;
use crate::error::Error;
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
    pub fn safe_delete(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked(entity_ref, reason, |_| Ok(()))
    }

    pub(super) fn safe_delete_checked(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<DeleteReceipt> {
        self.safe_delete_checked_in_phase(entity_ref, reason, check, false)
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
        self.safe_delete_checked_in_phase(entity_ref, reason, check, true)
    }

    fn safe_delete_checked_in_phase(
        &self,
        entity_ref: &str,
        reason: SafeDeleteReason,
        check: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
        stop_check_after_soft_scrub: bool,
    ) -> MemoryResult<DeleteReceipt> {
        let gate = self.evaluate_deletion_gate()?;
        let id = self.resolve_ref(entity_ref)?;
        // Keep the exact binding-layer refusal while the engine sees a typed
        // concurrent-write stand-in. Both callbacks are invoked only under
        // the deletion rail's writer transaction.
        let refusal: std::cell::RefCell<Option<MemoryError>> = std::cell::RefCell::new(None);
        let map_refusal = |err| {
            *refusal.borrow_mut() = Some(err);
            Error::ConcurrentWrite("deletion authority or preview changed before commit")
        };
        let reverify = |txn: &heed::RoTxn<'_>| -> Result<(), Error> {
            verify_deletion_authority_in_txn(self.vault, txn, self.actor, self.actor_class)
                .map_err(&map_refusal)
        };
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
        };
        let outcome = self
            .vault
            .delete_entity_with_reason_gated(&id, reason.delete_reason(), gated)
            .map_err(|err| refusal.take().unwrap_or_else(|| MemoryError::from(err)))?;
        Ok(DeleteReceipt {
            existed: outcome.existed,
            reason: reason.as_str().to_owned(),
            receipt_ref: outcome
                .receipt_id
                .map(|receipt| format!("redaction:{}", receipt.to_hex())),
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
        Ok(self.vault.preview_entity_delete_in_txn(&txn, id)?)
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
