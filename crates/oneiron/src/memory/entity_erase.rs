//! Owner erase that can also take every record in this vault holding the same bytes. The
//! default drops one record and its own hold on shared bytes; the same-bytes flag is a live
//! vault owner's act by hand.

use std::collections::BTreeMap;

use super::support::verify_deletion_authority_in_txn;
use super::{
    DeleteReceipt, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError,
    MemoryResult, SafeDeleteReason,
};
use crate::deletion::DeleteEntityPreview;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::federation::SharedVaultPreset;
use crate::write_envelope::WriteActor;

/// The named reason of an owner erase. Both purge the record and write a receipt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum EraseReason {
    #[default]
    UserHardDelete,
    /// A GDPR Art. 17 request: every record holding the same bytes is erased at once, another
    /// owner's included.
    GdprDelete,
}

impl EraseReason {
    const fn safe_delete_reason(self) -> SafeDeleteReason {
        match self {
            Self::UserHardDelete => SafeDeleteReason::UserHardDelete,
            Self::GdprDelete => SafeDeleteReason::GdprDelete,
        }
    }
}

/// What a confirmed erase covers. The same-bytes flag is off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EraseOptions {
    pub reason: EraseReason,
    /// Also erase every other record in this vault holding the same blob bytes.
    pub also_same_bytes: bool,
}

/// Why a record holding the same bytes was left in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SameBytesHold {
    /// A shared vault's record whose writer is not the caller, or does not resolve: it needs
    /// that owner's veto window.
    AnotherOwnersRecord,
}

/// What became of one other record holding the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameBytesOutcome {
    Erased(DeleteReceipt),
    Held(SameBytesHold),
    /// Its own checked delete returned this error, for one when it no longer holds the previewed
    /// bytes. As with a confirmed delete that fails part way, it may be unchanged, or its delete
    /// may be accepted and pending (it then reads as deleted and the deletion recovery finishes
    /// it): preview it again to see which.
    Failed(MemoryError),
}

/// The confirmed record's receipt, then one row per other record holding its bytes, in id
/// order. Empty rows without the same-bytes flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityEraseOutcome {
    pub first: DeleteReceipt,
    pub same_bytes: Vec<(EntityId, SameBytesOutcome)>,
}

impl Memory<'_> {
    /// Erases the previewed record under a named hard reason: revokes its
    /// previewed brief grants, publishes its tombstone, purges it and writes
    /// its receipt. Bytes it shares stay while another record holds them.
    ///
    /// With `also_same_bytes`, which only a live owner of this vault may set,
    /// every other record the preview names as holding the same blob bytes
    /// ([`DeleteEntityPreview::same_bytes_matches`]) is then erased the same
    /// way, in id order: its own live brief grants are revoked, then its own
    /// checked delete writes its tombstone, purge and receipt. In a shared
    /// vault a record another actor wrote is held, not erased, unless the
    /// reason is a GDPR request. Owner authority, the preview and every
    /// holder's classification are read in one snapshot before anything is
    /// destroyed. A failure on the confirmed record returns the error and
    /// erases nothing else; a later row's failure never hides an earlier
    /// completed erase.
    ///
    /// A byte carrier (the content-addressed ASSET every holder reads its
    /// bytes through) is refused: erasing it would take the bytes from every
    /// holder at once. Erase a record that holds them instead.
    pub fn confirm_entity_erase(
        &self,
        preview: &DeleteEntityPreview,
        options: EraseOptions,
    ) -> MemoryResult<EntityEraseOutcome> {
        let plan = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::Error::from)?;
            verify_deletion_authority_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
            preview.check_before_unshare(self.vault, &txn)?;
            if let Some(raw) = self
                .vault
                .store
                .entities
                .get(&txn, preview.entity().as_bytes())?
                && crate::blob_artifact::carrier_content_hash(&preview.entity(), &raw)?.is_some()
            {
                return Err(carrier_erase_refused());
            }
            let mut plan = Vec::new();
            if options.also_same_bytes {
                self.require_live_owner_in_txn(&txn)?;
                for (holder, hashes) in previewed_holdings(preview) {
                    plan.push(PlannedMatch {
                        hold: self.same_bytes_hold_in_txn(&txn, &holder, options.reason)?,
                        holder,
                        hashes,
                    });
                }
            }
            plan
        };
        let actor = WriteActor::new(self.actor, self.actor_class);
        for (share_id, _) in preview.shared_with() {
            self.vault
                .revoke_share(share_id, &actor, self.vault.store.clock.now_recorded_at())?;
        }
        let reason = options.reason.safe_delete_reason();
        let first =
            self.safe_delete_preview_checked(&preview.entity().to_hex(), reason, |txn| {
                preview
                    .check_after_unshare(self.vault, txn)
                    .map_err(Into::into)
            })?;
        let same_bytes = plan
            .into_iter()
            .map(|planned| {
                let outcome = match planned.hold {
                    Some(hold) => SameBytesOutcome::Held(hold),
                    None => self.erase_match(&planned, options.reason),
                };
                (planned.holder, outcome)
            })
            .collect();
        Ok(EntityEraseOutcome { first, same_bytes })
    }

    /// One planned match through its own checked delete.
    fn erase_match(&self, planned: &PlannedMatch, reason: EraseReason) -> SameBytesOutcome {
        match self.unshare_and_erase_match(planned, reason) {
            Ok(receipt) => SameBytesOutcome::Erased(receipt),
            Err(error) => SameBytesOutcome::Failed(error),
        }
    }

    /// As for the confirmed record: the match's own live brief grants are
    /// revoked first, then every destructive transaction of its delete
    /// refuses while a grant on it is live.
    fn unshare_and_erase_match(
        &self,
        planned: &PlannedMatch,
        reason: EraseReason,
    ) -> MemoryResult<DeleteReceipt> {
        let store = &self.vault.store;
        let check = |txn: &heed::RoTxn<'_>| {
            self.still_erasable_in_txn(txn, &planned.holder, &planned.hashes, reason)
        };
        let shares = {
            let txn = store.env.read_txn().map_err(crate::Error::from)?;
            check(&txn)?;
            crate::share::active_brief_shares_for(
                store,
                &txn,
                &planned.holder,
                store.clock.now_recorded_at(),
            )?
        };
        let actor = WriteActor::new(self.actor, self.actor_class);
        for (share_id, _) in shares {
            self.vault
                .revoke_share(&share_id, &actor, store.clock.now_recorded_at())?;
        }
        #[cfg(all(test, feature = "sync"))]
        if FAIL_NEXT_MATCH_AFTER_TOMBSTONE.replace(false) {
            crate::deletion::arm_fail_after_tombstone_before_purge();
        }
        self.safe_delete_checked(
            &planned.holder.to_hex(),
            reason.safe_delete_reason(),
            |txn| {
                check(txn)?;
                if crate::share::active_brief_shares_for(
                    store,
                    txn,
                    &planned.holder,
                    store.clock.now_recorded_at(),
                )?
                .is_empty()
                {
                    Ok(())
                } else {
                    Err(Error::ConcurrentWrite("delete shares changed").into())
                }
            },
        )
    }

    /// The same-bytes flag reaches records the caller did not name, so it asks for a live owner
    /// of this vault, not only deletion authority.
    fn require_live_owner_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        if crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &self.actor)? {
            return Ok(());
        }
        Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!(
                "actor {} is no live owner of this vault; the same-bytes erase is an owner's act",
                self.actor.to_hex()
            ),
            &["Erase the one record without the same-bytes flag, or ask a vault owner."],
        ))
    }

    /// `None` when this caller may erase `holder` with the record it confirmed:
    /// outside a shared vault, under a GDPR request, or when the caller wrote
    /// it. An unresolvable writer is not the caller.
    fn same_bytes_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &EntityId,
        reason: EraseReason,
    ) -> MemoryResult<Option<SameBytesHold>> {
        if reason == EraseReason::GdprDelete {
            return Ok(None);
        }
        let shared = self
            .vault
            .shared_vault_creation_in_txn(txn)?
            .is_some_and(|creation| creation.preset != Some(SharedVaultPreset::Personal));
        if !shared
            || crate::blob_artifact::artifact_author_in_txn(self.vault, txn, holder)?
                == Some(self.actor)
        {
            return Ok(None);
        }
        Ok(Some(SameBytesHold::AnotherOwnersRecord))
    }

    /// Rechecked in the holder's own delete transactions: the caller is still a
    /// live owner, the holder still holds one of the bytes the preview named
    /// for it, and this caller may still erase it.
    fn still_erasable_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: &EntityId,
        hashes: &[[u8; 32]],
        reason: EraseReason,
    ) -> MemoryResult<()> {
        self.require_live_owner_in_txn(txn)?;
        for hash in hashes {
            if crate::blob_artifact::content_holders_in_txn(&self.vault.store, txn, hash)?
                .contains(holder)
            {
                if self.same_bytes_hold_in_txn(txn, holder, reason)?.is_none() {
                    return Ok(());
                }
                break;
            }
        }
        Err(Error::ConcurrentWrite("delete preview stale").into())
    }
}

/// One other holder of the previewed bytes, classified in the planning snapshot.
struct PlannedMatch {
    holder: EntityId,
    hashes: Vec<[u8; 32]>,
    hold: Option<SameBytesHold>,
}

#[cfg(all(test, feature = "sync"))]
thread_local! {
    static FAIL_NEXT_MATCH_AFTER_TOMBSTONE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// Arms the delete rail's one-shot failure after a durable tombstone for the next same-bytes
/// match, not the confirmed record.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_next_match_after_tombstone() {
    FAIL_NEXT_MATCH_AFTER_TOMBSTONE.with(|armed| armed.set(true));
}

fn carrier_erase_refused() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_BAD_REQUEST,
        "this record is the byte carrier its holders read through; erasing it would take the bytes from every holder",
        &[
            "Erase a record that holds these bytes; with the same-bytes flag, every holder goes and the bytes with the last.",
        ],
    )
}

/// Every other holder the preview names, sorted, with the hashes it held.
fn previewed_holdings(preview: &DeleteEntityPreview) -> BTreeMap<EntityId, Vec<[u8; 32]>> {
    let mut holdings: BTreeMap<EntityId, Vec<[u8; 32]>> = BTreeMap::new();
    for row in preview.held_bytes() {
        for holder in row.other_holders() {
            holdings
                .entry(*holder)
                .or_default()
                .push(row.content_hash());
        }
    }
    holdings
}
