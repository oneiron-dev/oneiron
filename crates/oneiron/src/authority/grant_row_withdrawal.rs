//! A Grant row's withdrawal, in the writer that deletes it: a guest revoke, a shared-vault
//! member's removal or demotion, an owner-agent or GitPush revoke, an own-device retirement, a
//! house unlink and a batch delete. The writer stages the row's hard erasure for sync (FIX-LIST
//! 10772), so a peer holding the Grant materializes the delete in turn.
//!
//! The withdrawal itself is the counted end of the Grant's line (Fable pass 28; R2c ends every
//! taking back by a counted act): a row re-put at the Grant's id, restored or replayed by a
//! peer the tombstone never reached, stands for nothing once that end counts, at every reader
//! and on every replica that folds it. Until it counts, the end is owed here, and the readers
//! that read a withdrawal ask that debt ([`crate::federation::grant_end_owed_in_txn`]). Pass 28
//! R3e removed the permanent local marker that stood in for both (FIX-LIST 5107). An own-device
//! Grant and a base agent's engine-default Grant take no act: they are read as derived (R4).
//!
//! A membership change that deletes a Grant an owner's signed mint made also logs the host's
//! signed withdrawal of it ([`crate::Vault::log_membership_grant_withdrawal_in_txn`], FIX 7135),
//! so the authority audit pairs that mint with a revoke. With no host issuer to sign it, the
//! change's carrier-signed membership execution record names the Grant instead, pending until
//! it counts (FIX 12335).

use super::{AuthorityOp, HostSlipIssuer};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// How a new isolation check answers when its own input cannot be read
/// (CALLS "ISOLATION_NEW_CHECK_ERROR_MODE", open): the path today's code
/// takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewCheckErrorMode {
    /// The check is skipped and the caller goes on as before it existed.
    KeepExistingPath,
}

/// The one mode every FIX-LIST 5107 and 8224 read takes.
pub(crate) const ISOLATION_NEW_CHECK_ERROR_MODE: NewCheckErrorMode =
    NewCheckErrorMode::KeepExistingPath;

/// A local withdrawal of the row `grant`, in the writer about to delete it
/// (FIX-LIST 10772), by its stored type alone: a FEDERATION_GRANT row stored
/// here, live or as a deleted shell, has its hard erasure staged for sync (its
/// permanent `dt:` marker, and its `pt:` intent in the base window of its
/// learned-at, which the window's next load publishes); any other kind, or no
/// row, is not. Any delete door may take it for every id it tears; the
/// writer's counted end, or the end it owes, is its own.
pub(crate) fn withdraw_grant_row_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    let Some(row) = crate::ports::EntityStoreRead::port_entity_record(store, &*wtxn, &grant)?
        .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT)
    else {
        return Ok(());
    };
    // The Grant's scope, bound to this withdrawal's tombstone, while its row
    // is still live (FIX 11780): a narrower grant's selector export then
    // carries the tombstone too, as whole-vault member sync does. A capture
    // never fails the withdrawal (deletion/tombstone_scope.rs).
    let request_id = *grant.as_bytes();
    crate::deletion::tombstone_scope::capture_deleted_scope_in_store_txn(
        store,
        wtxn,
        &grant,
        Some(&request_id),
    );
    let withdrawn_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    crate::deletion::stage_engine_row_hard_erasure_in_txn(
        store,
        wtxn,
        &grant,
        row.learned_at,
        &crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserHardDelete,
            deleted_at: withdrawn_at,
            request_id,
        },
    )
}

impl crate::Vault {
    /// The host's signed withdrawal of `grant`, a Grant an owner's signed
    /// mint made (a GitPush grant or an owner's agent grant) that a
    /// shared-vault membership change deletes in the caller's writer `txn`
    /// (FIX 7135): the `SlipGrantRevoke` a guest revoke also logs, signed by
    /// `issuer` as the host that carried the change, never as an owner act.
    /// The authority audit lists it as that Grant's revoke beside its signed
    /// mint, links it to the same writer's actual membership `receipt`, and
    /// every replica's fold withdraws any slip minted under it.
    /// An issuer that is no live host of this vault's roster signs nothing
    /// and refuses nothing: `false`, and the change lands with the Grant
    /// named in its pending carrier-signed record (FIX 12335).
    ///
    /// # Errors
    /// A store, fold or clock failure, or an entry the fold did not count.
    pub(crate) fn log_membership_grant_withdrawal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        grant: EntityId,
        receipt: &str,
    ) -> Result<bool> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if super::slip_vault::require_host(&fold, issuer).is_err() {
            return Ok(false);
        }
        self.append_slip_op_in_txn(
            txn,
            issuer,
            AuthorityOp::SlipGrantRevoke {
                grant_ref: grant,
                membership_receipt: Some(receipt.to_owned()),
            },
        )?;
        Ok(true)
    }
}
