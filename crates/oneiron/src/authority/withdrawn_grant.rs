//! A positively withdrawn Grant stays withdrawn (FIX-LIST 5107).
//!
//! Every semantic withdrawal of a FEDERATION_GRANT row writes one durable,
//! presence-only marker in the same writer as the row's delete: a guest
//! revoke, a shared-vault member's removal or demotion, an owner-agent or
//! GitPush revoke, an own-device retirement, and a peer's deletion this
//! replica materializes. A local withdrawal also stages its row's hard
//! erasure for sync in that writer (FIX-LIST 10772), so a peer holding the
//! Grant materializes the delete and marks it in turn. A failed marker write
//! fails that writer, so a Grant is never deleted here without it. The
//! marker is permanent and restores LIVE over an older image, so neither a
//! restored nor a re-put row at the same id, nor its absence, gives a
//! carried act standing again ([`super::owner_act::grant_standing_in_txn`]
//! reads it first). Cache and residence eviction never write it: they are
//! not withdrawals. A replica that never held the Grant learns nothing here
//! and keeps trusting the carrier.
//!
//! The owner-agent Grant enumeration every reader shares
//! (`federation::agent_grants_for_store_in_txn`) reads it too, so a marked
//! Grant re-put at its id gives no read or principal standing either.
//!
//! A membership change that deletes a Grant an owner's signed mint made also
//! logs the host's signed withdrawal of it
//! ([`crate::Vault::log_membership_grant_withdrawal_in_txn`], FIX 7135), so
//! the authority audit pairs that mint with a revoke.

use super::{AuthorityOp, HostSlipIssuer};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;

/// One marker per Grant withdrawn here. Key: hex32 (the Grant id). Empty
/// value; never cleared, never reused for a new Grant.
const WITHDRAWN_GRANT: SideTable<HexId, (), Raw> =
    SideTable::new(&side_table::AUTHORITY_WITHDRAWN_GRANT);

/// How a new isolation check answers when its own input cannot be read
/// (CALLS "ISOLATION_NEW_CHECK_ERROR_MODE", open): the path today's code
/// takes. A failed write of the withdrawal marker is not such a check: it
/// fails the withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewCheckErrorMode {
    /// The check is skipped and the caller goes on as before it existed.
    KeepExistingPath,
}

/// The one mode every FIX-LIST 5107 and 8224 read takes.
pub(crate) const ISOLATION_NEW_CHECK_ERROR_MODE: NewCheckErrorMode =
    NewCheckErrorMode::KeepExistingPath;

/// Records, in the writer that deletes it, that `grant` was withdrawn here.
fn mark_withdrawn_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    WITHDRAWN_GRANT.put(store, wtxn, &HexId(grant), &())
}

/// A local withdrawal of the row `grant`, in the writer about to delete it
/// (FIX-LIST 10772), by its stored type alone: a FEDERATION_GRANT row stored
/// here, live or as a deleted shell, is marked, and its hard erasure staged
/// for sync (its permanent `dt:` marker, and its `pt:` intent in the base
/// window of its learned-at, which the window's next load publishes); any
/// other kind, or no row, is not. Any delete door may take it for every id
/// it tears.
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
    mark_withdrawn_grant_in_txn(store, wtxn, grant)?;
    let withdrawn_at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    crate::deletion::stage_engine_row_hard_erasure_in_txn(
        store,
        wtxn,
        &grant,
        row.learned_at,
        &crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserHardDelete,
            deleted_at: withdrawn_at,
            request_id: *grant.as_bytes(),
        },
    )
}

/// [`mark_withdrawn_grant_in_txn`] for a row a peer's delete is about to
/// remove, by its stored type alone: a FEDERATION_GRANT row this replica
/// holds, live or as a deleted shell (the type read off the shell), is
/// marked; any other kind, or no row, is not. No Grant body is decoded here.
pub(crate) fn mark_if_withdrawn_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    if crate::ports::EntityStoreRead::port_entity_record(store, &*wtxn, &id)?
        .is_some_and(|row| row.entity_type == crate::registry::ENTITY_TYPE_FEDERATION_GRANT)
    {
        mark_withdrawn_grant_in_txn(store, wtxn, id)?;
    }
    Ok(())
}

/// Whether `grant` is positively known withdrawn here. A marker that cannot
/// be read answers by [`ISOLATION_NEW_CHECK_ERROR_MODE`]: not known, so the
/// standing read goes on as it did before the marker existed.
pub(crate) fn grant_known_withdrawn_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
) -> bool {
    match WITHDRAWN_GRANT.contains(store, txn, &HexId(grant)) {
        Ok(known) => known,
        Err(_) => match ISOLATION_NEW_CHECK_ERROR_MODE {
            NewCheckErrorMode::KeepExistingPath => false,
        },
    }
}

impl crate::Vault {
    /// The host's signed withdrawal of `grant`, a Grant an owner's signed
    /// mint made (a GitPush grant or an owner's agent grant) that a
    /// shared-vault membership change deletes in the caller's writer `txn`
    /// (FIX 7135): the `SlipGrantRevoke` a guest revoke also logs, signed by
    /// `issuer` as the host that carried the change, never as an owner act.
    /// The authority audit lists it as that Grant's revoke beside its signed
    /// mint, and every replica's fold withdraws any slip minted under it.
    /// An issuer that is no live host of this vault's roster signs nothing
    /// and refuses nothing: `false`, and the change lands as before.
    ///
    /// # Errors
    /// A store, fold or clock failure, or an entry the fold did not count.
    pub(crate) fn log_membership_grant_withdrawal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        issuer: &HostSlipIssuer,
        grant: EntityId,
    ) -> Result<bool> {
        if super::slip_vault::require_host(&self.authority_view_readonly_in_txn(txn)?, issuer)
            .is_err()
        {
            return Ok(false);
        }
        self.append_slip_op_in_txn(
            txn,
            issuer,
            AuthorityOp::SlipGrantRevoke { grant_ref: grant },
        )?;
        Ok(true)
    }
}
