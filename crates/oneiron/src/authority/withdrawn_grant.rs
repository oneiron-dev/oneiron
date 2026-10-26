//! A positively withdrawn Grant stays withdrawn (FIX-LIST 5107).
//!
//! Every semantic withdrawal of a FEDERATION_GRANT row writes one durable,
//! presence-only marker in the same writer as the row's delete: a guest
//! revoke, a shared-vault member's removal or demotion, an owner-agent or
//! GitPush revoke, an own-device retirement, and a peer's deletion this
//! replica materializes. A failed marker write fails that writer, so a
//! Grant is never deleted here without it. The marker is permanent and
//! restores LIVE over an older image, so neither a restored nor a re-put
//! row at the same id, nor its absence, gives a carried act standing again
//! ([`super::owner_act::grant_standing_in_txn`] reads it first). Cache and
//! residence eviction never write it: they are not withdrawals. A replica
//! that never held the Grant learns nothing here and keeps trusting the
//! carrier.
//!
//! The owner-agent Grant enumeration every reader shares
//! (`federation::agent_grants_for_store_in_txn`) reads it too, so a marked
//! Grant re-put at its id gives no read or principal standing either.

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
pub(crate) fn mark_withdrawn_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    grant: EntityId,
) -> Result<()> {
    WITHDRAWN_GRANT.put(store, wtxn, &HexId(grant), &())
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
