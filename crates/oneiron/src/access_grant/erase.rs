//! Scrub an erased principal out of non-brief ACCESS_GRANT bodies (FIX 4980).
//!
//! Every scope's body carries `principal_ref` on the grant itself; FIX 4231
//! named brief shares only. This pass rewrites each stored grant whose live
//! body still names `actor` and whose scope is not `SharedBrief` as its
//! inert history: the same body with its principal naming no one. Admitted
//! shares stay owned by the 4231 path; admission-less `SharedBrief` rows
//! remain that path's pre-existing gap (drop the `!SharedBrief` filter to
//! close it).
//!
//! No liveness gate: an unapplied delete leaves body+hex, and FIX 8640
//! "deleted is no row" is about resolution, not stored bytes. Future
//! migrations must read these rows through the live decoder, never the
//! strict one.

use crate::Vault;
use crate::deletion::names_no_actor;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ACCESS_GRANT;
use crate::store::Store;

use super::codec::{decode_access_grant_body, decode_erased_grant_body, encode_erased_grant_body};
use super::record::AccessGrantScope;

/// Erasing `actor` out of the non-brief access grants (FIX 4980): each
/// stored grant whose live body still names it, of any scope but
/// `SharedBrief`, is rewritten as its inert history naming no one, through
/// the one grant body writer in the erase's own transaction at the recorded
/// clock. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a grant body that cannot be rewritten.
pub(crate) fn erase_principal_grants_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<usize> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(0);
    }
    let store = &vault.store;
    let mut scrubbed = Vec::new();
    for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
        store,
        wtxn,
        ENTITY_TYPE_ACCESS_GRANT,
        None,
    )? {
        let id = id?;
        let Some(body) = grant_body_in_txn(store, wtxn, &id)? else {
            continue;
        };
        if body.is_empty() {
            continue;
        }
        let grant = match decode_access_grant_body(&body) {
            Ok(grant) => grant,
            // Already scrubbed: its live body no longer names anyone.
            Err(_) if decode_erased_grant_body(&body).is_ok() => continue,
            // A malformed row is no grant.
            Err(_) => continue,
        };
        if grant.principal_ref == *actor
            && !matches!(grant.scope, AccessGrantScope::SharedBrief { .. })
        {
            scrubbed.push((id, grant));
        }
    }
    if scrubbed.is_empty() {
        return Ok(0);
    }
    let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    for (id, grant) in &scrubbed {
        vault.apply_access_grant_body(wtxn, id, at, encode_erased_grant_body(grant)?)?;
    }
    Ok(scrubbed.len())
}

/// The stored body of the grant `id` names, if it is one.
fn grant_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<u8>>> {
    match store.port_entity_record(txn, id) {
        Ok(Some(raw)) if raw.entity_type == ENTITY_TYPE_ACCESS_GRANT => Ok(Some(raw.body)),
        // A malformed row is no grant. Storage failures still propagate.
        Ok(_) | Err(Error::CorruptedIndex("entity header")) => Ok(None),
        Err(error) => Err(error),
    }
}
