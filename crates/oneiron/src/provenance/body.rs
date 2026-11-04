//! Who owns a body and whether it is whole. One descriptor shape serves every
//! family that keeps bytes for a record: code-mode results (inline in LMDB or
//! one content-addressed file beside `data.mdb`), artifact versions and office
//! bodies. The descriptor is metadata only; bytes stay where their family keeps
//! them.
//!
//! Canon: a result is published complete only after its whole body is durable,
//! and a crash before that leaves it explicitly incomplete, never an empty
//! success (storage ABI, result body store; EIRI-ARCH-0002). Erase starts at
//! the owning record and removes its references; shared bytes outlive one
//! owner while another holds them (ARCH-0005a, ERASE-SHARED = B). A digest is
//! never an owner and never a read permit.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
pub(crate) mod checkpoint;
#[cfg(all(unix, feature = "sync"))]
mod retained;
#[cfg(all(unix, feature = "sync"))]
pub(crate) use self::retained::retained_body_side_keys_in_txn;

pub use crate::store::body_descriptor::{
    BodyLocation, BodyRef, BodyState, OwnedBody, RetainedResultProvenance,
};

use crate::store::owned_body::{BODY, BODY_DIGEST, BODY_RELEASED};

pub(crate) use crate::store::owned_body::{
    digest_is_held_in_txn, file_body_of_row, owned_bodies_in_txn, owned_body_in_txn,
    prune_digest_in_rows, queue_pruned_file_in_txn, released_bodies_in_txn, take_released_in_txn,
};

/// Publishes `body`'s descriptor in the caller's transaction. An occurrence
/// may go from absent or incomplete to incomplete or complete; a complete
/// body is final, so the same descriptor again is a no-op and a different one
/// is refused. A publisher makes the bytes durable first, then publishes the
/// complete descriptor in the transaction that binds the result.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the occurrence is already complete with
/// another descriptor; storage errors as they occur.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn publish_body_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    body: &OwnedBody,
) -> Result<()> {
    let key = (body.owner, body.occurrence);
    if let Some(prior) = BODY.get(store, txn, &key)? {
        if prior == *body {
            return Ok(());
        }
        if prior.state.is_complete() {
            return Err(Error::InvariantViolation(
                "a complete body's descriptor is final",
            ));
        }
        if let Some(held) = prior.state.held() {
            BODY_DIGEST.delete(store, txn, &(held.blake3, body.occurrence))?;
            release_if_unheld(store, txn, held)?;
        }
    }
    BODY.put(store, txn, &key, body)?;
    if let Some(held) = body.state.held() {
        BODY_DIGEST.put(store, txn, &(held.blake3, body.occurrence), &body.owner)?;
        BODY_RELEASED.delete(store, txn, &held.blake3)?;
    }
    Ok(())
}

/// Drops every body `owner` holds and queues each file digest no other
/// descriptor holds for the collector. Returns how many descriptors left.
pub(crate) fn release_owner_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
) -> Result<usize> {
    let bodies = owned_bodies_in_txn(store, txn, owner)?;
    for body in &bodies {
        BODY.delete(store, txn, &(body.owner, body.occurrence))?;
        if let Some(held) = body.state.held() {
            BODY_DIGEST.delete(store, txn, &(held.blake3, body.occurrence))?;
            release_if_unheld(store, txn, held)?;
        }
    }
    Ok(bodies.len())
}

/// Drops `owner`'s one `occurrence` and queues its file digest for the
/// collector when no other descriptor holds it. `false` when the owner holds
/// no such occurrence.
pub(crate) fn release_body_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
    occurrence: &EntityId,
) -> Result<bool> {
    let key = (*owner, *occurrence);
    let Some(body) = BODY.get(store, txn, &key)? else {
        return Ok(false);
    };
    BODY.delete(store, txn, &key)?;
    if let Some(held) = body.state.held() {
        BODY_DIGEST.delete(store, txn, &(held.blake3, *occurrence))?;
        release_if_unheld(store, txn, held)?;
    }
    Ok(true)
}

/// A digest whose last holder just went: a file queues for the collector,
/// and an erase of an earlier holder that waited on this release retires
/// its instance now (KS-2A); a delete or a collection keeps the key. A raw
/// output that holds the body on its own keeps it, file and row, unless
/// that erase lifted its hold (FIX 5399b).
fn release_if_unheld(store: &impl ManifestDbs, txn: &mut RwTxn<'_>, held: &BodyRef) -> Result<()> {
    if digest_is_held_in_txn(store, txn, &held.blake3)? {
        return Ok(());
    }
    #[cfg(unix)]
    crate::store::release_body_in_txn(store, txn, &held.blake3)?;
    #[cfg(unix)]
    if crate::code_run::code_run_body_held_in_txn(store, txn, &held.blake3)? {
        return Ok(());
    }
    if held.location == BodyLocation::File {
        let at = crate::ports::recorded_at_in_txn(store, txn)?;
        BODY_RELEASED.put(store, txn, &held.blake3, &at)?;
    }
    Ok(())
}

impl crate::Vault {
    /// Every body `owner` holds, with its completion state.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored descriptor that does not decode.
    pub fn owned_bodies(&self, owner: &EntityId) -> Result<Vec<OwnedBody>> {
        let rtxn = self.store.env.read_txn()?;
        owned_bodies_in_txn(&self.store, &rtxn, owner)
    }
}
