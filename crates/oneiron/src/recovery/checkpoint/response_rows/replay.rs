//! The census, binding and stale release of a replay row's and a step
//! start's parts (FIX 9180, coord-b slice d; L04 option (b)).
//!
//! A decoded replay row whose spawns reached resolved targets is noted as
//! its parts ([`note_row`]): each part's carrier is a response the census
//! holds, bound or not, so its binding is never stale, and a part with no
//! instance bound to its bytes holds the snapshot back until the binding
//! pass binds one, as a whole row's response does. The binding pass binds
//! a part ([`bind_in_txn`]) to the bytes its row or start holds now,
//! re-derived in its own writer, with an obligation for each owner the
//! part names: the reply's and rest's the whole row's, an ask's each seat
//! its call's host resolved. A whole row's carrier whose row now travels as
//! its parts binds nothing, and its binding is stale ([`holds_in_txn`]).

use heed::RoTxn;

use super::{Noted, ResponseCensus, row_in_txn};
use crate::store::{
    ResponseBinding, ResponseDb, ResponseFamily, Store, bind_response_in_txn, carrier_row,
    response_binding_in_txn,
};
use crate::{EntityId, Result};

impl ResponseCensus {
    /// Notes one part, `carrier`, whose bytes' BLAKE3 is `digest`: the
    /// instance bound to them, or `None` when none is yet, so the binding
    /// pass binds one before an image carries it.
    ///
    /// # Errors
    ///
    /// Storage errors, and a binding that does not decode.
    pub(in crate::recovery::checkpoint) fn note_part(
        &mut self,
        store: &Store,
        txn: &RoTxn<'_>,
        carrier: Vec<u8>,
        digest: &[u8; 32],
    ) -> Result<Option<[u8; 16]>> {
        let bound =
            response_binding_in_txn(store, txn, &carrier)?.filter(|bound| bound.digest == *digest);
        self.responses.insert(carrier.clone());
        if bound.is_none() {
            self.unbound.push(carrier);
        }
        Ok(bound.map(|bound| bound.instance))
    }
}

/// FIX 9180: the replay row `key`, holding `value`, noted as its parts:
/// its skeleton for the image row, and each part's descriptor and bytes;
/// [`Noted::Unbound`] while a part has no instance bound to its bytes.
/// `None` for a row that does not travel as parts, which the census takes
/// as before.
///
/// # Errors
///
/// Storage errors, and a binding that does not decode.
pub(super) fn note_row(
    census: &mut ResponseCensus,
    store: &Store,
    txn: &RoTxn<'_>,
    key: &[u8],
    value: &[u8],
) -> Result<Option<Noted>> {
    let Some(crate::code_run::ReplayParts {
        skeleton: Some(skeleton),
        parts,
    }) = crate::code_run::replay_row_parts(value)
    else {
        return Ok(None);
    };
    let mut carried = Vec::with_capacity(parts.len());
    let mut unbound = false;
    for part in parts {
        let carrier = ResponseFamily::replay_part_carrier(key, part.request);
        let digest = *blake3::hash(&part.bytes).as_bytes();
        match census.note_part(store, txn, carrier.clone(), &digest)? {
            Some(instance) => carried.push(super::super::carried_bodies::replay::carried_part(
                key, carrier, part, instance, digest,
            )),
            None => unbound = true,
        }
    }
    Ok(Some(if unbound {
        Noted::Unbound
    } else {
        Noted::Parts(skeleton, carried)
    }))
}

/// FIX 9180: the binding pass's bind of a Replay part's carrier: `instance`
/// bound to the bytes its row or start holds now, with an obligation for
/// each owner the part names, unless it holds the part no longer or an
/// instance was bound to its bytes since, when `instance` is debris. A
/// whole replay row's carrier whose row now travels as its parts leaves
/// `instance` debris too. `None` for any other carrier, which binds as
/// before.
///
/// # Errors
///
/// Storage errors.
pub(super) fn bind_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    carrier: &[u8],
    instance: [u8; 16],
) -> Result<Option<Vec<(Vec<u8>, Vec<u8>)>>> {
    let Some((row, request)) = ResponseFamily::replay_part_of(carrier) else {
        return Ok(partitioned_in_txn(store, txn, carrier)?.then(Vec::new));
    };
    let Some((bytes, owners)) = part_in_txn(store, txn, row, request)? else {
        return Ok(Some(Vec::new()));
    };
    let digest = *blake3::hash(&bytes).as_bytes();
    if response_binding_in_txn(store, txn, carrier)?.is_some_and(|bound| bound.digest == digest) {
        return Ok(Some(Vec::new()));
    }
    bind_response_in_txn(
        store,
        txn,
        carrier,
        ResponseBinding { instance, digest },
        &owners,
    )
    .map(Some)
}

/// FIX 9180: whether the row or start a Replay part's carrier names still
/// holds the part, its binding kept; a whole replay row's carrier whose row
/// now travels as its parts holds none. `None` for any other carrier.
///
/// # Errors
///
/// Storage errors.
pub(super) fn holds_in_txn(store: &Store, txn: &RoTxn<'_>, carrier: &[u8]) -> Result<Option<bool>> {
    let Some((row, request)) = ResponseFamily::replay_part_of(carrier) else {
        return Ok(partitioned_in_txn(store, txn, carrier)?.then_some(false));
    };
    Ok(Some(part_in_txn(store, txn, row, request)?.is_some()))
}

/// Whether `carrier` is a whole replay row's whose row travels as its
/// parts.
fn partitioned_in_txn(store: &Store, txn: &RoTxn<'_>, carrier: &[u8]) -> Result<bool> {
    let Some((ResponseDb::VaultMeta, key)) = carrier_row(carrier) else {
        return Ok(false);
    };
    if !key.starts_with(crate::side_table::CODE_RUN_REPLAY.prefix) {
        return Ok(false);
    }
    let Some(value) = row_in_txn(store, txn, ResponseDb::VaultMeta, key)? else {
        return Ok(false);
    };
    Ok(crate::code_run::replay_row_parts(&value).is_some())
}

/// The part `request` (`None`, the rest) of the row `row` as `txn` holds
/// it now: its bytes and its owners; `None` when it holds no such part.
fn part_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    row: &[u8],
    request: Option<(u32, u64)>,
) -> Result<Option<(Vec<u8>, Vec<EntityId>)>> {
    let (parts, kept) = if row.starts_with(crate::side_table::CODE_RUN_REPLAY.prefix) {
        let Some(value) = row_in_txn(store, txn, ResponseDb::VaultMeta, row)? else {
            return Ok(None);
        };
        (crate::code_run::replay_row_parts(&value), None)
    } else {
        let Some(kept) = crate::code_run::kept_step_start_in_txn(store, txn, row)? else {
            return Ok(None);
        };
        (crate::code_run::step_start_parts(&kept.bytes), Some(kept))
    };
    let Some(part) = parts
        .into_iter()
        .flat_map(|parts| parts.parts)
        .find(|part| part.request == request)
    else {
        return Ok(None);
    };
    let owners = match (request, kept) {
        (Some(_), _) => part.seats,
        (None, None) => crate::code_run::replay_owners(store, txn, &part.bytes)?,
        (None, Some(kept)) => crate::code_run::step_start_owners_in_txn(store, txn, &kept)?,
    };
    Ok(Some((part.bytes, owners)))
}
