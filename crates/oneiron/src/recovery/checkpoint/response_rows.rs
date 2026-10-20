//! The row-held responses a checkpoint carries (KS-2B1, FIX 5683 part B1):
//! a turn program's STEP bodies, LLM step-state payloads, terminal
//! `dreamer.step` claims' inline responses and code runs' replay outcomes.
//!
//! The census finds each row holding a response, and the instance bound to
//! its bytes. A bound one travels sealed under its instance, its row as the
//! stub its family writes (never the response), and a restore lands the
//! exact bytes in the stub's place; one with no instance bound to its bytes
//! yet holds the snapshot back until the binding pass binds one. A binding
//! whose row no longer holds a response stays out of the image, and the
//! binding pass drops it, keeping every key and obligation.
//!
//! A restore requires each carried instance with the rest. A retired one's
//! row keeps the erased disposition its stub names, as the erase that
//! retired it left its vault: a STEP row its evidence, a step-state row a
//! terminal erased state, a replay record its terminal evidence, and a claim
//! the erase's shell, deindexed and marked deleted.

use std::collections::BTreeSet;

use heed::RoTxn;
use heed::types::Bytes;

use super::carried_bodies::CarriedInline;
use super::restore_class::{Class, Classes};
use super::{CanonicalRows, CheckpointImage, codec_error};
use crate::store::{
    RESPONSE_BINDINGS, ResponseBinding, ResponseCarriage, ResponseDb, ResponseFamily, Store,
    bind_response_in_txn, carrier_row, release_response_in_txn, response_binding_in_txn,
    response_carrier,
};
use crate::{Error, Result};

/// What the census found of one row.
pub(super) enum Noted {
    /// No response: the row travels as it is.
    Not,
    /// A response with no instance bound to its bytes yet.
    Unbound,
    /// A response bound to `instance`: the image row holds the stub, and
    /// the bytes after `keep`, whose BLAKE3 is `digest`, travel sealed.
    Bound {
        carriage: ResponseCarriage,
        instance: [u8; 16],
        digest: [u8; 32],
    },
}

/// The responses a snapshot's rows hold, and the bindings it read.
#[derive(Default)]
pub(super) struct ResponseCensus {
    /// The carrier of each binding row read.
    bindings: BTreeSet<Vec<u8>>,
    /// The carrier of each row holding a response, bound or not.
    responses: BTreeSet<Vec<u8>>,
    /// The carrier of each response with no instance bound to its bytes.
    unbound: Vec<Vec<u8>>,
}

impl ResponseCensus {
    /// Notes the canonical row `key` of `database`, holding `value`.
    ///
    /// # Errors
    ///
    /// Storage errors, and a binding that does not decode.
    pub(super) fn note(
        &mut self,
        store: &Store,
        txn: &RoTxn<'_>,
        database: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<Noted> {
        let Some(db) = ResponseDb::of_name(database) else {
            return Ok(Noted::Not);
        };
        if db == ResponseDb::VaultMeta
            && let Some(carrier) = key.strip_prefix(RESPONSE_BINDINGS.decl().prefix)
        {
            self.bindings.insert(carrier.to_vec());
            return Ok(Noted::Not);
        }
        let Some(carriage) =
            ResponseFamily::of_row(db, key, value).and_then(|family| family.carriage(value))
        else {
            return Ok(Noted::Not);
        };
        let carrier = response_carrier(db, key);
        let digest = *blake3::hash(&value[carriage.keep..]).as_bytes();
        self.responses.insert(carrier.clone());
        match response_binding_in_txn(store, txn, &carrier)? {
            Some(binding) if binding.digest == digest => Ok(Noted::Bound {
                carriage,
                instance: binding.instance,
                digest,
            }),
            _ => {
                self.unbound.push(carrier);
                Ok(Noted::Unbound)
            }
        }
    }

    /// The carrier of each response with no instance bound to its bytes.
    pub(super) fn unbound(&self) -> &[Vec<u8>] {
        &self.unbound
    }

    /// The full key of each binding whose row holds no response now: the
    /// image leaves it out, and the binding pass drops it.
    pub(super) fn stale(&self) -> BTreeSet<Vec<u8>> {
        self.bindings
            .difference(&self.responses)
            .map(|carrier| RESPONSE_BINDINGS.key_bytes(carrier))
            .collect()
    }
}

/// The carried inline body of a bound response, and the stub its row
/// travels as.
pub(super) fn carry(
    database: &str,
    key: &[u8],
    value: &[u8],
    (carriage, instance, digest): (ResponseCarriage, [u8; 16], [u8; 32]),
) -> Result<(CarriedInline, Vec<u8>, Vec<u8>)> {
    let body = value[carriage.keep..].to_vec();
    let carried = CarriedInline {
        database: database.to_owned(),
        key: key.to_vec(),
        keep: u32::try_from(carriage.keep).map_err(|_| codec_error())?,
        instance,
        digest,
        len: body.len() as u64,
        stored_len: 0,
        retired: Some(u32::try_from(carriage.retired).map_err(|_| codec_error())?),
        superseded: false,
    };
    Ok((carried, body, carriage.stub))
}

/// The row `key` of `db` as `txn` holds it.
fn row_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    db: ResponseDb,
    key: &[u8],
) -> Result<Option<Vec<u8>>> {
    let table = store
        .env
        .open_database::<Bytes, Bytes>(txn, Some(db.name()))?
        .ok_or(Error::CorruptedIndex("canonical checkpoint image"))?;
    Ok(table.get(txn, key)?.map(<[u8]>::to_vec))
}

/// Binds `instance` to the response the row `carrier` names holds now, in
/// the binding pass's writer, with an obligation for each owner its stamps
/// name; unless the row holds none any longer, or an instance was bound to
/// its bytes since: then `instance` is debris.
///
/// # Errors
///
/// Storage errors.
pub(super) fn bind_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    carrier: &[u8],
    instance: [u8; 16],
) -> Result<()> {
    let Some((db, key)) = carrier_row(carrier) else {
        return Ok(());
    };
    let Some(value) = row_in_txn(store, txn, db, key)? else {
        return Ok(());
    };
    let Some(family) = ResponseFamily::of_row(db, key, &value) else {
        return Ok(());
    };
    let Some(carriage) = family.carriage(&value) else {
        return Ok(());
    };
    let digest = *blake3::hash(&value[carriage.keep..]).as_bytes();
    if response_binding_in_txn(store, txn, carrier)?.is_some_and(|bound| bound.digest == digest) {
        return Ok(());
    }
    let owners = family.owners(store, txn, key, &value)?;
    bind_response_in_txn(
        store,
        txn,
        carrier,
        ResponseBinding { instance, digest },
        &owners,
    )
}

/// Drops each binding in `stale` (full keys) whose row still holds no
/// response, in the binding pass's writer: a delete, an overwrite or an
/// expiry keeps every key and every obligation.
///
/// # Errors
///
/// Storage errors.
pub(super) fn release_stale_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    stale: &BTreeSet<Vec<u8>>,
) -> Result<()> {
    for full in stale {
        let Some(carrier) = full.strip_prefix(RESPONSE_BINDINGS.decl().prefix) else {
            continue;
        };
        let holds = match carrier_row(carrier) {
            Some((db, key)) => row_in_txn(store, txn, db, key)?.is_some_and(|value| {
                ResponseFamily::of_row(db, key, &value)
                    .and_then(|family| family.carriage(&value))
                    .is_some()
            }),
            None => false,
        };
        if !holds {
            release_response_in_txn(store, txn, carrier)?;
        }
    }
    Ok(())
}

/// Leaves each carried response whose instance is `retired` its row's
/// erased disposition in the image, before anything lands: its stub as far
/// as the disposition keeps it, and what the erase took beside the row (a
/// claim's step-index rows, its deletion marks). Its binding went with the
/// prune.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for a carried response the image's rows do not
/// hold.
pub(super) fn retire_carried(
    image: &mut CheckpointImage,
    retired: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    let gone: Vec<(String, Vec<u8>, usize)> = image
        .inline_bodies
        .iter()
        .filter(|carried| !carried.superseded && retired.contains(&carried.instance))
        .filter_map(|carried| {
            carried
                .retired
                .map(|keep| (carried.database.clone(), carried.key.clone(), keep as usize))
        })
        .collect();
    for (database, key, keep) in gone {
        let rows = image.databases.get_mut(&database).ok_or_else(codec_error)?;
        let value = row_mut(rows, &key)?;
        if value.len() < keep {
            return Err(codec_error());
        }
        value.truncate(keep);
        let family = ResponseDb::of_name(&database)
            .and_then(|db| ResponseFamily::of_row(db, &key, value))
            .ok_or_else(codec_error)?;
        family.retire_in_rows(&mut image.databases, &key)?;
    }
    Ok(())
}

/// Marks each carried response whose row a restore over `current` keeps as
/// `current` holds it, a Live family's (a media job's, KS-2B2): the
/// authority carry put `current`'s row in the image's place, absent when
/// `current` holds none, and `current`'s binding with it, so the image's
/// copy is passed over, never required, retired or landed. Its stream keeps
/// its place among the artifact's.
///
/// # Errors
///
/// Storage errors reading `current`'s classes.
pub(super) fn supersede_live(image: &mut CheckpointImage, current: &crate::Vault) -> Result<()> {
    let classes = Classes::new(current, &image.databases)?;
    for carried in &mut image.inline_bodies {
        if carried.retired.is_some()
            && classes.row(&carried.database, &carried.key, &[]).0 == Class::Live
        {
            carried.superseded = true;
        }
    }
    Ok(())
}

/// The value of the row `key` among sorted `rows`.
pub(super) fn row_mut<'r>(rows: &'r mut CanonicalRows, key: &[u8]) -> Result<&'r mut Vec<u8>> {
    let at = rows
        .binary_search_by(|(row, _)| row.as_slice().cmp(key))
        .map_err(|_| codec_error())?;
    Ok(&mut rows[at].1)
}
