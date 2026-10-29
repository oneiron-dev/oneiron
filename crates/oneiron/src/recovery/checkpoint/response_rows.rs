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
//! terminal erased state, a replay record its terminal evidence, a claim
//! the erase's shell, deindexed and marked deleted, a wait's reply its erased
//! form, an agent dispatch's attempt row its text-free form, and a captured
//! request nothing at all (FIX 6588, 7115, 6708).
//!
//! A row its family recognizes that does not decode travels the same way,
//! whole and opaque (FIX 6227): its descriptor says so, a live instance
//! lands its exact bytes, and a retired one leaves the explicit erased
//! marker (a claim, its shell).
//!
//! A decoded replay row whose spawns reached resolved targets travels as its
//! parts instead, each bound and carried on its own ([`replay`], FIX 9180).
//!
//! What an erase after the image's cut took that no obligation names, a
//! restore takes again ([`removals`]).

pub(super) mod removals;
mod replay;

use std::borrow::Cow;
use std::collections::BTreeSet;

use heed::RoTxn;
use heed::types::Bytes;

use super::carried_bodies::CarriedInline;
use super::restore_class::{Class, Classes};
use super::{CanonicalRows, CheckpointImage, codec_error, rebuild};
use crate::attempt_queue::AttemptId;
use crate::store::{
    RESPONSE_BINDINGS, ResponseBinding, ResponseCarriage, ResponseDb, ResponseFamily, Store,
    bind_response_in_txn, carrier_row, release_response_in_txn, response_binding_in_txn,
    response_carrier, response_owed_to_all_in_txn, stamp_opaque_erased,
};
use crate::vault_cleanup::refresh_archived_attempt_in_rows;
use crate::{Error, Result};

/// What the census found of one row.
pub(super) enum Noted {
    /// No response: the row travels as it is.
    Not,
    /// A response with no instance bound to its bytes yet.
    Unbound,
    /// A response bound to `instance`: the image row holds the stub, and
    /// the bytes after `keep`, whose BLAKE3 is `digest`, travel sealed;
    /// `opaque` when the row does not decode (FIX 6227).
    Bound {
        carriage: ResponseCarriage,
        instance: [u8; 16],
        digest: [u8; 32],
        opaque: bool,
    },
    /// A replay row travelling as its parts (FIX 9180): the skeleton its
    /// image row holds, and each part's descriptor and bytes.
    Parts(Vec<u8>, Vec<(CarriedInline, Vec<u8>)>),
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
        let Some(family) = ResponseFamily::of_row(db, key, value) else {
            return Ok(Noted::Not);
        };
        if family == ResponseFamily::Replay
            && let Some(noted) = replay::note_row(self, store, txn, key, value)?
        {
            return Ok(noted);
        }
        let Some((carriage, opaque)) = family.scan(key, value).carriage() else {
            return Ok(Noted::Not);
        };
        let carrier = response_carrier(db, key);
        let digest = *blake3::hash(&value[carriage.keep..]).as_bytes();
        self.responses.insert(carrier.clone());
        let binding =
            response_binding_in_txn(store, txn, &carrier)?.filter(|bound| bound.digest == digest);
        // A shared reply's late holder joins its instance's obligations at
        // the binding pass before an image carries it (FIX 6588).
        let joined = match binding {
            Some(binding) if family.shared() => {
                let owners = family.owners(store, txn, key, value)?;
                response_owed_to_all_in_txn(store, txn, family, &binding.instance, &owners)?
            }
            _ => true,
        };
        match binding {
            Some(binding) if joined => Ok(Noted::Bound {
                carriage,
                instance: binding.instance,
                digest,
                opaque,
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
/// travels as; `opaque` for a row that does not decode (FIX 6227).
pub(super) fn carry(
    database: &str,
    key: &[u8],
    value: &[u8],
    (carriage, instance, digest, opaque): (ResponseCarriage, [u8; 16], [u8; 32], bool),
) -> Result<(CarriedInline, Vec<u8>, Vec<u8>)> {
    let body = value[carriage.keep..].to_vec();
    // A queue row lands unleased (FIX 7115): the length it lands at. An
    // opaque one the strict reader refuses lands as it rested (FIX 9390).
    let landed_len = if database != ResponseDb::Attempts.name() {
        None
    } else if opaque {
        rebuild::unlease_opaque_attempt(key, value)?.map(|row| row.len() as u64)
    } else {
        Some(rebuild::unlease_attempt(key, value)?.len() as u64)
    };
    let carried = CarriedInline {
        database: database.to_owned(),
        key: key.to_vec(),
        keep: u32::try_from(carriage.keep).map_err(|_| codec_error())?,
        instance,
        digest,
        len: body.len() as u64,
        stored_len: 0,
        retired: Some(u32::try_from(carriage.retired).map_err(|_| codec_error())?),
        landed_len,
        opaque,
        superseded: false,
        replay: None,
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
/// its bytes since: then `instance` is debris. Returns the obligation rows
/// the writer journals before it commits.
///
/// # Errors
///
/// Storage errors.
pub(super) fn bind_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    carrier: &[u8],
    instance: [u8; 16],
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // A replay part's carrier names no row (FIX 9180).
    if let Some(history) = replay::bind_in_txn(store, txn, carrier, instance)? {
        return Ok(history);
    }
    let Some((db, key)) = carrier_row(carrier) else {
        return Ok(Vec::new());
    };
    let Some(value) = row_in_txn(store, txn, db, key)? else {
        return Ok(Vec::new());
    };
    let Some(family) = ResponseFamily::of_row(db, key, &value) else {
        return Ok(Vec::new());
    };
    let Some((carriage, opaque)) = family.scan(key, &value).carriage() else {
        return Ok(Vec::new());
    };
    let digest = *blake3::hash(&value[carriage.keep..]).as_bytes();
    if let Some(bound) =
        response_binding_in_txn(store, txn, carrier)?.filter(|bound| bound.digest == digest)
    {
        if !family.shared() {
            return Ok(Vec::new());
        }
        // A shared reply's late holder joins the instance its images carry
        // it under (FIX 6588); `instance` is debris.
        let owners = family.owners(store, txn, key, &value)?;
        if response_owed_to_all_in_txn(store, txn, family, &bound.instance, &owners)? {
            return Ok(Vec::new());
        }
        return bind_response_in_txn(store, txn, carrier, bound, &owners);
    }
    let owners = if opaque {
        // An opaque response's owners are what its key proves (FIX 6227);
        // the rest are reported, never invented.
        let owners = family.opaque_owners(store, txn, key, &value)?;
        if !owners.proved() {
            tracing::warn!(
                ?family,
                "an undecodable response is bound under the owners its key proves; the ones \
                 its row stamps are not known"
            );
        }
        owners.into_ids()
    } else {
        family.owners(store, txn, key, &value)?
    };
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
        // A replay part's carrier names no row (FIX 9180).
        let holds = match replay::holds_in_txn(store, txn, carrier)? {
            Some(holds) => holds,
            None => match carrier_row(carrier) {
                Some((db, key)) => row_in_txn(store, txn, db, key)?.is_some_and(|value| {
                    ResponseFamily::of_row(db, key, &value)
                        .and_then(|family| family.scan(key, &value).carriage())
                        .is_some()
                }),
                None => false,
            },
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
    type Gone = (String, Vec<u8>, usize, [u8; 16], [u8; 32]);
    let gone: Vec<Gone> = image
        .inline_bodies
        .iter()
        .filter(|carried| !carried.superseded && retired.contains(&carried.instance))
        .filter_map(|carried| {
            carried.retired.map(|keep| {
                let (database, key) = (carried.database.clone(), carried.key.clone());
                (
                    database,
                    key,
                    keep as usize,
                    carried.instance,
                    carried.digest,
                )
            })
        })
        .collect();
    for (database, key, keep, instance, digest) in gone {
        let rows = image.databases.get_mut(&database).ok_or_else(codec_error)?;
        let value = row_mut(rows, &key)?;
        if value.len() < keep {
            return Err(codec_error());
        }
        value.truncate(keep);
        let family = ResponseDb::of_name(&database)
            .and_then(|db| ResponseFamily::of_row(db, &key, value))
            .ok_or_else(codec_error)?;
        // A keyed entry its own caller's erase retired goes, as that erase
        // dropped it live; any other owner's erase leaves its erased form
        // (FIX 7470). The erase's receipt rows name who erased it.
        let caller = (family == ResponseFamily::Http)
            .then(|| crate::store::http_erase_drop_caller(value))
            .flatten();
        // An opaque one's erased marker takes the time it retired, as a live
        // prune stamps it, so a restored vault's marker expires as a live
        // one's does (FIX 10710); a row its family drops goes all the same.
        if let Cow::Owned(stamped) = stamp_opaque_erased(value) {
            *value = stamped;
        }
        // An attempt's archive mark bound its carried bytes: it follows the
        // row to its text-free form (FIX 7115).
        if family == ResponseFamily::AttemptPayload {
            let after = *blake3::hash(value).as_bytes();
            if let (Ok(id), Some(rows)) = (
                AttemptId::from_bytes(&key),
                image.databases.get_mut("vault_meta"),
            ) {
                refresh_archived_attempt_in_rows(rows, id, &digest, &after);
            }
        }
        if let Some(caller) = caller
            && erased_by(&image.databases, &caller, &instance)
        {
            if let Some(rows) = image.databases.get_mut(&database) {
                rows.retain(|(row, _)| row.as_slice() != key.as_slice());
            }
            continue;
        }
        family.retire_in_rows(&mut image.databases, &key)?;
    }
    Ok(())
}

/// Unleases each queue row a restore landed from its carried bytes, after
/// they land and before any row does, as a snapshot unleases every other
/// (FIX 7115): the instance seals the row as it stood, so its image row is
/// normalized only here. Its archive mark follows it when it bound the bytes
/// carried. A Landing attempt refuses, as at the snapshot. An opaque one the
/// strict reader refuses keeps its exact bytes (FIX 9390).
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for a carried row the image does not hold, and
/// an attempt that does not decode or is landing.
pub(super) fn unlease_carried_attempts(
    image: &mut CheckpointImage,
    retired: &BTreeSet<[u8; 16]>,
) -> Result<()> {
    let landed: Vec<(Vec<u8>, [u8; 32], bool)> = image
        .inline_bodies
        .iter()
        .filter(|carried| {
            carried.database == ResponseDb::Attempts.name()
                && !carried.superseded
                && !retired.contains(&carried.instance)
        })
        .map(|carried| (carried.key.clone(), carried.digest, carried.opaque))
        .collect();
    for (key, digest, opaque) in landed {
        let rows = image
            .databases
            .get_mut(ResponseDb::Attempts.name())
            .ok_or_else(codec_error)?;
        let value = row_mut(rows, &key)?;
        if opaque {
            match rebuild::unlease_opaque_attempt(&key, value)? {
                Some(unleased) => *value = unleased,
                None => continue,
            }
        } else {
            *value = rebuild::unlease_attempt(&key, value)?;
        }
        let after = *blake3::hash(value).as_bytes();
        if let (Ok(id), Some(rows)) = (
            AttemptId::from_bytes(&key),
            image.databases.get_mut("vault_meta"),
        ) {
            refresh_archived_attempt_in_rows(rows, id, &digest, &after);
        }
    }
    Ok(())
}

/// Whether the image `databases` hold `owner`'s erase receipt row for
/// `instance`: that erase retired it.
fn erased_by(
    databases: &std::collections::BTreeMap<String, CanonicalRows>,
    owner: &crate::EntityId,
    instance: &[u8; 16],
) -> bool {
    let mut key = crate::side_table::PROVENANCE_BODY_ERASED.prefix.to_vec();
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(instance);
    databases.get("vault_meta").is_some_and(|rows| {
        rows.binary_search_by(|(row, _)| row.as_slice().cmp(&key))
            .is_ok()
    })
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
