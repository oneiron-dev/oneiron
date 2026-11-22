//! The custody reads of a keyed passport lookup that found no passport
//! carrying its `(system, uid)` as written: a stored system name or UID
//! that holds a custody handle is read as the value the handle stands for,
//! each only where something else pins it
//! (CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT). The scans that
//! pick a source's passports without a key read them the same way: a pull's
//! absence sweep and its written-only tombstone check
//! (CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP).

use std::collections::BTreeSet;

use super::{
    CalendarError, CalendarPassportValue, exception_head_counts_for_ingest, passport_uid_is,
    passport_uid_pinned_is, uid_pinned_to_in_txn,
};
use crate::calendar::claims::{PREDICATE_CALENDAR_SERIES_EXCEPTION, decode_series_exception_value};
use crate::claim::ClaimSubject;
use crate::code_run::CompareKnown;
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// A keyed lookup of `(system, uid)` that found no passport carrying the key
/// as written: it reads a stored system or UID as custody reads it, each only
/// where something else pins it, since a custody record keeps every value it
/// held and one handle meets each of them. The UID must be pinned to the
/// passport's EVENT ([`uid_pinned_to_event_in_txn`]); the system must be
/// stored under handles whose records each hold that one value
/// ([`passport_system_is`]).
pub(super) struct MaskedKey<'k> {
    system: &'k str,
    uid: &'k str,
    /// Whether `uid` is pinned to the EVENT whose passports are read.
    uid_pinned: bool,
}

impl<'k> MaskedKey<'k> {
    /// The pins of `(system, uid)` on `event_ref` as `txn` reads them.
    pub(super) fn read_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        event_ref: &EntityId,
        system: &'k str,
        uid: &'k str,
    ) -> Result<Self, CalendarError> {
        Ok(Self {
            system,
            uid,
            uid_pinned: uid_pinned_to_event_in_txn(vault, txn, event_ref, uid)?,
        })
    }

    /// Whether `value`, a passport on the EVENT, carries the key: its UID
    /// and its system each as written or, where pinned, as custody reads it.
    /// The UID is read first: unpinned, it is a compare as written that
    /// needs no custody read.
    pub(super) fn carried_by(
        &self,
        value: &CalendarPassportValue,
        known: &CompareKnown<'_>,
    ) -> Result<bool, CalendarError> {
        Ok(
            passport_uid_pinned_is(&value.uid, self.uid, self.uid_pinned, known)?
                && passport_system_is(&value.system, self.system, known)?,
        )
    }
}

/// Whether `held`, the UID a passport on `event_ref` stored, is one of
/// `uids`: as written, or as custody reads it where `event_ref` pins that
/// UID ([`uid_pinned_to_event_in_txn`]), as the vault reads it now. A handle
/// meets every value its custody record ever held, so only the pin makes one
/// of `uids` the passport's own. A stored UID that holds no handle custody
/// knows meets only itself ([`CompareKnown::reads_as_written_only`]), so a
/// sweep compares each of `uids` with a masked passport's UID alone.
///
/// # Errors
///
/// Store failures, the custody read's, and an exception claim that does not
/// decode.
pub(in crate::calendar) fn passport_uid_among(
    vault: &Vault,
    event_ref: &EntityId,
    held: &str,
    uids: &BTreeSet<&str>,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if uids.contains(held) {
        return Ok(true);
    }
    if uids.is_empty() || known.reads_as_written_only(&rmpv::Value::from(held))? {
        return Ok(false);
    }
    let mut carried = Vec::new();
    for uid in uids {
        if passport_uid_is(held, uid, known)? {
            carried.push(*uid);
        }
    }
    if carried.is_empty() {
        return Ok(false);
    }
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    for uid in carried {
        if uid_pinned_to_event_in_txn(vault, &txn, event_ref, uid)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `held`, the UID a passport on `event_ref` stored, is one of
/// `uids` that `derive` mints `event_ref` for: one custody reads `held` as
/// ([`passport_uid_is`]) and whose derived EVENT id is `event_ref`, or the
/// master `event_ref` is a detached instance of. A pack calendar source
/// mints its EVENT at an id derived from the source and the UID and writes
/// no UID index entry for it, so the derived id is what pins such a UID
/// (blind review round 1 of #10312). A stored UID that holds no handle
/// custody knows meets only itself, which [`passport_uid_among`] has read.
///
/// # Errors
///
/// Store failures, `derive`'s, the custody read's, and an exception claim
/// that does not decode.
pub(in crate::calendar) fn derived_uid_among(
    vault: &Vault,
    event_ref: &EntityId,
    held: &str,
    uids: &BTreeSet<&str>,
    known: &CompareKnown<'_>,
    derive: impl Fn(&str) -> Result<EntityId, CalendarError>,
) -> Result<bool, CalendarError> {
    if uids.is_empty() || known.reads_as_written_only(&rmpv::Value::from(held))? {
        return Ok(false);
    }
    let master = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        live_series_master_in_txn(vault, &txn, event_ref)?
    };
    for &uid in uids {
        if !passport_uid_is(held, uid, known)? {
            continue;
        }
        let minted = derive(uid)?;
        if minted == *event_ref || master == Some(minted) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether `held`, the system name a passport stored, is `system`: as
/// written, or with a custody handle in place of a value custody holds
/// ([`passport_uid_is`]'s read), when each handle `held` holds names a
/// record that holds one value alone ([`CompareKnown::reads_as_one_value`]).
/// Such a `held` meets one system name alone, the one the claim door masked,
/// so it reads as that name would read as written, whichever source filed
/// it: a seat's, a feed's, an owner upload's or a pack source's
/// (CAL-PASSPORT-STORES-NO-SYSTEM-IDENTITY). A custody record keeps every
/// value it held, so once a record that held one source's system name holds
/// another's, one handle meets both names: a passport stored under such a
/// handle is read as written only, so one calendar's pull never takes or
/// sweeps another source's passport, whose deletes would then read as the
/// first calendar's host cancels (blind review round 1 of #10312).
///
/// # Errors
///
/// The custody read's, or a value the wall cannot read.
pub(in crate::calendar) fn passport_system_is(
    held: &str,
    system: &str,
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if held == system {
        return Ok(true);
    }
    if !known.reads_as_one_value(&rmpv::Value::from(held))? {
        return Ok(false);
    }
    passport_uid_is(held, system, known)
}

/// Whether `uid` is pinned to `event_ref` ([`uid_pinned_to_in_txn`]), or
/// `event_ref` is a detached instance of a series and `uid` is pinned to its
/// master. A member EVENT carries its series' UID, and the UID index points
/// that UID at the master alone, so a member's passport UID stored as a
/// custody handle is read through it only where the master pins the UID
/// (CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT).
///
/// # Errors
///
/// Store failures, and an exception claim that does not decode.
fn uid_pinned_to_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    uid: &str,
) -> Result<bool, CalendarError> {
    if uid_pinned_to_in_txn(vault, txn, event_ref, uid)? {
        return Ok(true);
    }
    match live_series_master_in_txn(vault, txn, event_ref)? {
        Some(master) => uid_pinned_to_in_txn(vault, txn, &master, uid),
        None => Ok(false),
    }
}

/// The master of `event` when the ingest diff reads `event` as a detached
/// series instance ([`super::is_live_series_exception`]): the one master its
/// counted exception heads name, as `txn` reads them. None when no head
/// counts, when two of them name different masters, or when a head names
/// `event` itself.
///
/// # Errors
///
/// Store failures, and an exception claim that does not decode.
fn live_series_master_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: &EntityId,
) -> Result<Option<EntityId>, CalendarError> {
    let mut master = None;
    for id in vault.claims_for_subject_in_txn(txn, event)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_SERIES_EXCEPTION
            || body.subject != ClaimSubject::Entity(*event)
            || !exception_head_counts_for_ingest(&body)
        {
            continue;
        }
        let named = decode_series_exception_value(&body.value)?.master_ref;
        if master.is_some_and(|prior| prior != named) {
            return Ok(None);
        }
        master = Some(named);
    }
    Ok(master.filter(|named| named != event))
}
