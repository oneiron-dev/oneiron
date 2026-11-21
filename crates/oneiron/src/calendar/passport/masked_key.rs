//! The custody reads of a keyed passport lookup that found no passport
//! carrying its `(system, uid)` as written: a stored system name or UID
//! that holds a custody handle is read as the value the handle stands for,
//! each only where something else pins it
//! (CAL-PASSPORT-SYSTEM-UID-LOOKUP-MISSES-MASKED-PASSPORT).

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
/// passport's EVENT ([`uid_pinned_to_event_in_txn`]); the system must be one
/// of the vault's calendar systems that no other of them could stand for
/// ([`passport_system_is`]).
pub(super) struct MaskedKey<'k> {
    system: &'k str,
    uid: &'k str,
    /// The vault's calendar systems ([`calendar_systems_in_txn`]).
    systems: Vec<String>,
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
            systems: calendar_systems_in_txn(vault, txn)?,
            uid_pinned: uid_pinned_to_event_in_txn(vault, txn, event_ref, uid)?,
        })
    }

    /// Whether `value`, a passport on the EVENT, carries the key: its system
    /// and its UID each as written or, where pinned, as custody reads it.
    pub(super) fn carried_by(
        &self,
        value: &CalendarPassportValue,
        known: &CompareKnown<'_>,
    ) -> Result<bool, CalendarError> {
        Ok(
            passport_system_is(&value.system, self.system, &self.systems, known)?
                && passport_uid_pinned_is(&value.uid, self.uid, self.uid_pinned, known)?,
        )
    }
}

/// Whether `held`, the system name a passport stored, is `system`: as
/// written, or with a custody handle in place of a value custody holds
/// ([`passport_uid_is`]'s read), when `system` is one of `systems`, the
/// vault's calendar systems, and no other of them reads as `held`. A custody
/// record keeps every value it held, so once a record that held a value in
/// one seat's system name holds one in another seat's, one handle meets both
/// names: a passport stored under such a handle is read as written only, so
/// one calendar's pull never takes another calendar's passport, whose deletes
/// would then read as the first calendar's host cancels. A system no seat or
/// feed of the vault names (an upload's own) is read as written only too.
///
/// # Errors
///
/// The custody read's, or a value the wall cannot read.
fn passport_system_is(
    held: &str,
    system: &str,
    systems: &[String],
    known: &CompareKnown<'_>,
) -> Result<bool, CalendarError> {
    if held == system {
        return Ok(true);
    }
    if !systems.iter().any(|named| named == system) || !passport_uid_is(held, system, known)? {
        return Ok(false);
    }
    for named in systems {
        if named != system && passport_uid_is(held, named, known)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The calendar systems the vault names, as `txn` reads them: each connector
/// seat's, installed or taken out of service
/// ([`crate::calendar::connectors::door::seat_systems_in_txn`]), and each ICS
/// feed's, installed or polled before
/// ([`crate::calendar::ingest::feed_door::feed_systems_in_txn`]).
fn calendar_systems_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<String>, CalendarError> {
    let mut systems = crate::calendar::connectors::door::seat_systems_in_txn(vault, txn)?;
    systems.extend(crate::calendar::ingest::feed_door::feed_systems_in_txn(
        vault, txn,
    )?);
    Ok(systems)
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
