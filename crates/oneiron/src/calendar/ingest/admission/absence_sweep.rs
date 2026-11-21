//! Which live passports a pull's absence sweep reads as its own source's,
//! and which of them the pull leaves out. The claim door can store a
//! passport's system name or UID as a custody handle, so each is read as
//! custody reads it where it is pinned, as the keyed lookup reads them
//! (CAL-MASKED-SYSTEM-LITERAL-COMPARES-OUTSIDE-KEYED-LOOKUP).

use std::collections::{BTreeMap, BTreeSet};

use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarPassportValue;
use crate::calendar::ics::ParsedIcsFeed;
use crate::calendar::passport::{CalendarSystems, derived_uid_among, passport_uid_among};
use crate::code_run::CompareKnown;
use crate::entity_id::EntityId;
use crate::vault::Vault;

use super::source_events::{pack_source, source_event_id};

/// One sweep's source: its system, the vault's calendar systems, the pack
/// calendar source the system names, the UIDs a sync delta names (every UID
/// of the system when `None`), and the UIDs the pull carries by instance
/// (the exception start a VEVENT's RECURRENCE-ID names; `None` for none).
pub(super) struct SweepSource<'s> {
    vault: &'s Vault,
    system: &'s str,
    systems: CalendarSystems,
    /// The pack calendar source `system` names, whose EVENT ids derive from
    /// the source and the UID ([`source_event_id`]).
    pack: Option<EntityId>,
    only_uids: Option<&'s BTreeSet<&'s str>>,
    present: BTreeMap<Option<u64>, BTreeSet<&'s str>>,
}

impl<'s> SweepSource<'s> {
    /// The source of a pull of `system` that carries `feed`.
    ///
    /// # Errors
    ///
    /// Store failures, a seat or feed row that does not decode, and a
    /// system with the pack's prefix that names no calendar source.
    pub(super) fn read(
        vault: &'s Vault,
        system: &'s str,
        only_uids: Option<&'s BTreeSet<&'s str>>,
        feed: &'s ParsedIcsFeed,
    ) -> Result<Self, CalendarError> {
        let mut present: BTreeMap<Option<u64>, BTreeSet<&str>> = BTreeMap::new();
        for event in &feed.events {
            present
                .entry(event.properties.recurrence_id_utc)
                .or_default()
                .insert(event.uid.as_str());
        }
        Ok(Self {
            vault,
            system,
            systems: CalendarSystems::read(vault)?,
            pack: pack_source(vault, system)?.map(|pack| pack.source),
            only_uids,
            present,
        })
    }

    /// Whether the pull leaves out `value`, a live passport of `event_ref`
    /// (`instance` its exception start, `None` for no exception); `None`
    /// when the passport is not this sweep's: another system's, or of a UID
    /// the delta does not name. The stored system name is the source's as
    /// [`CalendarSystems::carries`] reads it, and the stored UID is one the
    /// pull names as [`Self::names_uid`] reads it on `event_ref`.
    ///
    /// # Errors
    ///
    /// Store failures, the custody read's, and an exception claim that does
    /// not decode.
    pub(super) fn omission(
        &self,
        event_ref: &EntityId,
        instance: Option<u64>,
        value: &CalendarPassportValue,
        known: &CompareKnown<'_>,
    ) -> Result<Option<bool>, CalendarError> {
        if !self.systems.carries(&value.system, self.system, known)? {
            return Ok(None);
        }
        if let Some(named) = self.only_uids
            && !self.names_uid(event_ref, &value.uid, named, known)?
        {
            return Ok(None);
        }
        let Some(carried) = self.present.get(&instance) else {
            return Ok(Some(true));
        };
        Ok(Some(
            !self.names_uid(event_ref, &value.uid, carried, known)?,
        ))
    }

    /// Whether `held`, the UID a passport of this source on `event_ref`
    /// stored, is one of `uids`: as [`passport_uid_among`] reads it, or, for
    /// a pack calendar source, one custody reads it as whose derived EVENT
    /// is `event_ref` or its master ([`derived_uid_among`]): a pack EVENT
    /// has no UID index entry to pin a masked UID by.
    ///
    /// # Errors
    ///
    /// Store failures, the custody read's, and an exception claim that does
    /// not decode.
    fn names_uid(
        &self,
        event_ref: &EntityId,
        held: &str,
        uids: &BTreeSet<&str>,
        known: &CompareKnown<'_>,
    ) -> Result<bool, CalendarError> {
        if passport_uid_among(self.vault, event_ref, held, uids, known)? {
            return Ok(true);
        }
        let Some(source) = self.pack else {
            return Ok(false);
        };
        derived_uid_among(self.vault, event_ref, held, uids, known, |uid| {
            source_event_id(source, uid)
        })
    }
}
