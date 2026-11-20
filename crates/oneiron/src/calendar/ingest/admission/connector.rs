//! Connector admissions: CalDAV and provider pulls admit through the same
//! gated importer a feed poll runs, keeping their own routing.

use super::*;

/// Connector resources use the same gated importer, but retain their routing.
pub(in crate::calendar) fn connector_event_ref(
    vault: &Vault,
    event: &ParsedVEvent,
) -> Result<Option<EntityId>, CalendarError> {
    let master = crate::calendar::passport::resolve_event_by_uid(vault, &event.uid)?;
    match event.properties.recurrence_id_utc {
        None => Ok(master),
        Some(original) => Ok(Some(recurrence::exception_id(
            master.ok_or_else(|| ingest("recurrence exception has no master"))?,
            original,
        )?)),
    }
}
fn connector_admission<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: ConnectorAdmissionSource<'a>,
    now: u64,
) -> PollAdmission<'a> {
    PollAdmission {
        vault,
        system,
        preserve_direction: true,
        screener: source.screen.screener,
        safeguard_enabled: source.screen.safeguard_enabled,
        now,
        blob_ref: source.record,
        source: None,
        verdict_fold: VerdictFold::default(),
        continuations: None,
        owed_booking_moves: 0,
        admitted_claims: Vec::new(),
    }
}
/// Checks every event's values before any is admitted. Value checks run no
/// screen, so the record alone names the source.
pub(in crate::calendar) fn preflight_connector_feed(
    vault: &Vault,
    system: &str,
    source: &str,
    feed: &super::super::ics::ParsedIcsFeed,
    now: u64,
) -> Result<(), CalendarError> {
    let admission = connector_admission(vault, system, source.into(), now);
    for event in &feed.events {
        admission.preflight_event(event)?;
    }
    Ok(())
}

/// The owner's CAL-09 screen a connector admission runs under, as a feed
/// poll runs it: the dial's live value and the host's screener. The default
/// is the dial off with no screener.
#[derive(Clone, Copy, Default)]
pub(in crate::calendar) struct ConnectorScreen<'a> {
    pub(in crate::calendar) screener: Option<&'a dyn CalendarBodyScreener>,
    pub(in crate::calendar) safeguard_enabled: bool,
}

/// What a connector admission admits from: the pull record its claims cite,
/// the archived resource version a property continuation reads again, and
/// the screen each admission runs under.
#[derive(Clone, Copy)]
pub(in crate::calendar) struct ConnectorAdmissionSource<'a> {
    pub(in crate::calendar) record: &'a str,
    pub(in crate::calendar) source_version: Option<&'a str>,
    pub(in crate::calendar) screen: ConnectorScreen<'a>,
    /// The exact archived version the admitted passports keep, when the pull archived one.
    pub(in crate::calendar) source: Option<CalendarPassportSource>,
}

impl<'a> From<&'a str> for ConnectorAdmissionSource<'a> {
    /// A pull record with no archived version, admitted with the dial off:
    /// every property is admitted in one pass, unscreened.
    fn from(record: &'a str) -> Self {
        Self {
            record,
            source_version: None,
            screen: ConnectorScreen::default(),
            source: None,
        }
    }
}

/// Admits one connector event as an ICS admission admits it: under the
/// source's screen, one pass's count of new property claims, and a queued
/// continuation reading the archived resource version again for the rest
/// (FIX 12163), which runs the same screen.
///
/// True when a pending emergency delivery held the event's booking move
/// back (FIX 22385): nothing of the event was admitted, and the caller keeps
/// the resource owed so the next pull reads it again.
pub(in crate::calendar) fn admit_connector_event<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    event: &ParsedVEvent,
    now: u64,
) -> Result<bool, CalendarError> {
    let source = source.into();
    let mut admission = connector_admission(vault, system, source, now);
    admission.source = source.source;
    let Some(source_version) = source.source_version else {
        admission.apply_event(event)?;
        return Ok(admission.owed_booking_moves > 0);
    };
    admission.continuations = Some(Vec::new());
    admission.apply_event(event)?;
    admission.queue_property_continuations_reading(source_version)?;
    Ok(admission.owed_booking_moves > 0)
}

/// A pulled resource the echo law acknowledged: `passport`, the source's
/// live passport, already carries its SEQUENCE and content hash, so nothing
/// of it is admitted again.
///
/// An uncancelled resource at the version of a passport that dates a
/// cancellation (`cancelled_since`, a held sighting, or the owner's
/// cancelled write) is the calendar showing the EVENT again: that report is
/// withdrawn
/// ([`withdraw_tombstone_report`]).
///
/// For a cancellation, when an admission of pulled bytes committed that
/// passport (it keeps their archived source), the deposit refund and status
/// are asked again, as a feed poll asks them on an unchanged sighting: the
/// passport commits before they do, so a stop between them leaves the next
/// pull of the same bytes here, and this is where they are repaired. A
/// passport the seat's own write committed keeps no source: its echo is the
/// owner's own write coming back, not a cancellation made in that calendar,
/// and writes nothing.
pub(in crate::calendar) fn repeat_connector_echo<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: ConnectorAdmissionSource<'a>,
    event_ref: EntityId,
    passport: &CalendarPassportValue,
    event: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarError> {
    let mut admission = connector_admission(vault, system, source, now);
    if !event.cancelled {
        return withdraw_tombstone_report(&mut admission, event_ref, passport, event);
    }
    if passport.source.is_none() {
        return Ok(());
    }
    admission.repeat_imported_cancel(event_ref, event)
}

/// A cancelled version of `event` a pull held back unread, since a cancelled
/// write of its member to this calendar is still in flight and the version
/// may be that write coming back
/// (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS). `passport`, the
/// source's live passport, keeps this first sighting as
/// `deferred_cancel_seen_at`, unless it already dates a cancellation or a
/// held sighting. A write that settles, or proves to be the stored copy,
/// drops it; when the write was refused and the copy is not its own, the
/// next pull admits the version as the source's cancellation, dated by this
/// sighting rather than by that later read.
pub(in crate::calendar) fn defer_connector_cancel<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: ConnectorAdmissionSource<'a>,
    event_ref: EntityId,
    passport: &CalendarPassportValue,
    event: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarError> {
    if passport.cancelled_since.is_some() || passport.deferred_cancel_seen_at.is_some() {
        return Ok(());
    }
    let mut admission = connector_admission(vault, system, source, now);
    let mut next = passport.clone();
    next.deferred_cancel_seen_at = Some(now);
    admission.admit_superseding_passport(event_ref, &next, &screen_body(event))
}

/// A live passport a tombstone dated, whose calendar shows the uncancelled
/// EVENT again at the same version, drops that date: the host took the
/// deletion back, so it can no longer date a host cancel that another
/// calendar's omission later concludes, and no deposit moves on it. The
/// passport keeps its presence and direction, so an Outbound one stays no
/// absence vote. Only an Outbound passport can stand live with such a date:
/// an inbound-bearing one flips absent at its tombstone, and its
/// reappearance is an update whose passport carries no cancellation.
///
/// The live version ends a held cancelled one too, as an update does: its
/// first sighting (`deferred_cancel_seen_at`) goes, so a cancel first seen
/// later is dated by its own sighting and not by the withdrawn one
/// (BK-ECHO-DEFERRED-SIGHTING-OUTLIVES-ECHO-RESTORE), and so does a mark of
/// the owner's cancelled write, which no later cancellation of the shown
/// EVENT inherits.
///
/// Only the passport's own version (its SEQUENCE and content hash) shows the
/// EVENT again. A version below it is a stale replay, which never regresses
/// passport state: a live copy a pull read before the owner's cancelled
/// write settled leaves that write's mark, so the provider's later rewrite
/// of the cancellation still reads as the owner's own write.
fn withdraw_tombstone_report(
    admission: &mut PollAdmission<'_>,
    event_ref: EntityId,
    passport: &CalendarPassportValue,
    event: &ParsedVEvent,
) -> Result<(), CalendarError> {
    let dated = passport.cancelled_since.is_some()
        || passport.deferred_cancel_seen_at.is_some()
        || passport.written_cancelled;
    let same_version =
        event.sequence == passport.last_sequence && event.content_hash == passport.content_hash;
    if !dated || !same_version || passport.presence != CalendarPassportPresence::Live {
        return Ok(());
    }
    let mut next = passport.clone();
    next.cancelled_since = None;
    next.deferred_cancel_seen_at = None;
    next.written_cancelled = false;
    next.last_seen_at = admission.now;
    admission.admit_superseding_passport(event_ref, &next, &screen_body(event))
}
/// Sweeps one resource's omitted events under the source's screen, as a
/// complete feed's sweep runs under its poll's.
pub(in crate::calendar) fn sweep_connector_resource<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    feed: &super::super::ics::ParsedIcsFeed,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source.into(), now).sweep_resource(
        feed,
        Some(&std::collections::BTreeSet::from([uid])),
        CalendarStatusBasis::ImportedAbsence,
    )
}

/// Marks every UID in `uids` absent for `system` in one EVENT scan: each of
/// its live inbound passports there, master and instances, as an omitted
/// feed item does, under the source's screen.
pub(in crate::calendar) fn sweep_connector_uids<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    uids: &std::collections::BTreeSet<&str>,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source.into(), now).sweep_resource(
        &super::super::ics::ParsedIcsFeed { events: Vec::new() },
        Some(uids),
        CalendarStatusBasis::ImportedAbsence,
    )
}

/// An explicit provider tombstone cancels with a stronger basis than an omitted feed item.
pub(in crate::calendar) fn delete_connector_resource<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source.into(), now).sweep_resource(
        &super::super::ics::ParsedIcsFeed { events: Vec::new() },
        Some(&std::collections::BTreeSet::from([uid])),
        CalendarStatusBasis::ImportedCancel,
    )
}
