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
        verdict_fold: VerdictFold::default(),
        continuations: None,
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
}

impl<'a> From<&'a str> for ConnectorAdmissionSource<'a> {
    /// A pull record with no archived version, admitted with the dial off:
    /// every property is admitted in one pass, unscreened.
    fn from(record: &'a str) -> Self {
        Self {
            record,
            source_version: None,
            screen: ConnectorScreen::default(),
        }
    }
}

/// Admits one connector event as an ICS admission admits it: under the
/// source's screen, one pass's count of new property claims, and a queued
/// continuation reading the archived resource version again for the rest
/// (FIX 12163), which runs the same screen.
pub(in crate::calendar) fn admit_connector_event<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    event: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarError> {
    let source = source.into();
    let mut admission = connector_admission(vault, system, source, now);
    let Some(source_version) = source.source_version else {
        return admission.apply_event(event);
    };
    admission.continuations = Some(Vec::new());
    admission.apply_event(event)?;
    admission.queue_property_continuations_reading(source_version)
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
        Some(uid),
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
        Some(uid),
        CalendarStatusBasis::ImportedCancel,
    )
}
