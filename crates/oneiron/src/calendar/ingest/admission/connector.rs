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
    source: &'a str,
    now: u64,
) -> PollAdmission<'a> {
    PollAdmission {
        vault,
        system,
        preserve_direction: true,
        screener: None,
        safeguard_enabled: false,
        now,
        blob_ref: source,
        verdict_fold: VerdictFold::default(),
        continuations: None,
    }
}
pub(in crate::calendar) fn preflight_connector_feed(
    vault: &Vault,
    system: &str,
    source: &str,
    feed: &super::super::ics::ParsedIcsFeed,
    now: u64,
) -> Result<(), CalendarError> {
    let admission = connector_admission(vault, system, source, now);
    for event in &feed.events {
        admission.preflight_event(event)?;
    }
    Ok(())
}
/// What a connector admission admits from: the pull record its claims cite,
/// and the archived resource version a property continuation reads again.
#[derive(Clone, Copy)]
pub(in crate::calendar) struct ConnectorAdmissionSource<'a> {
    pub(in crate::calendar) record: &'a str,
    pub(in crate::calendar) source_version: Option<&'a str>,
}

impl<'a> From<&'a str> for ConnectorAdmissionSource<'a> {
    /// A pull record with no archived version: every property is admitted
    /// in one pass.
    fn from(record: &'a str) -> Self {
        Self {
            record,
            source_version: None,
        }
    }
}

/// Admits one connector event as an ICS admission admits it: one pass's
/// count of new property claims, and a queued continuation reading the
/// archived resource version again for the rest (FIX 12163).
pub(in crate::calendar) fn admit_connector_event<'a>(
    vault: &'a Vault,
    system: &'a str,
    source: impl Into<ConnectorAdmissionSource<'a>>,
    event: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarError> {
    let source = source.into();
    let mut admission = connector_admission(vault, system, source.record, now);
    let Some(source_version) = source.source_version else {
        return admission.apply_event(event);
    };
    admission.continuations = Some(Vec::new());
    admission.apply_event(event)?;
    admission.queue_property_continuations_reading(source_version)
}
pub(in crate::calendar) fn sweep_connector_resource(
    vault: &Vault,
    system: &str,
    source: &str,
    feed: &super::super::ics::ParsedIcsFeed,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source, now).sweep_resource(
        feed,
        Some(uid),
        CalendarStatusBasis::ImportedAbsence,
    )
}

/// An explicit provider tombstone cancels with a stronger basis than an omitted feed item.
pub(in crate::calendar) fn delete_connector_resource(
    vault: &Vault,
    system: &str,
    source: &str,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    connector_admission(vault, system, source, now).sweep_resource(
        &super::super::ics::ParsedIcsFeed { events: Vec::new() },
        Some(uid),
        CalendarStatusBasis::ImportedCancel,
    )
}
