//! A pack calendar source's pulled changes (FIX 12559 rows 3 and 5), landed
//! through the connector admission under the source's own system: each
//! resource is archived in an artifact bound to the source's audience at
//! birth, then admitted, its EVENTs bound at birth by the admission
//! ([`crate::mail_pack::bind_calendar_source_row_in_txn`]); a provider
//! delete marks the source's passport absent and cancels, as a connector
//! pull's does.

use super::admission::{PollAdmission, VerdictFold};
use crate::calendar::CalendarError;
use crate::calendar::connectors::{RemoteCalendarChange, RemoteCalendarObject};
use crate::calendar::ics::{ParsedIcsFeed, parse_ics_feed};
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::MAIL_CALENDAR_SOURCE_BLOB;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::vault::Vault;

/// What one pulled change did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CalendarSourceChange {
    /// The resource's series landed or moved; `span` is its master's start
    /// and end, Unix seconds (an all-day or floating one's civil times read
    /// as UTC).
    Applied { span: Option<(u64, u64)> },
    /// The provider deleted it: the source's passport is absent, and the
    /// EVENT cancelled once no live source reports it.
    Deleted,
}

/// Lands one change a pack calendar source's wire pulled, under the
/// source's calendar `system`.
///
/// # Errors
///
/// The resource does not parse as one UID's series, the source is not an
/// Active calendar of an installed pack, or the admission refuses.
pub(crate) fn apply_calendar_source_change(
    vault: &Vault,
    system: &str,
    change: &RemoteCalendarChange,
    now: u64,
) -> Result<CalendarSourceChange, CalendarError> {
    match change {
        RemoteCalendarChange::Upsert(object) => Ok(CalendarSourceChange::Applied {
            span: apply_upsert(vault, system, object, now)?,
        }),
        RemoteCalendarChange::Delete { uid, .. } => {
            let record = format!("calendar-source:{system}:{uid}");
            super::delete_connector_resource(vault, system, &record, uid, now)?;
            Ok(CalendarSourceChange::Deleted)
        }
    }
}

/// Lands one whole feed a pack calendar source's wire read (an ICS file or
/// subscription), under the source's calendar `system`: archived bound to
/// the source, admitted as an ICS feed poll admits one, then every UID the
/// complete feed no longer carries marked absent for this source. Returns
/// how many VEVENTs the feed carried.
///
/// # Errors
///
/// The feed does not parse completely (nothing is read as removed), the
/// source is not an Active calendar of an installed pack, or the admission
/// refuses.
pub(crate) fn apply_calendar_source_feed(
    vault: &Vault,
    system: &str,
    ics: &[u8],
    now: u64,
) -> Result<usize, CalendarError> {
    let feed = parse_ics_feed(ics)?;
    let archived = archive_source_resource(vault, system, FEED_ARCHIVE_KEY, ics, now)?;
    let mut admission = PollAdmission {
        vault,
        screener: None,
        safeguard_enabled: false,
        system,
        preserve_direction: false,
        now,
        blob_ref: &archived.record,
        verdict_fold: VerdictFold::default(),
        continuations: None,
    };
    admission.apply_feed(&feed)?;
    admission.sweep_absent_sources(&feed)?;
    Ok(feed.events.len())
}

/// Marks every UID in `uids` absent for a pack calendar source whose full
/// listing finished without them, under its calendar `system`: each
/// passport of the source for that UID, master and instances, is absent,
/// and the EVENT cancelled once no live source reports it. The claims cite
/// the omitted UIDs, archived bound to the source.
///
/// # Errors
///
/// The source is not an Active calendar of an installed pack, or the
/// admission refuses.
pub(crate) fn apply_calendar_source_omissions(
    vault: &Vault,
    system: &str,
    uids: &[String],
    now: u64,
) -> Result<(), CalendarError> {
    if uids.is_empty() {
        return Ok(());
    }
    let mut omitted = String::from("listing finished without:\r\n");
    for uid in uids {
        omitted.push_str(uid);
        omitted.push_str("\r\n");
    }
    let record =
        archive_source_resource(vault, system, LISTING_ARCHIVE_KEY, omitted.as_bytes(), now)?
            .record;
    let uids: std::collections::BTreeSet<&str> = uids.iter().map(String::as_str).collect();
    super::sweep_connector_uids(vault, system, &record, &uids, now)
}

/// The archive key of a whole feed, beside the per-UID resources.
const FEED_ARCHIVE_KEY: &str = "#feed";
/// The archive key of the UIDs a finished listing omitted.
const LISTING_ARCHIVE_KEY: &str = "#listing";

/// Lands one resource; answers its master's span.
fn apply_upsert(
    vault: &Vault,
    system: &str,
    object: &RemoteCalendarObject,
    now: u64,
) -> Result<Option<(u64, u64)>, CalendarError> {
    let feed = parse_resource(&object.ics)?;
    let uid = feed
        .events
        .first()
        .map(|event| event.uid.clone())
        .ok_or_else(|| parse_error("calendar resource carries no VEVENT"))?;
    // Archived before any semantic write: the admitted claims cite exactly
    // these bytes.
    let archived = archive_source_resource(vault, system, &uid, &object.ics, now)?;
    let record = archived.record.as_str();
    super::preflight_connector_feed(vault, system, record, &feed, now)?;
    for parsed in &feed.events {
        super::admit_connector_event(vault, system, record, parsed, now)?;
    }
    // Only a series, now or in the resource's version before, can have
    // dropped an instance this resource no longer carries; a single event
    // that was single has nothing to sweep, and the sweep reads every EVENT.
    if is_series(&feed) || earlier_was_series(vault, &archived)? {
        super::sweep_connector_resource(vault, system, record, &feed, &uid, now)?;
    }
    Ok(feed.events.first().and_then(span))
}

/// An event's start and end, Unix seconds: its UTC times, else its civil
/// times read as UTC; an end it lacks is its start.
fn span(event: &crate::calendar::ics::ParsedVEvent) -> Option<(u64, u64)> {
    let start = match event.starts_at_utc {
        Some(start) => start,
        None => civil_seconds(event.properties.wall_time.as_ref()?)?,
    };
    let end = event
        .ends_at_utc
        .or_else(|| event.properties.wall_end.as_ref().and_then(civil_seconds))
        .unwrap_or(start)
        .max(start);
    Some((start, end))
}

/// A civil time read as UTC, Unix seconds.
fn civil_seconds(wall: &crate::calendar::claims::CalendarWallTimeValue) -> Option<u64> {
    let at = chrono::NaiveDate::from_ymd_opt(wall.y, u32::from(wall.mo), u32::from(wall.d))?
        .and_hms_opt(
            u32::from(wall.h),
            u32::from(wall.mi),
            u32::from(wall.s.min(59)),
        )?
        .and_utc()
        .timestamp();
    u64::try_from(at).ok()
}

/// Whether a resource carries a series: a master with a rule, or detached
/// instances.
fn is_series(feed: &ParsedIcsFeed) -> bool {
    feed.events.len() > 1
        || feed
            .events
            .first()
            .is_some_and(|master| master.properties.rrule.is_some())
}

/// Whether the version the archived one descends from carried a series. A
/// version that no longer reads or parses counts as one.
fn earlier_was_series(vault: &Vault, archived: &ArchivedResource) -> Result<bool, CalendarError> {
    let Some(parent) = archived.parent_version else {
        return Ok(false);
    };
    let Some(bytes) = vault.read_blob_artifact_version(&archived.artifact_id, parent)? else {
        return Ok(true);
    };
    Ok(match parse_ics_feed(&bytes) {
        Ok(feed) => is_series(&feed),
        Err(_) => true,
    })
}

/// One resource: one UID's master first, then its detached instances.
fn parse_resource(ics: &[u8]) -> Result<ParsedIcsFeed, CalendarError> {
    let feed = parse_ics_feed(ics)?;
    let first = feed
        .events
        .first()
        .ok_or_else(|| parse_error("calendar resource carries no VEVENT"))?;
    if first.properties.recurrence_id_utc.is_some() {
        return Err(parse_error("calendar resource omits its series master"));
    }
    if feed.events.iter().any(|event| event.uid != first.uid) {
        return Err(parse_error("calendar resource carries more than one UID"));
    }
    Ok(feed)
}

/// One pulled resource as archived.
struct ArchivedResource {
    /// The `hex#vN` reference the admitted claims cite.
    record: String,
    artifact_id: EntityId,
    /// The version this one descends from, when it is not the first.
    parent_version: Option<u64>,
}

/// Archives one pulled resource of `(system, uid)`: one artifact per
/// resource, bound to the source's audience in its birth commit, then one
/// version per body.
fn archive_source_resource(
    vault: &Vault,
    system: &str,
    uid: &str,
    ics: &[u8],
    now: u64,
) -> Result<ArchivedResource, CalendarError> {
    let artifact_id = EntityId::derive(
        MAIL_CALENDAR_SOURCE_BLOB,
        &[system.as_bytes(), uid.as_bytes()],
    )?;
    let at = crate::TimeRange {
        start: now,
        end: now,
    };
    if vault.get_blob_artifact(&artifact_id)?.is_none() {
        let data = crate::blob_artifact::encode_blob_artifact_body(
            &crate::blob_artifact::BlobArtifactBody::new(
                format!("calendar-source:{system}"),
                "text/calendar",
            ),
        )?;
        vault.with_write_txn_grouped(|txn| {
            vault
                .batch_in()
                .put(&artifact_id, ENTITY_TYPE_BLOB_ARTIFACT, at, now, &data)
                .apply(txn)?;
            crate::mail_pack::bind_calendar_source_row_in_txn(vault, txn, system, &artifact_id)
        })?;
    }
    let actor = super::ensure_ics_import_actor(vault, now)?;
    let version = vault.append_blob_artifact_version(
        &artifact_id,
        ics,
        &crate::blob_artifact::BlobVersionProvenance::AgentRun {
            run_ref: format!("calendar-source:{}", artifact_id.to_hex()),
        },
        crate::WriteActor::new(actor, crate::edge::EdgeActorClass::System),
        at,
        now,
    )?;
    Ok(ArchivedResource {
        record: format!("{}#v{}", artifact_id.to_hex(), version.version),
        artifact_id,
        parent_version: version.parent_version,
    })
}

fn parse_error(reason: &str) -> CalendarError {
    CalendarError::IcsParse {
        reason: reason.to_owned(),
    }
}
