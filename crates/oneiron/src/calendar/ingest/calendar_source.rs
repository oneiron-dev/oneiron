//! A pack calendar source's pulled changes (FIX 12559 rows 3 and 5), landed
//! through the connector admission under the source's own system: each
//! resource is archived in an artifact bound to the source's audience at
//! birth, then admitted, its EVENTs bound at birth by the admission
//! ([`crate::mail_pack::bind_calendar_source_row_in_txn`]); a provider
//! delete marks the source's passport absent and cancels, as a connector
//! pull's does.

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
    /// The resource's series landed or moved.
    Applied,
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
        RemoteCalendarChange::Upsert(object) => {
            apply_upsert(vault, system, object, now)?;
            Ok(CalendarSourceChange::Applied)
        }
        RemoteCalendarChange::Delete { uid, .. } => {
            let record = format!("calendar-source:{system}:{uid}");
            super::delete_connector_resource(vault, system, &record, uid, now)?;
            Ok(CalendarSourceChange::Deleted)
        }
    }
}

fn apply_upsert(
    vault: &Vault,
    system: &str,
    object: &RemoteCalendarObject,
    now: u64,
) -> Result<(), CalendarError> {
    let feed = parse_resource(&object.ics)?;
    let uid = feed
        .events
        .first()
        .map(|event| event.uid.clone())
        .ok_or_else(|| parse_error("calendar resource carries no VEVENT"))?;
    // Archived before any semantic write: the admitted claims cite exactly
    // these bytes.
    let record = archive_source_resource(vault, system, &uid, &object.ics, now)?;
    super::preflight_connector_feed(vault, system, &record, &feed, now)?;
    for parsed in &feed.events {
        super::admit_connector_event(vault, system, record.as_str(), parsed, now)?;
    }
    super::sweep_connector_resource(vault, system, &record, &feed, &uid, now)
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

/// Archives one pulled resource of `(system, uid)`: one artifact per
/// resource, bound to the source's audience in its birth commit, then one
/// version per body. Returns the `hex#vN` reference the admitted claims
/// cite.
fn archive_source_resource(
    vault: &Vault,
    system: &str,
    uid: &str,
    ics: &[u8],
    now: u64,
) -> Result<String, CalendarError> {
    let artifact_id =
        EntityId::derive(MAIL_CALENDAR_SOURCE_BLOB, &[system.as_bytes(), uid.as_bytes()])?;
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
    Ok(format!("{}#v{}", artifact_id.to_hex(), version.version))
}

fn parse_error(reason: &str) -> CalendarError {
    CalendarError::IcsParse {
        reason: reason.to_owned(),
    }
}
