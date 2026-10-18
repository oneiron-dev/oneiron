//! Uploaded ICS import and a single imported-instance amendment. Both reuse
//! the poll importer's UID diff, exception identity, screen and claim gates.
use serde::{Deserialize, Serialize};

use super::admission::{PollAdmission, VerdictFold, connector_event_ref};
use crate::calendar::ics::{ParsedIcsFeed, parse_ics_feed};
use crate::calendar::passport::{admitted_passport_for_in_txn, resolve_admitted_event_by_uid};
use crate::calendar::{CalendarError, CalendarReadRequest};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

/// An exact uploaded version is the immutable raw archive. No URL, importer
/// actor, approval override or decoded-text assertion is accepted here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarIcsImportRequest {
    pub system: String,
    pub source_blob_ref: String,
    pub source_version: u64,
}

/// A move imports just this detached component from an uploaded amendment,
/// never the whole feed. Unrelated components, passports and masks stay put.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarInstanceMoveRequest {
    pub system: String,
    pub source_blob_ref: String,
    pub source_version: u64,
    pub uid: String,
    pub original_start_utc: u64,
    pub start_utc: u64,
    pub end_utc: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarImportClaimReceipt {
    pub claim_ref: String,
    pub predicate: String,
    pub approval: String,
    pub lifecycle: String,
}

/// References are returned even when their imported claims await consent.
/// A successful parse/import is not an approval or an admitted occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarImportedEvent {
    pub event_ref: String,
    pub uid: String,
    pub original_start_utc: Option<u64>,
    pub claims: Vec<CalendarImportClaimReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarIcsImportReceipt {
    pub source_blob_ref: String,
    pub source_version: u64,
    pub events: Vec<CalendarImportedEvent>,
    pub screen_verdict: String,
}

/// Calendar errors keep their importer diagnostic; refusal never causes a
/// retry with different authority, an auto approval or an internal lane.
fn calendar_error(error: CalendarError) -> MemoryError {
    MemoryError::bad_request(error.to_string())
}

fn read_upload(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    system: &str,
    source: &str,
    version: u64,
) -> MemoryResult<(EntityId, ParsedIcsFeed)> {
    let actor = owner.revalidate(memory.vault())?;
    if actor != memory.actor() || memory.actor_class() != EdgeActorClass::Human {
        return Err(MemoryError::bad_request("calendar import must act as its authenticated owner"));
    }
    if system.trim().is_empty() || system.len() > 128 || system.chars().any(char::is_control) {
        return Err(MemoryError::bad_request("system must be non-empty, bounded and printable"));
    }
    let source_id = EntityId::from_hex(source)
        .map_err(|_| MemoryError::bad_request("invalid source_blob_ref"))?;
    let read = memory.get_entity(source)?;
    if read.value.is_none() {
        return Err(MemoryError::not_found("ICS source is absent or withheld")
            .with_read_receipt(read.receipt));
    }
    let bytes = memory.read_blob_version(source, version)?
        .ok_or_else(|| MemoryError::not_found("ICS source version is absent"))?;
    let feed = parse_ics_feed(&bytes).map_err(calendar_error)?;
    memory.produced_from([source_id]);
    Ok((source_id, feed))
}

/// Owner-authorized import of one complete uploaded feed, including the
/// existing complete-empty-feed absence law. No poll is scheduled by a file.
/// Screening uses the poll runner's production default: off, reported skipped.
pub fn import_ics_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsImportRequest,
) -> MemoryResult<CalendarIcsImportReceipt> {
    let (source, feed) = read_upload(
        memory, owner, &input.system, &input.source_blob_ref, input.source_version,
    )?;
    apply_upload(memory, owner, &input.system, source, input.source_version, &feed, true)
}

/// The owner applies one sourced instance move. The original key must name an
/// admitted occurrence; the uploaded component must actually carry that key
/// and the requested new interval. No synthetic imported evidence is minted.
pub fn move_instance_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarInstanceMoveRequest,
) -> MemoryResult<CalendarIcsImportReceipt> {
    let (source, mut feed) = read_upload(
        memory, owner, &input.system, &input.source_blob_ref, input.source_version,
    )?;
    if input.start_utc > input.end_utc {
        return Err(MemoryError::bad_request("calendar range start must not exceed end"));
    }
    let master = resolve_admitted_event_by_uid(memory.vault(), &input.uid)
        .map_err(calendar_error)?
        .ok_or_else(|| MemoryError::not_found("series master is absent or not admitted"))?;
    let visible = memory.calendar_read(&CalendarReadRequest { event_ref: master.to_hex() })?;
    if visible.value.is_none()
        || !memory.calendar_instance_admitted(master, &input.uid, input.original_start_utc)?
    {
        return Err(MemoryError::not_found("series occurrence is absent or withheld")
            .with_read_receipt(visible.receipt));
    }
    {
        let vault = memory.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        owner.revalidate_in_txn(vault, &txn)?;
        if admitted_passport_for_in_txn(vault, &txn, &master, &input.system, &input.uid)
            .map_err(calendar_error)?.is_none()
        {
            return Err(MemoryError::not_found("series has no admitted passport for this system"));
        }
    }
    feed.events.retain(|event| event.uid == input.uid
        && event.properties.recurrence_id_utc == Some(input.original_start_utc));
    let [event] = feed.events.as_slice() else {
        return Err(MemoryError::bad_request("upload must contain the named detached instance"));
    };
    if event.starts_at_utc != Some(input.start_utc) || event.ends_at_utc != Some(input.end_utc)
        || event.properties.rrule.is_some() || event.cancelled
    {
        return Err(MemoryError::bad_request("uploaded instance does not describe the requested move"));
    }
    let target = connector_event_ref(memory.vault(), event).map_err(calendar_error)?
        .ok_or_else(|| MemoryError::not_found("instance identity is unavailable"))?;
    if matches!(
        crate::calendar::passport::classify_event_passport(
            memory.vault(), target, &input.system, &input.uid, event.sequence, event.content_hash,
        ).map_err(calendar_error)?,
        crate::calendar::PassportDecision::SkipUnchanged { .. }
    ) {
        let current = memory.calendar_read(&CalendarReadRequest { event_ref: target.to_hex() })?;
        if current.value.as_ref().is_none_or(|view| {
            view.start_utc != Some(input.start_utc) || view.end_utc != Some(input.end_utc)
        }) {
            return Err(MemoryError::bad_request("stale instance amendment would not move the occurrence"));
        }
    }
    apply_upload(memory, owner, &input.system, source, input.source_version, &feed, false)
}

fn apply_upload(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    system: &str,
    source: EntityId,
    version: u64,
    feed: &ParsedIcsFeed,
    complete: bool,
) -> MemoryResult<CalendarIcsImportReceipt> {
    owner.revalidate(memory.vault())?;
    let vault = memory.vault();
    let blob_ref = format!("{}#v{version}", source.to_hex());
    let mut admission = PollAdmission {
        vault, screener: None, safeguard_enabled: false, system,
        preserve_direction: !complete, now: vault.now_recorded_at(), blob_ref: &blob_ref,
        verdict_fold: VerdictFold::default(),
    };
    admission.apply_feed(feed).map_err(calendar_error)?;
    if complete {
        admission.sweep_absent_sources(feed).map_err(calendar_error)?;
    }
    let mut events = Vec::new();
    for event in &feed.events {
        let id = connector_event_ref(vault, event).map_err(calendar_error)?
            .ok_or_else(|| MemoryError::not_found("import did not resolve an EVENT"))?;
        let mut claims = Vec::new();
        for claim_id in vault.claims_for_subject(&id)? {
            if let Some(body) = vault.get_claim(&claim_id)? {
                claims.push(CalendarImportClaimReceipt {
                    claim_ref: claim_id.to_hex(), predicate: body.predicate,
                    approval: body.approval.as_str().to_owned(),
                    lifecycle: body.lifecycle.as_str().to_owned(),
                });
            }
        }
        memory.produced_from(std::iter::once(id).chain(claims.iter()
            .filter_map(|claim| EntityId::from_hex(&claim.claim_ref).ok())));
        events.push(CalendarImportedEvent {
            event_ref: id.to_hex(), uid: event.uid.clone(),
            original_start_utc: event.properties.recurrence_id_utc, claims,
        });
    }
    Ok(CalendarIcsImportReceipt {
        source_blob_ref: source.to_hex(), source_version: version, events,
        screen_verdict: admission.verdict_fold.token().to_owned(),
    })
}
