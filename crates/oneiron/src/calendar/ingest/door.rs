//! Uploaded ICS import and a single imported-instance amendment. Both reuse
//! the poll importer's UID diff, exception identity, screen and claim gates.

use super::admission::{PollAdmission, VerdictFold, connector_event_ref};
use crate::calendar::claims::CalendarPassportSource;
use crate::calendar::connectors::door::seat_of_system_in_txn;
use crate::calendar::ics::{ParsedIcsFeed, parse_ics_feed};
use crate::calendar::passport::{admitted_passport_for_in_txn, resolve_admitted_event_by_uid};
use crate::calendar::safeguard::CalendarBodyScreener;
use crate::calendar::{CalendarError, CalendarReadRequest};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

#[doc(hidden)]
pub use oneiron_verb_wire::calendar::ingest::door::{
    CalendarIcsImportReceipt, CalendarIcsImportRequest, CalendarImportClaimReceipt,
    CalendarImportedEvent, CalendarInstanceMoveRequest,
};

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
        return Err(MemoryError::bad_request(
            "calendar import must act as its authenticated owner",
        ));
    }
    if system.trim().is_empty() || system.len() > 128 || system.chars().any(char::is_control) {
        return Err(MemoryError::bad_request(
            "system must be non-empty, bounded and printable",
        ));
    }
    let source_id = EntityId::from_hex(source)
        .map_err(|_| MemoryError::bad_request("invalid source_blob_ref"))?;
    let read = memory.get_entity(source)?;
    if read.value.is_none() {
        return Err(MemoryError::not_found("ICS source is absent or withheld")
            .with_read_receipt(read.receipt));
    }
    let bytes = memory
        .read_blob_version(source, version)?
        .ok_or_else(|| MemoryError::not_found("ICS source version is absent"))?;
    let feed = parse_ics_feed(&bytes).map_err(calendar_error)?;
    memory.produced_from([source_id]);
    Ok((source_id, feed))
}

/// Owner-authorized import of one complete uploaded feed, including the
/// existing complete-empty-feed absence law. No poll is scheduled by a file.
/// The owner's CAL-09 dial decides whether `screener` (or its recorded
/// absence) screens each imported admission, as an installed feed's poll
/// screens; with the dial off the receipt reports `skipped`. The upload never
/// runs under the system of an installed ICS feed, of a CalDAV seat or of a
/// pack calendar source, whose events its absence sweep would cancel.
pub fn import_ics_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarIcsImportRequest,
    screener: Option<&dyn CalendarBodyScreener>,
) -> MemoryResult<CalendarIcsImportReceipt> {
    // FIX 4797: the vault's one calendar admission turn, across the diff.
    let _turn = super::admission_turn(memory.vault()).map_err(calendar_error)?;
    let (source, feed) = read_upload(
        memory,
        owner,
        &input.system,
        &input.source_blob_ref,
        input.source_version,
    )?;
    refuse_installed_source_system(memory, &input.system)?;
    apply_upload(
        memory,
        owner,
        &input.system,
        source,
        input.source_version,
        &feed,
        true,
        screener,
    )
}

/// A complete upload marks absent every live inbound passport of its system whose UID the file
/// lacks, and cancels each EVENT no live source reports any more. Under the system of an
/// installed ICS feed, the feed's events would stay cancelled until a poll with a changed body
/// carries them again; under a CalDAV seat's (a stopped seat's too), until the remote object
/// changes; under a pack calendar source's, until its next complete listing. So the upload
/// takes another system, under which its UIDs still attach to the same EVENTs. A system whose
/// feed was uninstalled is open to an upload, since no poll of that feed runs again. The check
/// reads the installed sources once, under the upload's admission turn and before its writes. A
/// feed's install and a seat's take that turn too (`feed_door::ics_feed_write_turn`,
/// `connectors::door::seat_setup_write_turn`), so none lands while the upload runs.
fn refuse_installed_source_system(memory: &Memory<'_>, system: &str) -> MemoryResult<()> {
    crate::mail_pack::refuse_calendar_source_system(system)?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    if super::feed_door::registration_in_txn(vault, &txn, system)?.is_some() {
        return Err(MemoryError::bad_request(
            "an installed ICS feed imports under this system, and a complete upload would \
             cancel the feed's events that the file lacks; use another system",
        ));
    }
    if let Some(seat_ref) = seat_of_system_in_txn(vault, &txn, system)? {
        return Err(MemoryError::bad_request(format!(
            "the CalDAV seat `{seat_ref}` imports under this system, and a complete upload \
             would cancel its events that the file lacks; use another system"
        )));
    }
    Ok(())
}

/// The owner applies one sourced instance move. The original key must name an
/// admitted occurrence; the uploaded component must actually carry that key
/// and the requested new interval. No synthetic imported evidence is minted.
pub fn move_instance_as_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarInstanceMoveRequest,
    screener: Option<&dyn CalendarBodyScreener>,
) -> MemoryResult<CalendarIcsImportReceipt> {
    // FIX 4797: the vault's one calendar admission turn, from the passport
    // checks through the apply.
    let _turn = super::admission_turn(memory.vault()).map_err(calendar_error)?;
    let (source, mut feed) = read_upload(
        memory,
        owner,
        &input.system,
        &input.source_blob_ref,
        input.source_version,
    )?;
    if input.start_utc > input.end_utc {
        return Err(MemoryError::bad_request(
            "calendar range start must not exceed end",
        ));
    }
    let master = resolve_admitted_event_by_uid(memory.vault(), &input.uid)
        .map_err(calendar_error)?
        .ok_or_else(|| MemoryError::not_found("series master is absent or not admitted"))?;
    let visible = memory.calendar_read(&CalendarReadRequest {
        event_ref: master.to_hex(),
        filter: None,
    })?;
    if visible.value.is_none()
        || !memory.calendar_instance_admitted(master, &input.uid, input.original_start_utc)?
    {
        return Err(
            MemoryError::not_found("series occurrence is absent or withheld")
                .with_read_receipt(visible.receipt),
        );
    }
    {
        let vault = memory.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        owner.revalidate_in_txn(vault, &txn)?;
        if admitted_passport_for_in_txn(vault, &txn, &master, &input.system, &input.uid)
            .map_err(calendar_error)?
            .is_none()
        {
            return Err(MemoryError::not_found(
                "series has no admitted passport for this system",
            ));
        }
    }
    feed.events.retain(|event| {
        event.uid == input.uid
            && event.properties.recurrence_id_utc == Some(input.original_start_utc)
    });
    let [event] = feed.events.as_slice() else {
        return Err(MemoryError::bad_request(
            "upload must contain the named detached instance",
        ));
    };
    if event.starts_at_utc != Some(input.start_utc)
        || event.ends_at_utc != Some(input.end_utc)
        || event.properties.rrule.is_some()
        || event.cancelled
    {
        return Err(MemoryError::bad_request(
            "uploaded instance does not describe the requested move",
        ));
    }
    let target = connector_event_ref(memory.vault(), event)
        .map_err(calendar_error)?
        .ok_or_else(|| MemoryError::not_found("instance identity is unavailable"))?;
    if matches!(
        crate::calendar::passport::classify_event_passport(
            memory.vault(),
            target,
            &input.system,
            &input.uid,
            event.sequence,
            event.content_hash,
        )
        .map_err(calendar_error)?,
        crate::calendar::PassportDecision::SkipUnchanged { .. }
    ) {
        let current = memory.calendar_read(&CalendarReadRequest {
            event_ref: target.to_hex(),
            filter: None,
        })?;
        if current.value.as_ref().is_none_or(|view| {
            view.start_utc != Some(input.start_utc) || view.end_utc != Some(input.end_utc)
        }) {
            return Err(MemoryError::bad_request(
                "stale instance amendment would not move the occurrence",
            ));
        }
    }
    apply_upload(
        memory,
        owner,
        &input.system,
        source,
        input.source_version,
        &feed,
        false,
        screener,
    )
}

fn apply_upload(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    system: &str,
    source: EntityId,
    version: u64,
    feed: &ParsedIcsFeed,
    complete: bool,
    screener: Option<&dyn CalendarBodyScreener>,
) -> MemoryResult<CalendarIcsImportReceipt> {
    owner.revalidate(memory.vault())?;
    let safeguard_enabled = super::feed_door::inbound_safeguard_enabled(memory)?;
    let vault = memory.vault();
    let blob_ref = format!("{}#v{version}", source.to_hex());
    let mut admission = PollAdmission {
        vault,
        screener,
        safeguard_enabled,
        system,
        preserve_direction: !complete,
        now: vault.now_recorded_at(),
        blob_ref: &blob_ref,
        source: Some(CalendarPassportSource {
            artifact: source,
            version,
        }),
        verdict_fold: VerdictFold::default(),
        continuations: Some(Vec::new()),
        owed_booking_moves: 0,
        admitted_claims: Vec::new(),
    };
    admission.apply_feed(feed).map_err(calendar_error)?;
    if complete {
        admission
            .sweep_absent_sources(feed)
            .map_err(calendar_error)?;
    }
    let mut events = Vec::new();
    for event in &feed.events {
        let id = connector_event_ref(vault, event)
            .map_err(calendar_error)?
            .ok_or_else(|| MemoryError::not_found("import did not resolve an EVENT"))?;
        let mut claims = Vec::new();
        for claim_id in vault.claims_for_subject(&id)? {
            if let Some(body) = vault.get_claim(&claim_id)? {
                claims.push(CalendarImportClaimReceipt {
                    claim_ref: claim_id.to_hex(),
                    predicate: body.predicate,
                    approval: body.approval.as_str().to_owned(),
                    lifecycle: body.lifecycle.as_str().to_owned(),
                });
            }
        }
        memory.produced_from(
            std::iter::once(id).chain(
                claims
                    .iter()
                    .filter_map(|claim| EntityId::from_hex(&claim.claim_ref).ok()),
            ),
        );
        events.push(CalendarImportedEvent {
            event_ref: id.to_hex(),
            uid: event.uid.clone(),
            original_start_utc: event.properties.recurrence_id_utc,
            claims,
        });
    }
    Ok(CalendarIcsImportReceipt {
        source_blob_ref: source.to_hex(),
        source_version: version,
        events,
        screen_verdict: admission.verdict_fold.token().to_owned(),
        owed_booking_moves: admission.owed_booking_moves,
    })
}
