//! Pull orchestration: apply, admit, enqueue, and reconcile.

use super::outbound::{CalendarRemoteObjectRow, ingest_error, write_remote_object};
use super::remote::{
    CalendarRemoteTransport, CalendarSyncOutcome, EchoDisposition, RemoteCalendarChange,
    RemoteCalendarObject, classify_remote_change, parse_remote_object,
};
use super::seat::{
    CalendarConnectorError, CalendarConnectorSeatState, CalendarConnectorSyncPayload,
    calendar_sync_attempt_kind, seat_identity,
};

use crate::attempt_queue::{AttemptQueue, EnqueueAttempt};
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarPassportPresence;
use crate::calendar::ingest::admit_calendar_import_claim;
use crate::calendar::passport::live_passport_for;
use crate::calendar::safeguard::{CalendarInboundBody, screen_then_claim};
use crate::entity_id::EntityId;
use crate::vault::Vault;

/// Runs one connector sync for `seat`.
///
/// Killed seats short-circuit with [`CalendarSyncOutcome::Killed`]: no transport
/// call, no claim, no re-enqueue. Otherwise the run pulls from the seat cursor,
/// re-parses every upsert through [`parse_ics_feed`](crate::calendar::parse_ics_feed), classifies it
/// against the live passport, applies semantic changes through the CAL-02
/// Gate-backed imported-evidence door, and re-enqueues one attempt inside the
/// configured jitter window.
///
/// # Errors
///
/// [`CalendarConnectorError`] for seat, transport, parse, timezone, and store
/// failures. A failure applies nothing further and enqueues nothing.
pub fn run_calendar_connector_sync(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    now: u64,
    jitter_seed: u64,
) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
    seat.validate()?;
    if seat.kill_switch_engaged() {
        // No pull, no write, no next attempt — and nothing erased.
        return Ok(CalendarSyncOutcome::Killed);
    }

    let batch = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    )?;

    let mut counters = SyncCounters::default();
    for change in &batch.changes {
        apply_remote_change(
            vault,
            seat,
            transport.provider_key(),
            change,
            now,
            &mut counters,
        )?;
    }

    let next_not_before = seat.jittered_next_poll_at(now, jitter_seed)?;
    enqueue_next_sync(
        vault,
        seat,
        transport.provider_key(),
        batch.next_cursor.clone(),
        next_not_before,
        now,
    )?;

    Ok(CalendarSyncOutcome::Reenqueued {
        next_cursor: batch.next_cursor,
        next_not_before,
        applied: counters.applied,
        acknowledged: counters.acknowledged,
        source_absences: counters.source_absences,
        status_cancellations: counters.status_cancellations,
    })
}

/// Per-run counters folded into [`CalendarSyncOutcome::Reenqueued`].
#[derive(Default)]
struct SyncCounters {
    applied: u32,
    acknowledged: u32,
    source_absences: u32,
    status_cancellations: u32,
}

/// Applies one pulled change under the echo law.
fn apply_remote_change(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    change: &RemoteCalendarChange,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    match change {
        RemoteCalendarChange::Upsert(object) => {
            let feed = super::remote::parse_remote_resource(object)?;
            let primary = feed
                .events
                .first()
                .ok_or_else(|| ingest_error("remote resource has no event"))?;
            let source = pull_source_record_id(provider, seat, &primary.uid);
            crate::calendar::ingest::preflight_connector_feed(vault, system, &source, &feed, now)?;
            for parsed in &feed.events {
                let normalized = RemoteCalendarChange::Upsert(RemoteCalendarObject {
                    href: object.href.clone(),
                    etag: object.etag.clone(),
                    uid: parsed.uid.clone(),
                    sequence: parsed.sequence,
                    content_hash: parsed.content_hash,
                    ics: object.ics.clone(),
                });
                let event_ref = crate::calendar::ingest::connector_event_ref(vault, parsed)?;
                let current = match event_ref {
                    Some(id) => {
                        live_passport_for(vault, &id, system, &parsed.uid)?.map(|(_, value)| value)
                    }
                    None => None,
                };
                match classify_remote_change(current.as_ref(), &normalized) {
                    EchoDisposition::AcknowledgeEcho => counters.acknowledged += 1,
                    EchoDisposition::ApplyInbound | EchoDisposition::ApplyRemoteUpdate => {
                        crate::calendar::ingest::admit_connector_event(
                            vault, system, &source, parsed, now,
                        )?;
                        counters.applied += 1;
                    }
                    EchoDisposition::ApplyRemoteDeletion => {
                        return Err(ingest_error("an upsert cannot classify as deletion"));
                    }
                }
            }
            crate::calendar::ingest::sweep_connector_resource(
                vault,
                system,
                &source,
                &feed,
                &primary.uid,
                now,
            )?;
            write_remote_object(
                vault,
                &CalendarRemoteObjectRow {
                    system: system.to_owned(),
                    calendar_ref: seat.config.calendar_ref.clone(),
                    uid: primary.uid.clone(),
                    href: Some(object.href.clone()),
                    etag: object.etag.clone(),
                    last_sequence: primary.sequence,
                    content_hash: super::remote::ics_content_hash(&object.ics, &primary.uid)?,
                    last_seen_at: now,
                },
            )?;
            Ok(())
        }
        RemoteCalendarChange::Delete { uid, .. } => {
            debug_assert_eq!(
                classify_remote_change(None, change),
                EchoDisposition::ApplyRemoteDeletion
            );
            apply_remote_deletion(vault, seat, provider, uid, now, counters)
        }
    }
}

/// A remote deletion marks exactly one source's passport absent, once.
///
/// Multi-source law, verbatim: feed-absence cancellation applies ONLY when every
/// live inbound passport for the EVENT reports absence; a single-source absence
/// supersedes only that passport, never the EVENT status. The EVENT is never
/// deleted, CAL-07's outcome predicate is never written, and no delete is bounced
/// back to any provider.
fn apply_remote_deletion(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    uid: &str,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let mut absent_count = 0;
    let mut newly_absent = Vec::new();
    let mut after = None;
    loop {
        let ids = vault.entities_by_type_page(
            crate::registry::ENTITY_TYPE_EVENT,
            after.as_ref(),
            4096,
        )?;
        if ids.is_empty() {
            break;
        }
        for event in &ids {
            if crate::calendar::passport::live_passport_for(vault, event, &seat.config.system, uid)?
                .is_some_and(|(_, value)| {
                    value.presence == CalendarPassportPresence::Live
                        && value.direction.is_inbound_bearing()
                })
            {
                absent_count += 1;
                newly_absent.push((*event, imported_cancellation(vault, *event)?));
            }
        }
        after = ids.last().copied();
    }
    crate::calendar::ingest::delete_connector_resource(
        vault,
        &seat.config.system,
        &pull_source_record_id(provider, seat, uid),
        uid,
        now,
    )?;
    counters.source_absences += absent_count;
    for (event, was_cancelled) in newly_absent {
        if !was_cancelled && imported_cancellation(vault, event)? {
            counters.status_cancellations += 1;
        }
    }
    Ok(())
}

fn imported_cancellation(vault: &Vault, event: EntityId) -> Result<bool, CalendarConnectorError> {
    use crate::calendar::claims::{
        CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_STATUS, decode_status_value,
    };
    for id in vault.claims_for_subject(&event)? {
        if let Some(body) = vault.get_claim(&id)?
            && body.lifecycle == crate::ClaimLifecycleStatus::Active
            && body.predicate == PREDICATE_CALENDAR_STATUS
        {
            let status = decode_status_value(&body.value)?;
            if status.status == CalendarStatus::Cancelled
                && matches!(
                    status.basis,
                    CalendarStatusBasis::ImportedAbsence | CalendarStatusBasis::ImportedCancel
                )
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(super) fn admit_screened(
    vault: &Vault,
    event_ref: EntityId,
    body: &CalendarInboundBody,
    source_record_id: &str,
    predicate: &str,
    value: rmpv::Value,
    now: u64,
) -> Result<EntityId, CalendarConnectorError> {
    let screened = screen_then_claim(false, None, body, |_request| {
        admit_calendar_import_claim(vault, &event_ref, predicate, value, source_record_id, now)
    })
    .map_err(CalendarError::from)?;
    Ok(screened.value)
}

/// Enqueues the next poll attempt, due inside the configured jitter window.
///
/// Attempt-queue work, not a new recurrence primitive: the generation-scoped
/// dedupe key keeps one chain per seat alive across the executing row and stays
/// idempotent for a redundant run at the same due instant.
fn enqueue_next_sync(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    cursor: Option<String>,
    not_before: u64,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let payload = serde_json::to_vec(&CalendarConnectorSyncPayload {
        config: seat.config.clone(),
        cursor,
        not_before,
    })
    .map_err(|_| ingest_error("connector sync payload did not encode"))?;
    let dedupe_key = format!("{}:due:{not_before}", seat_identity(provider, &seat.config));
    AttemptQueue::new(vault).enqueue(EnqueueAttempt {
        kind: calendar_sync_attempt_kind(provider),
        payload,
        dedupe_key: Some(dedupe_key),
        run_id: None,
        now,
    })?;
    Ok(())
}

/// Refreshes the local view of one remote object after a precondition failure.
/// Best-effort by design: the mismatch verdict is what the caller must see, and
/// a reconciliation pull that itself fails must not mask it.
pub(super) fn reconcile_remote_object(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
) {
    let Ok(batch) = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    ) else {
        return;
    };
    for change in &batch.changes {
        let RemoteCalendarChange::Upsert(object) = change else {
            continue;
        };
        if object.uid != uid {
            continue;
        }
        let Ok(parsed) = parse_remote_object(object) else {
            continue;
        };
        let _ = write_remote_object(
            vault,
            &CalendarRemoteObjectRow {
                system: seat.config.system.clone(),
                calendar_ref: seat.config.calendar_ref.clone(),
                uid: uid.to_owned(),
                href: Some(object.href.clone()),
                etag: object.etag.clone(),
                last_sequence: parsed.sequence,
                content_hash: parsed.content_hash,
                last_seen_at: now,
            },
        );
    }
}

/// The EVENT's stored occurrence from the parsed times.
pub(super) fn read_event_name(body: &[u8]) -> Option<String> {
    let mut cursor = std::io::Cursor::new(body);
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    entries.iter().find_map(|(key, value)| {
        (key.as_str() == Some("name"))
            .then(|| value.as_str().map(str::to_owned))
            .flatten()
    })
}

/// Provenance ref for a pulled candidate.
fn pull_source_record_id(provider: &str, seat: &CalendarConnectorSeatState, uid: &str) -> String {
    format!(
        "calendar-connector:{provider}:{}:{}:{uid}",
        seat.config.system, seat.config.calendar_ref
    )
}
