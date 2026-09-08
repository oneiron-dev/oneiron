//! Pull orchestration: apply, admit, enqueue, and reconcile.

use super::outbound::{CalendarRemoteObjectRow, ingest_error, ingest_reason, write_remote_object};
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
use crate::calendar::claims::{
    CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection, CalendarPassportPresence,
    CalendarPassportValue, CalendarStatus, CalendarStatusBasis, CalendarTimeKind,
    PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS,
    PREDICATE_CALENDAR_TIME_KIND, decode_status_value, decode_time_kind_value,
};
use crate::calendar::ics::ParsedVEvent;
use crate::calendar::ingest::admit_calendar_import_claim;
use crate::calendar::passport::{
    all_live_inbound_passports_absent, encode_passport_value, index_passport_uid,
    live_passport_for, resolve_event_by_uid, supersede_calendar_passport,
};
use crate::calendar::safeguard::{CalendarInboundBody, screen_then_claim};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Runs one connector sync for `seat`.
///
/// Killed seats short-circuit with [`CalendarSyncOutcome::Killed`]: no transport
/// call, no claim, no re-enqueue. Otherwise the run pulls from the seat cursor,
/// re-parses every upsert through [`super::ics::parse_ics_feed`], classifies it
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
            // ICS truth, not transport truth: UID/SEQUENCE/hash come from the
            // parse, and every time value crosses the CAL-01 border inside it.
            let parsed = parse_remote_object(object)?;
            let normalized = RemoteCalendarChange::Upsert(RemoteCalendarObject {
                href: object.href.clone(),
                etag: object.etag.clone(),
                uid: parsed.uid.clone(),
                sequence: parsed.sequence,
                content_hash: parsed.content_hash,
                ics: object.ics.clone(),
            });
            let event_ref = resolve_event_by_uid(vault, &parsed.uid)?;
            let current = match event_ref {
                Some(event_ref) => live_passport_for(vault, &event_ref, system, &parsed.uid)?
                    .map(|(_, value)| value),
                None => None,
            };
            match classify_remote_change(current.as_ref(), &normalized) {
                EchoDisposition::AcknowledgeEcho => {
                    // Acknowledgement only: the provider's view of the resource
                    // is refreshed, no semantic claim is rewritten, and nothing
                    // is written back.
                    counters.acknowledged += 1;
                }
                EchoDisposition::ApplyInbound | EchoDisposition::ApplyRemoteUpdate => {
                    apply_inbound_event(vault, seat, provider, event_ref, &parsed, now)?;
                    counters.applied += 1;
                }
                EchoDisposition::ApplyRemoteDeletion => {
                    return Err(ingest_error("an upsert can never classify as a deletion"));
                }
            }
            write_remote_object(
                vault,
                &CalendarRemoteObjectRow {
                    system: system.to_owned(),
                    calendar_ref: seat.config.calendar_ref.clone(),
                    uid: parsed.uid.clone(),
                    href: Some(object.href.clone()),
                    etag: object.etag.clone(),
                    last_sequence: parsed.sequence,
                    content_hash: parsed.content_hash,
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
    let system = seat.config.system.as_str();
    let Some(event_ref) = resolve_event_by_uid(vault, uid)? else {
        return Ok(());
    };
    let Some((_, current)) = live_passport_for(vault, &event_ref, system, uid)? else {
        return Ok(());
    };
    if current.presence == CalendarPassportPresence::Absent {
        // Applied once: a repeated delete row is idempotent.
        return Ok(());
    }

    let mut absent = current;
    absent.presence = CalendarPassportPresence::Absent;
    absent.last_seen_at = now;
    let source_record_id = pull_source_record_id(provider, seat, uid);
    let new_id = admit_screened(
        vault,
        event_ref,
        &CalendarInboundBody::default(),
        &source_record_id,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&absent),
        now,
    )?;
    supersede_calendar_passport(vault, event_ref, system, uid, &new_id, now)?;
    counters.source_absences += 1;

    if all_live_inbound_passports_absent(vault, &event_ref)?
        && admit_status_if_changed(
            vault,
            event_ref,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
            now,
        )?
    {
        counters.status_cancellations += 1;
    }
    Ok(())
}

/// Applies one inbound VEVENT: mint-or-rewrite the EVENT, then admit the
/// `calendar.*` heads through the CAL-02 Gate-backed imported door.
fn apply_inbound_event(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    event_ref: Option<EntityId>,
    parsed: &ParsedVEvent,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    let source_record_id = pull_source_record_id(provider, seat, &parsed.uid);
    let body = inbound_body(parsed);
    let occurred = parsed_occurred(parsed, now);
    let event_body = encode_event_body(event_display_name(parsed))?;

    let (event_ref, minted) = match event_ref {
        Some(event_ref) => {
            // The update verdict moves the EVENT, not just the passport head.
            vault.put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, now, &event_body)?;
            (event_ref, false)
        }
        None => {
            let event_ref = EntityId::now();
            vault.put_entity(&event_ref, ENTITY_TYPE_EVENT, occurred, now, &event_body)?;
            index_passport_uid(vault, &parsed.uid, &event_ref)?;
            (event_ref, true)
        }
    };

    if minted {
        admit_screened(
            vault,
            event_ref,
            &body,
            &source_record_id,
            PREDICATE_CALENDAR_ORIGIN,
            rmpv::Value::from(CalendarOrigin::Imported.as_str()),
            now,
        )?;
    }
    admit_time_kind_if_changed(
        vault,
        event_ref,
        &body,
        &source_record_id,
        parsed.busy_transparency,
        now,
    )?;

    let current = live_passport_for(vault, &event_ref, system, &parsed.uid)?;
    let next = CalendarPassportValue {
        system: system.to_owned(),
        uid: parsed.uid.clone(),
        last_sequence: parsed.sequence,
        content_hash: parsed.content_hash,
        // A pulled row preserves the seat's established routing and mints
        // `Inbound` for a source seen for the first time.
        direction: current
            .as_ref()
            .map_or(CalendarPassportDirection::Inbound, |(_, value)| {
                value.direction
            }),
        last_seen_at: now,
        presence: CalendarPassportPresence::Live,
    };
    let new_id = admit_screened(
        vault,
        event_ref,
        &body,
        &source_record_id,
        PREDICATE_CALENDAR_PASSPORT,
        encode_passport_value(&next),
        now,
    )?;
    if current.is_some() {
        supersede_calendar_passport(vault, event_ref, system, &parsed.uid, &new_id, now)?;
    }

    if parsed.cancelled {
        admit_status_if_changed(
            vault,
            event_ref,
            &source_record_id,
            CalendarStatus::Cancelled,
            CalendarStatusBasis::ImportedCancel,
            now,
        )?;
    }
    Ok(())
}

/// Admits `calendar.time_kind` when its value moved, superseding the prior live
/// claim. `busy_transparency` is CAL-02's ingest truth carried through unchanged
/// — the connector invents no second field.
fn admit_time_kind_if_changed(
    vault: &Vault,
    event_ref: EntityId,
    body: &CalendarInboundBody,
    source_record_id: &str,
    transparency: CalendarBusyTransparency,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let mut prior_live: Option<EntityId> = None;
    for claim_id in vault.claims_for_subject(&event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.predicate != PREDICATE_CALENDAR_TIME_KIND
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let current = decode_time_kind_value(&claim.value)
            .map_err(|_| ingest_error("stored time claim did not decode"))?;
        if current.kind == CalendarTimeKind::Absolute && current.busy_transparency == transparency {
            return Ok(());
        }
        prior_live = Some(claim_id);
    }
    let value = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from(CalendarTimeKind::Absolute.as_str()),
        ),
        (
            rmpv::Value::from("busy_transparency"),
            rmpv::Value::from(transparency.as_str()),
        ),
    ]);
    let new_id = admit_screened(
        vault,
        event_ref,
        body,
        source_record_id,
        PREDICATE_CALENDAR_TIME_KIND,
        value,
        now,
    )?;
    if let Some(old_id) = prior_live {
        vault.supersede_claim(&new_id, &old_id, now)?;
    }
    Ok(())
}

/// Admits one `calendar.status` claim, superseding the prior live one. Returns
/// whether a claim was actually written.
fn admit_status_if_changed(
    vault: &Vault,
    event_ref: EntityId,
    source_record_id: &str,
    status: CalendarStatus,
    basis: CalendarStatusBasis,
    now: u64,
) -> Result<bool, CalendarConnectorError> {
    let mut prior_live: Option<EntityId> = None;
    for claim_id in vault.claims_for_subject(&event_ref)? {
        let Some(claim) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if claim.predicate != PREDICATE_CALENDAR_STATUS
            || claim.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let current = decode_status_value(&claim.value)
            .map_err(|_| ingest_error("stored status claim did not decode"))?;
        if current.status == status && current.basis == basis {
            return Ok(false);
        }
        prior_live = Some(claim_id);
    }
    let value = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("status"),
            rmpv::Value::from(status.as_str()),
        ),
        (
            rmpv::Value::from("basis"),
            rmpv::Value::from(basis.as_str()),
        ),
        (rmpv::Value::from("recorded_at"), rmpv::Value::from(now)),
    ]);
    let new_id = admit_screened(
        vault,
        event_ref,
        &CalendarInboundBody::default(),
        source_record_id,
        PREDICATE_CALENDAR_STATUS,
        value,
        now,
    )?;
    if let Some(old_id) = prior_live {
        vault.supersede_claim(&new_id, &old_id, now)?;
    }
    Ok(true)
}

/// The one admission door for both connectors.
///
/// Every semantic candidate crosses CAL-09's ordering hook and then CAL-02's
/// Gate-backed imported-evidence door — never `put_claim`. The seat surface
/// wires no screener of its own (CAL-09's dial lives on the feed poll runner),
/// so the verdict is `Skipped`, which is explicitly not "assume clear".
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
fn parsed_occurred(parsed: &ParsedVEvent, now: u64) -> TimeRange {
    match (parsed.starts_at_utc, parsed.ends_at_utc) {
        (Some(start), Some(end)) => TimeRange {
            start,
            end: end.max(start),
        },
        (Some(start), None) => TimeRange { start, end: start },
        (None, _) => TimeRange {
            start: now,
            end: now,
        },
    }
}

/// The EVENT's display name: SUMMARY, with a UID fallback.
fn event_display_name(parsed: &ParsedVEvent) -> &str {
    parsed
        .summary
        .as_deref()
        .filter(|summary| !summary.is_empty())
        .unwrap_or(parsed.uid.as_str())
}

/// The CAL-09 screen body for one pulled VEVENT.
fn inbound_body(parsed: &ParsedVEvent) -> CalendarInboundBody {
    CalendarInboundBody {
        description: parsed.description.clone().unwrap_or_default(),
        attachment_text: Vec::new(),
    }
}

/// The EVENT body row: a MessagePack map carrying only the name.
fn encode_event_body(name: &str) -> Result<Vec<u8>, CalendarError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .map_err(|_| ingest_reason("event body did not encode"))?;
    Ok(body)
}

/// Reads the EVENT body's `name` field, tolerating non-map bodies.
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
