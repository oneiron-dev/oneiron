//! Pull orchestration: apply, admit, enqueue, and reconcile.

use super::door::CalendarConnectorOperation;
use super::outbound::{
    CalendarRemoteObjectRow, cancelled_members_in_flight, first_write_unsettled, ingest_error,
    omission_observed, prove_unproven_replay, write_remote_object,
};
use super::remote::{
    CalendarRemoteTransport, CalendarSyncOutcome, EchoDisposition, RemoteCalendarChange,
    RemoteCalendarObject, classify_remote_change, parse_remote_object,
};
use super::seat::{
    CalendarConnectorError, CalendarConnectorSeatState, CalendarConnectorSyncPayload,
    calendar_sync_attempt_kind, seat_identity,
};

use crate::attempt_queue::EnqueueAttempt;
use crate::calendar::CalendarError;
use crate::calendar::claims::CalendarPassportPresence;
use crate::calendar::ingest::{
    ConnectorAdmissionSource, ConnectorScreen, admit_calendar_import_claim,
    admit_calendar_import_claim_in_txn,
};
use crate::calendar::passport::live_passport_for;
use crate::calendar::safeguard::{CalendarBodyScreener, CalendarInboundBody, screen_then_claim};
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
/// The safeguard dial is off and no screener runs. An owner's pull
/// ([`run_calendar_connector_sync_with_screener`]) runs under the owner's
/// CAL-09 dial instead.
///
/// # Errors
///
/// [`CalendarConnectorError`] for seat, transport, parse, timezone, and store
/// failures. A failure applies nothing further and enqueues nothing.
pub fn run_calendar_connector_sync(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    now: u64,
    jitter_seed: u64,
) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
    run_calendar_connector_sync_with_screener(
        vault,
        operation,
        transport,
        None,
        false,
        now,
        jitter_seed,
    )
}

/// [`run_calendar_connector_sync`] with CAL-09's safeguard wired, as a feed
/// poll wires it: when `safeguard_enabled`, `screener` (or its recorded
/// absence) produces a verdict immediately before every imported-claim
/// admission the pull makes, its absence sweeps and remote deletions
/// included.
///
/// # Errors
///
/// Same contract as [`run_calendar_connector_sync`].
pub fn run_calendar_connector_sync_with_screener(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    screener: Option<&dyn CalendarBodyScreener>,
    safeguard_enabled: bool,
    now: u64,
    jitter_seed: u64,
) -> Result<CalendarSyncOutcome, CalendarConnectorError> {
    let seat = &operation.registration().seat;
    seat.validate()?;
    if seat.kill_switch_engaged() {
        // No pull, no write, no next attempt — and nothing erased.
        return Ok(CalendarSyncOutcome::Killed);
    }

    operation.revalidate(vault)?;
    let batch = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    )?;

    let screen = ConnectorScreen {
        screener,
        safeguard_enabled,
    };
    let mut counters = SyncCounters::default();
    // A sync answer that reports a resource gone beside a copy of its UID is
    // the provider's report of a moved resource (CalDAV: the old href's 404
    // and the new href's copy in one delta), not a cancellation: the delete
    // is dropped and the copy is read as any other version, a cancelled one
    // included (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
    let live_uids: std::collections::BTreeSet<&str> = batch
        .changes
        .iter()
        .filter_map(|change| match change {
            RemoteCalendarChange::Upsert(object) => Some(object.uid.as_str()),
            _ => None,
        })
        .collect();
    for change in &batch.changes {
        if let RemoteCalendarChange::Delete { uid, .. } = change
            && live_uids.contains(uid.as_str())
        {
            continue;
        }
        apply_remote_change(
            vault,
            operation,
            seat,
            transport.provider_key(),
            change,
            screen,
            now,
            &mut counters,
        )?;
    }

    // An omission a write in flight or a moved row holds back stays owed:
    // every other change of this pull stands, and the next pull lists the
    // calendar whole again, so the omission is read again, never dropped
    // (fix list row 19192). A booking move a pending emergency delivery held
    // back stays owed the same way (FIX 22385), and so does a cancelled
    // version a cancelled write in flight holds back
    // (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS) and a first write's
    // copy read before the write settled
    // (CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT).
    let next_cursor = match batch.next_cursor {
        Some(cursor)
            if counters.owed_omissions > 0
                || counters.owed_booking_moves > 0
                || counters.owed_cancelled_versions > 0
                || counters.owed_first_write_copies > 0 =>
        {
            transport.cursor_owing_full_listing(&cursor)
        }
        cursor => cursor,
    };
    let next_not_before = seat.jittered_next_poll_at(now, jitter_seed)?;
    enqueue_next_sync(
        vault,
        seat,
        transport.provider_key(),
        next_cursor.clone(),
        next_not_before,
        now,
    )?;

    Ok(CalendarSyncOutcome::Reenqueued {
        next_cursor,
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
    /// Omissions a write in flight or a moved row held back (fix list row
    /// 19192).
    owed_omissions: u32,
    /// Resources whose booking move a pending emergency delivery held back
    /// (FIX 22385).
    owed_booking_moves: u32,
    /// Resources read cancelled while a cancelled write of the same member
    /// was in flight (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS).
    owed_cancelled_versions: u32,
    /// Resources read while the first write of their EVENT, under the UID
    /// it minted, was in flight
    /// (CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT).
    owed_first_write_copies: u32,
}

/// Applies one pulled change under the echo law, each admission under
/// `screen`.
fn apply_remote_change(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    change: &RemoteCalendarChange,
    screen: ConnectorScreen<'_>,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let system = seat.config.system.as_str();
    // FIX 4797: the vault's one calendar admission turn, from the echo
    // classification through the sweep and the remote object row.
    let _turn = crate::calendar::ingest::admission_turn(vault)?;
    match change {
        RemoteCalendarChange::Upsert(object) => {
            let feed = super::remote::parse_remote_resource(object)?;
            let primary = feed
                .events
                .first()
                .ok_or_else(|| ingest_error("remote resource has no event"))?;
            let source = pull_source_record_id(provider, seat, &primary.uid);
            // A replayed write whose refusal's read proved nothing is proved
            // by this read first, so its own copy never lands unmarked
            // (BK-ECHO-RECONCILE-FAILURE-RELEASES-UNMARKED-COPY), nor a first
            // write's as a second EVENT.
            prove_unproven_replay(vault, operation, provider, object, &primary.uid, now)?;
            // A first write's copy coming back before the write binds its
            // UID resolves no EVENT: nothing names the UID the write minted
            // until its passport lands. The resource stays owed and unread,
            // so it never imports a second EVENT, on this seat or on any
            // other seat of the collection, and the next pull after the
            // write binds the UID reads it on the written EVENT
            // (CAL-FIRST-WRITE-COPY-PULLED-UNSETTLED-IMPORTS-DUPLICATE-EVENT).
            if first_write_unsettled(vault, &primary.uid)? {
                counters.owed_first_write_copies += 1;
                return Ok(());
            }
            // A cancelled version of a member a write of this UID still in
            // flight writes cancelled may be that write coming back before
            // its settlement marks the member's passport, and would read as a
            // host cancel that refunds the deposit. The resource stays owed
            // and unread, as an omission a write in flight holds back does,
            // and each cancelled member's passport keeps this first sighting,
            // which dates the cancellation if the write proves not to be the
            // stored copy (BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS).
            // A VEVENT is the staged member its UID and staged RECURRENCE-ID
            // name, whatever exception claims the member holds now.
            let in_flight = cancelled_members_in_flight(vault, operation, &primary.uid)?;
            if !in_flight.is_empty() {
                let mut cancelled = Vec::new();
                for parsed in feed.events.iter().filter(|parsed| parsed.cancelled) {
                    let staged = in_flight
                        .iter()
                        .find(|(_, identity)| {
                            parsed.uid == primary.uid
                                && *identity == parsed.properties.recurrence_id_utc
                        })
                        .map(|(member, _)| *member);
                    let member = match staged {
                        Some(member) => Some(member),
                        None => crate::calendar::ingest::connector_event_ref(vault, parsed)?,
                    };
                    if let Some(member) = member {
                        cancelled.push((member, parsed));
                    }
                }
                if cancelled
                    .iter()
                    .any(|(member, _)| in_flight.iter().any(|(staged, _)| staged == member))
                {
                    for (member, parsed) in cancelled {
                        if let Some((_, passport)) =
                            live_passport_for(vault, &member, system, &parsed.uid)?
                        {
                            crate::calendar::ingest::defer_connector_cancel(
                                vault,
                                system,
                                ConnectorAdmissionSource {
                                    record: source.as_str(),
                                    source_version: None,
                                    screen,
                                    source: None,
                                },
                                member,
                                &passport,
                                parsed,
                                now,
                            )?;
                        }
                    }
                    counters.owed_cancelled_versions += 1;
                    return Ok(());
                }
            }
            // Archived before any semantic write, once the bytes are known to
            // parse: a later write renders over exactly this copy.
            let archived = super::resource::archive_remote_source(
                vault,
                system,
                &seat.config.calendar_ref,
                &primary.uid,
                &object.ics,
                now,
            )?;
            let source_blob_ref = archived.blob_ref();
            crate::calendar::ingest::preflight_connector_feed(vault, system, &source, &feed, now)?;
            let admission_source = ConnectorAdmissionSource {
                record: source.as_str(),
                source_version: Some(source_blob_ref.as_str()),
                screen,
                source: Some(archived),
            };
            let mut owed_booking_move = false;
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
                    EchoDisposition::AcknowledgeEcho => {
                        // A cancellation whose admission stopped before its
                        // deposit refund or status reads as an echo on the
                        // next pull of the same bytes: they are asked again
                        // here. An uncancelled echo withdraws a tombstone's
                        // date from its passport.
                        if let (Some(id), Some(passport)) = (event_ref, current.as_ref()) {
                            crate::calendar::ingest::repeat_connector_echo(
                                vault,
                                system,
                                admission_source,
                                id,
                                passport,
                                parsed,
                                now,
                            )?;
                        }
                        counters.acknowledged += 1;
                    }
                    EchoDisposition::ApplyInbound | EchoDisposition::ApplyRemoteUpdate => {
                        if crate::calendar::ingest::admit_connector_event(
                            vault,
                            system,
                            admission_source,
                            parsed,
                            now,
                        )? {
                            owed_booking_move = true;
                        } else {
                            counters.applied += 1;
                        }
                    }
                    EchoDisposition::ApplyRemoteDeletion => {
                        return Err(ingest_error("an upsert cannot classify as deletion"));
                    }
                }
            }
            // A booking move a pending emergency delivery held back keeps
            // the resource owed (FIX 22385): no sweep and no new remote
            // object row, and the pull's cursor lists the calendar whole
            // again, so the next pull reads the move again.
            if owed_booking_move {
                counters.owed_booking_moves += 1;
                return Ok(());
            }
            crate::calendar::ingest::sweep_connector_resource(
                vault,
                system,
                admission_source,
                &feed,
                &primary.uid,
                now,
            )?;
            write_remote_object(
                vault,
                operation,
                &CalendarRemoteObjectRow {
                    system: system.to_owned(),
                    calendar_ref: seat.config.calendar_ref.clone(),
                    uid: primary.uid.clone(),
                    href: Some(object.href.clone()),
                    etag: object.etag.clone(),
                    last_sequence: primary.sequence,
                    content_hash: super::remote::ics_content_hash(&object.ics, &primary.uid)?,
                    last_seen_at: now,
                    source_blob_ref: Some(source_blob_ref),
                    carrier: None,
                },
                None,
            )?;
            Ok(())
        }
        RemoteCalendarChange::Delete { uid, .. } => {
            debug_assert_eq!(
                classify_remote_change(None, change),
                EchoDisposition::ApplyRemoteDeletion
            );
            // A provider that keeps a cancelled event as a deleted one
            // reports a cancelled write of this UID still in flight as a
            // tombstone before its settlement marks the member's passport,
            // and the tombstone would read as the host's cancel. It stays owed and unread, as a cancelled version a
            // write in flight holds back does, and each passport it would
            // date keeps this first sighting
            // (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
            if !cancelled_members_in_flight(vault, operation, uid)?.is_empty() {
                let record = pull_source_record_id(provider, seat, uid);
                crate::calendar::ingest::defer_connector_delete(
                    vault,
                    system,
                    ConnectorAdmissionSource {
                        record: &record,
                        source_version: None,
                        screen,
                        source: None,
                    },
                    uid,
                    now,
                )?;
                counters.owed_cancelled_versions += 1;
                return Ok(());
            }
            apply_remote_deletion(
                vault,
                seat,
                provider,
                uid,
                RemovalEvidence::Tombstone,
                screen,
                now,
                counters,
            )
        }
        RemoteCalendarChange::Omitted {
            uid, observation, ..
        } => {
            // Fix list row 19192: checked inside this turn, which a write's
            // prepared row is published in too, so the row and the outbox
            // are the ones the absence lands against.
            operation.revalidate(vault)?;
            if !omission_observed(vault, operation, uid, *observation)? {
                counters.owed_omissions += 1;
                return Ok(());
            }
            let settles_held_cancel =
                !super::outbound::replay_copy_unproven(vault, operation, uid)?;
            apply_remote_deletion(
                vault,
                seat,
                provider,
                uid,
                RemovalEvidence::Omission {
                    settles_held_cancel,
                },
                screen,
                now,
                counters,
            )
        }
    }
}

/// What says a remote resource is gone.
#[derive(Clone, Copy)]
enum RemovalEvidence {
    /// The provider's own tombstone: an explicit cancellation.
    Tombstone,
    /// A full listing that no longer carries it (fix list row 19192): an
    /// absence, as an omitted feed item is.
    Omission {
        /// Whether it settles a cancellation this seat reported while a
        /// cancelled write of the UID was in flight, which the pull held back
        /// ([`apply_remote_deletion`]): false while that write is a replay
        /// whose refusal read no copy.
        settles_held_cancel: bool,
    },
}

/// A remote deletion marks exactly one source's passport absent, once.
///
/// Multi-source law, verbatim: feed-absence cancellation applies ONLY when every
/// live inbound passport for the EVENT reports absence; a single-source absence
/// supersedes only that passport, never the EVENT status. The EVENT is never
/// deleted, CAL-07's outcome predicate is never written, and no delete is bounced
/// back to any provider.
#[expect(
    clippy::too_many_arguments,
    reason = "a removal's evidence and its pull's screen meet the one passport sweep"
)]
fn apply_remote_deletion(
    vault: &Vault,
    seat: &CalendarConnectorSeatState,
    provider: &'static str,
    uid: &str,
    evidence: RemovalEvidence,
    screen: ConnectorScreen<'_>,
    now: u64,
    counters: &mut SyncCounters,
) -> Result<(), CalendarConnectorError> {
    let mut absent_count = 0;
    let mut newly_absent = Vec::new();
    let mut held_cancel = false;
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
            let Some((_, value)) = crate::calendar::passport::live_passport_for(
                vault,
                event,
                &seat.config.system,
                uid,
            )?
            else {
                continue;
            };
            held_cancel |= value.deferred_cancel_seen_at.is_some();
            if value.presence == CalendarPassportPresence::Live
                && value.direction.is_inbound_bearing()
            {
                absent_count += 1;
                newly_absent.push((*event, imported_cancellation(vault, *event)?));
            }
        }
        after = ids.last().copied();
    }
    let record = pull_source_record_id(provider, seat, uid);
    let source = ConnectorAdmissionSource {
        record: &record,
        source_version: None,
        screen,
        source: None,
    };
    // A full listing can only leave a gone resource out, never send its
    // tombstone again. So an omission of a resource whose cancellation this
    // seat reported while a cancelled write of the UID was in flight, held
    // back as `deferred_cancel_seen_at`, settles that report as the tombstone
    // it was, dated by its first sighting: no write is in flight any more (an
    // omission waits on one), a write that settled dropped the sighting, and
    // a refusal that stored nothing, or whose read proved the stored copy
    // another writer's, leaves the host's report. A replay whose read proved
    // nothing leaves it held, since the gone copy may be the engine's own
    // cancelled write (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
    let evidence = match evidence {
        RemovalEvidence::Omission {
            settles_held_cancel: true,
        } if held_cancel => RemovalEvidence::Tombstone,
        evidence => evidence,
    };
    match evidence {
        RemovalEvidence::Tombstone => crate::calendar::ingest::delete_connector_resource(
            vault,
            &seat.config.system,
            source,
            uid,
            now,
        )?,
        RemovalEvidence::Omission { .. } => crate::calendar::ingest::sweep_connector_uids(
            vault,
            &seat.config.system,
            source,
            &std::collections::BTreeSet::from([uid]),
            now,
        )?,
    }
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

pub(super) fn admit_screened_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
    body: &CalendarInboundBody,
    source_record_id: &str,
    predicate: &str,
    value: rmpv::Value,
    now: u64,
) -> Result<EntityId, CalendarConnectorError> {
    let screened = screen_then_claim(false, None, body, |_request| {
        admit_calendar_import_claim_in_txn(
            vault,
            txn,
            &event_ref,
            predicate,
            value,
            source_record_id,
            now,
        )
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
    vault.with_write_txn_grouped(|txn| {
        crate::ports::JobQueue::port_job_enqueue(
            vault,
            txn,
            EnqueueAttempt {
                kind: calendar_sync_attempt_kind(provider),
                payload,
                dedupe_key: Some(dedupe_key),
                run_id: None,
                now,
            },
        )
    })?;
    Ok(())
}

/// Refreshes the local view of one remote object after a precondition failure.
/// Best-effort by design: the mismatch verdict is what the caller must see, and
/// a reconciliation pull that itself fails must not mask it. Returns the last
/// copy of the object the pull read, if any.
pub(super) fn reconcile_remote_object(
    vault: &Vault,
    operation: &CalendarConnectorOperation,
    transport: &dyn CalendarRemoteTransport,
    uid: &str,
    now: u64,
) -> Option<RemoteCalendarObject> {
    if operation.revalidate(vault).is_err() {
        return None;
    }
    let seat = &operation.registration().seat;
    let Ok(batch) = transport.pull(
        &seat.config.secret_ref,
        &seat.config.calendar_ref,
        seat.cursor.as_deref(),
    ) else {
        return None;
    };
    let mut read = None;
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
        // The whole resource's hash, as a pull stores it, so a full
        // listing's omission sweep reads this row as the archived copy.
        let Ok(content_hash) = super::remote::ics_content_hash(&object.ics, uid) else {
            continue;
        };
        // The refreshed copy is the base a rebased write renders over.
        let source_blob_ref = super::resource::archive_remote_source(
            vault,
            &seat.config.system,
            &seat.config.calendar_ref,
            uid,
            &object.ics,
            now,
        )
        .ok()
        .map(|source| source.blob_ref());
        let _ = write_remote_object(
            vault,
            operation,
            &CalendarRemoteObjectRow {
                system: seat.config.system.clone(),
                calendar_ref: seat.config.calendar_ref.clone(),
                uid: uid.to_owned(),
                href: Some(object.href.clone()),
                etag: object.etag.clone(),
                last_sequence: parsed.sequence,
                content_hash,
                last_seen_at: now,
                source_blob_ref,
                carrier: None,
            },
            None,
        );
        read = Some(object.clone());
    }
    read
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
