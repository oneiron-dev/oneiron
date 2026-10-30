//! The queued continuation of one event's property admissions (FIX 11997).
//!
//! One admission pass admits at most
//! [`CALENDAR_PROPERTY_ADMISSIONS_PER_PASS`] new property claims for one
//! event. An event that owes more, a very large attendee set most of all, is
//! signalled and, once its feed is applied and its passport admitted, queues
//! one `calendar.ics.property_continuation` attempt. Its run reads the
//! archived version the pass admitted from again (an ICS feed version, or a
//! connector's pulled resource, FIX 12163) and admits the next pass's worth
//! the same way, through the same screen and gate, until nothing is owed. A
//! continuation whose event is gone, or whose passport names other content
//! now, settles with nothing to do: the pass that moved it on reconciled it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::*;
use crate::attempt_queue::EnqueueAttempt;
use crate::calendar::ics::parse_ics_feed;
use crate::calendar::ingest::property_claims::CALENDAR_PROPERTY_ADMISSIONS_PER_PASS;
use crate::calendar::passport::live_passport_for;

/// Attempt kind for one event's queued property continuation.
pub const ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND: &str = "calendar.ics.property_continuation";

/// What one queued property continuation reads again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcsPropertyContinuationPayload {
    /// The foreign system the admission ran for.
    pub system: String,
    /// The source the admission's claims cite: the archived feed version
    /// for an ICS admission, the pull record for a connector's. The claims
    /// the continuation admits cite it too, as the first pass's do.
    pub blob_ref: String,
    /// The archived version the continuation reads the event from again,
    /// `artifact#vN`: the feed version itself for an ICS admission, the
    /// pulled resource's for a connector's.
    pub source_version: String,
    /// Hex id of the EVENT the properties are claims on.
    pub event_ref: String,
    /// The event's UID.
    pub uid: String,
    /// A detached occurrence's original start; `None` for the event itself.
    pub recurrence_id_utc: Option<u64>,
}

/// One event's property claims a pass left owing, kept until its feed is
/// applied.
pub(crate) struct OwedProperties {
    event_ref: EntityId,
    uid: String,
    recurrence_id_utc: Option<u64>,
    owed: usize,
}

impl PollAdmission<'_> {
    /// Signals an event whose properties pass the per-pass count: it is
    /// logged, and an event that still owes `owed` property claims is kept
    /// for [`Self::queue_property_continuations`]. An admission that keeps
    /// no continuations admits every property in its one pass and owes
    /// none.
    pub(super) fn signal_property_continuation(
        &mut self,
        event_ref: EntityId,
        event: &ParsedVEvent,
        owed: usize,
    ) {
        let carried = event.properties.attendees.len() + event.properties.meeting_links.len();
        if carried > CALENDAR_PROPERTY_ADMISSIONS_PER_PASS {
            tracing::warn!(
                system = self.system,
                uid = %event.uid,
                attendees = event.properties.attendees.len(),
                links = event.properties.meeting_links.len(),
                owed,
                "calendar event carries more properties than one admission pass admits"
            );
        }
        if owed == 0 {
            return;
        }
        if let Some(continuations) = self.continuations.as_mut() {
            continuations.push(OwedProperties {
                event_ref,
                uid: event.uid.clone(),
                recurrence_id_utc: event.properties.recurrence_id_utc,
                owed,
            });
        }
    }

    /// Queues one continuation for each event this admission left owing,
    /// once the passports its continuation checks are admitted. Each reads
    /// again the archived feed version the admission's claims cite.
    pub(super) fn queue_property_continuations(&mut self) -> Result<(), CalendarError> {
        let source_version = self.blob_ref;
        self.queue_property_continuations_reading(source_version)
    }

    /// Queues as [`Self::queue_property_continuations`] does, each
    /// continuation reading the archived version `source_version` again:
    /// for a connector admission, the pulled resource its claims' pull
    /// record does not name.
    pub(super) fn queue_property_continuations_reading(
        &mut self,
        source_version: &str,
    ) -> Result<(), CalendarError> {
        let Some(continuations) = self.continuations.as_mut() else {
            return Ok(());
        };
        for OwedProperties {
            event_ref,
            uid,
            recurrence_id_utc,
            owed,
        } in std::mem::take(continuations)
        {
            let payload = IcsPropertyContinuationPayload {
                system: self.system.to_owned(),
                blob_ref: self.blob_ref.to_owned(),
                source_version: source_version.to_owned(),
                event_ref: event_ref.to_hex(),
                uid,
                recurrence_id_utc,
            };
            let bytes = serde_json::to_vec(&payload)
                .map_err(|_| ingest("property continuation payload did not encode"))?;
            // One row per event, admitted version and count still owed: the
            // run that queues the next pass's row while its own is leased is
            // not folded into it.
            let parts: [&[u8]; 4] = [
                payload.system.as_bytes(),
                payload.blob_ref.as_bytes(),
                payload.source_version.as_bytes(),
                payload.event_ref.as_bytes(),
            ];
            let identity = Sha256::digest(parts.join(&0_u8));
            let dedupe_key =
                format!("{ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND}:{identity:x}:owed:{owed}");
            self.vault.with_write_txn_grouped(|txn| {
                crate::ports::JobQueue::port_job_enqueue(
                    self.vault,
                    txn,
                    EnqueueAttempt {
                        kind: ICS_PROPERTY_CONTINUATION_ATTEMPT_KIND.to_owned(),
                        payload: bytes,
                        dedupe_key: Some(dedupe_key),
                        run_id: None,
                        now: self.now,
                    },
                )
            })?;
        }
        Ok(())
    }
}

/// Runs one queued property continuation: the event's next pass of property
/// admissions from the archived version `payload` names, screened under
/// `screener` while `safeguard_enabled`, as a feed poll screens. An event
/// that still owes more queues the next continuation.
///
/// # Errors
///
/// Store, parse, screen and gate failures as typed [`CalendarError`]
/// variants; the row runs again later.
pub fn run_ics_property_continuation(
    vault: &Vault,
    screener: Option<&dyn CalendarBodyScreener>,
    safeguard_enabled: bool,
    payload: &IcsPropertyContinuationPayload,
) -> Result<(), CalendarError> {
    let event_ref = EntityId::from_hex(&payload.event_ref)
        .map_err(|_| ingest("property continuation names no event"))?;
    if vault.get_entity_type(&event_ref)? != Some(ENTITY_TYPE_EVENT) {
        return Ok(());
    }
    let Some(bytes) = read_archived_version(vault, &payload.source_version)? else {
        return Ok(());
    };
    let feed = parse_ics_feed(&bytes)?;
    let Some(event) = feed.events.iter().find(|event| {
        event.uid == payload.uid && event.properties.recurrence_id_utc == payload.recurrence_id_utc
    }) else {
        return Ok(());
    };
    if !live_passport_for(vault, &event_ref, &payload.system, &payload.uid)?
        .is_some_and(|(_, passport)| passport.content_hash == event.content_hash)
    {
        return Ok(());
    }
    let mut admission = PollAdmission {
        vault,
        screener,
        safeguard_enabled,
        system: &payload.system,
        preserve_direction: true,
        now: vault.now_recorded_at(),
        blob_ref: &payload.blob_ref,
        verdict_fold: VerdictFold::default(),
        continuations: Some(Vec::new()),
    };
    admission.preflight_event(event)?;
    admission.admit_properties(event_ref, event)?;
    admission.queue_property_continuations_reading(&payload.source_version)
}

/// The bytes of the archived version an `artifact#vN` reference names;
/// `None` for any other shape or a version no longer stored.
fn read_archived_version(vault: &Vault, blob_ref: &str) -> Result<Option<Vec<u8>>, CalendarError> {
    let Some((hex, version)) = blob_ref.split_once("#v") else {
        return Ok(None);
    };
    let (Ok(artifact_id), Ok(version)) = (EntityId::from_hex(hex), version.parse::<u64>()) else {
        return Ok(None);
    };
    Ok(vault.read_blob_artifact_version(&artifact_id, version)?)
}
