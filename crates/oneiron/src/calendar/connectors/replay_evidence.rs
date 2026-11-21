//! The replay-evidence claim of a cancel Oneiron cannot attribute
//! (FIX [BK-REPLAY-NOTE-NOT-CARRIED-TO-NEW-HOME], BK-REPLAY-NOTE-DELIVERY = A).
//!
//! A seat's replay of the owner's cancelled write that reads a stored copy
//! with no write marker as the owner's own (BK-ECHO-UNMARKED-SAME-SHAPE-COPY
//! = C) runs on the node that holds the seat's outbox row. The booking's
//! deposit may live on another node by then: a home move carries the
//! deposit, not the seat. So the proof writer records the replay as a synced
//! `calendar.replay_cancel_evidence` claim on each EVENT the write cancelled,
//! and the node that holds the live deposit reads it there
//! (`booking::lifecycle::deposit::held`).

use rmpv::Value;

use super::inbound::admit_screened_in_txn;
use super::seat::CalendarConnectorError;
use crate::calendar::claims::{
    CalendarReplayCancelEvidenceValue, PREDICATE_CALENDAR_REPLAY_CANCEL_EVIDENCE,
    decode_replay_cancel_evidence_value, encode_replay_cancel_evidence_value,
};
use crate::calendar::safeguard::CalendarInboundBody;
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSource};
use crate::registry::ENTITY_TYPE_EVENT;
use crate::{EntityId, Vault};

/// The prefix of the provenance ref a seat's own write records
/// (`outbound::write_source_record_id`).
pub(super) const WRITE_SOURCE_RECORD_PREFIX: &str = "calendar-connector-write:";

/// Records, in the proof writer `txn`, that a seat's replay of the owner's
/// cancelled write of the EVENT `member` at `sequence` read an unmarked
/// stored copy as the owner's own, proved at `now` under the write's own
/// provenance ref `source_record_id`. The first proof is the one the owner's
/// line dates, so an EVENT that already carries one takes no second; an
/// EVENT that is gone takes none.
pub(super) fn record_replay_cancel_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    member: EntityId,
    source_record_id: &str,
    sequence: u32,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    if vault.get_entity_type_in_txn(txn, &member)? != Some(ENTITY_TYPE_EVENT)
        || replay_cancel_evidence_in_txn(vault, txn, &member)?.is_some()
    {
        return Ok(());
    }
    let value = CalendarReplayCancelEvidenceValue {
        sequence,
        proved_at: now,
    };
    admit_screened_in_txn(
        vault,
        txn,
        member,
        &CalendarInboundBody::default(),
        source_record_id,
        PREDICATE_CALENDAR_REPLAY_CANCEL_EVIDENCE,
        encode_replay_cancel_evidence_value(&value),
        now,
    )?;
    Ok(())
}

/// The first replay proof recorded on the EVENT `event_ref`
/// ([`record_replay_cancel_evidence_in_txn`]), read in `txn`: of the live
/// claims a seat's own write recorded, the earliest proved (claim id breaks
/// a tie); `None` while none was. A claim of the predicate that no seat's
/// write recorded, or whose value does not decode, proves nothing and is
/// skipped.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn replay_cancel_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> crate::Result<Option<CalendarReplayCancelEvidenceValue>> {
    let mut first: Option<(u64, EntityId, CalendarReplayCancelEvidenceValue)> = None;
    for claim_id in vault.claims_for_subject_in_txn(txn, event_ref)? {
        let Some(body) = vault.get_claim_in_txn(txn, &claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_REPLAY_CANCEL_EVIDENCE
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !recorded_by_seat_write(&body)
        {
            continue;
        }
        let Ok(value) = decode_replay_cancel_evidence_value(&body.value) else {
            continue;
        };
        let earlier = first.as_ref().is_none_or(|(proved_at, kept_id, _)| {
            (value.proved_at, claim_id.as_bytes()) < (*proved_at, kept_id.as_bytes())
        });
        if earlier {
            first = Some((value.proved_at, claim_id, value));
        }
    }
    Ok(first.map(|(_, _, value)| value))
}

/// Whether `body` came through the calendar import door under a seat's own
/// write ref, as [`record_replay_cancel_evidence_in_txn`] admits it.
fn recorded_by_seat_write(body: &ClaimBody) -> bool {
    body.source == Some(ClaimSource::Imported)
        && body
            .evidence
            .as_ref()
            .and_then(|evidence| {
                evidence_field(
                    evidence,
                    crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
                )
            })
            .is_some_and(|candidate| {
                evidence_field(candidate, "kind").and_then(Value::as_str)
                    == Some("imported_evidence")
                    && evidence_field(candidate, "source_id").and_then(Value::as_str)
                        == Some(crate::ingest::ICS_FEED_SOURCE_ID)
                    && evidence_field(candidate, "source_record_id")
                        .and_then(Value::as_str)
                        .is_some_and(|source| source.starts_with(WRITE_SOURCE_RECORD_PREFIX))
            })
}

fn evidence_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}
