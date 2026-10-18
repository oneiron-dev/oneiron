//! Hydration under the caller's lane, shared by prep, check-in and transcript linking.
use crate::calendar::PrepEvent;
use crate::calendar::claims::{
    CalendarStatus, CalendarTimeKind, PREDICATE_CALENDAR_ATTENDEE, PREDICATE_CALENDAR_STATUS,
    PREDICATE_CALENDAR_TIME_KIND, decode_attendee_value, decode_status_value,
    decode_time_kind_value,
};
use crate::claim::{ScopedRead, claim_surfaceable};
use crate::ports::TombstoneStore;
use crate::{EntityId, Result, Vault};

pub(super) fn readable_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lane: &ScopedRead<'_>,
    event: EntityId,
) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &event)? != Some(crate::registry::ENTITY_TYPE_EVENT)
        || vault.port_tombstone_is_deleted(txn, &event)?
        || !lane.entities_readable_in_txn(txn, &[event])?[0]
        || crate::calendar::origin::invalidated_in_txn(vault, txn, event)?
    {
        return Ok(false);
    }
    // A withheld deciding claim never turns into an absent/default fact.
    let mut claims = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &event)? {
        if vault
            .get_claim_in_txn(txn, &id)?
            .is_some_and(|body| body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
        {
            claims.push(id);
        }
    }
    if !lane
        .entities_readable_in_txn(txn, &claims)?
        .into_iter()
        .all(|readable| readable)
    {
        return Ok(false);
    }
    Ok(crate::calendar::origin::live_origin(&vault.store, txn, event)?.is_some())
}

pub(in crate::calendar) fn meeting_event_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lane: &ScopedRead<'_>,
    event: EntityId,
) -> Result<Option<PrepEvent>> {
    if !readable_event_in_txn(vault, txn, lane, event)? {
        return Ok(None);
    }
    let header = vault
        .entity_header_in_txn(txn, &event)?
        .ok_or(crate::Error::EntityNotFound)?;
    if header.occurred_start == 0 || header.occurred_end < header.occurred_start {
        return Ok(None);
    }
    let mut result = PrepEvent {
        event_ref: event,
        start_utc: header.occurred_start,
        end_utc: header.occurred_end,
        attendee_refs: Vec::new(),
        external_attendee_count: 0,
        has_campaign_linkage: false,
        has_commitment_linkage: false,
        internal_meeting_opt_in: false,
    };
    for id in vault.claims_for_subject_in_txn(txn, &event)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)?.filter(claim_surfaceable) else {
            continue;
        };
        if body.predicate == PREDICATE_CALENDAR_STATUS
            && decode_status_value(&body.value)?.status == CalendarStatus::Cancelled
        {
            return Ok(None);
        }
        if body.predicate == PREDICATE_CALENDAR_TIME_KIND
            && !matches!(
                decode_time_kind_value(&body.value)?.kind,
                CalendarTimeKind::Absolute | CalendarTimeKind::Zoned
            )
        {
            return Ok(None);
        }
        if !crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, txn, &id)? {
            continue;
        }
        if body.predicate == PREDICATE_CALENDAR_ATTENDEE {
            let attendee = decode_attendee_value(&body.value)?;
            result.external_attendee_count = result.external_attendee_count.saturating_add(1);
            if let Ok(person) = EntityId::from_hex(&attendee.who)
                && lane.entities_readable_in_txn(txn, &[person])?[0]
                && !result.attendee_refs.contains(&person)
            {
                result.attendee_refs.push(person);
            }
        }
        result.has_campaign_linkage |= body.predicate.starts_with("campaign.");
        result.has_commitment_linkage |= body.predicate.starts_with("commitment.");
    }
    Ok(Some(result))
}
