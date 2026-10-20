use super::*;

/// A read-only snapshot, never an executable action. The original constraint,
/// visitor zone, and revision authority must come from the lifecycle owner;
/// they must not be reconstructed as `None`, UTC, or a new token here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AffectedBooking {
    pub calendar: CalendarRevision,
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    pub occurrence: TimeRange,
    pub context: crate::booking::lifecycle::BookingConfirmationContext,
}

/// Enumerates confirmed future overlapping bookings of this owner, sorted by
/// `(start_utc, event_ref)`. `now_utc` is supplied by the host, never sampled.
///
/// Owner isolation comes from the exact confirmation-time host binding in
/// the EVENT, never from current routing membership. A missing context is an
/// individual batch refusal. Snapshots are rechecked in the lifecycle writer.
///
/// # Errors
/// Unlogged/mismatched instruction, ambiguous host/fact/passport binding, or
/// storage errors. Missing original-context APIs do not permit guessing.
pub fn enumerate_affected_bookings(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    now_utc: u64,
) -> Result<Vec<AffectedBooking>, BookingError> {
    enumerate_with_refusals(vault, request, now_utc, &mut Vec::new())
}

pub(super) fn enumerate_with_refusals(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    now_utc: u64,
    refusals: &mut Vec<(EntityId, String)>,
) -> Result<Vec<AffectedBooking>, BookingError> {
    verify_logged_owner_instruction(vault, request)?;
    let mut events = Vec::new();
    visit_calendar_events_for_effect(&CalendarRead::Vault(vault), |row| {
        if let Some(occurred) = row.occurred
            && occurred.start > now_utc
            && occurred.start <= request.affected_window.end
            && occurred.end >= request.affected_window.start
        {
            events.push((row.id, occurred));
        }
        Ok(())
    })
    .map_err(storage_failure)?;
    let mut affected = Vec::new();
    for (event_ref, occurred) in events {
        let candidate = (|| {
            let context =
                crate::booking::lifecycle::booking_confirmation_context(vault, &event_ref)?
                    .ok_or_else(|| {
                        refused("missing original booking context; no owner inferred")
                    })?;
            if context.owner_refs.is_empty() {
                return Err(refused(
                    "missing exact selected-host binding; no owner inferred",
                ));
            }
            if !context.owner_refs.contains(&request.owner_ref.to_hex()) {
                return Ok(None);
            }
            if target_fact::<BookingStatusValue>(
                vault,
                request,
                event_ref,
                BOOKING_STATUS_PREDICATE,
            )?
            .is_none_or(|value| value.status != BookingStatus::Confirmed)
            {
                return Ok(None);
            }
            let page = target_fact::<BookingSourcePageValue>(
                vault,
                request,
                event_ref,
                BOOKING_SOURCE_PAGE_PREDICATE,
            )?
            .ok_or_else(|| refused("confirmed booking has no source page"))?
            .page_ref;
            let event_type = target_fact::<BookingEventTypeRefValue>(
                vault,
                request,
                event_ref,
                BOOKING_EVENT_TYPE_REF_PREDICATE,
            )?
            .ok_or_else(|| refused("confirmed booking has no event type"))?
            .event_type;
            let txn = vault.store.env.read_txn().map_err(storage_failure)?;
            let calendar =
                crate::booking::lifecycle::emergency_current_revision_in(vault, &txn, event_ref)?;
            Ok(Some(AffectedBooking {
                calendar,
                page_ref: page,
                event_type,
                context,
                occurrence: TimeRange {
                    start: occurred.start,
                    end: occurred.end.checked_add(1).ok_or_else(|| {
                        refused("booking occurrence cannot be represented half-open")
                    })?,
                },
            }))
        })();
        match candidate {
            Ok(Some(booking)) => affected.push(booking),
            Ok(None) => {}
            Err(error @ (BookingError::SlotOracle(_) | BookingError::Boundary(_))) => {
                return Err(error);
            }
            Err(error) => refusals.push((event_ref, error.to_string())),
        }
    }
    affected.sort_by_key(|item| (item.occurrence.start, item.calendar.event_ref));
    Ok(affected)
}

/// The fact an emergency acts on. A Cancel only restricts, so it takes a held
/// fact as it stands; any other action never acts on a held fact.
fn target_fact<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    subject: EntityId,
    predicate: &str,
) -> Result<Option<T>, BookingError> {
    let cancel = request.action_policy == EmergencyActionPolicy::Cancel;
    Ok(live_fact(vault, subject, predicate)?
        .and_then(|(value, settled)| (settled || cancel).then_some(value)))
}

/// The one live `predicate` fact on `subject`, and whether its confirm is
/// settled. A held fact still competes.
pub(super) fn live_fact<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    subject: EntityId,
    predicate: &str,
) -> Result<Option<(T, bool)>, BookingError> {
    let mut found = None;
    let mut settled = false;
    for id in vault
        .claims_for_subject(&subject)
        .map_err(storage_failure)?
    {
        let Some(body) = vault.get_claim(&id).map_err(storage_failure)? else {
            continue;
        };
        if body.subject != ClaimSubject::Entity(subject)
            || body.predicate != predicate
            || !claim_surfaceable(&body)
        {
            continue;
        }
        // FIX 5994: a head no booking process issued is no competing fact.
        let txn = vault.store.env.read_txn().map_err(storage_failure)?;
        if !crate::booking::lifecycle::booking_head_counts_in_txn(vault, &txn, &id, &body)
            .map_err(storage_failure)?
        {
            continue;
        }
        if found.is_some() {
            return Err(refused("booking has competing live facts"));
        }
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &body.value).map_err(storage_failure)?;
        found =
            Some(rmp_serde::from_slice(&bytes).map_err(|_| refused("booking fact is malformed"))?);
        settled = vault
            .claim_settled_and_active(&id)
            .map_err(storage_failure)?;
    }
    Ok(found.map(|value| (value, settled)))
}
