use super::*;

pub(super) fn record_event_outcome_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
    value: &EventOutcomeClaimValue,
    source: ClaimSource,
) -> Result<EntityId> {
    let mut body = ClaimBody::new(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(event_ref),
        encode_event_outcome_value(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    body.valid_from = Some(value.recorded_at);

    let new_id = EntityId::now();
    let occurred = TimeRange {
        start: value.recorded_at,
        end: value.recorded_at,
    };
    let prior = live_outcome_heads_in(vault, wtxn, &event_ref)?;
    vault.put_claim_in_txn(wtxn, &new_id, &body, occurred, value.recorded_at)?;
    for head in prior {
        // Evidence can arrive out of order — CAL-08 will supersede an owner
        // answer with a transcript observed during the meeting. The head it
        // replaces still stops being current no earlier than it started, so
        // the closure never writes an inverted validity window.
        let closed_at = value.recorded_at.max(head.value.recorded_at);
        vault.supersede_claim_in_txn(wtxn, &new_id, &head.claim_id, closed_at)?;
    }
    Ok(new_id)
}

/// Conditional lifecycle correction, using all live heads (including pending
/// evidence) in the same transaction that writes and supersedes the outcome.
/// None permits only silence/older Unknown; Some requires the exact cancelled
/// head this lifecycle transition previously recorded. Held/NoShow never lose.
pub(crate) fn record_lifecycle_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event: EntityId,
    value: &EventOutcomeClaimValue,
    expected: Option<EventOutcomeClaimValue>,
) -> Result<()> {
    let heads = live_outcome_heads_in(vault, txn, &event)?;
    if heads.iter().all(|head| head.value == *value) && !heads.is_empty() {
        return Ok(());
    }
    if heads.iter().any(|head| {
        matches!(
            head.value.outcome,
            EventOutcome::Held | EventOutcome::NoShow
        ) || head.value.recorded_at > value.recorded_at
            || match expected {
                Some(expected) => head.value != expected,
                None => head.value.outcome != EventOutcome::Unknown,
            }
    }) || (expected.is_some() && heads.is_empty())
    {
        return Ok(()); // Preserve newer or independently established evidence.
    }
    record_event_outcome_in_txn(vault, txn, event, value, ClaimSource::UserStated)?;
    Ok(())
}
