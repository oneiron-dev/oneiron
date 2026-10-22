//! Conditional calendar event outcome writes.
//! Entry: `record_event_outcome_in_txn`.
//! Defines its own items.

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
    )?;
    body.source = Some(source);
    body.valid_from = Some(value.recorded_at);

    record_with(vault, wtxn, event_ref, value, None, |txn, id, occurred| {
        vault.put_claim_in_txn(txn, id, &body, occurred, value.recorded_at)
    })
}

/// Caller-bound writes use the same head and supersession law as the projector.
pub(crate) fn record_event_outcome_as_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    event: EntityId,
    value: &EventOutcomeClaimValue,
    envelope: &crate::WriteEnvelope,
    evidence: Option<EntityId>,
) -> Result<EntityId> {
    if value.basis == EventOutcomeBasis::OwnerAttested
        && live_outcome_heads_in(vault, txn, &event)?
            .iter()
            .any(|head| head.value.basis == EventOutcomeBasis::Machine)
    {
        return Err(crate::Error::InvalidClaimBody(
            "owner check-in cannot replace machine evidence",
        ));
    }
    let mut candidate = crate::ClaimCandidate::new(
        PREDICATE_CALENDAR_EVENT_OUTCOME,
        ClaimSubject::Entity(event),
        encode_event_outcome_value(value),
        1.0,
    )
    .with_validity(Some(value.recorded_at), None);
    if let Some(evidence) = evidence {
        candidate = candidate.with_evidence(rmpv::Value::Map(vec![(
            rmpv::Value::from("evidence_ref"),
            rmpv::Value::from(evidence.to_hex()),
        )]));
    }
    record_with(
        vault,
        txn,
        event,
        value,
        Some(envelope.actor()),
        |txn, id, occurred| {
            vault
                .batch_in()
                .claim_candidate(id, candidate, envelope, occurred, value.recorded_at)
                .apply(txn)?;
            let stored = vault
                .get_claim_in_txn(txn, id)?
                .ok_or(crate::Error::EntityNotFound)?;
            if !claim_surfaceable(&stored) {
                return Err(crate::Error::InvalidClaimBody(
                    "calendar outcome requires live gate admission",
                ));
            }
            Ok(())
        },
    )
}

fn record_with(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: EntityId,
    value: &EventOutcomeClaimValue,
    actor: Option<crate::WriteActor>,
    write: impl FnOnce(&mut heed::RwTxn<'_>, &EntityId, TimeRange) -> Result<()>,
) -> Result<EntityId> {
    if vault.get_entity_type_in_txn(wtxn, &event_ref)? != Some(crate::registry::ENTITY_TYPE_EVENT)
        || crate::ports::TombstoneStore::port_tombstone_is_deleted(vault, wtxn, &event_ref)?
    {
        return Err(crate::Error::EntityNotFound);
    }
    let new_id = vault.store.clock.entity_id()?;
    let occurred = TimeRange {
        start: value.recorded_at,
        end: value.recorded_at,
    };
    let prior = live_outcome_heads_in(vault, wtxn, &event_ref)?;
    write(wtxn, &new_id, occurred)?;
    for head in prior {
        // Evidence can arrive out of order — CAL-08 will supersede an owner
        // answer with a transcript observed during the meeting. The head it
        // replaces still stops being current no earlier than it started, so
        // the closure never writes an inverted validity window.
        let closed_at = value.recorded_at.max(head.value.recorded_at);
        vault.supersede_claim_in_txn_as(wtxn, &new_id, &head.claim_id, closed_at, actor)?;
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
