use super::*;

/// Commits locally on the home node, then consumes the real CAL outcome and
/// outbound doors. A failed effect leaves an immutable, resumable item.
pub fn execute_emergency_plan(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    plan: &EmergencyPlan,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    input: &crate::booking::BookingLifecycleConsumerInput,
    sink: &mut impl crate::outbound::OutboundExecutionSink,
) -> Result<EmergencyItem, BookingError> {
    verify_logged_owner_instruction(vault, request)?;
    if plan.request != *request {
        return Err(refused("plan belongs to another owner instruction"));
    }
    let mut item = crate::booking::lifecycle::commit_emergency_item(vault, plan, calendars, input)?;
    if item.picked.is_some() {
        return Err(refused(
            "a picked emergency item cannot send its old revision",
        ));
    }
    record_cancel_outcome(vault, &item)?;
    if !item.calendar_delivered {
        // CAL hydrates current hygiene again. Replay is lawful here: the
        // passport and checkpoint deliberately precede the frozen intent.
        verify_plan_blob(vault, plan)?;
        crate::calendar::admit_calendar_invite(
            vault,
            request.owner_ref,
            &plan.payload,
            input.now_utc,
        )
        .map_err(storage_failure)?;
        dispatch_item_effect(vault, &item, EmergencyEffect::Calendar, sink, input.now_utc)?;
        mark_delivered(vault, &mut item, true)?;
    }
    if !item.apology_delivered {
        let bytes = serde_json::to_vec(&serde_json::json!({ "reason": request.reason,
            "actions": item.actions.iter().zip(&plan.proposals).map(|(token, slot)| serde_json::json!({
                "action": format!("booking:emergency-pick:{}", token.0), "proposal": slot
            })).collect::<Vec<_>>() })).map_err(storage_failure)?;
        let artifact = blob_id(&bytes)?;
        if vault
            .get_blob_artifact(&artifact)
            .map_err(storage_failure)?
            .is_none()
        {
            vault
                .put_blob_artifact(
                    &artifact,
                    &crate::blob_artifact::BlobArtifactBody::new(
                        &plan.booking.event_type.0,
                        "application/json",
                    ),
                    TimeRange {
                        start: item.committed_at,
                        end: item.committed_at,
                    },
                    item.committed_at,
                )
                .map_err(storage_failure)?;
        }
        vault
            .append_blob_artifact_version(
                &artifact,
                &bytes,
                &crate::blob_artifact::BlobVersionProvenance::UserUpload,
                crate::write_envelope::WriteActor::new(
                    request.owner_ref,
                    crate::edge::EdgeActorClass::Human,
                ),
                TimeRange {
                    start: item.committed_at,
                    end: item.committed_at,
                },
                item.committed_at,
            )
            .map_err(storage_failure)?;
        dispatch_item_effect(
            vault,
            &item,
            EmergencyEffect::Apology(format!("blob:{}", artifact.to_hex())),
            sink,
            input.now_utc,
        )?;
        mark_delivered(vault, &mut item, false)?;
    }
    Ok(item)
}

fn record_cancel_outcome(vault: &Vault, item: &EmergencyItem) -> Result<(), BookingError> {
    use crate::calendar::outcome::{
        EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, read_event_outcome,
        record_event_outcome,
    };
    if item.basis != EmergencyLocalBasis::PreStartCancellation {
        return Ok(());
    }
    let value = EventOutcomeClaimValue {
        outcome: EventOutcome::CancelledPreStart,
        basis: EventOutcomeBasis::OwnerAttested,
        recorded_at: item.committed_at,
    };
    let prior = read_event_outcome(vault, item.calendar.event_ref).map_err(storage_failure)?;
    if prior == Some(value) {
        return Ok(());
    }
    if prior.is_some_and(|prior| prior.recorded_at > value.recorded_at) {
        return Err(refused(
            "newer outcome evidence supersedes this emergency cancellation",
        ));
    }
    record_event_outcome(
        vault,
        item.calendar.event_ref,
        &value,
        crate::claim::ClaimSource::UserStated,
    )
    .map_err(storage_failure)?;
    Ok(())
}

pub(super) enum EmergencyEffect {
    Calendar,
    Apology(String),
    Pick,
}

pub(super) fn dispatch_item_effect(
    vault: &Vault,
    item: &EmergencyItem,
    effect: EmergencyEffect,
    sink: &mut impl crate::outbound::OutboundExecutionSink,
    now_utc: u64,
) -> Result<(), BookingError> {
    use crate::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
        OutboundIntentTrigger,
    };
    verify_logged_owner_instruction(vault, &item.plan.request)?;
    let (lane, payload, content_ref, hash) = match effect {
        EmergencyEffect::Calendar => (
            "calendar",
            Some(&item.plan.payload),
            None,
            item.plan.content_hash,
        ),
        EmergencyEffect::Apology(content) => {
            ("apology", None, Some(content), item.plan.content_hash)
        }
        EmergencyEffect::Pick => {
            let picked = item
                .picked
                .as_ref()
                .ok_or_else(|| refused("missing pick checkpoint"))?;
            ("pick", Some(&picked.payload), None, picked.content_hash)
        }
    };
    let intent_ref = format!(
        "intent:booking_emergency:{}:{lane}",
        hex_lower(&content_hash(&(
            item_key(&item.plan.request, item.calendar.event_ref)?,
            hash
        ))?)
    );
    let (verb, channel) = if payload.is_some() {
        (crate::calendar::CALENDAR_INVITE_VERB, "calendar")
    } else {
        ("send", "email")
    };
    let owner = item.plan.request.owner_ref;
    let mut draft = OutboundIntentDraft::new(
        owner.to_hex(),
        verb,
        channel,
        item.plan.payload.recipient.clone(),
    )
    .idempotency_key(intent_ref.clone());
    draft.content_ref = content_ref;
    let intent = OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(hex_lower(
            &item.plan.request.authority.request_hash,
        )),
    );
    let mut dispatch = OutboundDispatchRequest::new(
        format!("outbound:{intent_ref}"),
        intent_ref,
        intent,
        OutboundDispatchActor::agent(owner),
        OutboundDispatchGate::allow_when_policy_grants(),
        now_utc,
        OutboundDeliveryWindowDecision::DeliverNow,
    )
    .counterparty_ref(item.plan.payload.recipient.clone());
    if let Some(payload) = payload {
        dispatch = dispatch.calendar_invite(payload.clone());
    }
    let result = vault
        .dispatch_outbound_intent(dispatch, sink)
        .map_err(storage_failure)?;
    if result.outcome != OutboundDispatchOutcome::DeliveredToChannel {
        return Err(refused(
            "emergency effect is not delivered; resume its existing intent",
        ));
    }
    Ok(())
}

fn mark_delivered(
    vault: &Vault,
    item: &mut EmergencyItem,
    calendar: bool,
) -> Result<(), BookingError> {
    *item = booking_writer(vault, |txn| {
        let mut current = read_item_in(
            vault,
            &*txn,
            &item_key(&item.plan.request, item.calendar.event_ref)?,
        )?
        .ok_or_else(|| refused("emergency checkpoint disappeared"))?;
        if current.plan != item.plan {
            return Err(refused("emergency checkpoint content conflict"));
        }
        if calendar {
            current.calendar_delivered = true;
        } else {
            current.apology_delivered = true;
        }
        write_item_in(vault, txn, &current)?;
        Ok(current)
    })?;
    Ok(())
}
