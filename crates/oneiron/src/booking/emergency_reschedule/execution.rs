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
    if !item.calendar_delivered {
        // CAL hydrates current hygiene again. Replay is lawful here: the
        // passport and checkpoint deliberately precede the frozen intent.
        verify_plan_blob(vault, plan)?;
        crate::calendar::admit_calendar_invite(
            vault,
            request.owner_ref,
            plan.payload
                .as_ref()
                .ok_or_else(|| refused("missing pending calendar payload"))?,
            input.now_utc,
        )
        .map_err(calendar_failure)?;
        dispatch_item_effect(vault, &item, EmergencyEffect::Calendar, sink, input.now_utc)?;
        mark_delivered(vault, &mut item, true)?;
    }
    if !item.apology_delivered {
        let bytes = state::apology_bytes(&item)?;
        let content = booking_writer(vault, |txn| {
            verify_plan_in(vault, txn, plan)?;
            persist_content_in(
                vault,
                txn,
                request,
                &plan.booking.event_type.0,
                "application/json",
                &bytes,
                item.committed_at,
            )
        })?;
        dispatch_item_effect(
            vault,
            &item,
            EmergencyEffect::Apology(content),
            sink,
            input.now_utc,
        )?;
        mark_delivered(vault, &mut item, false)?;
    }
    Ok(item)
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
            item.plan.payload.as_ref(),
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
    let intent_ref = state::effect_ref(item, lane, hash)?;
    let (verb, channel) = if payload.is_some() {
        (crate::calendar::CALENDAR_INVITE_VERB, "calendar")
    } else {
        ("send", "email")
    };
    let owner = item.plan.request.owner_ref;
    let mut draft =
        OutboundIntentDraft::new(owner.to_hex(), verb, channel, item.plan.recipient.clone())
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
    .counterparty_ref(item.plan.recipient.clone());
    if let Some(payload) = payload {
        dispatch = dispatch.calendar_invite(payload.clone());
    }
    let result = vault
        .dispatch_outbound_intent_with_verified_actor(
            dispatch,
            sink,
            owner,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|error| {
            BookingError::Boundary(Box::new(
                crate::memory::facade_error_from_outbound_dispatch(error),
            ))
        })?;
    if result.outcome != OutboundDispatchOutcome::DeliveredToChannel {
        let gate_outcome = result.receipt.fields.get("gate_outcome");
        let denied = gate_outcome.is_some_and(|outcome| outcome == "deny" || outcome == "pending");
        return Err(BookingError::Boundary(Box::new(
            crate::memory::MemoryError {
                code: if denied {
                    crate::memory::MEMORY_CODE_FORBIDDEN
                } else {
                    crate::memory::MEMORY_CODE_INVALID_STATE
                }
                .to_owned(),
                message: "emergency effect is not delivered; resume its existing intent".to_owned(),
                suggestions: vec!["Inspect the outbound receipt before retrying.".to_owned()],
                successor_short_id: None,
                gate_denial: if denied {
                    Some(Box::new(crate::memory::MemoryGateDenial {
                        outcome: gate_outcome.cloned().unwrap_or_default(),
                        reason_codes: result
                            .receipt
                            .fields
                            .get("gate_reason_codes")
                            .map(|codes| {
                                codes
                                    .split(',')
                                    .filter(|code| !code.is_empty())
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }))
                } else {
                    None
                },
            },
        )));
    }
    Ok(())
}

fn mark_delivered(
    vault: &Vault,
    item: &mut EmergencyItem,
    calendar: bool,
) -> Result<(), BookingError> {
    *item = booking_writer(vault, |txn| {
        verify_plan_in(vault, txn, &item.plan)?;
        if crate::booking::lifecycle::emergency_current_revision_in(
            vault,
            txn,
            item.calendar.event_ref,
        )? != item.calendar
        {
            return Err(refused("delivery checkpoint is superseded"));
        }
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
