//! Emergency reschedule effect delivery.
//! Entry: `execute_emergency_plan`.
//! Defines its own items.

use super::*;

/// What the owner's emergency run answers (FIX [BK-EMERGENCY-UNCERTAIN-SEND-NOT-SHOWN-TO-OWNER];
/// Engine ANSWER BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A, 21 Nov 09:14): the checkpoint as it
/// now stands, and a notice for each effect this home delivered whose send had ended uncertain
/// on the old home before a home move carried the checkpoint here.
#[derive(Debug, Clone, PartialEq)]
pub struct EmergencyExecution {
    pub item: EmergencyItem,
    /// Each delivered effect that may reach the booker twice, answered once
    /// (`super::uncertain_send`).
    pub repeat_notices: Vec<EmergencyRepeatNotice>,
}

/// One effect this home sent again after its send ended uncertain on the old home: the booker
/// may receive it twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyRepeatNotice {
    /// `"calendar"`, the updated invite, or `"apology"`, the owner's message to the booker.
    pub effect: &'static str,
    /// [`EMERGENCY_REPEAT_NOTICE`].
    pub message: &'static str,
}

/// What a repeat notice tells the owner.
pub const EMERGENCY_REPEAT_NOTICE: &str =
    "this send ended uncertain on the old home and may repeat";

/// Commits locally on the home node, then consumes the real CAL outcome and
/// outbound doors. A failed effect leaves an immutable, resumable item. The
/// answer names each effect that may repeat ([`EmergencyExecution`]).
pub fn execute_emergency_plan(
    vault: &Vault,
    request: &EmergencyRescheduleRequest,
    plan: &EmergencyPlan,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    input: &crate::booking::BookingLifecycleConsumerInput,
    sink: &mut impl crate::outbound::OutboundExecutionSink,
) -> Result<EmergencyExecution, BookingError> {
    let item = deliver_emergency_effects(vault, request, plan, calendars, input, sink)?;
    let repeat_notices = super::uncertain_send::answer_delivered(vault, &item)?;
    Ok(EmergencyExecution {
        item,
        repeat_notices,
    })
}

/// The owner's run up to its answer ([`execute_emergency_plan`]): commits the checkpoint and
/// delivers each effect it still owes, each delivery committed on the checkpoint before the
/// next. The checkpoint as it then stands.
pub(crate) fn deliver_emergency_effects(
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
        // Recheck the pinned bytes. The outbound writer admits and publishes
        // the passport with its frozen intent; this checkpoint does not advance it.
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
        // The gate principal is the verified human owner, not the agent trigger.
        OutboundDispatchActor {
            actor_class: crate::edge::EdgeActorClass::Human
                .gate_actor_class()
                .to_owned(),
            actor_ref: Some(owner.to_hex()),
            actor_entity_ref: Some(owner),
        },
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
                extraction_layout: None,
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
                        ask_ref: None,
                        // FIX 6424: a hold names the digest the owner's press carries.
                        approval_digest: result.approval_digest.clone(),
                    }))
                } else {
                    None
                },
                read_receipt: None,
                policy_denial: None,
                wrong_root: None,
                hook: None,
                retry_after: None,
                resets_at: Vec::new(),
                reason_codes: Vec::new(),
                legal_hold: None,
                room_join_hold: None,
                pending: None,
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
