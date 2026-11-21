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
    /// Each delivered effect that may reach the booker twice, answered by every run over the
    /// checkpoint (`super::uncertain_send`).
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
    let repeat_notices = super::uncertain_send::repeat_notices(vault, &item)?;
    // A picked checkpoint sends nothing of its old revision. Its run still answers each repeat a
    // run delivered, since once the booker picked no other run would (review round 1 of
    // #10166), and again on each later run (round 2); with none it refuses, as before.
    if item.picked.is_some() && repeat_notices.is_empty() {
        return Err(refused(
            "a picked emergency item cannot send its old revision",
        ));
    }
    Ok(EmergencyExecution {
        item,
        repeat_notices,
    })
}

/// The owner's run up to its answer ([`execute_emergency_plan`]): commits the checkpoint and
/// delivers each effect it still owes, each delivery committed on the checkpoint before the
/// next. The checkpoint as it then stands. A picked checkpoint owes neither: the booker's
/// actions are released only once both deliveries complete.
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
        return Ok(item);
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
    let send = EffectSend {
        lane,
        payload,
        content_ref,
        hash,
    };
    // A send an earlier ledger generation delivered since this home took a fresh attempt is
    // delivered: the fresh attempt never goes (review round 1 of #10220).
    if state::earlier_generation_delivered(vault, item, lane, hash)? {
        return Ok(());
    }
    // The attempt this send is admitted by: a later ledger generation than the one its
    // idempotency key names only once this home adopted the checkpoint back over its own
    // earlier send, and that send's row never goes again (FIX
    // [BK-EMERGENCY-DEFERRED-SEND-STRANDED-ON-FORMER-HOME]; review round 2 of #10220).
    let (raised, read_again) = readopted_attempt(vault, item, lane, hash)?;
    let item = raised.as_ref().unwrap_or(item);
    let Err(error) = send_effect(vault, item, &send, sink, now_utc) else {
        return Ok(());
    };
    // An earlier generation's send delivered it while this one was admitted (review round 2 of
    // #10220): every outbound check of this attempt refused it (`state::verify_frozen_effect_in`).
    if state::earlier_generation_delivered(vault, item, lane, hash)? {
        return Ok(());
    }
    // The replay of a readopted send with no provider key and no outcome read it back first and
    // found no answer: it stopped it unasked and sent nothing (FIX 9379), so the fresh attempt
    // goes now, as any other new home's would.
    if read_again && let Some(raised) = readopted_attempt_after_replay(vault, item, lane, hash)? {
        return send_effect(vault, &raised, &send, sink, now_utc);
    }
    Err(error)
}

/// One emergency effect's send: its lane, the calendar payload or apology content it carries,
/// and the content hash its idempotency key names.
struct EffectSend<'a> {
    lane: &'static str,
    payload: Option<&'a crate::calendar::CalendarInvitePayload>,
    content_ref: Option<String>,
    hash: [u8; 32],
}

/// The checkpoint `item` the owner's resume sends its effect on `lane` from, over this home's
/// own row of a send it held when it adopted the checkpoint back
/// (`EmergencyItem::readopted_sends`): `Some` at the effect's next ledger generation once that
/// row reads as one that never goes again (`state::readopted_send_takes_fresh_attempt`). A row
/// with no provider-native key that its replay may send again is marked replayed first, so a
/// later stop of this home's own send never reads as one the move marked uncertain; `true` when
/// that row has no outcome yet, whose replay reads its delivery back before anything goes (FIX
/// 9379), so its stop is read again once the replay ends undelivered.
fn readopted_attempt(
    vault: &Vault,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<(Option<EmergencyItem>, bool), BookingError> {
    use crate::outbound_intent_ledger::{IntentResolution, RetryDisposition};
    let Some(readopted) = current_readopted_send(item, lane) else {
        return Ok((None, false));
    };
    let record = {
        let txn = vault.store.custody_snapshot().map_err(storage_failure)?;
        state::ledger_record_in(vault, &txn, item, lane, hash, readopted.generation)?
    };
    let Some(record) = record else {
        return Ok((None, false));
    };
    if state::readopted_send_takes_fresh_attempt(&record, readopted) {
        return Ok((
            Some(update_readopted_send(vault, item, lane, readopted, true)?),
            false,
        ));
    }
    match IntentResolution::from_record(&record) {
        Ok(IntentResolution::Pending { retry, .. }) if !record.idempotency_supported => {
            let marked = (!readopted.replayed)
                .then(|| update_readopted_send(vault, item, lane, readopted, false))
                .transpose()?;
            Ok((marked, retry == RetryDisposition::NoAutomaticRetry))
        }
        _ => Ok((None, false)),
    }
}

/// After the replay of this home's readopted send with no provider key and no outcome ended
/// undelivered ([`readopted_attempt`]): `item` at the effect's next ledger generation when that
/// replay stopped the row unasked (`NonIdempotentPending`), the one stop it reaches without a
/// send, so the row's only possible delivery is the one the move marked uncertain.
fn readopted_attempt_after_replay(
    vault: &Vault,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<Option<EmergencyItem>, BookingError> {
    use crate::outbound_intent_ledger::{IntentEscalationReason, IntentResolution};
    let Some(readopted) = current_readopted_send(item, lane) else {
        return Ok(None);
    };
    let record = {
        let txn = vault.store.custody_snapshot().map_err(storage_failure)?;
        state::ledger_record_in(vault, &txn, item, lane, hash, readopted.generation)?
    };
    if !record.is_some_and(|record| {
        matches!(
            IntentResolution::from_record(&record),
            Ok(IntentResolution::Stopped {
                reason: IntentEscalationReason::NonIdempotentPending,
                ..
            })
        )
    }) {
        return Ok(None);
    }
    update_readopted_send(vault, item, lane, readopted, true).map(Some)
}

/// `item`'s readopted send on `lane` while its generation is still the effect's current one.
fn current_readopted_send(item: &EmergencyItem, lane: &str) -> Option<planning::ReadoptedSend> {
    item.readopted_sends
        .get(lane)
        .copied()
        .filter(|readopted| readopted.generation == state::ledger_generation(item, lane))
}

/// Commits `item`'s readopted send on `lane`, still `readopted` as stored: with `raise`, the
/// effect's next ledger generation, which ends the readopted send (its row never goes again);
/// else the mark that a replay here may send its row again. The EFFECT lookup follows the
/// current generation (`write_item_in`). The checkpoint as it now stands.
fn update_readopted_send(
    vault: &Vault,
    item: &EmergencyItem,
    lane: &str,
    readopted: planning::ReadoptedSend,
    raise: bool,
) -> Result<EmergencyItem, BookingError> {
    // The revision the effect's send is admitted at: the pick's once the booker picked.
    let expected = if lane == "pick" {
        &item
            .picked
            .as_ref()
            .ok_or_else(|| refused("pick checkpoint disappeared"))?
            .calendar
    } else {
        &item.calendar
    };
    booking_writer(vault, |txn| {
        verify_plan_in(vault, txn, &item.plan)?;
        if crate::booking::lifecycle::emergency_current_revision_in(
            vault,
            txn,
            item.calendar.event_ref,
        )? != *expected
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
        if current_readopted_send(&current, lane) != Some(readopted) {
            // Another resume moved it on first: send from the checkpoint as it stands.
            return Ok(current);
        }
        if raise {
            let next = readopted
                .generation
                .checked_add(1)
                .ok_or_else(|| refused("an emergency effect has no next ledger generation"))?;
            current.ledger_generations.insert(lane.to_owned(), next);
            current.readopted_sends.remove(lane);
        } else if let Some(stored) = current.readopted_sends.get_mut(lane) {
            stored.replayed = true;
        }
        write_item_in(vault, txn, &current)?;
        Ok(current)
    })
}

/// Sends `send` under `item`'s current ledger identity of its effect
/// (`state::effect_ledger_ref`), under the provider key the effect's first ledger row carries.
fn send_effect(
    vault: &Vault,
    item: &EmergencyItem,
    send: &EffectSend<'_>,
    sink: &mut impl crate::outbound::OutboundExecutionSink,
    now_utc: u64,
) -> Result<(), BookingError> {
    use crate::outbound::{
        OutboundDeliveryWindowDecision, OutboundDispatchActor, OutboundDispatchGate,
        OutboundDispatchOutcome, OutboundDispatchRequest, OutboundIntent, OutboundIntentDraft,
        OutboundIntentTrigger,
    };
    let EffectSend {
        lane,
        payload,
        ref content_ref,
        hash,
    } = *send;
    let intent_ref = state::effect_ref(item, lane, hash)?;
    let ledger_ref = state::effect_ledger_ref(item, lane, hash)?;
    let (verb, channel) = if payload.is_some() {
        (crate::calendar::CALENDAR_INVITE_VERB, "calendar")
    } else {
        ("send", "email")
    };
    let owner = item.plan.request.owner_ref;
    let mut draft =
        OutboundIntentDraft::new(owner.to_hex(), verb, channel, item.plan.recipient.clone())
            .idempotency_key(intent_ref.clone());
    draft.content_ref = content_ref.clone();
    let intent = OutboundIntent::from_trigger(
        draft,
        OutboundIntentTrigger::agent_immediate(hex_lower(
            &item.plan.request.authority.request_hash,
        )),
    );
    let mut dispatch = OutboundDispatchRequest::new(
        format!("outbound:{ledger_ref}"),
        intent_ref.clone(),
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
    if ledger_ref != intent_ref {
        dispatch.ledger_identity_ref = Some(ledger_ref);
        dispatch.idempotency_identity_ref = Some(intent_ref.clone());
    }
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
                task_assignment_conflict: None,
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
