//! A schedule's request checks: context, counterparty spelling, APNs level, and its trigger.

use super::*;

/// Refuses a schedule whose context, counterparty or APNs level cannot ride
/// its channel and verb.
pub(super) fn admit_outbound_schedule(
    draft: &OutboundDraftInput,
    schedule_context: &OutboundScheduleContext,
    counterparty_ref: Option<&str>,
) -> MemoryResult<()> {
    schedule_context.validate()?;
    if let Some(party) = counterparty_ref {
        crate::comm::validate_comm_party_key(party).map_err(|_| {
            MemoryError::bad_request("counterparty_ref is not a valid comm party key")
        })?;
        // A capability lookup accepts aliases such as " email ", but a
        // counterparty-bound receipt is a projector source. Refuse those
        // aliases before any gate, TASK, or provider delivery can persist
        // a channel/verb the comm projector cannot decode.
        if outbound_verb_contract(&draft.channel, &draft.verb).is_ok()
            && !crate::outbound::is_canonical_outbound_verb(&draft.channel, &draft.verb)
        {
            return Err(MemoryError::bad_request(
                "counterparty-bound channel and verb must use manifest spellings",
            ));
        }
    }
    if schedule_context.apns_interruption_level.is_some()
        && !(draft.channel == "apns" && draft.verb == "push")
    {
        return Err(MemoryError::bad_request_with(
            "APNs interruption level requires an APNs push",
            &["Do not attach APNs levels to chat, email, voice, or ring sends."],
        ));
    }
    Ok(())
}

/// The intent trigger the draft names, carrying its job.
pub(super) fn outbound_trigger(draft: &OutboundDraftInput) -> MemoryResult<OutboundIntentTrigger> {
    let trigger = match draft.trigger.as_str() {
        "commitment" | "commitment_timer_wake" => {
            OutboundIntentTrigger::commitment_timer_wake(draft.trigger_ref.clone())
        }
        "gap_queue" => OutboundIntentTrigger::gap_queue(draft.trigger_ref.clone()),
        "agent_immediate" => OutboundIntentTrigger::agent_immediate(draft.trigger_ref.clone()),
        other => {
            return Err(MemoryError::bad_request_with(
                format!("unknown outbound trigger {other:?}"),
                &["Use one of: commitment_timer_wake, gap_queue, agent_immediate."],
            ));
        }
    };
    let trigger = match &draft.job_ref {
        Some(job_ref) => trigger.job_ref(job_ref.clone()),
        None => trigger,
    };
    Ok(trigger)
}
