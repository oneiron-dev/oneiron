use super::OutboundDeliveryWindowDecision;
use super::capability::{OutboundVerbContract, normalize_key};
use super::dispatch_types::OutboundDispatchRequest;
use super::intent::OutboundIntent;
use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::delivery_window::{
    DeliveryWindowEvaluationContext, DeliveryWindowEvaluator, DeliveryWindowMatch,
    DeliveryWindowPolicyClaim, DeliveryWindowResolution, DeliveryWindowResolvedLevel,
    DeliveryWindowVerbClass, is_delivery_window_claim_predicate,
};
use crate::entity_id::EntityId;

/// Reads the LIVE `delivery_window.*` claims at the execute door and runs the
/// frozen ladder over them exactly once. The resolution carries both the
/// policy observation and the effective action, so the decision the door
/// enforces and the evidence the receipt records can never disagree.
pub(super) fn outbound_delivery_window_resolution_at_door(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
) -> crate::Result<DeliveryWindowResolution> {
    let subjects = outbound_delivery_window_subjects(request);
    let stored_claims = stored_delivery_window_policy_claims(vault, &subjects)?;
    let verb_class = outbound_delivery_window_verb_class(
        &request.intent,
        verb_contract,
        request.delivery_window_resolved_level,
    );
    // A human-explicit send is executable, not policy-invisible: evaluate its
    // observed decision on the interrupt rung before retaining the requested action.
    let evaluation_verb_class = if request.delivery_window_human_explicit_instant {
        DeliveryWindowVerbClass::Interrupt
    } else {
        verb_class
    };
    // Fail closed: an interrupt-class send with live window claims and no
    // local wall-clock minute cannot be evaluated, so it holds rather than
    // sinking. A human-explicit instant is exempt — it already named the time.
    if evaluation_verb_class == DeliveryWindowVerbClass::Interrupt
        && request.delivery_window_local_minute_of_day.is_none()
        && !request.delivery_window_human_explicit_instant
    {
        let unevaluable = stored_claims
            .iter()
            .filter(|claim| claim.window.is_some())
            .map(|claim| DeliveryWindowMatch {
                predicate: claim.predicate.clone(),
                reason: claim.reason.clone(),
                retry_at: None,
            })
            .collect::<Vec<_>>();
        if !unevaluable.is_empty() {
            return Ok(DeliveryWindowResolution::missing_local_minute(unevaluable));
        }
    }

    let context = outbound_delivery_window_context(request, verb_contract, evaluation_verb_class)?;
    Ok(DeliveryWindowEvaluator::resolve(&context, &stored_claims))
}

/// Composes the resolved live-policy action with the caller's own seeded
/// window decision. The caller's seed is a wall of its own — the bridge's
/// schedule-time `bridge_scheduled` hold rides here — so the door takes the
/// more restrictive of the two. The human-explicit lift is already baked into
/// `resolution.effective`, never re-derived from the seed.
pub(super) fn outbound_delivery_window_decision_at_door(
    request: &OutboundDispatchRequest,
    resolution: &DeliveryWindowResolution,
) -> OutboundDeliveryWindowDecision {
    most_restrictive_delivery_window_decision(
        request.window_decision.clone(),
        resolution.effective.clone(),
    )
}

pub(super) fn stored_delivery_window_policy_claims(
    vault: &Vault,
    subjects: &[EntityId],
) -> crate::Result<Vec<DeliveryWindowPolicyClaim>> {
    let mut claims = Vec::new();
    for body in
        vault.claim_bodies_for_subjects_matching(subjects, delivery_window_claim_for_subject)?
    {
        claims.push(DeliveryWindowPolicyClaim::from_claim_body(&body)?);
    }
    Ok(claims)
}

fn delivery_window_claim_for_subject(body: &ClaimBody, subject: &EntityId) -> bool {
    is_delivery_window_claim_predicate(&body.predicate)
        && body.subject == ClaimSubject::Entity(*subject)
}

fn outbound_delivery_window_subjects(request: &OutboundDispatchRequest) -> Vec<EntityId> {
    let mut subjects = Vec::new();
    push_delivery_window_subject(&mut subjects, request.delivery_window_subject_ref);
    push_delivery_window_subject(&mut subjects, request.actor.actor_entity_ref);
    push_delivery_window_subject(&mut subjects, request.channel_identity_ref);
    push_delivery_window_subject(
        &mut subjects,
        EntityId::from_hex(&request.intent.target).ok(),
    );
    subjects
}

fn push_delivery_window_subject(subjects: &mut Vec<EntityId>, subject: Option<EntityId>) {
    if let Some(subject) = subject
        && !subjects.contains(&subject)
    {
        subjects.push(subject);
    }
}

fn outbound_delivery_window_context(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    verb_class: DeliveryWindowVerbClass,
) -> crate::Result<DeliveryWindowEvaluationContext> {
    let local_minute_of_day = request.delivery_window_local_minute_of_day.unwrap_or(0);
    let channel = request
        .delivery_window_channel
        .clone()
        .unwrap_or_else(|| outbound_delivery_window_channel(&request.intent));
    let interrupt_surface = request
        .delivery_window_interrupt_surface
        .clone()
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                normalize_key(&request.intent.channel),
                verb_contract.kind
            )
        });
    let mut context =
        DeliveryWindowEvaluationContext::new(request.occurred_at, local_minute_of_day, verb_class)?
            .channel(channel)
            .interrupt_surface(interrupt_surface);
    if let Some(surface) = request.delivery_window_degrade_to.as_ref() {
        context = context.degrade_to(surface.clone());
    }
    if let Some(level) = request.delivery_window_apns_interruption_level {
        context = context.apns_interruption_level(level);
    }
    if request.delivery_window_human_explicit_instant {
        context = context.human_explicit_instant();
    }
    for condition in &request.active_delivery_contexts {
        context = context.active_context(*condition);
    }
    Ok(context)
}

fn outbound_delivery_window_verb_class(
    intent: &OutboundIntent,
    verb_contract: &OutboundVerbContract,
    resolved_level: Option<DeliveryWindowResolvedLevel>,
) -> DeliveryWindowVerbClass {
    if outbound_delivery_window_is_chat_like_ambient(intent, verb_contract, resolved_level) {
        DeliveryWindowVerbClass::Ambient
    } else {
        DeliveryWindowVerbClass::from(verb_contract.interruption_class.clone())
    }
}

fn outbound_delivery_window_channel(intent: &OutboundIntent) -> String {
    normalize_key(&intent.channel)
}

/// Derive wall-clock minute from the frozen host offset, never a timezone database.
pub(crate) fn local_minute_of_day_at(epoch_secs: u64, utc_offset_minutes: i16) -> u16 {
    (((epoch_secs / 60) as i64 + i64::from(utc_offset_minutes)).rem_euclid(1440)) as u16
}

// "the single local_minute_of_day currently applies to ALL subjects' claims — counterparty windows evaluate against the caller's clock. Real fix = subject tz as a vault fact (locale claim on actor/counterparty); rides the ONE-1751 claims direction, NOT this ticket."
///
/// The frozen ambient token set — the single convergence point for every
/// implementer. Exactly:
///
/// - `slack | discord` × `send | send_media` — thread-landing writes.
/// - `email` × `send` only. `email × send_media` is NOT promoted: media sends
///   are not in the ruled set and must not be over-promoted out of the
///   manifest's interrupt class.
/// - `telegram | line | imessage_mfb | imessage_bridge` × `send` ONLY when the
///   host resolved that compatibility verb to plain chat. `imessage_mfb` and
///   `imessage_bridge` are the real shipping connector keys for the iMessage
///   family. Those manifests declare `send` as
///   Interrupt today, so this helper is the sole ambient promotion for them
///   and it never guesses: without a resolved plain-chat level the manifest's
///   interrupt class stands.
///
/// Dedicated push/call/ring verbs and every other connector remain
/// interrupt-class.
pub(super) fn outbound_delivery_window_is_chat_like_ambient(
    intent: &OutboundIntent,
    verb_contract: &OutboundVerbContract,
    resolved_level: Option<DeliveryWindowResolvedLevel>,
) -> bool {
    let connector = normalize_key(&intent.channel);
    let verb = verb_contract.kind.as_str();
    match connector.as_str() {
        "slack" | "discord" => matches!(verb, "send" | "send_media"),
        "email" => verb == "send",
        // "do not guess ambient from the string alone": the schedule context
        // must carry the resolved level for these compatibility verbs.
        //
        // `imessage_mfb` and `imessage_bridge` are the REAL shipping connector
        // keys — the bare `imessage` in the blueprint prose is not a registered
        // manifest, so no intent can ever reach here with it. It is kept only as
        // a harmless blueprint alias and promotes nothing on its own.
        "telegram" | "line" | "imessage_mfb" | "imessage_bridge" | "imessage" => {
            verb == "send" && resolved_level.is_some_and(DeliveryWindowResolvedLevel::is_plain_chat)
        }
        _ => false,
    }
}

pub(super) fn most_restrictive_delivery_window_decision(
    current: OutboundDeliveryWindowDecision,
    candidate: OutboundDeliveryWindowDecision,
) -> OutboundDeliveryWindowDecision {
    let current_rank = delivery_window_decision_rank(&current);
    let candidate_rank = delivery_window_decision_rank(&candidate);
    if candidate_rank > current_rank
        || (candidate_rank == current_rank
            && same_rank_candidate_is_more_restrictive(&current, &candidate))
    {
        candidate
    } else {
        current
    }
}

fn same_rank_candidate_is_more_restrictive(
    current: &OutboundDeliveryWindowDecision,
    candidate: &OutboundDeliveryWindowDecision,
) -> bool {
    match (current, candidate) {
        (
            OutboundDeliveryWindowDecision::Hold {
                retry_at: current_retry_at,
                ..
            },
            OutboundDeliveryWindowDecision::Hold {
                retry_at: candidate_retry_at,
                ..
            },
        ) => hold_retry_rank(candidate_retry_at) > hold_retry_rank(current_retry_at),
        _ => false,
    }
}

fn hold_retry_rank(retry_at: &Option<u64>) -> (bool, u64) {
    (retry_at.is_none(), retry_at.unwrap_or(0))
}

fn delivery_window_decision_rank(decision: &OutboundDeliveryWindowDecision) -> u8 {
    match decision {
        OutboundDeliveryWindowDecision::DeliverNow => 0,
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => 1,
        OutboundDeliveryWindowDecision::Degrade { .. } => 2,
        OutboundDeliveryWindowDecision::Hold { .. } => 3,
        OutboundDeliveryWindowDecision::LetGo { .. } => 4,
    }
}
