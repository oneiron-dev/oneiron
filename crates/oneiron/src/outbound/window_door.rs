//! Delivery-window resolution at the outbound dispatch door.
//! Entry: `outbound_delivery_window_resolution_at_door`.
//! Defines its own items.

use super::OutboundDeliveryWindowDecision;
use super::capability::{OutboundVerbContract, normalize_key};
use super::dispatch_types::OutboundDispatchRequest;
use super::intent::OutboundIntent;
use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::counterparty_contact::normalize_channel_class;
use crate::delivery_window::{
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowEvaluationContext, DeliveryWindowEvaluator,
    DeliveryWindowMatch, DeliveryWindowPolicyClaim, DeliveryWindowResolution,
    DeliveryWindowResolvedLevel, DeliveryWindowVerbClass, is_delivery_window_claim_predicate,
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
    let door_clock = DoorClock::sample(vault, request);
    // Fail closed: an interrupt-class send with live window claims and no
    // local wall-clock minute cannot be evaluated, so it holds rather than
    // sinking. A human-explicit instant is exempt — it already named the time.
    if evaluation_verb_class == DeliveryWindowVerbClass::Interrupt
        && door_clock.local_minute_of_day.is_none()
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

    let context = outbound_delivery_window_context(
        request,
        verb_contract,
        evaluation_verb_class,
        door_clock,
    )?;
    Ok(DeliveryWindowEvaluator::resolve(&context, &stored_claims))
}

/// The instant and local minute the door evaluates one send at (FIX 8817). A
/// drained send reads the vault clock again here, so a slow earlier send in
/// the same drain moves this one's minute on; any other send keeps the
/// instant and minute its caller froze.
#[derive(Clone, Copy)]
struct DoorClock {
    evaluated_at: u64,
    local_minute_of_day: Option<u16>,
}

impl DoorClock {
    fn sample(vault: &Vault, request: &OutboundDispatchRequest) -> Self {
        let Some(clock) = request.delivery_window_clock else {
            return Self {
                evaluated_at: request.occurred_at,
                local_minute_of_day: request.delivery_window_local_minute_of_day,
            };
        };
        let spent = vault
            .now_recorded_at()
            .saturating_sub(clock.anchor_recorded_at);
        let evaluated_at = request.occurred_at.saturating_add(spent);
        Self {
            evaluated_at,
            local_minute_of_day: Some(local_minute_of_day_at(
                evaluated_at,
                clock.utc_offset_minutes,
            )),
        }
    }
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

/// The `delivery_window.*` claims the execute door reads for `subjects`: each
/// claim on one of them that its `claim_of` edge reaches.
pub(crate) fn stored_delivery_window_policy_claims(
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
    door_clock: DoorClock,
) -> crate::Result<DeliveryWindowEvaluationContext> {
    let local_minute_of_day = door_clock.local_minute_of_day.unwrap_or(0);
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
    let mut context = DeliveryWindowEvaluationContext::new(
        door_clock.evaluated_at,
        local_minute_of_day,
        verb_class,
    )?
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
    normalize_channel_class(&intent.channel)
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
/// - Email family (`email`, Resend, SES, Postmark) × `send` only. Media sends
///   are not in the ruled set and must not be over-promoted out of the
///   manifest's interrupt class.
/// - `telegram | imessage_mfb` × `send` ONLY when the host resolved that
///   compatibility verb to plain chat.
/// - `line | imessage_bridge` × `send | send_media` ONLY when the host
///   resolved the verb to plain chat ([`PLAIN_CHAT_MEDIA_CONNECTORS`], FIX
///   7961): their manifests send media the way they send text, as one
///   asynchronous chat message.
///
/// `imessage_mfb` and `imessage_bridge` are the real shipping connector keys
/// for the iMessage family. Those manifests declare `send` (and the bridge's
/// `send_media`) as Interrupt today, so this helper is the sole ambient
/// promotion for them and it never guesses: without a resolved plain-chat
/// level the manifest's interrupt class stands.
///
/// Dedicated push/call/ring verbs and every other connector remain
/// interrupt-class.
pub(super) fn outbound_delivery_window_is_chat_like_ambient(
    intent: &OutboundIntent,
    verb_contract: &OutboundVerbContract,
    resolved_level: Option<DeliveryWindowResolvedLevel>,
) -> bool {
    let connector = normalize_channel_class(&intent.channel);
    let verb = verb_contract.kind.as_str();
    let plain_chat = resolved_level.is_some_and(DeliveryWindowResolvedLevel::is_plain_chat);
    match connector.as_str() {
        "slack" => matches!(verb, "send" | "send_media"),
        "discord" => matches!(verb, "send" | "send_media"),
        "email" => verb == "send",
        // "do not guess ambient from the string alone": the schedule context
        // must carry the resolved level for these compatibility verbs.
        media_chat if PLAIN_CHAT_MEDIA_CONNECTORS.contains(&media_chat) => {
            matches!(verb, "send" | "send_media") && plain_chat
        }
        // The bare `imessage` in the blueprint prose is not a registered
        // manifest, so no intent can ever reach here with it. It is kept only as
        // a harmless blueprint alias and promotes nothing on its own.
        "telegram" | "imessage_mfb" | "imessage" => verb == "send" && plain_chat,
        _ => false,
    }
}

/// The compatibility connectors whose resolved plain-chat media send is
/// ambient like their text send (FIX 7961).
const PLAIN_CHAT_MEDIA_CONNECTORS: [&str; 2] = ["line", "imessage_bridge"];

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
        // Two APNs caps: the less interrupting destination wins, so a seeded
        // cap never weakens a live one (FIX 8819). A label neither side can
        // read keeps the current decision.
        (
            OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { to: current_to, .. },
            OutboundDeliveryWindowDecision::DeliverNowWithApnsCap {
                to: candidate_to, ..
            },
        ) => match (
            apns_destination_rank(current_to),
            apns_destination_rank(candidate_to),
        ) {
            (Some(current), Some(candidate)) => candidate < current,
            (None, Some(_)) => true,
            _ => false,
        },
        _ => false,
    }
}

fn hold_retry_rank(retry_at: &Option<u64>) -> (bool, u64) {
    (retry_at.is_none(), retry_at.unwrap_or(0))
}

/// An APNs cap's destination level, read once for both the merge and the
/// cap's application: passive < active < time sensitive < critical (FIX
/// 8819). `None` for a label that names no level.
fn apns_destination_level(label: &str) -> Option<DeliveryWindowApnsInterruptionLevel> {
    label
        .strip_prefix("push:")
        .and_then(DeliveryWindowApnsInterruptionLevel::parse)
}

/// The interruption rank of an APNs cap's destination; a lower rank
/// interrupts less.
fn apns_destination_rank(label: &str) -> Option<u8> {
    apns_destination_level(label).map(|level| match level {
        DeliveryWindowApnsInterruptionLevel::Passive => 0,
        DeliveryWindowApnsInterruptionLevel::Active => 1,
        DeliveryWindowApnsInterruptionLevel::TimeSensitive => 2,
        DeliveryWindowApnsInterruptionLevel::Critical => 3,
    })
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

pub(super) fn apply_apns_window_cap(
    request: &mut OutboundDispatchRequest,
    decision: &OutboundDeliveryWindowDecision,
) {
    if let OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { to, .. } = decision
        && let Some(level) = apns_destination_level(to)
    {
        request.delivery_window_apns_interruption_level = Some(level);
    }
}
