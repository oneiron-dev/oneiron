//! Ladder resolve/evaluate_with_evidence plus restriction ranking helpers.

use crate::claim::ClaimSource;

use super::claims::{DeliveryWindowPolicyClaim, Restriction};
use super::context::DeliveryWindowEvaluationContext;
use super::types::{
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowDecision, DeliveryWindowLadderRung,
    DeliveryWindowMatch, DeliveryWindowResolution, DeliveryWindowVerbClass, MINUTES_PER_DAY,
    PREDICATE_DELIVERY_WINDOW_CHANNEL, PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_QUIET,
};

pub struct DeliveryWindowEvaluator;

impl DeliveryWindowEvaluator {
    #[must_use]
    pub fn evaluate(
        context: &DeliveryWindowEvaluationContext,
        claims: &[DeliveryWindowPolicyClaim],
    ) -> DeliveryWindowDecision {
        Self::evaluate_with_evidence(context, claims).0
    }

    /// Runs the frozen execute-time ladder. The top applicable rung wins, and
    /// the live policy observation is preserved beside the effective action so
    /// an override can never erase the standing claim from a receipt.
    #[must_use]
    pub fn resolve(
        context: &DeliveryWindowEvaluationContext,
        claims: &[DeliveryWindowPolicyClaim],
    ) -> DeliveryWindowResolution {
        let (observed, matched) = Self::evaluate_with_evidence(context, claims);
        if context.local_minute_of_day >= MINUTES_PER_DAY {
            return DeliveryWindowResolution::missing_local_minute(matched);
        }
        // Rung 1 — a human chose this instant. The specific fresh decision
        // beats the standing general policy, so a parked observation (hold or
        // cross-surface degrade) lifts to an executing DeliverNow. An already
        // executing observation is kept verbatim: the APNs companion ceiling
        // is not a window park, and capping it is what admits the send.
        if context.human_explicit_instant {
            let effective = match &observed {
                DeliveryWindowDecision::Hold { .. } | DeliveryWindowDecision::Degrade { .. } => {
                    DeliveryWindowDecision::DeliverNow
                }
                admitting => admitting.clone(),
            };
            return DeliveryWindowResolution {
                observed,
                effective,
                matched,
                rung: DeliveryWindowLadderRung::HumanExplicitInstant,
            };
        }
        let rung = match observed {
            // Rung 3 — interrupt-class but degradable: content lands, buzz drops.
            DeliveryWindowDecision::DeliverNowWithApnsCap { .. }
            | DeliveryWindowDecision::Degrade { .. } => DeliveryWindowLadderRung::InterruptDegraded,
            // Rung 4 — interrupt-class, not degradable: park to the window edge.
            DeliveryWindowDecision::Hold { .. } => DeliveryWindowLadderRung::InterruptHeld,
            // Rung 2 — nothing interrupted: an ambient verb, or an interrupt
            // verb that no live window restricts. Both deliver now, and the
            // frozen rung enum names that outcome `ambient`.
            _ => DeliveryWindowLadderRung::Ambient,
        };
        DeliveryWindowResolution {
            effective: observed.clone(),
            observed,
            matched,
            rung,
        }
    }

    pub fn evaluate_with_evidence(
        context: &DeliveryWindowEvaluationContext,
        claims: &[DeliveryWindowPolicyClaim],
    ) -> (DeliveryWindowDecision, Vec<DeliveryWindowMatch>) {
        if context.local_minute_of_day >= MINUTES_PER_DAY {
            return (invalid_context_decision(context), Vec::new());
        }
        let restrictions = claims
            .iter()
            .filter_map(|claim| claim.restriction_at(context))
            .collect::<Vec<_>>();
        let matched = restrictions
            .iter()
            .map(|r| DeliveryWindowMatch {
                predicate: r.predicate.clone(),
                reason: r.reason.clone(),
                retry_at: r.retry_at,
            })
            .collect();
        if restrictions.is_empty() {
            return (
                apns_ceiling_decision(context).unwrap_or(DeliveryWindowDecision::DeliverNow),
                matched,
            );
        }
        let selected = most_restrictive_restriction(&restrictions)
            .expect("non-empty restrictions have a selected restriction");
        if let Some(level) = context.apns_interruption_level {
            let to = level.quiet_window_degrade();
            if level != to {
                return (
                    DeliveryWindowDecision::DeliverNowWithApnsCap {
                        reason: selected.reason.clone(),
                        from: level.push_label(),
                        to: to.push_label(),
                    },
                    matched,
                );
            }
            if level == DeliveryWindowApnsInterruptionLevel::Passive {
                return (DeliveryWindowDecision::DeliverNow, matched);
            }
        }
        if let Some(to) = context.degrade_to.as_ref() {
            return (
                DeliveryWindowDecision::Degrade {
                    reason: selected.reason.clone(),
                    from: context
                        .interrupt_surface
                        .clone()
                        .unwrap_or_else(|| "interrupt".to_owned()),
                    to: to.clone(),
                },
                matched,
            );
        }
        (
            DeliveryWindowDecision::Hold {
                reason: selected.reason.clone(),
                retry_at: selected.retry_at,
            },
            matched,
        )
    }
}

fn invalid_context_decision(context: &DeliveryWindowEvaluationContext) -> DeliveryWindowDecision {
    if context.verb_class == DeliveryWindowVerbClass::Interrupt {
        DeliveryWindowDecision::Hold {
            reason: "invalid_local_minute".to_owned(),
            retry_at: None,
        }
    } else {
        DeliveryWindowDecision::DeliverNow
    }
}

fn apns_ceiling_decision(
    context: &DeliveryWindowEvaluationContext,
) -> Option<DeliveryWindowDecision> {
    let level = context.apns_interruption_level?;
    let capped = level.companion_ceiling();
    (level != capped).then(|| DeliveryWindowDecision::DeliverNowWithApnsCap {
        reason: "apns_time_sensitive_ceiling".to_owned(),
        from: level.push_label(),
        to: capped.push_label(),
    })
}

fn most_restrictive_restriction(restrictions: &[Restriction]) -> Option<&Restriction> {
    restrictions
        .iter()
        .max_by(|left, right| restriction_rank(left).cmp(&restriction_rank(right)))
}

fn restriction_rank(restriction: &Restriction) -> (bool, u64, u8, &str, &str) {
    (
        restriction.retry_at.is_none(),
        restriction.retry_at.unwrap_or(0),
        source_priority(restriction.source),
        restriction.predicate.as_str(),
        restriction.reason.as_str(),
    )
}

const fn source_priority(source: Option<ClaimSource>) -> u8 {
    match source {
        Some(ClaimSource::UserStated) => 2,
        Some(_) => 1,
        None => 0,
    }
}

pub(super) fn default_reason(predicate: &str) -> &'static str {
    match predicate {
        PREDICATE_DELIVERY_WINDOW_QUIET => "quiet_window",
        PREDICATE_DELIVERY_WINDOW_CONTEXT => "context_window",
        PREDICATE_DELIVERY_WINDOW_CHANNEL => "channel_window",
        _ => "restricted",
    }
}

pub(super) fn normalize_channel_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}
