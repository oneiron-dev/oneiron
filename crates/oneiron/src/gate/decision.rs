#[cfg(test)]
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::counterparty_contact::CounterpartyFirstTouch;
use crate::write_envelope::communication::SendOverrideMatch;

use super::input::ExternalEffectGateContext;

pub(super) use crate::store::gate_reason::{GATE_METRIC_OUTCOME_COUNT, GATE_METRIC_REASON_CLASS_COUNT};

/// One vault's gate outcome x reason-class counters.
///
/// Owned by that vault's store handle (`StoreCore::diagnostics`), so a reader
/// sees only what its own vault's doors decided.
pub(crate) struct GateMetrics {
    counters: [[AtomicU64; GATE_METRIC_REASON_CLASS_COUNT]; GATE_METRIC_OUTCOME_COUNT],
}

impl Default for GateMetrics {
    fn default() -> Self {
        Self {
            counters: [const { [const { AtomicU64::new(0) }; GATE_METRIC_REASON_CLASS_COUNT] };
                GATE_METRIC_OUTCOME_COUNT],
        }
    }
}

impl GateMetrics {
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn snapshot(&self) -> GateMetricsSnapshot {
        let mut counters =
            Vec::with_capacity(GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT);
        for outcome in GateOutcome::metric_values() {
            for reason_class in GateMetricReasonClass::metric_values() {
                counters.push(GateMetricCounter {
                    outcome,
                    reason_class,
                    count: self.counters[outcome.metric_index()][reason_class.metric_index()]
                        .load(AtomicOrdering::Relaxed),
                });
            }
        }
        GateMetricsSnapshot { counters }
    }

    pub(super) fn record_decision(&self, decision: &GateDecision) {
        #[cfg(test)]
        GATE_METRIC_EMISSIONS.with(|count| count.set(count.get().saturating_add(1)));
        let outcome = decision.outcome();
        // A decision with multiple reason codes records one outcome/reason-class co-occurrence per code.
        for reason_code in decision.reason_codes() {
            let reason_class = reason_code.metric_reason_class();
            self.counters[outcome.metric_index()][reason_class.metric_index()]
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
    }
}

pub(crate) use crate::store::gate_reason::{GateOutcome, GateReasonCode};
pub(super) use crate::store::gate_reason::GateMetricReasonClass;

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRefusal {
    pub(crate) level: Option<String>,
    pub(crate) row_ref: Option<String>,
    pub(crate) role: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateDecision {
    outcome: GateOutcome,
    reason_codes: Vec<GateReasonCode>,
    receipt_reasons: Vec<&'static str>,
    policy_row_ref: Option<String>,
    precedence_row_ref: Option<Option<String>>,
    policy_refusal: Option<PolicyRefusal>,
    delegation_narrowing: Option<super::definition_ceiling::DelegationNarrowing>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateDecision {
    pub(super) fn allow() -> Self {
        Self {
            outcome: GateOutcome::Allow,
            reason_codes: vec![GateReasonCode::Allow],
            receipt_reasons: Vec::new(),
            policy_row_ref: None,
            precedence_row_ref: None,
            policy_refusal: None,
            delegation_narrowing: None,
        }
    }

    pub(super) fn deny(reason_code: GateReasonCode) -> Self {
        Self {
            outcome: GateOutcome::Deny,
            reason_codes: vec![reason_code],
            receipt_reasons: Vec::new(),
            policy_row_ref: None,
            precedence_row_ref: None,
            policy_refusal: None,
            delegation_narrowing: None,
        }
    }

    pub(super) fn pending(reason_codes: Vec<GateReasonCode>) -> Self {
        Self {
            outcome: GateOutcome::Pending,
            reason_codes,
            receipt_reasons: Vec::new(),
            policy_row_ref: None,
            precedence_row_ref: None,
            policy_refusal: None,
            delegation_narrowing: None,
        }
    }

    /// This decision held for review by the delegation ancestor `narrowing`
    /// names (FIX 10537): an Allow pends on
    /// [`GateReasonCode::PendingDelegationChainCeiling`] alone, a Pending
    /// adds it, and a Deny stands as it is.
    pub(super) fn held_by_delegation_chain(
        mut self,
        narrowing: super::definition_ceiling::DelegationNarrowing,
    ) -> Self {
        match self.outcome {
            GateOutcome::Deny => return self,
            GateOutcome::Allow => {
                self.outcome = GateOutcome::Pending;
                self.reason_codes = vec![GateReasonCode::PendingDelegationChainCeiling];
            }
            GateOutcome::Pending => {
                self.reason_codes
                    .push(GateReasonCode::PendingDelegationChainCeiling);
            }
        }
        self.delegation_narrowing = Some(narrowing);
        self
    }

    /// The receipt token naming the delegation ancestor whose live bound
    /// held this decision, by its AGENT_DEF row and attempt, when one did
    /// ([`GateReasonCode::PendingDelegationChainCeiling`]).
    #[must_use]
    pub(crate) fn delegation_narrowing_receipt(&self) -> Option<String> {
        self.delegation_narrowing.map(|narrowing| {
            format!(
                "delegation_ancestor_{}_attempt_{}",
                narrowing.agent.to_hex(),
                crate::entity_id::bytes_to_hex_lower(narrowing.attempt.as_bytes()),
            )
        })
    }

    pub(super) fn with_policy_row_ref(mut self, row_ref: Option<&str>) -> Self {
        self.policy_row_ref = row_ref.map(str::to_owned);
        self
    }

    pub(super) fn with_policy_refusal(
        mut self,
        level: Option<String>,
        row_ref: Option<&str>,
        hidden_world: bool,
    ) -> Self {
        self.policy_refusal = Some(if hidden_world {
            PolicyRefusal {
                level: None,
                row_ref: None,
                role: None,
            }
        } else {
            PolicyRefusal {
                level,
                row_ref: row_ref.map(str::to_owned),
                role: Some("policy_power_holder"),
            }
        });
        self
    }

    pub(crate) fn policy_refusal(&self) -> Option<&PolicyRefusal> {
        self.policy_refusal.as_ref()
    }

    pub(super) fn with_precedence_row_ref(mut self, row_ref: Option<&str>) -> Self {
        self.precedence_row_ref = Some(row_ref.map(str::to_owned));
        self
    }

    #[must_use]
    pub(crate) fn precedence_row_ref(&self) -> Option<Option<&str>> {
        self.precedence_row_ref.as_ref().map(|row| row.as_deref())
    }

    #[must_use]
    pub(crate) fn policy_row_ref(&self) -> Option<&str> {
        self.policy_row_ref.as_deref()
    }

    pub(super) fn with_receipt_reasons(
        mut self,
        reasons: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        for reason in reasons {
            if !self.receipt_reasons.contains(&reason) {
                self.receipt_reasons.push(reason);
            }
        }
        self
    }

    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) fn reason_codes(&self) -> &[GateReasonCode] {
        &self.reason_codes
    }

    #[must_use]
    pub(crate) fn receipt_reasons(&self) -> &[&'static str] {
        &self.receipt_reasons
    }
}

/// The receipt vocabulary one external effect contributes, in source order.
///
/// Three chained sources, each contributing at most one token: the opt-out
/// reason, the first-touch class, and — ONE-1752 — the `comm.send_override`
/// head hydration matched for this send. The override token records the
/// DECISION SOURCE of an opt-out fall-through; it is never both scopes, because
/// the match itself is one variant.
pub(super) fn external_effect_receipt_reasons(
    effect: &ExternalEffectGateContext,
) -> impl Iterator<Item = &'static str> {
    effect
        .counterparty_opt_out_receipt_reason
        .into_iter()
        .chain(
            effect
                .counterparty_first_touch
                .map(CounterpartyFirstTouch::receipt_reason),
        )
        .chain(match effect.counterparty_send_override {
            Some(SendOverrideMatch::Standing) => Some("comm_send_override_standing"),
            Some(SendOverrideMatch::OneShot) => Some("comm_send_override_one_shot"),
            None => None,
        })
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GateMetricCounter {
    outcome: GateOutcome,
    reason_class: GateMetricReasonClass,
    count: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GateMetricsSnapshot {
    counters: Vec<GateMetricCounter>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricsSnapshot {
    #[must_use]
    pub(crate) fn count(&self, outcome: GateOutcome, reason_class: GateMetricReasonClass) -> u64 {
        self.counters
            .iter()
            .find(|counter| counter.outcome == outcome && counter.reason_class == reason_class)
            .map_or(0, |counter| counter.count)
    }
}

#[cfg(test)]
thread_local! {
    static GATE_METRIC_EMISSIONS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn gate_metric_emission_count_for_test() -> u64 {
    GATE_METRIC_EMISSIONS.with(Cell::get)
}
