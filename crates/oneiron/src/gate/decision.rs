#[cfg(test)]
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::counterparty_contact::CounterpartyFirstTouch;

use super::input::ExternalEffectGateContext;

pub(super) const GATE_METRIC_OUTCOME_COUNT: usize = 3;
pub(super) const GATE_METRIC_REASON_CLASS_COUNT: usize = 15;

static GATE_METRIC_COUNTERS: [[AtomicU64; GATE_METRIC_REASON_CLASS_COUNT];
    GATE_METRIC_OUTCOME_COUNT] = [const { [const { AtomicU64::new(0) }; GATE_METRIC_REASON_CLASS_COUNT] };
    GATE_METRIC_OUTCOME_COUNT];

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    Allow,
    Pending,
    Deny,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateOutcome {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Pending => "pending",
            Self::Deny => "deny",
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::Allow => 0,
            Self::Pending => 1,
            Self::Deny => 2,
        }
    }

    const fn metric_values() -> [Self; GATE_METRIC_OUTCOME_COUNT] {
        [Self::Allow, Self::Pending, Self::Deny]
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateMetricReasonClass {
    Allow,
    MissingActorClass,
    MissingActorProvenance,
    MissingPolicyManifestVersion,
    PolicyFailClosed,
    ActorCeiling,
    SourceTrust,
    CriticalityFloor,
    PolicyManifestAuthority,
    ExternalEffectAuthority,
    CounterpartyOptOut,
    EffectorBudget,
    CharterPolicy,
    /// DEC-0006 consent ladder: catastrophe floor, irreversible effect, bound
    /// exceeded, and write-classification failure all meter here.
    Consent,
    /// CA-06 campaign compliance: a seeded legal rule row refused the dispatch.
    CampaignCompliance,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricReasonClass {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::MissingActorClass => "missing_actor_class",
            Self::MissingActorProvenance => "missing_actor_provenance",
            Self::MissingPolicyManifestVersion => "missing_policy_manifest_version",
            Self::PolicyFailClosed => "policy_fail_closed",
            Self::ActorCeiling => "actor_ceiling",
            Self::SourceTrust => "source_trust",
            Self::CriticalityFloor => "criticality_floor",
            Self::PolicyManifestAuthority => "policy_manifest_authority",
            Self::ExternalEffectAuthority => "external_effect_authority",
            Self::CounterpartyOptOut => "counterparty_opt_out",
            Self::EffectorBudget => "effector_budget",
            Self::CharterPolicy => "charter_policy",
            Self::Consent => "consent",
            Self::CampaignCompliance => "campaign_compliance",
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::Allow => 0,
            Self::MissingActorClass => 1,
            Self::MissingActorProvenance => 2,
            Self::MissingPolicyManifestVersion => 3,
            Self::PolicyFailClosed => 4,
            Self::ActorCeiling => 5,
            Self::SourceTrust => 6,
            Self::CriticalityFloor => 7,
            Self::PolicyManifestAuthority => 8,
            Self::ExternalEffectAuthority => 9,
            Self::CounterpartyOptOut => 10,
            Self::EffectorBudget => 11,
            Self::CharterPolicy => 12,
            Self::Consent => 13,
            Self::CampaignCompliance => 14,
        }
    }

    const fn metric_values() -> [Self; GATE_METRIC_REASON_CLASS_COUNT] {
        [
            Self::Allow,
            Self::MissingActorClass,
            Self::MissingActorProvenance,
            Self::MissingPolicyManifestVersion,
            Self::PolicyFailClosed,
            Self::ActorCeiling,
            Self::SourceTrust,
            Self::CriticalityFloor,
            Self::PolicyManifestAuthority,
            Self::ExternalEffectAuthority,
            Self::CounterpartyOptOut,
            Self::EffectorBudget,
            Self::CharterPolicy,
            Self::Consent,
            Self::CampaignCompliance,
        ]
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateReasonCode {
    Allow,
    DenyMissingActorClass,
    DenyMissingActorProvenance,
    DenyMissingPolicyManifestVersion,
    DenyPolicyFailClosed,
    PendingActorCeiling,
    PendingSourceTrust,
    PendingCriticalityFloor,
    PendingPolicyManifestAuthority,
    PendingExternalEffectAuthority,
    PendingConnectorKeyUnregistered,
    DenyCounterpartyOptOut,
    DenyEffectorBudgetExhausted,
    DenyConnectorKeySuspended,
    DenyCharterNeverList,
    PendingCharterDrift,
    /// DEC-0006 invariant 1: the operation is irreversible in effect and no
    /// approve-once receipt or covering standing grant authorizes it.
    PendingConsentIrreversibleEffect,
    /// DEC-0006 invariant 3: a standing grant exists but the candidate exceeds
    /// its bound. Widening is its own owner decision, never a side effect of
    /// reuse — so this is a fresh ask, not a silent auto.
    PendingConsentBoundExceeded,
    /// DEC-0006 invariant 7: the operation matched the closed catastrophe
    /// floor. Gated at ANY trust level, non-rememberable.
    PendingConsentCatastropheFloor,
    /// DEC-0006 invariant 8: the engine-owned write facts were malformed or
    /// absent, so no reversibility verdict could be produced. Writes fail safe
    /// by asking.
    PendingConsentWriteClassificationFailed,
    /// CA-06 (ONE-1777): a seeded campaign-compliance row refused this
    /// dispatch. Enforcement, not an ask — an owner approval must not be able
    /// to unlock a send the governing legal row forbids, so this is a deny.
    DenyCampaignCompliance,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateReasonCode {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "gate.allow",
            Self::DenyMissingActorClass => "gate.deny.missing_actor_class",
            Self::DenyMissingActorProvenance => "gate.deny.missing_actor_provenance",
            Self::DenyMissingPolicyManifestVersion => "gate.deny.missing_policy_manifest_version",
            Self::DenyPolicyFailClosed => "gate.deny.policy_fail_closed",
            Self::PendingActorCeiling => "gate.pending.actor_ceiling",
            Self::PendingSourceTrust => "gate.pending.source_trust",
            Self::PendingCriticalityFloor => "gate.pending.criticality_floor",
            Self::PendingPolicyManifestAuthority => "gate.pending.policy_manifest_authority",
            Self::PendingExternalEffectAuthority => "gate.pending.external_effect_authority",
            Self::PendingConnectorKeyUnregistered => "gate.pending.connector_key_unregistered",
            Self::DenyCounterpartyOptOut => "gate.deny.counterparty_opt_out",
            Self::DenyEffectorBudgetExhausted => "gate.deny.effector_budget_exhausted",
            Self::DenyConnectorKeySuspended => "gate.deny.connector_key_suspended",
            Self::DenyCharterNeverList => "gate.deny.charter_never_list",
            Self::PendingCharterDrift => "gate.pending.charter_drift",
            Self::PendingConsentIrreversibleEffect => "gate.pending.consent.irreversible_effect",
            Self::PendingConsentBoundExceeded => "gate.pending.consent.bound_exceeded",
            Self::PendingConsentCatastropheFloor => "gate.pending.consent.catastrophe_floor",
            Self::PendingConsentWriteClassificationFailed => {
                "gate.pending.consent.write_classification_failed"
            }
            Self::DenyCampaignCompliance => "gate.deny.campaign_compliance",
        }
    }

    const fn metric_reason_class(self) -> GateMetricReasonClass {
        match self {
            Self::Allow => GateMetricReasonClass::Allow,
            Self::DenyMissingActorClass => GateMetricReasonClass::MissingActorClass,
            Self::DenyMissingActorProvenance => GateMetricReasonClass::MissingActorProvenance,
            Self::DenyMissingPolicyManifestVersion => {
                GateMetricReasonClass::MissingPolicyManifestVersion
            }
            Self::DenyPolicyFailClosed => GateMetricReasonClass::PolicyFailClosed,
            Self::PendingActorCeiling => GateMetricReasonClass::ActorCeiling,
            Self::PendingSourceTrust => GateMetricReasonClass::SourceTrust,
            Self::PendingCriticalityFloor => GateMetricReasonClass::CriticalityFloor,
            Self::PendingPolicyManifestAuthority => GateMetricReasonClass::PolicyManifestAuthority,
            Self::PendingExternalEffectAuthority | Self::PendingConnectorKeyUnregistered => {
                GateMetricReasonClass::ExternalEffectAuthority
            }
            Self::DenyCounterpartyOptOut => GateMetricReasonClass::CounterpartyOptOut,
            Self::DenyEffectorBudgetExhausted | Self::DenyConnectorKeySuspended => {
                GateMetricReasonClass::EffectorBudget
            }
            Self::DenyCharterNeverList | Self::PendingCharterDrift => {
                GateMetricReasonClass::CharterPolicy
            }
            Self::PendingConsentIrreversibleEffect
            | Self::PendingConsentBoundExceeded
            | Self::PendingConsentCatastropheFloor
            | Self::PendingConsentWriteClassificationFailed => GateMetricReasonClass::Consent,
            Self::DenyCampaignCompliance => GateMetricReasonClass::CampaignCompliance,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateDecision {
    outcome: GateOutcome,
    reason_codes: Vec<GateReasonCode>,
    receipt_reasons: Vec<&'static str>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateDecision {
    pub(super) fn allow() -> Self {
        Self {
            outcome: GateOutcome::Allow,
            reason_codes: vec![GateReasonCode::Allow],
            receipt_reasons: Vec::new(),
        }
    }

    pub(super) fn deny(reason_code: GateReasonCode) -> Self {
        Self {
            outcome: GateOutcome::Deny,
            reason_codes: vec![reason_code],
            receipt_reasons: Vec::new(),
        }
    }

    pub(super) fn pending(reason_codes: Vec<GateReasonCode>) -> Self {
        Self {
            outcome: GateOutcome::Pending,
            reason_codes,
            receipt_reasons: Vec::new(),
        }
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
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricCounter {
    outcome: GateOutcome,
    reason_class: GateMetricReasonClass,
    count: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricCounter {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) fn reason_class(&self) -> GateMetricReasonClass {
        self.reason_class
    }

    #[must_use]
    pub(crate) fn count(&self) -> u64 {
        self.count
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricsSnapshot {
    counters: Vec<GateMetricCounter>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricsSnapshot {
    #[must_use]
    pub(crate) fn counters(&self) -> &[GateMetricCounter] {
        &self.counters
    }

    #[must_use]
    pub(crate) fn count(&self, outcome: GateOutcome, reason_class: GateMetricReasonClass) -> u64 {
        self.counters
            .iter()
            .find(|counter| counter.outcome == outcome && counter.reason_class == reason_class)
            .map_or(0, |counter| counter.count)
    }
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn gate_metrics_snapshot() -> GateMetricsSnapshot {
    let mut counters =
        Vec::with_capacity(GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT);
    for outcome in GateOutcome::metric_values() {
        for reason_class in GateMetricReasonClass::metric_values() {
            counters.push(GateMetricCounter {
                outcome,
                reason_class,
                count: GATE_METRIC_COUNTERS[outcome.metric_index()][reason_class.metric_index()]
                    .load(AtomicOrdering::Relaxed),
            });
        }
    }
    GateMetricsSnapshot { counters }
}

pub(super) fn record_gate_decision_metrics(decision: &GateDecision) {
    #[cfg(test)]
    GATE_METRIC_EMISSIONS.with(|count| count.set(count.get().saturating_add(1)));
    let outcome = decision.outcome();
    // A decision with multiple reason codes records one outcome/reason-class co-occurrence per code.
    for reason_code in decision.reason_codes() {
        let reason_class = reason_code.metric_reason_class();
        GATE_METRIC_COUNTERS[outcome.metric_index()][reason_class.metric_index()]
            .fetch_add(1, AtomicOrdering::Relaxed);
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
