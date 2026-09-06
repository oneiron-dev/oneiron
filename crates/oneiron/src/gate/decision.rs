#[cfg(test)]
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::comm::SendOverrideMatch;
use crate::counterparty_contact::CounterpartyFirstTouch;

use super::input::ExternalEffectGateContext;

pub(super) const GATE_METRIC_OUTCOME_COUNT: usize = 3;
pub(super) const GATE_METRIC_REASON_CLASS_COUNT: usize = 17;

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
    /// GATE-12: deterministic pre-commit validation refused a Dreamer-authored
    /// claim before any decision was applied.
    DreamerPrecommit,
    /// ONE-1686 (RT-04): the witness MESSAGE ceiling door refused an envelope
    /// at the shared witness write boundary.
    WitnessMessageCeiling,
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
            Self::DreamerPrecommit => "dreamer_precommit",
            Self::WitnessMessageCeiling => "witness_message_ceiling",
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
            Self::DreamerPrecommit => 15,
            Self::WitnessMessageCeiling => 16,
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
            Self::DreamerPrecommit,
            Self::WitnessMessageCeiling,
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
    /// GATE-12 check 1: the Dreamer's claim value was empty-after-trim or
    /// opened with narration instead of a value.
    DenyDreamerDegenerateOutput,
    /// GATE-12 check 2: predicate, confidence, subject or value shape was
    /// outside the claim contract.
    DenyDreamerMalformed,
    /// GATE-12 check 3: a non-runtime-record Dreamer claim cited no evidence
    /// ref that resolves to an existing entity. Validity, not authority — so
    /// it is a deny and never becomes an owner-review row.
    DenyDreamerNoEvidence,
    /// ONE-1686 (RT-04): the witnessed MESSAGE envelope was malformed — an
    /// unknown author bucket, an out-of-shape message type, an out-of-range
    /// order, an incoherent author/visibility pair, metadata that exceeded the
    /// bounds or restated an envelope axis, or staged body bytes that were not
    /// the canonical encoding of the axes presented. Validity, not authority.
    DenyWitnessMessageMalformedEnvelope,
    /// ONE-1686 (RT-04): the actor may not author this envelope. Today the only
    /// bucket that needs authority beyond a bound actor is `system`, whose rows
    /// carry no `AuthoredBy` edge and so speak in the engine's own voice.
    DenyWitnessMessageAuthorNotAuthorized,
    /// GATE-13: a Dreamer-authored write landed on a persona-core predicate.
    /// The ceiling is forced to Proposed — never Auto — and the row rides
    /// beside [`Self::PendingCriticalityFloor`] so every inbox dial surfaces
    /// it.
    PendingPersonaIsolation,
    /// GATE-13: a Dreamer-authored write landed on a mirroring-prone
    /// predicate. Same forced Proposed ceiling and same criticality marker,
    /// with no multi-cycle evidence floor of its own.
    PendingMirroringIsolation,
    /// GATE-13: a persona-core Dreamer write cited evidence spanning fewer
    /// than two distinct SESSION entities. A persona head may only move on
    /// deliberate transformation, so one cycle is refused outright rather
    /// than parked for review.
    DenyPersonaSingleCycle,
    /// ONE-1752 (ARCH-0057 §3.1): the counterparty is opted out, no
    /// `comm.send_override` covers this send, and the resolved
    /// `comm_opt_out_posture` is `escalate`. The send is HELD for the owner
    /// rather than denied to them: suppression is the counterparty's word about
    /// the counterparty, and the owner's own instrument may not refuse the
    /// owner outright. [`Self::DenyCounterpartyOptOut`] keeps its position,
    /// token and metric class for decode compatibility and is no longer emitted
    /// on the owner path. Appended LAST — this enum is append-only.
    PendingCounterpartyOptOut,
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
            Self::DenyDreamerDegenerateOutput => "gate.deny.dreamer_precommit.degenerate_output",
            Self::DenyDreamerMalformed => "gate.deny.dreamer_precommit.malformed",
            Self::DenyDreamerNoEvidence => "gate.deny.dreamer_precommit.no_evidence",
            Self::DenyWitnessMessageMalformedEnvelope => {
                "gate.deny.witness_message.malformed_envelope"
            }
            Self::DenyWitnessMessageAuthorNotAuthorized => {
                "gate.deny.witness_message.author_not_authorized"
            }
            Self::PendingPersonaIsolation => "gate.pending.persona_isolation",
            Self::PendingMirroringIsolation => "gate.pending.mirroring_isolation",
            Self::DenyPersonaSingleCycle => "gate.deny.dreamer_precommit.persona_single_cycle",
            Self::PendingCounterpartyOptOut => "gate.pending.counterparty_opt_out",
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
            // The consequence moved from deny to pending-escalation; the METRIC
            // class did not. Both reason codes count as one opt-out class so
            // dashboards keep their series across the cutover.
            Self::DenyCounterpartyOptOut | Self::PendingCounterpartyOptOut => {
                GateMetricReasonClass::CounterpartyOptOut
            }
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
            Self::DenyDreamerDegenerateOutput
            | Self::DenyDreamerMalformed
            | Self::DenyDreamerNoEvidence => GateMetricReasonClass::DreamerPrecommit,
            Self::DenyWitnessMessageMalformedEnvelope
            | Self::DenyWitnessMessageAuthorNotAuthorized => {
                GateMetricReasonClass::WitnessMessageCeiling
            }
            // GATE-13 isolation rides the classes it already belongs to: the
            // two pends carry the existing criticality marker, and the
            // persona single-cycle refusal is a Dreamer pre-commit denial. No
            // new metric class, so the counter width is unchanged.
            Self::PendingPersonaIsolation | Self::PendingMirroringIsolation => {
                GateMetricReasonClass::CriticalityFloor
            }
            Self::DenyPersonaSingleCycle => GateMetricReasonClass::DreamerPrecommit,
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
