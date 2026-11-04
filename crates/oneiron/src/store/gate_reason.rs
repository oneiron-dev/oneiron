//! Gate outcomes, stable reason codes, and pure metric classification.

pub(crate) const GATE_METRIC_OUTCOME_COUNT: usize = 3;
pub(crate) const GATE_METRIC_REASON_CLASS_COUNT: usize = 18;

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

    pub(crate) const fn metric_index(self) -> usize {
        match self {
            Self::Allow => 0,
            Self::Pending => 1,
            Self::Deny => 2,
        }
    }

    pub(crate) const fn metric_values() -> [Self; GATE_METRIC_OUTCOME_COUNT] {
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
    /// OF-063 (FIX 1220): a claim named a record its writer cannot read.
    UnresolvedRecordReference,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricReasonClass {
    pub(crate) const fn metric_index(self) -> usize {
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
            Self::UnresolvedRecordReference => 17,
        }
    }

    pub(crate) const fn metric_values() -> [Self; GATE_METRIC_REASON_CLASS_COUNT] {
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
            Self::UnresolvedRecordReference,
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
    PendingConnectorManifestDrift,
    PendingConnectorManifestStale,
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
    /// on the owner path. New reason codes append after this entry.
    PendingCounterpartyOptOut,
    /// ONE-1296: the manifest's auto checker HELD an otherwise-Auto Dreamer
    /// write. The ceiling falls to Proposed and the checker's own reasons ride
    /// the receipt beside this code.
    PendingChecker,
    /// ONE-1296: the auto checker could not answer — unavailable, panicked,
    /// past its deadline, out of budget, or malformed. Fail-closed is the same
    /// answer as a hold, spelled differently so an owner can tell "the checker
    /// said no" from "nothing checked".
    PendingCheckerUnavailable,
    /// A forward claim lacks the confidence for its subtype (care is stricter).
    PendingCarryForwardConfidence,
    /// OF-063 (FIX 1218/1220): a typed record ref the claim names does not
    /// resolve under its writer's own scoped read in the final write's
    /// snapshot. Invented, missing and unreadable are this one refusal. A
    /// deny, never an owner-review row: no approval makes a named record
    /// exist, so it is never retried as Proposed.
    DenyUnresolvedRecordReference,
    /// FIX 10537: a delegated child's write its own bound allows, which an
    /// ancestor on its live delegation chain no longer does. The decision's
    /// receipt names that ancestor
    /// ([`GateDecision::delegation_narrowing_receipt`]); an owner's review,
    /// as for [`Self::PendingActorCeiling`], decides it.
    PendingDelegationChainCeiling,
    /// FIX 12542: a campaign-compliance Block is held for the owner's
    /// clearance rather than overriding a would-be Allow or Pending with Deny.
    PendingCampaignCompliance,
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
            Self::PendingConnectorManifestDrift => "gate.pending.connector_manifest_drift",
            Self::PendingConnectorManifestStale => "gate.pending.connector_manifest_stale",
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
            Self::PendingChecker => "gate.pending.checker",
            Self::PendingCheckerUnavailable => "gate.pending.checker.unavailable",
            Self::PendingCarryForwardConfidence => "gate.pending.carry_forward_confidence",
            Self::DenyUnresolvedRecordReference => "gate.deny.unresolved_record_reference",
            Self::PendingDelegationChainCeiling => "gate.pending.delegation_chain_ceiling",
            Self::PendingCampaignCompliance => "gate.pending.campaign_compliance",
        }
    }

    pub(crate) const fn metric_reason_class(self) -> GateMetricReasonClass {
        match self {
            Self::Allow => GateMetricReasonClass::Allow,
            Self::DenyMissingActorClass => GateMetricReasonClass::MissingActorClass,
            Self::DenyMissingActorProvenance => GateMetricReasonClass::MissingActorProvenance,
            Self::DenyMissingPolicyManifestVersion => {
                GateMetricReasonClass::MissingPolicyManifestVersion
            }
            Self::DenyPolicyFailClosed => GateMetricReasonClass::PolicyFailClosed,
            // The chain's narrowing is an actor ceiling met higher up: no new
            // metric class, so the counter width is unchanged.
            Self::PendingActorCeiling | Self::PendingDelegationChainCeiling => {
                GateMetricReasonClass::ActorCeiling
            }
            Self::PendingSourceTrust => GateMetricReasonClass::SourceTrust,
            Self::PendingCriticalityFloor => GateMetricReasonClass::CriticalityFloor,
            Self::PendingPolicyManifestAuthority => GateMetricReasonClass::PolicyManifestAuthority,
            Self::PendingExternalEffectAuthority
            | Self::PendingConnectorKeyUnregistered
            | Self::PendingConnectorManifestDrift
            | Self::PendingConnectorManifestStale => GateMetricReasonClass::ExternalEffectAuthority,
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
            Self::DenyCampaignCompliance | Self::PendingCampaignCompliance => {
                GateMetricReasonClass::CampaignCompliance
            }
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
            // ONE-1296 meters where it acts: the checker is only ever asked
            // about a source that `requires_explicit_auto_permit`, so a hold
            // is the explicit-auto-permit question answered by the host
            // instead of by a manifest row. No new metric class, so the
            // counter width is unchanged.
            Self::PendingChecker | Self::PendingCheckerUnavailable => {
                GateMetricReasonClass::SourceTrust
            }
            Self::PendingCarryForwardConfidence => GateMetricReasonClass::CriticalityFloor,
            Self::DenyUnresolvedRecordReference => GateMetricReasonClass::UnresolvedRecordReference,
        }
    }
}
