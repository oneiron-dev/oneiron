//! What a dated `can(effect)` preflight reads off one external-effect
//! judgment (C2:207; Engine 11:16, FIX 20734 = A): allow, deny or would-ask,
//! and every administrative hold named as a hold, never as one of those three
//! words. Its reason tokens are the Gate's own reason codes, which never name
//! a world or a policy row's hidden detail.

use super::*;

/// The word a dated preflight answers for one effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreflightVerdict {
    /// The Gate allows the effect.
    Allow,
    /// The Gate refuses the effect.
    Deny,
    /// The Gate holds the effect for an owner's decision.
    WouldAsk,
    /// An administrative hold holds the effect; an owner's press alone does
    /// not release it.
    Held,
}

/// The preflight answer one judgment carries.
pub(crate) struct ExternalEffectPreflight {
    pub(crate) verdict: PreflightVerdict,
    /// The decision's reason codes, [`GateReasonCode::as_str`] tokens,
    /// without `gate.allow`.
    pub(crate) reasons: Vec<&'static str>,
    /// Each administrative hold among them, its token without its
    /// `gate.pending.` prefix (for example `charter_drift`).
    pub(crate) holds: Vec<&'static str>,
    /// An allowed send would take its place in a full envelope window
    /// rather than go now (FIX 7948).
    pub(crate) waits_for_envelope_window: bool,
}

/// How a preflight reads one reason code.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreflightReason {
    Allow,
    Deny,
    /// A hold only the owner's decision releases.
    OwnerDecision,
    /// A hold the vault's own state keeps: a drift, a missing authority, a
    /// trust or criticality floor, a checker, a compliance clearance.
    AdministrativeHold,
}

/// The class of `code`. One exhaustive match: a new reason code does not
/// compile until it is classed.
const fn preflight_reason(code: GateReasonCode) -> PreflightReason {
    match code {
        GateReasonCode::Allow => PreflightReason::Allow,
        GateReasonCode::DenyMissingActorClass
        | GateReasonCode::DenyMissingActorProvenance
        | GateReasonCode::DenyMissingPolicyManifestVersion
        | GateReasonCode::DenyPolicyFailClosed
        | GateReasonCode::DenyCounterpartyOptOut
        | GateReasonCode::DenyEffectorBudgetExhausted
        | GateReasonCode::DenyConnectorKeySuspended
        | GateReasonCode::DenyCharterNeverList
        | GateReasonCode::DenyCampaignCompliance
        | GateReasonCode::DenyDreamerDegenerateOutput
        | GateReasonCode::DenyDreamerMalformed
        | GateReasonCode::DenyDreamerNoEvidence
        | GateReasonCode::DenyWitnessMessageMalformedEnvelope
        | GateReasonCode::DenyWitnessMessageAuthorNotAuthorized
        | GateReasonCode::DenyPersonaSingleCycle
        | GateReasonCode::DenyUnresolvedRecordReference => PreflightReason::Deny,
        GateReasonCode::PendingConsentIrreversibleEffect
        | GateReasonCode::PendingConsentBoundExceeded
        | GateReasonCode::PendingConsentCatastropheFloor
        | GateReasonCode::PendingConsentWriteClassificationFailed
        | GateReasonCode::PendingCounterpartyOptOut
        | GateReasonCode::PendingActorCeiling
        | GateReasonCode::PendingDelegationChainCeiling => PreflightReason::OwnerDecision,
        GateReasonCode::PendingSourceTrust
        | GateReasonCode::PendingCriticalityFloor
        | GateReasonCode::PendingPolicyManifestAuthority
        | GateReasonCode::PendingExternalEffectAuthority
        | GateReasonCode::PendingConnectorKeyUnregistered
        | GateReasonCode::PendingCharterDrift
        | GateReasonCode::PendingConnectorManifestDrift
        | GateReasonCode::PendingConnectorManifestStale
        | GateReasonCode::PendingPersonaIsolation
        | GateReasonCode::PendingMirroringIsolation
        | GateReasonCode::PendingChecker
        | GateReasonCode::PendingCheckerUnavailable
        | GateReasonCode::PendingCarryForwardConfidence
        | GateReasonCode::PendingCampaignCompliance => PreflightReason::AdministrativeHold,
    }
}

/// The preflight answer `judgment` carries: Deny and Allow as the Gate
/// decided them, and a Pending outcome `Held` when any of its reasons is an
/// administrative hold, else `WouldAsk`. Its holds are named either way.
pub(crate) fn preflight_answer(judgment: &ExternalEffectJudgment) -> ExternalEffectPreflight {
    let mut reasons = Vec::new();
    let mut holds = Vec::new();
    for &code in judgment.decision().reason_codes() {
        let class = preflight_reason(code);
        if class == PreflightReason::Allow {
            continue;
        }
        let token = code.as_str();
        reasons.push(token);
        if class == PreflightReason::AdministrativeHold {
            let hold = token.strip_prefix("gate.pending.").unwrap_or(token);
            if !holds.contains(&hold) {
                holds.push(hold);
            }
        }
    }
    let verdict = match judgment.outcome() {
        GateOutcome::Allow => PreflightVerdict::Allow,
        GateOutcome::Deny => PreflightVerdict::Deny,
        GateOutcome::Pending if holds.is_empty() => PreflightVerdict::WouldAsk,
        GateOutcome::Pending => PreflightVerdict::Held,
    };
    ExternalEffectPreflight {
        verdict,
        reasons,
        holds,
        waits_for_envelope_window: judgment.waits_for_envelope_window(),
    }
}
