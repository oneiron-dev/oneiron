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
    /// An allowed effect whose governing key's count-bound window is full
    /// would wait until this recording time, charged nothing (FIX 8686).
    pub(crate) rate_window_opens_at: Option<u64>,
}

/// How the door that would admit an effect meets its governing key's
/// budgets, as [`crate::outbound_chokepoint`] charges them.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PreflightBudget<'a> {
    /// The effect debits its key's sends rows (`BudgetClass::is_send`).
    pub(crate) send_like: bool,
    /// The door waits for a full count-bound window rather than refusing
    /// (FIX 8686, 8788).
    pub(crate) paces: bool,
    /// The tool whose declared price the door reserves on its key's
    /// preauthorizing Spend rows before it charges (a scoped call, FIX
    /// 8689); `None` for a door that reserves no price.
    pub(crate) priced_tool: Option<&'a str>,
}

/// How a preflight reads one reason code.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreflightReason {
    Allow,
    Deny,
    /// A hold the owner's word on this one effect releases: a press, an
    /// exact approval or an override.
    OwnerDecision,
    /// A hold the vault's own state keeps, which no word on this one effect
    /// releases: a drift, a missing key, a trust or criticality floor, an
    /// actor or delegation-chain ceiling, a checker.
    AdministrativeHold,
    /// Missing external-effect authority: an owner decision when the owner's
    /// press on this one effect supplies it, else an administrative hold.
    MissingAuthority,
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
        // The consent ladder's asks, the opted-out counterparty an override
        // passes, and a campaign-compliance hold, which an exact approval
        // returns to the decision it held (CA-06).
        GateReasonCode::PendingConsentIrreversibleEffect
        | GateReasonCode::PendingConsentBoundExceeded
        | GateReasonCode::PendingConsentCatastropheFloor
        | GateReasonCode::PendingConsentWriteClassificationFailed
        | GateReasonCode::PendingCounterpartyOptOut
        | GateReasonCode::PendingCampaignCompliance => PreflightReason::OwnerDecision,
        GateReasonCode::PendingExternalEffectAuthority => PreflightReason::MissingAuthority,
        // An approval of one effect releases consent only: an actor or
        // delegation-chain ceiling holds until its policy or grant changes.
        GateReasonCode::PendingActorCeiling
        | GateReasonCode::PendingDelegationChainCeiling
        | GateReasonCode::PendingSourceTrust
        | GateReasonCode::PendingCriticalityFloor
        | GateReasonCode::PendingPolicyManifestAuthority
        | GateReasonCode::PendingConnectorKeyUnregistered
        | GateReasonCode::PendingCharterDrift
        | GateReasonCode::PendingConnectorManifestDrift
        | GateReasonCode::PendingConnectorManifestStale
        | GateReasonCode::PendingPersonaIsolation
        | GateReasonCode::PendingMirroringIsolation
        | GateReasonCode::PendingChecker
        | GateReasonCode::PendingCheckerUnavailable
        | GateReasonCode::PendingCarryForwardConfidence => PreflightReason::AdministrativeHold,
    }
}

/// The words reason codes `codes` give, classed by [`preflight_reason`]:
/// each code's token without `gate.allow`, and each administrative hold
/// named. Missing external-effect authority is an owner decision when
/// `press_supplies_authority`, else a hold. The verdict is the codes' own:
/// `Deny` when any code is a Deny, else `Held` when any is an administrative
/// hold, else `WouldAsk` when any is an owner decision, else `Allow`. It
/// reads no envelope window and no budget.
pub(crate) fn preflight_words(
    codes: &[GateReasonCode],
    press_supplies_authority: bool,
) -> ExternalEffectPreflight {
    let mut reasons = Vec::new();
    let mut holds = Vec::new();
    let mut denies = false;
    let mut asks = false;
    for &code in codes {
        let class = match preflight_reason(code) {
            PreflightReason::MissingAuthority if press_supplies_authority => {
                PreflightReason::OwnerDecision
            }
            PreflightReason::MissingAuthority => PreflightReason::AdministrativeHold,
            class => class,
        };
        match class {
            PreflightReason::Allow => continue,
            PreflightReason::Deny => denies = true,
            PreflightReason::OwnerDecision => asks = true,
            PreflightReason::AdministrativeHold | PreflightReason::MissingAuthority => {}
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
    let verdict = if denies {
        PreflightVerdict::Deny
    } else if !holds.is_empty() {
        PreflightVerdict::Held
    } else if asks {
        PreflightVerdict::WouldAsk
    } else {
        PreflightVerdict::Allow
    };
    ExternalEffectPreflight {
        verdict,
        reasons,
        holds,
        waits_for_envelope_window: false,
        rate_window_opens_at: None,
    }
}

/// The preflight answer `judgment` carries: its reasons and holds as
/// [`preflight_words`] classes them, Deny and Allow as the Gate decided
/// them, and a Pending outcome `Held` when any of its reasons is an
/// administrative hold, else `WouldAsk`. Its holds are named either way.
fn preflight_answer(judgment: &ExternalEffectJudgment) -> ExternalEffectPreflight {
    let words = preflight_words(
        judgment.decision().reason_codes(),
        judgment.press_supplies_authority(),
    );
    let verdict = match judgment.outcome() {
        GateOutcome::Allow => PreflightVerdict::Allow,
        GateOutcome::Deny => PreflightVerdict::Deny,
        GateOutcome::Pending if words.holds.is_empty() => PreflightVerdict::WouldAsk,
        GateOutcome::Pending => PreflightVerdict::Held,
    };
    ExternalEffectPreflight {
        verdict,
        waits_for_envelope_window: judgment.waits_for_envelope_window(),
        ..words
    }
}

/// [`preflight_answer`] with the admission's budget stage read on `txn` at
/// `at`, charging, reserving and suspending nothing: an Allow that goes now
/// meets its governing key's budgets in the chokepoint's order. A door that
/// paces and meets a full count-bound window waits for it. A priced tool
/// whose price a preauthorizing Spend row has no room for, or an exhausted
/// row on the key or its catalog pool, denies the effect
/// ([`GateReasonCode::DenyEffectorBudgetExhausted`]), as the reservation or
/// the charge would.
pub(crate) fn preflight_answer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    judgment: &ExternalEffectJudgment,
    budget: PreflightBudget<'_>,
    at: u64,
) -> Result<ExternalEffectPreflight> {
    let mut answer = preflight_answer(judgment);
    if answer.verdict != PreflightVerdict::Allow || answer.waits_for_envelope_window {
        return Ok(answer);
    }
    let Some(target) = judgment.budget_target() else {
        return Ok(answer);
    };
    if budget.paces
        && let connector_key::BudgetBlock::Paced { next_eligible_at } =
            connector_key::budget_block_pooled(
                store,
                txn,
                &target.key_id,
                &target.key,
                &target.governing_connector,
                budget.send_like,
                at,
                true,
            )?
    {
        answer.rate_window_opens_at = Some(next_eligible_at);
        return Ok(answer);
    }
    let price = match budget.priced_tool {
        Some(tool) => connector_key::tool_spend_price_in_txn(store, txn, &target.key, tool)?,
        None => None,
    };
    let no_room = connector_key::spend_overrun_in_txn(
        store,
        txn,
        &target.key_id,
        &target.key,
        &target.governing_connector,
        price.as_ref(),
        at,
        true,
    )?
    .is_some();
    if no_room
        || connector_key::preflight_effector_budgets_pooled(
            store,
            txn,
            &target.key_id,
            &target.key,
            &target.governing_connector,
            budget.send_like,
            at,
            true,
        )?
        .is_some()
    {
        answer.verdict = PreflightVerdict::Deny;
        answer
            .reasons
            .push(GateReasonCode::DenyEffectorBudgetExhausted.as_str());
    }
    Ok(answer)
}
