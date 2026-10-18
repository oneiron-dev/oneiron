//! Typed consent-graduation public door. Authority and policy stay in the
//! existing ramp, graduation and standing-grant implementations.
use serde::{Deserialize, Serialize};

use super::{DemotionReason, RampScope, RampState, ScopeOutcomeStats};
use crate::consent::{AuthenticatedOwner, lifecycle::ConsentActReceipt};
use crate::edit_distance::graduation::{self, OfferAnswer, OfferAnswerOutcome, SnoozeState, ThresholdRow};
use crate::identity_topology::ProposalOutcome;
use crate::memory::{Memory, MemoryResult};
use crate::Vault;

/// The exact operation kind × target class × skill/agent tuple.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationScope {
    pub op_kind: String,
    pub target_class: String,
    pub actor: String,
}

impl GraduationScope {
    fn scope(&self) -> RampScope {
        RampScope {
            op_kind: self.op_kind.clone(),
            target_class: self.target_class.clone(),
            actor: self.actor.clone(),
        }
    }
}

impl From<RampScope> for GraduationScope {
    fn from(scope: RampScope) -> Self {
        Self { op_kind: scope.op_kind, target_class: scope.target_class, actor: scope.actor }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationScopeRequest {
    pub scope: GraduationScope,
}

/// Threshold and snooze knobs are policy inputs, never engine-default changes.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicy {
    pub scope_pattern: String,
    pub required_streak: u32,
    pub posterior_guard: f32,
    /// First and second decline backoffs, in seconds. The third decline pins.
    pub snooze_backoff_seconds: [u64; 2],
}

impl From<ThresholdRow> for GraduationPolicy {
    fn from(row: ThresholdRow) -> Self {
        Self {
            scope_pattern: row.scope_pattern,
            required_streak: row.required_streak,
            posterior_guard: row.posterior_guard,
            snooze_backoff_seconds: row.snooze_backoff_seconds,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicyRequest {
    #[serde(default)]
    pub scope: Option<GraduationScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationPolicies {
    pub rows: Vec<GraduationPolicy>,
    pub effective: Option<GraduationPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicySetRequest {
    pub policy: GraduationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationPolicyClearRequest {
    pub scope_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationChanged {
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraduationOutcome {
    ApprovedUntouched,
    ApprovedAmended,
    Rejected,
}

impl From<GraduationOutcome> for ProposalOutcome {
    fn from(outcome: GraduationOutcome) -> Self {
        match outcome {
            GraduationOutcome::ApprovedUntouched => Self::ApprovedUntouched,
            GraduationOutcome::ApprovedAmended => Self::ApprovedAmended,
            GraduationOutcome::Rejected => Self::Rejected,
        }
    }
}

impl From<ProposalOutcome> for GraduationOutcome {
    fn from(outcome: ProposalOutcome) -> Self {
        match outcome {
            ProposalOutcome::ApprovedUntouched => Self::ApprovedUntouched,
            ProposalOutcome::ApprovedAmended => Self::ApprovedAmended,
            ProposalOutcome::Rejected => Self::Rejected,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GraduationMode {
    #[serde(rename = "propose")]
    Propose,
    #[serde(rename = "offered")]
    Offered,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationStats {
    pub scope: GraduationScope,
    pub untouched_streak: u32,
    pub amended: u32,
    pub rejected: u32,
    pub last_outcome: Option<GraduationOutcome>,
    pub updated_at: u64,
    pub state: GraduationMode,
}

impl From<ScopeOutcomeStats> for GraduationStats {
    fn from(stats: ScopeOutcomeStats) -> Self {
        Self {
            scope: stats.scope.into(),
            untouched_streak: stats.untouched_streak,
            amended: stats.amended,
            rejected: stats.rejected,
            last_outcome: stats.last_outcome.map(Into::into),
            updated_at: stats.updated_at,
            state: match stats.state {
                RampState::Propose => GraduationMode::Propose,
                RampState::Offered => GraduationMode::Offered,
                RampState::Graduated => GraduationMode::Auto,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationOutcomeRequest {
    pub scope: GraduationScope,
    pub outcome: GraduationOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GraduationSnooze {
    None,
    Snoozed { count: u8, next_eligible_at: u64 },
    ManualPinned,
}

impl From<SnoozeState> for GraduationSnooze {
    fn from(state: SnoozeState) -> Self {
        match state {
            SnoozeState::None => Self::None,
            SnoozeState::Snoozed { count, next_eligible_at } => Self::Snoozed { count, next_eligible_at },
            SnoozeState::ManualPinned => Self::ManualPinned,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationTrustRow {
    pub scope: GraduationScope,
    pub stats: GraduationStats,
    pub threshold: GraduationPolicy,
    pub snooze: GraduationSnooze,
    pub grant_ref: Option<String>,
    pub offer_is_earned: bool,
    pub offer_reach: Option<String>,
}

impl From<graduation::TrustTableRow> for GraduationTrustRow {
    fn from(row: graduation::TrustTableRow) -> Self {
        Self {
            scope: row.scope.into(),
            stats: row.stats.into(),
            threshold: row.threshold.into(),
            snooze: row.snooze.into(),
            grant_ref: row.grant_ref,
            offer_is_earned: row.offer_is_earned,
            offer_reach: row.offer_reach,
        }
    }
}

/// An offer proposes the existing standing-grant door; reading grants nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationOffer {
    pub scope: GraduationScope,
    pub stats: GraduationStats,
    pub threshold: GraduationPolicy,
    pub reach: crate::vault_shape::ShapePlanReach,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
pub enum GraduationAnswer {
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "not-now")]
    NotNow,
    #[serde(rename = "manual_pinned")]
    ManualPinned,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationAnswerRequest {
    pub scope: GraduationScope,
    pub answer: GraduationAnswer,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GraduationAnswerReceipt {
    pub scope: GraduationScope,
    pub answer: GraduationAnswer,
    pub grant: Option<ConsentActReceipt>,
    pub snooze: GraduationSnooze,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GraduationDemotionReason {
    Rejected,
    Amended,
    AgentJudgment,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GraduationDemoteRequest {
    pub scope: GraduationScope,
    pub reason: GraduationDemotionReason,
}

pub fn policies(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationPolicyRequest,
) -> MemoryResult<GraduationPolicies> {
    vault.recheck_owner(owner)?;
    let effective = input.scope.map(|scope| {
        let scope = scope.scope();
        scope.validate()?;
        graduation::graduation_policy_for(vault, &scope).map(Into::into)
    }).transpose()?;
    Ok(GraduationPolicies {
        rows: graduation::graduation_policy_rows(vault)?.into_iter().map(Into::into).collect(),
        effective,
    })
}

pub fn set_policy(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationPolicySetRequest,
) -> MemoryResult<GraduationChanged> {
    let row = ThresholdRow {
        scope_pattern: input.policy.scope_pattern,
        required_streak: input.policy.required_streak,
        posterior_guard: input.policy.posterior_guard,
        snooze_backoff_seconds: input.policy.snooze_backoff_seconds,
    };
    graduation::set_graduation_policy_as_owner(vault, owner, &row)?;
    Ok(GraduationChanged { changed: true })
}

pub fn clear_policy(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationPolicyClearRequest,
) -> MemoryResult<GraduationChanged> {
    Ok(GraduationChanged {
        changed: graduation::clear_graduation_policy_as_owner(vault, owner, &input.scope_pattern)?,
    })
}

pub fn stats(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationScopeRequest,
) -> MemoryResult<Option<GraduationStats>> {
    vault.recheck_owner(owner)?;
    let scope = input.scope.scope();
    scope.validate()?;
    Ok(vault.scope_stats(&scope)?.map(Into::into))
}

pub fn record_outcome(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationOutcomeRequest,
) -> MemoryResult<GraduationStats> {
    Ok(vault.record_proposal_outcome_for_ramp(owner, &input.scope.scope(), input.outcome.into())?.into())
}

pub fn trust_table(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<Vec<GraduationTrustRow>> {
    vault.recheck_owner(owner)?;
    Ok(graduation::trust_table(vault)?.into_iter().map(Into::into).collect())
}

pub fn offers(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<Vec<GraduationOffer>> {
    vault.recheck_owner(owner)?;
    let scopes = vault.graduation_offers()?;
    let mut offers = Vec::new();
    for row in graduation::trust_table(vault)? {
        if scopes.contains(&row.scope) {
            offers.push(GraduationOffer {
                reach: vault.ramp_offer_reach(&row.scope)?,
                scope: row.scope.into(),
                stats: row.stats.into(),
                threshold: row.threshold.into(),
            });
        }
    }
    Ok(offers)
}

pub fn answer(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationAnswerRequest,
) -> MemoryResult<GraduationAnswerReceipt> {
    let answer = match input.answer {
        GraduationAnswer::Auto => OfferAnswer::GoAuto(owner),
        GraduationAnswer::NotNow => OfferAnswer::NotNow,
        GraduationAnswer::ManualPinned => OfferAnswer::ManualPinned,
    };
    let result = graduation::answer_graduation_offer_as_owner(vault, owner, &input.scope.scope(), answer)?;
    let (grant, snooze) = match result {
        OfferAnswerOutcome::Graduated(receipt) => (Some(receipt.into()), GraduationSnooze::None),
        OfferAnswerOutcome::Snoozed(state) => (None, state.into()),
    };
    Ok(GraduationAnswerReceipt { scope: input.scope, answer: input.answer, grant, snooze })
}

pub fn unpin(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationScopeRequest,
) -> MemoryResult<GraduationChanged> {
    graduation::unpin_scope_as_owner(vault, owner, &input.scope.scope())?;
    Ok(GraduationChanged { changed: true })
}

pub fn demote(
    vault: &Vault, owner: &AuthenticatedOwner, input: GraduationDemoteRequest,
) -> MemoryResult<GraduationChanged> {
    let reason = match input.reason {
        GraduationDemotionReason::Rejected => DemotionReason::Rejected,
        GraduationDemotionReason::Amended => DemotionReason::Amended,
        GraduationDemotionReason::AgentJudgment => DemotionReason::AgentJudgment,
    };
    vault.demote_scope_to_propose(owner, &input.scope.scope(), reason)?;
    Ok(GraduationChanged { changed: true })
}

pub fn demote_own(memory: &Memory<'_>, input: GraduationScopeRequest) -> MemoryResult<GraduationChanged> {
    memory.demote_own_ramp_scope(&input.scope.scope())?;
    Ok(GraduationChanged { changed: true })
}
