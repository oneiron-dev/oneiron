//! Pure stage-ladder schema types, validation, and ladder-query helpers.

use serde::{Deserialize, Serialize};

use super::projector::invalid;
use crate::EntityId;
use crate::Result;
use crate::campaign::claims::{EvidenceBasis, StageEvidenceClass, StageKey};

/// The ratified D+3 bump delay for no-show recovery, offered as preset data.
///
/// A default a ladder may adopt, never a threshold this module applies behind a
/// caller's back: [`NoShowRecoveryRule::bump_after_secs`] is what the recovery
/// plan actually reads.
pub const NO_SHOW_BUMP_AFTER_SECS: u64 = 3 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Ladder schema
// ---------------------------------------------------------------------------

/// Whether an earned transition writes the head or proposes it.
///
/// [`Self::Auto`] is the default posture: evidence that satisfies a configured
/// transition advances the stage. [`Self::Propose`] is a per-call dial for a
/// host that wants a human between evidence and pipeline movement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionMode {
    /// Earned evidence writes the stage head.
    Auto,
    /// Earned evidence writes a PROPOSED head for the existing claim-approval
    /// machinery to rule on. No CA-04 approval mechanism is minted.
    Propose,
}

/// Transition-request helper only; this is not the `crm.stage` wire value.
///
/// Deliberately not serde-derived: [`EntityId`] carries no serde impl and
/// `entity_id.rs` is a CA non-claim, so evidence references cross a wire through
/// CA-01's [`encode_crm_stage_value`] rather than a second serialization of the
/// same refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageEvidence {
    /// Which class of evidence this request cites.
    pub class: StageEvidenceClass,
    /// Machine derivation or owner attestation.
    pub basis: EvidenceBasis,
    /// Non-empty evidence references. An empty list is rejected at every door.
    pub evidence_refs: Vec<EntityId>,
    /// When the evidence was recorded.
    pub recorded_at: u64,
}

/// One declared stage. Position in [`StageLadderDefinition::stages`] IS the
/// ladder order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageDefinition {
    /// Opaque stage token, owned by CA-01's [`StageKey`].
    pub key: StageKey,
    /// Host-facing label. Content, not mechanism.
    pub label: String,
}

/// One configured way to earn a stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageTransitionRule {
    /// `None` means no live `crm.stage` head yet; `campaign.member` is not a stage.
    pub from: Option<StageKey>,
    /// Stage entered when this rule's evidence lands.
    pub to: StageKey,
    /// The one evidence class this transition accepts.
    pub evidence_class: StageEvidenceClass,
    /// Whether an owner attestation may stand in for machine evidence. Read
    /// together with the ladder's proposal boundary — see
    /// `require_owner_attestable`.
    pub owner_attested_allowed: bool,
}

/// The six ratified reply codes. Consultancy-neutral by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyCode {
    /// Wants to move now.
    PositiveNow,
    /// Interested, but not yet.
    PositiveLater,
    /// Points at someone else.
    Referral,
    /// Pushes back on a specific point.
    Objection,
    /// Declines.
    NotInterested,
    /// Objects to being contacted at all.
    Complaint,
}

/// What a coded reply does. The LADDER decides which code lands on which
/// disposition; no code-to-action mapping is hidden in this module's code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplyDisposition {
    /// Earn a stage, subject to a configured transition.
    Promote {
        /// Stage the reply earns.
        stage: StageKey,
    },
    /// Pause the membership with a wake condition.
    Snooze,
    /// Hand off to referral routing; no CA-04 write.
    RouteReferral,
    /// Keep the reply as history and change nothing.
    RecordOnly,
    /// Leave the cohort.
    Exit,
    /// Hold out of the cohort. Reuses CA-01 membership state; mints no second
    /// suppression primitive.
    Suppress,
}

/// One code-to-disposition row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRouteRule {
    /// The coded reply this row routes.
    pub code: ReplyCode,
    /// What it does.
    pub disposition: ReplyDisposition,
}

/// The ratified no-show recovery shape: same-day reschedule, then a bump, then
/// snooze. Each leg is a dial; the ORDER is not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoShowRecoveryRule {
    /// Offer a same-day reschedule first.
    pub same_day_reschedule: bool,
    /// Delay before the bump. [`NO_SHOW_BUMP_AFTER_SECS`] is the ratified D+3.
    pub bump_after_secs: u64,
    /// Snooze when the bump does not land.
    pub snooze_after_failed_bump: bool,
}

/// A whole stage ladder, as pure data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageLadderDefinition {
    /// Ladder identity, host-assigned.
    pub key: String,
    /// Declared stages, in ladder order.
    pub stages: Vec<StageDefinition>,
    /// Every configured way to earn a stage.
    pub transitions: Vec<StageTransitionRule>,
    /// Reply routing table.
    pub reply_routes: Vec<ReplyRouteRule>,
    /// No-show recovery dials.
    pub no_show_recovery: NoShowRecoveryRule,
}

// ---------------------------------------------------------------------------
// Ladder validation
// ---------------------------------------------------------------------------

/// Rejects a ladder that contradicts itself.
///
/// Every check answers "can this definition be read deterministically?", not
/// "is this a good sales process". Two uniqueness rules carry the weight:
/// `(from, to)` must be unique so a promotion names one rule, and
/// `(from, evidence_class)` must be unique so evidence-class-driven selection
/// (the calendar-outcome path) resolves from the current stage alone.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] with a distinct static reason per rejection:
/// empty ladder or stage key, duplicate stage, transition touching an undeclared
/// stage, duplicate or ambiguous transition, a reply code routed twice, or a
/// reply route promoting into an undeclared stage.
pub fn validate_ladder(definition: &StageLadderDefinition) -> Result<()> {
    if definition.key.trim().is_empty() {
        return Err(invalid("stage ladder key must not be empty"));
    }
    if definition.stages.is_empty() {
        return Err(invalid("stage ladder must declare at least one stage"));
    }
    let mut seen: Vec<&StageKey> = Vec::with_capacity(definition.stages.len());
    for stage in &definition.stages {
        if stage.key.0.trim().is_empty() {
            return Err(invalid("stage key must not be empty"));
        }
        if seen.contains(&&stage.key) {
            return Err(invalid("stage ladder declares a duplicate stage"));
        }
        seen.push(&stage.key);
    }
    validate_transitions(definition)?;
    validate_reply_routes(definition)
}

fn validate_transitions(definition: &StageLadderDefinition) -> Result<()> {
    let mut pairs = Vec::with_capacity(definition.transitions.len());
    let mut classes = Vec::with_capacity(definition.transitions.len());
    for rule in &definition.transitions {
        if rule
            .from
            .as_ref()
            .is_some_and(|from| !declares(definition, from))
        {
            return Err(invalid("stage transition leaves an undeclared stage"));
        }
        if !declares(definition, &rule.to) {
            return Err(invalid("stage transition enters an undeclared stage"));
        }
        let pair = (rule.from.clone(), rule.to.clone());
        if pairs.contains(&pair) {
            return Err(invalid("stage ladder declares a duplicate transition"));
        }
        pairs.push(pair);
        let class = (rule.from.clone(), rule.evidence_class);
        if classes.contains(&class) {
            return Err(invalid("stage ladder declares an ambiguous evidence class"));
        }
        classes.push(class);
    }
    Ok(())
}

fn validate_reply_routes(definition: &StageLadderDefinition) -> Result<()> {
    let mut codes = Vec::with_capacity(definition.reply_routes.len());
    for route in &definition.reply_routes {
        if codes.contains(&route.code) {
            return Err(invalid("stage ladder routes one reply code twice"));
        }
        codes.push(route.code);
        if let ReplyDisposition::Promote { stage } = &route.disposition
            && !declares(definition, stage)
        {
            return Err(invalid("reply route promotes into an undeclared stage"));
        }
    }
    Ok(())
}

// Ladder queries shared with the ingress children.

fn declares(definition: &StageLadderDefinition, key: &StageKey) -> bool {
    stage_index(definition, key).is_some()
}

pub(super) fn stage_index(definition: &StageLadderDefinition, key: &StageKey) -> Option<usize> {
    definition.stages.iter().position(|stage| stage.key == *key)
}

pub(super) fn transition_rule<'a>(
    definition: &'a StageLadderDefinition,
    from: Option<&StageKey>,
    to: &StageKey,
) -> Option<&'a StageTransitionRule> {
    definition
        .transitions
        .iter()
        .find(|rule| rule.from.as_ref() == from && rule.to == *to)
}

pub(super) fn evidence_class_rule<'a>(
    definition: &'a StageLadderDefinition,
    from: Option<&StageKey>,
    class: StageEvidenceClass,
) -> Option<&'a StageTransitionRule> {
    definition
        .transitions
        .iter()
        .find(|rule| rule.from.as_ref() == from && rule.evidence_class == class)
}

pub(super) fn proposal_boundary_index(definition: &StageLadderDefinition) -> Option<usize> {
    definition
        .transitions
        .iter()
        .filter(|rule| rule.evidence_class == StageEvidenceClass::DocumentArtifactAndSendReceipt)
        .filter_map(|rule| stage_index(definition, &rule.to))
        .min()
}
