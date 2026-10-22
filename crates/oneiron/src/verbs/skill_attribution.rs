//! Owner doors for proposal-delta settlement and skill attribution evidence.
//!
//! Settlement records the owner's exact replacement operations on a proposal
//! artifact, measures the delta from those recorded ops (never from a
//! client-supplied `d_norm`, never reconstructed from final text alone),
//! records the amendment evidence, judges it hunk by hunk and projects each
//! share to its own consumer. The attempt-lane doors beside it record outcome
//! evidence and run the attribution and positive projectors.
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::attribution::{
    AmendmentCause, AmendmentEvidence, AmendmentJudgment, PreferenceProposal,
    amendment_evidence as read_amendment_evidence, amendment_judgments, judge_amendment_hunks,
    judge_amendment_verdicts, pending_preference_proposals, project_amendment_lessons,
    project_amendment_reliability, project_edit_cost_claims, record_amendment_evidence,
    validate_share_vector,
};
use crate::edit_distance::delta::{AmendmentDelta, OpsSummary, amendment_delta};
use crate::edit_distance::{FinalizedProposalText, ProposalArtifactRef, finalized_proposal_text};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};
use crate::skill_attribution::{
    AttemptOutcome, AttributionJudgment, AttributionVerdict, DeviationCause, EditHunk,
    FollowedState, HunkVerdict, OutcomeEvidence, PositiveFinding, PositiveSkillProposal,
    SkillEditProposal, UnclearAttribution, attribution_judgments, pending_edit_proposals,
    pending_positive_proposals, read_attribution_cursor, record_attribution_evidence,
    retire_positive_proposal, run_attribution_projector, run_positive_attribution_pass,
    unclear_attributions,
};

fn invalid(message: &'static str) -> MemoryError {
    MemoryError::bad_request(message)
}

/// One attribution label, spelled as the engine's pinned token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributionLabel {
    SkillDefect,
    ExecutionLapse,
    Discovery,
    Environment,
    PreferenceShift,
    Unclear,
}

impl From<AttributionLabel> for AttributionVerdict {
    fn from(label: AttributionLabel) -> Self {
        match label {
            AttributionLabel::SkillDefect => Self::SkillDefect,
            AttributionLabel::ExecutionLapse => Self::ExecutionLapse,
            AttributionLabel::Discovery => Self::Discovery,
            AttributionLabel::Environment => Self::Environment,
            AttributionLabel::PreferenceShift => Self::PreferenceShift,
            AttributionLabel::Unclear => Self::Unclear,
        }
    }
}

impl From<AttributionVerdict> for AttributionLabel {
    fn from(verdict: AttributionVerdict) -> Self {
        match verdict {
            AttributionVerdict::SkillDefect => Self::SkillDefect,
            AttributionVerdict::ExecutionLapse => Self::ExecutionLapse,
            AttributionVerdict::Discovery => Self::Discovery,
            AttributionVerdict::Environment => Self::Environment,
            AttributionVerdict::PreferenceShift => Self::PreferenceShift,
            AttributionVerdict::Unclear => Self::Unclear,
        }
    }
}

/// Why the decider amended, spelled as the engine's pinned token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalAmendmentCause {
    ProposalWrong,
    ExternalChange,
    DeciderPreference,
}

impl From<ProposalAmendmentCause> for AmendmentCause {
    fn from(cause: ProposalAmendmentCause) -> Self {
        match cause {
            ProposalAmendmentCause::ProposalWrong => Self::ProposalWrong,
            ProposalAmendmentCause::ExternalChange => Self::ExternalChange,
            ProposalAmendmentCause::DeciderPreference => Self::DeciderPreference,
        }
    }
}

impl From<AmendmentCause> for ProposalAmendmentCause {
    fn from(cause: AmendmentCause) -> Self {
        match cause {
            AmendmentCause::ProposalWrong => Self::ProposalWrong,
            AmendmentCause::ExternalChange => Self::ExternalChange,
            AmendmentCause::DeciderPreference => Self::DeciderPreference,
        }
    }
}

/// One exact replacement the owner made: `before` must occur exactly once in
/// the text as it stands when this operation applies.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalReplacement {
    pub before: String,
    pub after: String,
}

/// The owner's label for one changed hunk, in replacement order.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalHunkVerdict {
    pub verdict: AttributionLabel,
    #[serde(default = "certain")]
    pub confidence: f32,
    #[serde(default)]
    pub note: Option<String>,
}

const fn certain() -> f32 {
    1.0
}

/// One entry of a claimed percentage vector. The vector is validated as a
/// distribution; routed shares are always the hunk-weighted computed ones.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalShareClaim {
    pub class: AttributionLabel,
    pub share: f32,
}

/// Settle one amended proposal: the proposed text, the owner's exact
/// replacements in order, the routing facts, and optionally the owner's
/// per-hunk labels and claimed percentage vector.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalDeltaSettleRequest {
    pub proposed_text: String,
    pub replacements: Vec<ProposalReplacement>,
    /// The actor whose proposal was amended.
    pub actor: EntityId,
    #[serde(default)]
    pub skill: Option<EntityId>,
    /// The terminal pack receipt of the attempt whose proposal was amended.
    #[serde(default)]
    pub attempt_receipt: Option<String>,
    #[serde(default)]
    pub source_turn_ref: Option<EntityId>,
    pub scope: String,
    #[serde(default)]
    pub cause: Option<ProposalAmendmentCause>,
    #[serde(default)]
    pub followed_skill: Option<bool>,
    #[serde(default)]
    pub skill_covered_step: Option<bool>,
    pub at: u64,
    /// One label per replacement, in order. Absent, the rule tier judges.
    #[serde(default)]
    pub hunk_verdicts: Option<Vec<ProposalHunkVerdict>>,
    /// The claimed percentage vector, validated before anything persists.
    #[serde(default)]
    pub shares: Option<Vec<ProposalShareClaim>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentDeltaView {
    pub proposed_ref: String,
    pub final_ref: String,
    pub source: String,
    pub d_norm: f32,
    pub ops_summary: OpsSummaryView,
    pub engine_ver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OpsSummaryView {
    pub ins: u32,
    pub del: u32,
    pub kept: u32,
    pub moved: u32,
    pub approx: bool,
}

impl From<OpsSummary> for OpsSummaryView {
    fn from(summary: OpsSummary) -> Self {
        Self {
            ins: summary.ins,
            del: summary.del,
            kept: summary.kept,
            moved: summary.moved,
            approx: summary.approx,
        }
    }
}

impl From<AmendmentDelta> for AmendmentDeltaView {
    fn from(delta: AmendmentDelta) -> Self {
        Self {
            proposed_ref: delta.proposed_ref,
            final_ref: delta.final_ref,
            source: delta.source.as_str().to_owned(),
            d_norm: delta.d_norm,
            ops_summary: delta.ops_summary.into(),
            engine_ver: delta.engine_ver,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentShareView {
    pub class: AttributionLabel,
    pub share: f32,
    pub subject: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentJudgmentView {
    pub receipt_id: String,
    pub split: Vec<AmendmentShareView>,
    pub scope: String,
    pub evidence_receipts: Vec<String>,
    pub d_norm: f32,
    pub at: u64,
}

impl From<AmendmentJudgment> for AmendmentJudgmentView {
    fn from(judgment: AmendmentJudgment) -> Self {
        Self {
            receipt_id: judgment.receipt_id,
            split: judgment
                .split
                .into_iter()
                .map(|share| AmendmentShareView {
                    class: share.class.into(),
                    share: share.share,
                    subject: share.subject,
                })
                .collect(),
            scope: judgment.scope,
            evidence_receipts: judgment.evidence_receipts,
            d_norm: judgment.d_norm,
            at: judgment.at,
        }
    }
}

/// One changed hunk as settled: the recorded replacement, its measured edit
/// mass, and the actor the recorded op attributes to when a span lines up.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettledHunkView {
    pub before: String,
    pub after: String,
    pub edit_mass: f64,
    pub actor: Option<EntityId>,
    pub trust: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalDeltaSettlement {
    pub receipt_id: String,
    pub artifact_ref: EntityId,
    pub proposed_text: String,
    pub final_text: String,
    pub delta: AmendmentDeltaView,
    pub hunks: Vec<SettledHunkView>,
    /// Absent when the judge abstained; the delta and evidence still stand.
    pub judgment: Option<AmendmentJudgmentView>,
    pub edit_cost_claims: Vec<EntityId>,
    pub reliability_heads: Vec<EntityId>,
    pub lessons: Vec<EntityId>,
}

/// The settlement receipt a proposal artifact's delta and judgment ride.
fn settlement_receipt(artifact: EntityId) -> String {
    format!("proposal-delta:{}", artifact.to_hex())
}

/// Applies the replacements to a scratch copy, refusing any that does not
/// match exactly once at its turn. Runs before any write.
fn preview_final_text(input: &ProposalDeltaSettleRequest) -> MemoryResult<String> {
    if input.replacements.is_empty() {
        return Err(invalid(
            "a proposal settlement records at least one replacement",
        ));
    }
    let mut text = input.proposed_text.clone();
    for replacement in &input.replacements {
        if replacement.before.is_empty() {
            return Err(invalid("a replacement names the exact text it replaces"));
        }
        let mut matches = text.match_indices(&replacement.before);
        let Some((start, _)) = matches.next() else {
            return Err(invalid("a replacement's text is absent from the proposal"));
        };
        if matches.next().is_some() {
            return Err(invalid("a replacement's text must occur exactly once"));
        }
        text.replace_range(start..start + replacement.before.len(), &replacement.after);
    }
    Ok(text)
}

fn claimed_shares(
    input: &ProposalDeltaSettleRequest,
) -> MemoryResult<Option<Vec<(AttributionVerdict, f32)>>> {
    let Some(shares) = &input.shares else {
        return Ok(None);
    };
    let vector: Vec<(AttributionVerdict, f32)> = shares
        .iter()
        .map(|claim| (claim.class.into(), claim.share))
        .collect();
    validate_share_vector(&vector)?;
    Ok(Some(vector))
}

pub fn skill_attribution_settle_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ProposalDeltaSettleRequest,
) -> MemoryResult<ProposalDeltaSettlement> {
    let owner_actor = owner.revalidate(vault)?;
    // Every pure check runs before the first write, so a refused settlement
    // records no artifact, no delta and no charge.
    let expected_final = preview_final_text(input)?;
    let expected_shares = claimed_shares(input)?;
    if let Some(verdicts) = &input.hunk_verdicts {
        if verdicts.len() != input.replacements.len() {
            return Err(invalid("one hunk verdict per replacement"));
        }
        if matches!(
            input.cause,
            Some(
                ProposalAmendmentCause::ExternalChange | ProposalAmendmentCause::DeciderPreference
            )
        ) {
            return Err(invalid(
                "a settled cause labels every hunk; per-hunk verdicts ride proposal_wrong",
            ));
        }
    }
    let record = record_proposal_ops(vault, owner, owner_actor, input, &expected_final)?;
    let artifact_ref = record.artifact_ref.entity_id();
    let receipt_id = settlement_receipt(artifact_ref);
    let delta = crate::edit_distance::delta::delta_from_recorded_ops(&record);
    vault.with_write_txn_grouped(|wtxn| {
        owner.revalidate_in_txn(vault, wtxn)?;
        crate::edit_distance::delta::put_amendment_delta_in_txn(vault, wtxn, &receipt_id, &delta)?;
        Ok(())
    })?;
    let mut evidence =
        AmendmentEvidence::new(receipt_id.as_str(), input.actor, input.scope.clone()).at(input.at);
    evidence.skill = input.skill;
    evidence.attempt_receipt = input.attempt_receipt.clone();
    evidence.cause = input.cause.map(Into::into);
    evidence.followed_skill = input.followed_skill;
    evidence.skill_covered_step = input.skill_covered_step;
    // The evidence door resolves the receipt's measured delta, the actor and
    // the skill inside its own checks before its write lands.
    record_amendment_evidence(vault, &evidence)?;
    let hunks: Vec<EditHunk<'_>> = input
        .replacements
        .iter()
        .map(|replacement| EditHunk {
            before: &replacement.before,
            after: &replacement.after,
        })
        .collect();
    let judgment = match &input.hunk_verdicts {
        Some(verdicts) => {
            let answers: Vec<HunkVerdict> = verdicts
                .iter()
                .map(|verdict| HunkVerdict {
                    verdict: verdict.verdict.into(),
                    confidence: verdict.confidence,
                    note: verdict.note.clone(),
                })
                .collect();
            judge_amendment_verdicts(
                vault,
                &receipt_id,
                &hunks,
                answers,
                expected_shares.as_deref(),
            )?
        }
        None => {
            if let Some(expected) = &expected_shares {
                validate_share_vector(expected)?;
            }
            judge_amendment_hunks(vault, &receipt_id, None, &hunks)?
        }
    };
    let (edit_cost_claims, reliability_heads, lessons) = match &judgment {
        Some(judgment) => (
            project_edit_cost_claims(vault, std::slice::from_ref(judgment))?,
            project_amendment_reliability(vault)?,
            project_amendment_lessons(vault, std::slice::from_ref(judgment))?,
        ),
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    let hunks = input
        .replacements
        .iter()
        .enumerate()
        .map(|(index, replacement)| {
            let span = record.ops_by_actor.get(index);
            SettledHunkView {
                before: replacement.before.clone(),
                after: replacement.after.clone(),
                edit_mass: crate::edit_distance::delta::delta_from_reconstructed(
                    &replacement.before,
                    &replacement.after,
                )
                .ops_summary
                .edit_mass(),
                actor: span.and_then(|(attribution, _)| {
                    attribution.actor().map(|actor| actor.entity_ref())
                }),
                trust: span.map(|(attribution, _)| attribution.as_str().to_owned()),
            }
        })
        .collect();
    Ok(ProposalDeltaSettlement {
        receipt_id,
        artifact_ref,
        proposed_text: record.proposed_text.clone(),
        final_text: record.final_text.clone(),
        delta: delta.into(),
        hunks,
        judgment: judgment.map(Into::into),
        edit_cost_claims,
        reliability_heads,
        lessons,
    })
}

#[cfg(feature = "sync")]
fn record_proposal_ops(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    owner_actor: EntityId,
    input: &ProposalDeltaSettleRequest,
    expected_final: &str,
) -> MemoryResult<FinalizedProposalText> {
    use crate::edge::EdgeActorClass;
    use crate::edit_distance::proposal_text::ProposalTextArtifact;
    use crate::write_envelope::WriteActor;

    let writer = WriteActor::new(owner_actor, EdgeActorClass::Human);
    let mut artifact =
        ProposalTextArtifact::open(vault, &input.proposed_text, &writer, input.source_turn_ref)?;
    for replacement in &input.replacements {
        let current = artifact.text();
        let start = current
            .find(&replacement.before)
            .ok_or_else(|| invalid("a replacement's text is absent from the proposal"))?;
        let char_start = current[..start].chars().count();
        let char_len = replacement.before.chars().count();
        let after = replacement.after.clone();
        artifact.edit_as(&writer, move |text| {
            text.delete(char_start, char_len)
                .map_err(|_| Error::InvariantViolation("proposal replacement delete"))?;
            text.insert(char_start, &after)
                .map_err(|_| Error::InvariantViolation("proposal replacement insert"))
        })?;
    }
    // The owner proof is rechecked before the recorded window is frozen.
    owner.revalidate(vault)?;
    let record = artifact.finalize(vault)?;
    if record.final_text != expected_final {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the recorded proposal ops did not land the settled final text",
            &[],
        ));
    }
    Ok(record)
}

#[cfg(not(feature = "sync"))]
fn record_proposal_ops(
    _vault: &Vault,
    _owner: &AuthenticatedOwner,
    _owner_actor: EntityId,
    _input: &ProposalDeltaSettleRequest,
    _expected_final: &str,
) -> MemoryResult<FinalizedProposalText> {
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "proposal delta settlement records CRDT ops, which a build without the sync feature cannot",
        &[],
    ))
}

/// Read one settlement by its receipt, with its artifact when the receipt
/// names one (or `artifact_ref` names it directly).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalDeltaReadRequest {
    pub receipt_id: String,
    #[serde(default)]
    pub artifact_ref: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalOpSpanView {
    pub actor: Option<EntityId>,
    pub trust: String,
    pub before_text: String,
    pub after_text: String,
    pub lamport: u32,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalArtifactView {
    pub artifact_ref: EntityId,
    pub proposed_text: String,
    pub final_text: String,
    pub source_turn_ref: Option<EntityId>,
    pub spans: Vec<ProposalOpSpanView>,
}

impl From<FinalizedProposalText> for ProposalArtifactView {
    fn from(record: FinalizedProposalText) -> Self {
        Self {
            artifact_ref: record.artifact_ref.entity_id(),
            proposed_text: record.proposed_text,
            final_text: record.final_text,
            source_turn_ref: record.source_turn_ref,
            spans: record
                .ops_by_actor
                .into_iter()
                .map(|(attribution, span)| ProposalOpSpanView {
                    actor: attribution.actor().map(|actor| actor.entity_ref()),
                    trust: attribution.as_str().to_owned(),
                    before_text: span.before_text,
                    after_text: span.after_text,
                    lamport: span.lamport,
                    timestamp: span.timestamp,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AmendmentEvidenceView {
    pub receipt_id: String,
    pub actor: EntityId,
    pub skill: Option<EntityId>,
    pub attempt_receipt: Option<String>,
    pub scope: String,
    pub cause: Option<ProposalAmendmentCause>,
    pub followed_skill: Option<bool>,
    pub skill_covered_step: Option<bool>,
    pub at: u64,
}

impl From<AmendmentEvidence> for AmendmentEvidenceView {
    fn from(evidence: AmendmentEvidence) -> Self {
        Self {
            receipt_id: evidence.receipt_id,
            actor: evidence.actor,
            skill: evidence.skill,
            attempt_receipt: evidence.attempt_receipt,
            scope: evidence.scope,
            cause: evidence.cause.map(Into::into),
            followed_skill: evidence.followed_skill,
            skill_covered_step: evidence.skill_covered_step,
            at: evidence.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PreferenceProposalView {
    pub receipt_id: String,
    pub scope: String,
    pub evidence_receipts: Vec<String>,
    pub share: f32,
    pub at: u64,
}

impl From<PreferenceProposal> for PreferenceProposalView {
    fn from(proposal: PreferenceProposal) -> Self {
        Self {
            receipt_id: proposal.receipt_id,
            scope: proposal.scope,
            evidence_receipts: proposal.evidence_receipts,
            share: proposal.share,
            at: proposal.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnclearNoteView {
    pub reason: String,
    pub leaning: Option<AttributionLabel>,
    pub confidence: f32,
    pub share: f32,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnclearAttributionView {
    pub lane: String,
    pub reference: String,
    pub evidence_receipts: Vec<String>,
    pub notes: Vec<UnclearNoteView>,
    pub at: u64,
}

impl From<UnclearAttribution> for UnclearAttributionView {
    fn from(row: UnclearAttribution) -> Self {
        Self {
            lane: row.lane.as_str().to_owned(),
            reference: row.reference,
            evidence_receipts: row.evidence_receipts,
            notes: row
                .notes
                .into_iter()
                .map(|note| UnclearNoteView {
                    reason: note.reason.as_str().to_owned(),
                    leaning: note.leaning.map(Into::into),
                    confidence: note.confidence,
                    share: note.share,
                    note: note.note,
                })
                .collect(),
            at: row.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProposalDeltaRead {
    pub receipt_id: String,
    pub delta: Option<AmendmentDeltaView>,
    pub artifact: Option<ProposalArtifactView>,
    pub evidence: Option<AmendmentEvidenceView>,
    pub judgment: Option<AmendmentJudgmentView>,
    pub preference_proposals: Vec<PreferenceProposalView>,
    pub unclear: Vec<UnclearAttributionView>,
}

pub fn skill_attribution_read_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ProposalDeltaReadRequest,
) -> MemoryResult<ProposalDeltaRead> {
    owner.revalidate(vault)?;
    let artifact = input
        .artifact_ref
        .or_else(|| {
            input
                .receipt_id
                .strip_prefix("proposal-delta:")
                .and_then(|hex| EntityId::from_hex(hex).ok())
        })
        .map(|id| finalized_proposal_text(vault, ProposalArtifactRef::new(id)))
        .transpose()?
        .flatten()
        .map(Into::into);
    let judgment = amendment_judgments(vault)?
        .into_iter()
        .find(|judgment| judgment.receipt_id == input.receipt_id)
        .map(Into::into);
    Ok(ProposalDeltaRead {
        receipt_id: input.receipt_id.clone(),
        delta: amendment_delta(vault, &input.receipt_id)?.map(Into::into),
        artifact,
        evidence: read_amendment_evidence(vault, &input.receipt_id)?.map(Into::into),
        judgment,
        preference_proposals: pending_preference_proposals(vault)?
            .into_iter()
            .filter(|proposal| proposal.receipt_id == input.receipt_id)
            .map(Into::into)
            .collect(),
        unclear: unclear_attributions(vault)?
            .into_iter()
            .filter(|row| row.reference == input.receipt_id)
            .map(Into::into)
            .collect(),
    })
}

/// How one loaded skill was followed, as recorded outcome evidence.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FollowedStateInput {
    Followed,
    Partly,
    Ignored,
    DeviatedWithReason {
        reason: String,
        #[serde(default)]
        cause: Option<String>,
    },
}

impl FollowedStateInput {
    fn engine(&self) -> MemoryResult<FollowedState> {
        Ok(match self {
            Self::Followed => FollowedState::Followed,
            Self::Partly => FollowedState::Partly,
            Self::Ignored => FollowedState::Ignored,
            Self::DeviatedWithReason { reason, cause } => FollowedState::DeviatedWithReason {
                reason: reason.clone(),
                cause: cause
                    .as_deref()
                    .map(|token| match token {
                        "incorrect_instruction" => Ok(DeviationCause::IncorrectInstruction),
                        "missing_instruction" => Ok(DeviationCause::MissingInstruction),
                        "executor_error" => Ok(DeviationCause::ExecutorError),
                        _ => Err(invalid("unknown deviation cause")),
                    })
                    .transpose()?,
            },
        })
    }
}

/// Record one attempt outcome for later attribution. Recording never
/// classifies; the projector owns the verdict.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionEvidenceRequest {
    pub receipt_ref: String,
    pub actor: EntityId,
    #[serde(default)]
    pub skill: Option<EntityId>,
    pub outcome: String,
    #[serde(default)]
    pub followed_skill: Option<bool>,
    #[serde(default)]
    pub followed_state: Option<FollowedStateInput>,
    #[serde(default)]
    pub skill_covered_step: Option<bool>,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionEvidenceReceipt {
    pub sequence: u64,
}

pub fn skill_attribution_evidence_record_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &AttributionEvidenceRequest,
) -> MemoryResult<AttributionEvidenceReceipt> {
    owner.revalidate(vault)?;
    let outcome = AttemptOutcome::parse(&input.outcome)
        .ok_or_else(|| invalid("outcome is succeeded or failed"))?;
    let mut evidence =
        OutcomeEvidence::new(input.receipt_ref.as_str(), input.actor, outcome, input.at);
    evidence.skill = input.skill;
    evidence.followed_skill = input.followed_skill;
    evidence.followed_state = input
        .followed_state
        .as_ref()
        .map(FollowedStateInput::engine)
        .transpose()?;
    evidence.skill_covered_step = input.skill_covered_step;
    // The engine door grounds the receipt, actor and skill before recording.
    let sequence = record_attribution_evidence(vault, &evidence)?;
    Ok(AttributionEvidenceReceipt { sequence })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttemptJudgmentView {
    pub sequence: u64,
    pub verdict: AttributionLabel,
    /// `None` once the actor it charged is erased (FIX 8988).
    pub subject: Option<EntityId>,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

impl From<AttributionJudgment> for AttemptJudgmentView {
    fn from(judgment: AttributionJudgment) -> Self {
        Self {
            sequence: judgment.sequence,
            verdict: judgment.verdict.into(),
            subject: judgment.subject,
            evidence_receipts: judgment.evidence_receipts,
            at: judgment.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkillEditProposalView {
    pub judgment_sequence: u64,
    pub skill: EntityId,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

impl From<SkillEditProposal> for SkillEditProposalView {
    fn from(proposal: SkillEditProposal) -> Self {
        Self {
            judgment_sequence: proposal.judgment_sequence,
            skill: proposal.skill,
            evidence_receipts: proposal.evidence_receipts,
            at: proposal.at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositiveProposalView {
    pub evidence_sequence: u64,
    pub skill: EntityId,
    pub actor: EntityId,
    pub finding: String,
    pub reason: Option<String>,
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

impl From<PositiveSkillProposal> for PositiveProposalView {
    fn from(proposal: PositiveSkillProposal) -> Self {
        let (finding, reason) = match proposal.finding {
            PositiveFinding::DeviationWorked { reason } => {
                ("deviation_worked".to_owned(), Some(reason))
            }
            PositiveFinding::UncoveredStepWorked => ("uncovered_step_worked".to_owned(), None),
        };
        Self {
            evidence_sequence: proposal.evidence_sequence,
            skill: proposal.skill,
            actor: proposal.actor,
            finding,
            reason,
            evidence_receipts: proposal.evidence_receipts,
            at: proposal.at,
        }
    }
}

/// Run one attribution pass. Absent `since_cursor`, the persisted cursor
/// admits only what is new.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionProjectRequest {
    #[serde(default)]
    pub since_cursor: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionProjection {
    pub cursor: u64,
    pub judgments: Vec<AttemptJudgmentView>,
    pub positive_proposals: Vec<PositiveProposalView>,
    pub pending_edit_proposals: Vec<SkillEditProposalView>,
}

pub fn skill_attribution_project_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &AttributionProjectRequest,
) -> MemoryResult<AttributionProjection> {
    owner.revalidate(vault)?;
    let since = match input.since_cursor {
        Some(cursor) => cursor,
        None => read_attribution_cursor(vault)?,
    };
    let judgments = run_attribution_projector(vault, since)?;
    let positive = run_positive_attribution_pass(vault)?;
    Ok(AttributionProjection {
        cursor: read_attribution_cursor(vault)?,
        judgments: judgments.into_iter().map(Into::into).collect(),
        positive_proposals: positive.into_iter().map(Into::into).collect(),
        pending_edit_proposals: pending_edit_proposals(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttributionListRequest {}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionJudgmentsView {
    pub cursor: u64,
    pub attempt_judgments: Vec<AttemptJudgmentView>,
    pub amendment_judgments: Vec<AmendmentJudgmentView>,
    pub unclear: Vec<UnclearAttributionView>,
}

pub fn skill_attribution_judgments_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &AttributionListRequest,
) -> MemoryResult<AttributionJudgmentsView> {
    owner.revalidate(vault)?;
    Ok(AttributionJudgmentsView {
        cursor: read_attribution_cursor(vault)?,
        attempt_judgments: attribution_judgments(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
        amendment_judgments: amendment_judgments(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
        unclear: unclear_attributions(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AttributionProposalsView {
    pub edit_proposals: Vec<SkillEditProposalView>,
    pub preference_proposals: Vec<PreferenceProposalView>,
    pub positive_proposals: Vec<PositiveProposalView>,
}

pub fn skill_attribution_proposals_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    _input: &AttributionListRequest,
) -> MemoryResult<AttributionProposalsView> {
    owner.revalidate(vault)?;
    Ok(AttributionProposalsView {
        edit_proposals: pending_edit_proposals(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
        preference_proposals: pending_preference_proposals(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
        positive_proposals: pending_positive_proposals(vault)?
            .into_iter()
            .map(Into::into)
            .collect(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PositiveRetireRequest {
    pub evidence_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PositiveRetireReceipt {
    pub retired: bool,
}

pub fn skill_attribution_positive_retire_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &PositiveRetireRequest,
) -> MemoryResult<PositiveRetireReceipt> {
    owner.revalidate(vault)?;
    Ok(PositiveRetireReceipt {
        retired: retire_positive_proposal(vault, input.evidence_sequence)?,
    })
}
