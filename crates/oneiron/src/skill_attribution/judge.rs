//! Classification: the deterministic rule tier, the host's decisions for the model tier
//! through the shared decision path, the note seam beside them, and verdict routing.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::llm::decision::catalogue::ATTRIBUTION_HUNK;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, MAX_DECISION_STATE_BYTES,
    ProviderDecision, ProviderPin, Reversibility, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;

use super::calibration::{AuditAnswerSource, RawAnswer};
use super::types::{
    AttemptOutcome, AttributionVerdict, DeviationCause, FollowedState, HunkVerdict, JudgeRequest,
    OutcomeEvidence,
};

/// [`CallPurpose::Other`] name for the model tier. Ambiguous evidence rides the
/// EXISTING engine LLM call surface under this purpose, inside the host's
/// [`AttributionDecisions`] providers — this module mints no client stack of
/// its own.
pub const ATTRIBUTION_CALL_PURPOSE_NAME: &str = "skill_attribution";

/// The rule tier's identity: its verdicts stamp `rule-attribution@1`.
const RULE_MODEL: &str = "rule-attribution";
const RULE_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// One outcome's answers, one per region in hunk order, and the exact
/// revision that gave them when one provider gave them all.
pub(crate) struct Attributed {
    pub(crate) answers: Vec<HunkVerdict>,
    pub(crate) revision: Option<String>,
}

/// What a judge said about one outcome before any floor or lane rule held an
/// answer: each region's raw label and probability, and the revision that
/// gave them, kept even when the outcome abstains. The held-out audit files
/// it as its calibration batch (OF-542).
pub(crate) struct JudgeTrace {
    pub(crate) source: AuditAnswerSource,
    pub(crate) answers: Vec<RawAnswer>,
    pub(crate) revision: Option<String>,
}

/// Generation beside a decided attribution: a short note for each answer that
/// is `unclear` or held below [`JudgeRequest::floor`], from the host's own
/// model transport. The labels and confidences are already decided; a note
/// cannot change them. The engine refuses a doubtful answer without one: the
/// note is what the Dreamer clusters.
pub trait AttributionNotes {
    /// One entry per answer, in hunk order; `None` where no note is needed.
    fn notes(
        &self,
        request: &JudgeRequest<'_>,
        answers: &[HunkVerdict],
    ) -> Result<Vec<Option<String>>>;
}

/// The [`CallPurpose`] a model-tier provider must stamp, so attribution calls
/// are budgeted and audited as their own class rather than hiding inside
/// another purpose's totals.
#[must_use]
pub fn attribution_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: ATTRIBUTION_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// The dial a host's attribution runs under unless it picks another. It ends
/// below Human: a doubtful hunk already holds in the unclear ledger, so the
/// ladder queues no person ask.
pub const ATTRIBUTION_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// The shared decision path the model tier goes through: the host's ladder,
/// the principal the answers are for, the dial and learned bands, the host's
/// wording of the per-hunk question, each outcome's anytime budget, and the
/// optional note seam. A host's decisions replace the rule tier; a host that
/// wants the rules first slots [`AttributionRules`] as its ladder's Rule rung.
///
/// A provider sees the actor and the skill as evidence ids, and the outcome's
/// routing facts and its hunks, each beside the id of the question that asks
/// about it, as the call's bounded state.
pub struct AttributionDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    /// Each outcome's one clock, from when its pack is asked.
    pub budget: Duration,
    pub notes: Option<&'a dyn AttributionNotes>,
}

impl AttributionDecisions<'_> {
    /// Labels each region of `request` as one pack: one Choice per region over
    /// the labels its lane admits, keyed by lane and position, with the
    /// decision's probability as its confidence. A region that abstains
    /// abstains the outcome, as a judge did. Doubtful answers then take their
    /// notes from [`AttributionNotes`]. The trace beside it keeps every raw
    /// answer, abstaining ones too.
    pub(crate) fn answer(
        &self,
        request: &JudgeRequest<'_>,
    ) -> Result<(Option<Attributed>, JudgeTrace)> {
        let options: Vec<String> = AttributionVerdict::ALL
            .iter()
            .filter(|verdict| verdict.valid_in(request.lane))
            .map(|verdict| verdict.as_str().to_owned())
            .collect();
        let questions = (0..request.regions())
            .map(|index| {
                let position = index.to_string();
                ATTRIBUTION_HUNK.question(
                    &[request.lane.as_str().as_bytes(), position.as_bytes()],
                    self.wording.clone(),
                    AnswerContract::Choice {
                        options: options.clone(),
                    },
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let evidence: Vec<EntityId> = std::iter::once(request.evidence.actor)
            .chain(request.evidence.skill)
            .collect();
        let decisions = self.ladder.run_pack(
            &questions.iter().collect::<Vec<_>>(),
            self.principal,
            &evidence,
            &bounded_state(request, &questions),
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        let revision = revision(&decisions);
        let trace = JudgeTrace {
            source: AuditAnswerSource::Model,
            answers: decisions
                .iter()
                .map(|decision| RawAnswer {
                    label: match &decision.answer {
                        DecisionAnswer::Choice(label) => Some(label.clone()),
                        _ => None,
                    },
                    confidence: decision.probability,
                })
                .collect(),
            revision: revision.clone(),
        };
        let mut answers = Vec::with_capacity(decisions.len());
        for decision in &decisions {
            let (DecisionAnswer::Choice(label), Some(probability)) =
                (&decision.answer, decision.probability)
            else {
                return Ok((None, trace));
            };
            let Some(verdict) = AttributionVerdict::parse(label) else {
                return Ok((None, trace));
            };
            answers.push(HunkVerdict::with_confidence(verdict, narrow(probability)));
        }
        if let Some(notes) = self.notes
            && answers.iter().any(|answer| doubtful(answer, request.floor))
        {
            let notes = notes.notes(request, &answers)?;
            if notes.len() != answers.len() {
                return Err(Error::InvalidClaimBody(
                    "attribution notes must cover every hunk",
                ));
            }
            for (answer, note) in answers.iter_mut().zip(notes) {
                answer.note = note;
            }
        }
        Ok((Some(Attributed { answers, revision }), trace))
    }
}

/// An answer the engine files as `unclear`, so it needs a note.
fn doubtful(answer: &HunkVerdict, floor: f32) -> bool {
    answer.verdict == AttributionVerdict::Unclear
        || !answer.confidence.is_finite()
        || answer.confidence < floor
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "a unit-interval probability narrowed to the judge's f32 confidence"
)]
fn narrow(probability: f64) -> f32 {
    probability as f32
}

/// The one provider every answer came from, as `model@version`; `None` when
/// they differ, so the verdicts stay unstamped.
fn revision(decisions: &[TypedDecision]) -> Option<String> {
    let mut pins = decisions
        .iter()
        .map(|decision| decision.receipt.providers.last());
    let first = pins.next()??;
    pins.all(|pin| pin == Some(first))
        .then(|| format!("{}@{}", first.model, first.version))
        .filter(|revision| revision.len() <= 256)
}

/// The call's bounded state. Each side of each hunk is cut shorter, halving,
/// until the whole fits [`MAX_DECISION_STATE_BYTES`]; `cut_at_bytes` says
/// where, so a provider knows it reads a cut text.
fn bounded_state(request: &JudgeRequest<'_>, questions: &[DecisionQuestion]) -> Value {
    let longest = request
        .hunks
        .iter()
        .map(|hunk| hunk.before.len().max(hunk.after.len()))
        .max()
        .unwrap_or(0);
    let mut cut = None;
    loop {
        let state = request_state(request, questions, cut);
        let fits =
            serde_json::to_vec(&state).is_ok_and(|bytes| bytes.len() <= MAX_DECISION_STATE_BYTES);
        cut = match cut {
            _ if fits => return state,
            None if longest > 0 => Some(longest / 2),
            Some(bytes) if bytes > 0 => Some(bytes / 2),
            // Nothing left to cut: the ladder refuses the state.
            _ => return state,
        };
    }
}

fn request_state(
    request: &JudgeRequest<'_>,
    questions: &[DecisionQuestion],
    cut: Option<usize>,
) -> Value {
    let hunks: Vec<Value> = request
        .hunks
        .iter()
        .zip(questions)
        .map(|(hunk, question)| {
            json!({
                "question": question.id.to_hex(),
                "before": cut_text(hunk.before, cut),
                "after": cut_text(hunk.after, cut),
            })
        })
        .collect();
    json!({
        "lane": request.lane.as_str(),
        "floor": request.floor,
        "receipt_ref": request.evidence.receipt_ref,
        "facts": RoutingFacts::of(request.evidence),
        "hunks": hunks,
        "cut_at_bytes": cut,
    })
}

fn cut_text(text: &str, cut: Option<usize>) -> &str {
    let Some(cut) = cut else {
        return text;
    };
    let mut end = text.len().min(cut);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The routing facts the rule table reads, as the call's state carries them.
#[derive(Debug, Serialize, Deserialize)]
struct RoutingFacts {
    outcome: String,
    has_skill: bool,
    followed_skill: Option<bool>,
    followed_state: Option<String>,
    deviation_reason: Option<String>,
    deviation_cause: Option<String>,
    skill_covered_step: Option<bool>,
}

impl RoutingFacts {
    fn of(evidence: &OutcomeEvidence) -> Self {
        let (followed_state, deviation_reason, deviation_cause) = match &evidence.followed_state {
            None => (None, None, None),
            Some(FollowedState::Followed) => (Some("followed"), None, None),
            Some(FollowedState::Partly) => (Some("partly"), None, None),
            Some(FollowedState::Ignored) => (Some("ignored"), None, None),
            Some(FollowedState::DeviatedWithReason { reason, cause }) => (
                Some("deviated_with_reason"),
                Some(reason.clone()),
                cause.map(|cause| match cause {
                    DeviationCause::IncorrectInstruction => "incorrect_instruction",
                    DeviationCause::MissingInstruction => "missing_instruction",
                    DeviationCause::ExecutorError => "executor_error",
                }),
            ),
        };
        Self {
            outcome: evidence.outcome.as_str().to_owned(),
            has_skill: evidence.skill.is_some(),
            followed_skill: evidence.followed_skill,
            followed_state: followed_state.map(str::to_owned),
            deviation_reason,
            deviation_cause: deviation_cause.map(str::to_owned),
            skill_covered_step: evidence.skill_covered_step,
        }
    }
}

/// The deterministic routing tier (ARCH-0053 §4).
///
/// | outcome | followed skill | skill covered step | verdict |
/// |---|---|---|---|
/// | failed | yes | yes | `SkillDefect` — the content was wrong |
/// | failed | ignored | — | `ExecutionLapse` — the executor ignored it |
/// | failed | partly | — | abstain — assess the partial work |
/// | failed | deviated with reason | — | resolved cause routes defect, discovery or lapse; otherwise abstain |
/// | failed | yes | no | `Discovery` — the content was missing |
/// | succeeded | — | — | abstain — a win attributes nothing here |
/// | any fact unsettled | | | abstain — the model tier's case |
///
/// A SUCCEEDED attempt abstains on purpose: this projector routes BLAME.
/// Crediting a win is the reliability posterior's job (ONE-1738), which reads
/// the same receipts.
///
/// It answers whenever a host brings no decisions, every region with its one
/// verdict, certain. As a host ladder's Rule rung it reads the routing facts
/// from the call's state and answers the label, certain, when the question
/// offers it; otherwise it abstains.
#[derive(Debug, Clone, Copy, Default)]
pub struct AttributionRules;

impl AttributionRules {
    /// The rule's verdict on every region of `request`, or `None` to abstain,
    /// beside its trace.
    pub(crate) fn answer(request: &JudgeRequest<'_>) -> (Option<Attributed>, JudgeTrace) {
        let verdict = rule_verdict(&RoutingFacts::of(request.evidence));
        let revision = Some(format!("{RULE_MODEL}@{RULE_VERSION}"));
        let trace = JudgeTrace {
            source: AuditAnswerSource::Rule,
            answers: vec![
                RawAnswer {
                    label: verdict.map(|verdict| verdict.as_str().to_owned()),
                    confidence: verdict.map(|_| 1.0),
                };
                request.regions()
            ],
            revision: revision.clone(),
        };
        let attributed = verdict.map(|verdict| Attributed {
            answers: vec![HunkVerdict::certain(verdict); request.regions()],
            revision,
        });
        (attributed, trace)
    }
}

impl DecisionProvider for AttributionRules {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Rule,
            model: RULE_MODEL.to_owned(),
            version: RULE_VERSION.to_owned(),
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let verdict = call
            .state
            .get("facts")
            .and_then(|facts| RoutingFacts::deserialize(facts).ok())
            .and_then(|facts| rule_verdict(&facts))
            .filter(|verdict| {
                matches!(
                    &call.question.contract,
                    AnswerContract::Choice { options }
                        if options.iter().any(|option| option == verdict.as_str())
                )
            });
        Ok(ProviderDecision {
            answer: verdict.map_or(DecisionAnswer::Abstain, |verdict| {
                DecisionAnswer::Choice(verdict.as_str().to_owned())
            }),
            probability: verdict.map(|_| 1.0),
            paired: None,
            person: None,
            served: None,
        })
    }
}

/// The table above over `facts`; `None` abstains.
fn rule_verdict(facts: &RoutingFacts) -> Option<AttributionVerdict> {
    if facts.outcome != AttemptOutcome::Failed.as_str() {
        return None;
    }
    match facts.followed_state.as_deref() {
        Some("ignored") => return Some(AttributionVerdict::ExecutionLapse),
        Some("deviated_with_reason") => {
            return match facts.deviation_cause.as_deref() {
                Some("executor_error") => Some(AttributionVerdict::ExecutionLapse),
                Some("incorrect_instruction") if facts.has_skill => {
                    Some(AttributionVerdict::SkillDefect)
                }
                Some("missing_instruction") if facts.has_skill => {
                    Some(AttributionVerdict::Discovery)
                }
                _ => None,
            };
        }
        Some("followed") => {}
        Some(_) => return None,
        None => {
            if !facts.followed_skill? {
                return Some(AttributionVerdict::ExecutionLapse);
            }
        }
    }
    // The remaining branches attribute to the SKILL, so an evidence row
    // with no skill in the manifest cannot be routed: fail to the actor's
    // lane would be a fabrication, so abstain.
    let skill_covered_step = facts.skill_covered_step?;
    if !facts.has_skill {
        return None;
    }
    Some(if skill_covered_step {
        AttributionVerdict::SkillDefect
    } else {
        AttributionVerdict::Discovery
    })
}

/// The entity a verdict routes to, or `None` when it charges nobody.
///
/// Three labels route to nothing on purpose: an environment verdict blames no
/// entity at all, an unclear one holds until the Dreamer has clustered it, and
/// a preference shift is [`crate::edit_distance::attribution`]'s to turn into
/// a proposal (the attempt lane never admits one). None of them leaves a
/// judgment row, rather than charging the nearest actor.
pub(super) fn verdict_subject(
    verdict: AttributionVerdict,
    evidence: &OutcomeEvidence,
) -> Option<EntityId> {
    match verdict {
        AttributionVerdict::ExecutionLapse => Some(evidence.actor),
        AttributionVerdict::SkillDefect | AttributionVerdict::Discovery => evidence.skill,
        AttributionVerdict::Environment
        | AttributionVerdict::PreferenceShift
        | AttributionVerdict::Unclear => None,
    }
}
