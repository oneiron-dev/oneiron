//! A review's typed questions: each lens asks its verdict, severity, scope and (when the lens has
//! one) hard check through the shared decision path, as one pack. Optional notes text is
//! separate generation.
use super::*;
use crate::llm::decision::catalogue::CRITIC_REVIEW;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionQuestion, DecisionReceipt, DecisionRung, Reversibility, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use std::time::{Duration, Instant};

const VERDICTS: [(&str, CritiqueVerdict); 3] = [
    ("accept", CritiqueVerdict::Accept),
    ("revise", CritiqueVerdict::Revise),
    ("discard", CritiqueVerdict::Discard),
];
const SEVERITIES: [(&str, CritiqueSeverity); 5] = [
    ("info", CritiqueSeverity::Info),
    ("low", CritiqueSeverity::Low),
    ("medium", CritiqueSeverity::Medium),
    ("high", CritiqueSeverity::High),
    ("blocking", CritiqueSeverity::Blocking),
];

/// The dial a review's questions run under unless the host picks another. It ends below Human,
/// as the host's model transport did; a host dial that includes Human queues the ask with its
/// own receipt and the review fails, as a failed critic call did.
pub const REVIEW_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// The host's wording for each typed question, asked after the lens's own prompt contract, so
/// every question of one lens shares that prefix. Hosts supply and localize it.
#[derive(Debug, Clone)]
pub struct ReviewWording {
    pub verdict: String,
    pub severity: String,
    pub hard_check: String,
    pub out_of_scope: String,
}

impl ReviewWording {
    fn validate(&self) -> Result<()> {
        for text in [
            &self.verdict,
            &self.severity,
            &self.hard_check,
            &self.out_of_scope,
        ] {
            if text.trim().is_empty() || text.len() > MAX_CONTRACT_BYTES {
                return Err(invalid_critic_config("invalid review wording"));
            }
        }
        Ok(())
    }
}

/// One lens's typed answers, handed to the host's optional notes.
#[derive(Debug, Clone)]
pub struct ReviewFinding {
    pub input: CriticReviewInput,
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    pub hard_check_passed: Option<bool>,
    pub out_of_scope: bool,
}

/// Generated text beside one finding. Both parts are optional.
#[derive(Debug, Clone, Default)]
pub struct ReviewNote {
    pub evidence_refs: Vec<String>,
    pub suggested_edit: Option<String>,
    pub prediction: Option<CriticPrediction>,
}

/// Generation beside a typed review: evidence refs and a suggested edit per finding, from the
/// host's own model transport. The answers are already decided; a note cannot change them.
pub trait ReviewNotes {
    fn notes(&self, findings: &[ReviewFinding]) -> Result<Vec<ReviewNote>>;
}

/// The shared decision path a review's questions go through: the host's ladder, the principal
/// the answers are for, the dial and learned bands, the bounded state the host built from the
/// artifact, each lens's anytime budget, the wording, and optional notes. The target reaches a
/// provider as an evidence id and that state; run and attempt ids stay host metadata.
pub struct ReviewDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// A JSON object of at most `MAX_DECISION_STATE_BYTES`, read by every provider.
    pub state: &'a serde_json::Value,
    /// Each lens's one clock, from when its pack is asked.
    pub budget: Duration,
    pub wording: ReviewWording,
    pub notes: Option<&'a dyn ReviewNotes>,
}

#[derive(Clone, Copy)]
enum Field {
    Verdict,
    Severity,
    HardCheck,
    OutOfScope,
}

impl Field {
    const fn token(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::Severity => "severity",
            Self::HardCheck => "hard_check",
            Self::OutOfScope => "out_of_scope",
        }
    }
}

impl ReviewArtifactKind {
    const fn token(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Design => "design",
            Self::ClaimWrite => "claim_write",
        }
    }
}

impl ReviewDecisions<'_> {
    pub(super) fn validate(&self) -> Result<()> {
        self.wording.validate()
    }

    /// Asks every lens's questions and assembles one artifact per input, in input order.
    pub(super) fn review(
        &self,
        inputs: &[CriticReviewInput],
        at: u64,
    ) -> Result<(Vec<CritiqueArtifact>, Vec<DecisionReceipt>)> {
        let mut findings = Vec::with_capacity(inputs.len());
        let mut meta = Vec::with_capacity(inputs.len());
        let mut receipts = Vec::new();
        for input in inputs {
            let fields: &[Field] = if input.lens.hard_check {
                &[
                    Field::Verdict,
                    Field::Severity,
                    Field::HardCheck,
                    Field::OutOfScope,
                ]
            } else {
                &[Field::Verdict, Field::Severity, Field::OutOfScope]
            };
            let questions = fields
                .iter()
                .map(|&field| self.question(input, field))
                .collect::<Result<Vec<_>>>()?;
            // One answer per question, in order.
            let decisions = self.ask(&questions, &[input.target])?;
            let verdict = label(&decisions[0], &VERDICTS)?;
            let identity = rmp_serde::to_vec_named(&(
                questions[0].id,
                input.target,
                &input.run_id,
                input.branch_attempt,
                input.lens_ref,
                &input.type_ref,
                &input.axis,
            ))
            .map_err(|_| invalid_critic_config("review artifact identity"))?;
            // A project's review is its own artifact (FIX 6038); a vault
            // review keeps the identity it has always had.
            let mut hasher = blake3::Hasher::new();
            hasher.update(&identity);
            if let Some(project) = input.project {
                hasher.update(project.as_bytes());
            }
            let id = format!("review_{}", hasher.finalize().to_hex());
            meta.push((id, provenance_of(input.critic, &decisions[0])?));
            let severity = label(&decisions[1], &SEVERITIES)?;
            let hard_check_passed = if input.lens.hard_check {
                Some(noul(&decisions[2])?)
            } else {
                None
            };
            let out_of_scope = noul(&decisions[fields.len() - 1])?;
            receipts.extend(decisions.into_iter().map(|decision| decision.receipt));
            findings.push(ReviewFinding {
                input: input.clone(),
                verdict,
                severity,
                hard_check_passed,
                out_of_scope,
            });
        }
        let notes = match self.notes {
            Some(notes) => notes.notes(&findings)?,
            None => vec![ReviewNote::default(); findings.len()],
        };
        if notes.len() != findings.len() {
            return Err(invalid_critic_config(
                "review notes must cover every finding",
            ));
        }
        let mut artifacts = Vec::with_capacity(inputs.len());
        for ((finding, note), (id, provenance)) in findings.into_iter().zip(notes).zip(meta) {
            let input = finding.input;
            let mut artifact = CritiqueArtifact::new(
                id,
                input.run_id,
                input.branch_attempt,
                input.target.to_hex(),
                &input.lens,
                provenance.clone(),
                LearningCell::new(LearningPredicate::Reliability, input.lens_ref)
                    .executor(provenance.executor()?)
                    .type_ref(input.type_ref)
                    .axis(input.axis)
                    .project(input.project),
                finding.verdict,
                finding.severity,
                finding.hard_check_passed,
                note.evidence_refs,
                note.suggested_edit,
                at,
            )?;
            artifact.out_of_scope = finding.out_of_scope;
            artifact.prediction = note.prediction;
            validate_critique_artifact(&artifact)?;
            artifacts.push(artifact);
        }
        Ok((artifacts, receipts))
    }

    /// One field's question for one lens. Its id derives from the field, the artifact kind, the
    /// lens and the exact wording, so changed wording is a new question with its own bands.
    fn question(&self, input: &CriticReviewInput, field: Field) -> Result<DecisionQuestion> {
        let (wording, contract) = match field {
            Field::Verdict => (&self.wording.verdict, choice(&VERDICTS)),
            Field::Severity => (&self.wording.severity, choice(&SEVERITIES)),
            Field::HardCheck => (&self.wording.hard_check, AnswerContract::Noul),
            Field::OutOfScope => (&self.wording.out_of_scope, AnswerContract::Noul),
        };
        let text = format!("{}\n\n{wording}", input.lens.prompt_contract);
        CRITIC_REVIEW.question(
            &[
                field.token().as_bytes(),
                input.kind.token().as_bytes(),
                input.lens.domain.as_bytes(),
                input.lens.id.as_bytes(),
            ],
            text,
            contract,
        )
    }

    /// One lens's questions as one pack over the shared state, under one clock. Any abstaining
    /// answer fails the whole review, as a failed critic call did.
    fn ask(
        &self,
        questions: &[DecisionQuestion],
        evidence: &[EntityId],
    ) -> Result<Vec<TypedDecision>> {
        let questions = questions.iter().collect::<Vec<_>>();
        let decisions = self.ladder.run_pack(
            &questions,
            self.principal,
            evidence,
            self.state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        if decisions
            .iter()
            .any(|decision| matches!(decision.answer, DecisionAnswer::Abstain))
        {
            return Err(invalid_critic_config("review question abstained"));
        }
        Ok(decisions)
    }
}

fn choice<T>(table: &[(&str, T)]) -> AnswerContract {
    AnswerContract::Choice {
        options: table.iter().map(|(label, _)| (*label).to_owned()).collect(),
    }
}

fn label<T: Copy>(decision: &TypedDecision, table: &[(&str, T)]) -> Result<T> {
    match &decision.answer {
        DecisionAnswer::Choice(answer) => table
            .iter()
            .find(|(label, _)| *label == answer.as_str())
            .map(|(_, value)| *value)
            .ok_or_else(|| invalid_critic_config("review answer is not an option")),
        _ => Err(invalid_critic_config("review answer is not a choice")),
    }
}

fn noul(decision: &TypedDecision) -> Result<bool> {
    match decision.answer {
        DecisionAnswer::Noul(answer) => Ok(answer),
        _ => Err(invalid_critic_config("review answer is not yes or no")),
    }
}

/// The verdict's answering rung names the critic's model.
fn provenance_of(critic: WriteActor, decision: &TypedDecision) -> Result<CritiqueProvenance> {
    let pin = decision
        .receipt
        .providers
        .last()
        .ok_or_else(|| invalid_critic_config("review answer has no provider"))?;
    CritiqueProvenance::new(
        critic,
        pin.model.clone(),
        (!pin.version.is_empty()).then(|| pin.version.clone()),
    )
}
