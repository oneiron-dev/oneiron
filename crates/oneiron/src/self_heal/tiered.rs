//! Model-graded detection over ARCH-0037 runs. No signed T1 run is minted here.
use super::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body, validate_token,
};
use crate::llm::decision::catalogue::TELEMETRY_ANOMALY;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionQuestion, DecisionReceipt, DecisionRung, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result, Vault, store::RetrievalRunRecord};
use rmpv::Value;
use std::time::{Duration, Instant};

/// A decision question's text bound. A detector's holds its prompt, its rubric and up to
/// `QUESTION_FRAMING` bytes of separators and evidence line.
const QUESTION_TEXT_MAX: usize = 16_384;
const QUESTION_FRAMING: usize = 256;

/// The dial a detector's questions run under unless the host picks another. It ends below
/// Human: a telemetry classifier never pages a person per run.
pub const DETECTOR_DIAL: DecisionDial = DecisionDial {
    first: DecisionRung::Local,
    ceiling: DecisionRung::Big,
    band: DecisionBand {
        low: 0.35,
        high: 0.65,
    },
};

/// A non-deterministic detector has only the proposed diagnostic door.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposedTier {
    Centroid,
    PromptClassifier,
    Judge,
    SessionJudge,
}
impl ProposedTier {
    fn token(self) -> &'static str {
        match self {
            Self::Centroid => "t2a",
            Self::PromptClassifier => "t2b",
            Self::Judge => "t3",
            Self::SessionJudge => "session_judge",
        }
    }
}

/// Policy is supplied by the host; prompts and rubrics are not shipped Rust constants.
#[derive(Clone, Debug)]
pub struct DetectorPolicy {
    pub family: String,
    pub class: DiagnosticEventClass,
    pub prompt: String,
    pub rubric: String,
    pub consecutive: usize,
}
impl DetectorPolicy {
    pub(super) fn validate(&self) -> Result<()> {
        validate_token(&self.family, "detector family is not a token")?;
        validate_token(
            &format!("session_judge.{}", self.family),
            "detector id is too long",
        )?;
        if self.prompt.is_empty()
            || self.rubric.is_empty()
            || self.consecutive == 0
            || self.consecutive > 64
            || self.prompt.len() + self.rubric.len() > QUESTION_TEXT_MAX - QUESTION_FRAMING
        {
            return Err(Error::InvalidConfig("invalid detector policy".into()));
        }
        Ok(())
    }

    /// The noul this policy asks at `tier`. Its id derives from the tier, the family and the
    /// exact wording, so a changed prompt or rubric is a new question with its own bands.
    /// `examples` counts the reviewed positive and negative findings that follow the
    /// assessed runs in the evidence.
    pub fn question(
        &self,
        tier: ProposedTier,
        examples: (usize, usize),
    ) -> Result<DecisionQuestion> {
        self.validate()?;
        let evidence_line = if examples == (0, 0) {
            String::new()
        } else {
            format!(
                "\n\nEvidence: the runs, then {} positive and {} negative reviewed findings.",
                examples.0, examples.1
            )
        };
        let text = format!("{}\n\nRubric:\n{}{evidence_line}", self.prompt, self.rubric);
        TELEMETRY_ANOMALY.question(
            &[tier.token().as_bytes(), self.family.as_bytes()],
            text,
            AnswerContract::Noul,
        )
    }
}

/// The shared decision path a detector's questions go through: the host's ladder, the
/// principal the answers are for, the dial and learned bands they run under, the bounded
/// state the host built from the runs, and each question's anytime budget. Telemetry reaches a
/// provider only as evidence ids and that state, as untrusted data, never as instructions; an
/// answer cannot choose its own detector id, event class or tier.
pub struct DetectorDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// A JSON object of at most `MAX_DECISION_STATE_BYTES`, read by every provider.
    pub state: &'a serde_json::Value,
    /// Each question's one clock, from when it is asked.
    pub budget: Duration,
}

impl DetectorDecisions<'_> {
    /// Abstaining fails the whole call, as a failed judge call did. A person the host's dial
    /// queues keeps that ask's own receipt; nothing here waits on them.
    fn raised(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<(bool, DecisionReceipt)> {
        let decision = self.ladder.run(
            question,
            self.principal,
            evidence,
            self.state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        match decision.answer {
            DecisionAnswer::Noul(raised) => Ok((raised, decision.receipt)),
            _ => Err(Error::InvalidConfig("detector question abstained".into())),
        }
    }
}

fn run_ids(runs: &[RetrievalRunRecord]) -> Result<Vec<EntityId>> {
    runs.iter()
        .map(|run| EntityId::from_bytes(run.run_id.as_bytes()))
        .collect()
}

/// A proposed-only output. No conversion from this type to SignedDetectorRun exists.
#[derive(Clone, Debug)]
pub struct ProposedDiagnostic {
    pub tier: ProposedTier,
    pub event_id: EntityId,
    pub event: DiagnosticEvent,
    /// The receipts of the decisions that raised it; none for the centroid rung.
    pub decisions: Vec<DecisionReceipt>,
}

pub(super) fn propose(
    vault: &Vault,
    tier: ProposedTier,
    policy: &DetectorPolicy,
    runs: &[RetrievalRunRecord],
    centroid: Option<([u8; 32], Vec<EntityId>)>,
    decisions: Vec<DecisionReceipt>,
) -> Result<Option<ProposedDiagnostic>> {
    let Some(last) = runs.last() else {
        return Ok(None);
    };
    let Some(first) = runs.first() else {
        return Ok(None);
    };
    let mut digest = blake3::Hasher::new();
    let mut evidence = Vec::new();
    for run in runs {
        let bytes = rmp_serde::to_vec_named(run)
            .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
        digest.update(&(bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
        evidence.push(EntityId::from_bytes(run.run_id.as_bytes())?);
    }
    evidence.sort();
    evidence.dedup();
    let centroid_snapshot = centroid.as_ref().map(|(hash, _)| *hash);
    let (digest, evidence) = centroid.unwrap_or((*digest.finalize().as_bytes(), evidence));
    let event = DiagnosticEvent {
        detector_id: format!("{}.{}", tier.token(), policy.family),
        event_class: policy.class,
        signal: None,
        actor_class: "system".into(),
        actor_ref: None,
        source: DiagnosticSourceKind::RetrievalTelemetry,
        criticality: DiagnosticCriticality::Normal,
        expected: Value::from(false),
        actual: Value::from(true),
        delta: Value::from(1),
        replay: DiagnosticReplayCoordinate {
            content_hash: digest,
            run_ref: Some(last.run_id.to_hex()),
            checkpoint_ref: None,
        },
        evidence_refs: evidence,
        valid_from: first.started_at,
        valid_to: None,
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    vault.emit_diagnostic_event(&id, &event)?;
    vault.capture_tier1_retrieval_window(id, runs, centroid_snapshot)?;
    Ok(Some(ProposedDiagnostic {
        tier,
        event_id: id,
        event,
        decisions,
    }))
}

pub(super) fn valid_runs(
    vault: &Vault,
    runs: &[RetrievalRunRecord],
    consecutive: usize,
) -> Result<()> {
    if runs.len() > 64
        || runs.len() < consecutive
        || runs.windows(2).any(|w| {
            (w[0].started_at, w[0].run_id.as_bytes()) >= (w[1].started_at, w[1].run_id.as_bytes())
        })
    {
        return Err(Error::InvalidConfig(
            "invalid ordered telemetry window".into(),
        ));
    }
    for run in runs {
        run.replay_state().validate()?;
        if vault.store.retrieval_run(run.run_id)?.as_ref() != Some(run) {
            return Err(Error::InvalidConfig(
                "unrecorded retrieval telemetry".into(),
            ));
        }
    }
    Ok(())
}

impl Vault {
    /// T2b spends model calls after the cheaper centroid rung did not match.
    /// Supply a strictly oldest-first telemetry window; `retrieval_runs` returns
    /// newest-first and its caller must reverse that bounded result first.
    pub fn classify_prompt(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        self.classify_prompt_with_examples(policy, decisions, runs, (&[], &[]))
    }

    /// `examples` are reviewed positive and negative diagnostic events, asked as evidence
    /// after each run.
    pub(super) fn classify_prompt_with_examples(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
        examples: (&[EntityId], &[EntityId]),
    ) -> Result<Option<ProposedDiagnostic>> {
        let question = policy.question(
            ProposedTier::PromptClassifier,
            (examples.0.len(), examples.1.len()),
        )?;
        valid_runs(self, runs, policy.consecutive)?;
        let mut streak = Vec::new();
        for run in runs {
            let mut evidence = run_ids(std::slice::from_ref(run))?;
            evidence.extend(examples.0.iter().chain(examples.1));
            let (raised, receipt) = decisions.raised(&question, &evidence)?;
            if raised {
                streak.push(receipt);
            } else {
                streak.clear();
            }
        }
        if streak.len() < policy.consecutive {
            return Ok(None);
        }
        propose(
            self,
            ProposedTier::PromptClassifier,
            policy,
            &runs[runs.len() - streak.len()..],
            None,
            streak,
        )
    }

    /// T3 receives an oldest-first bounded trace window and finds open anomalies.
    pub fn judge_retrieval_trace(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        let question = policy.question(ProposedTier::Judge, (0, 0))?;
        valid_runs(self, runs, policy.consecutive)?;
        let (raised, receipt) = decisions.raised(&question, &run_ids(runs)?)?;
        if !raised {
            return Ok(None);
        }
        propose(self, ProposedTier::Judge, policy, runs, None, vec![receipt])
    }

    /// Session quality is a T2/T3 model grade, never a BEAM score or auto arm.
    /// The telemetry window must be oldest-first and belong to one episode.
    pub fn judge_session_quality(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        let question = policy.question(ProposedTier::SessionJudge, (0, 0))?;
        valid_runs(self, runs, policy.consecutive)?;
        let Some(turn) = runs[0].turn else {
            return Err(Error::InvalidConfig("missing session identity".into()));
        };
        if runs
            .iter()
            .any(|run| run.turn.is_none_or(|t| t.episode_id != turn.episode_id))
        {
            return Err(Error::InvalidConfig("mixed sessions".into()));
        }
        let (raised, receipt) = decisions.raised(&question, &run_ids(runs)?)?;
        if !raised {
            return Ok(None);
        }
        propose(
            self,
            ProposedTier::SessionJudge,
            policy,
            runs,
            None,
            vec![receipt],
        )
    }
}
