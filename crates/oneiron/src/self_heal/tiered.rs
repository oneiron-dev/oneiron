//! Model-graded detection over ARCH-0037 runs. No signed T1 run is minted here. A positive
//! finding files the Coach's issue in the write that emits it, and a window asked whole with
//! no finding is a clean judgment for the Coach's open issues (OF-418 L3).
use super::issue_evidence::Observation;
use super::issue_work::ModelFinding;
use super::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body, validate_token,
};
use crate::limit_ask::EngineLimit;
use crate::llm::decision::catalogue::TELEMETRY_ANOMALY;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionLadder,
    DecisionQuestion, DecisionReceipt, DecisionRung, Reversibility,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result, Vault, store::RetrievalRunRecord};
use rmpv::Value;
use std::borrow::Cow;
use std::time::{Duration, Instant};

/// A decision question's text room (the ladder's typed-question bound). A detector's
/// question holds its prompt, its rubric and up to `QUESTION_FRAMING` bytes of separators
/// and evidence line; wording past that room rides whole in the state (OF-418 L7).
const QUESTION_TEXT_MAX: usize = 16_384;
const QUESTION_FRAMING: usize = 256;

/// The dial a detector's questions run under. It ends below Human: a telemetry classifier
/// never pages a person per run. The host starts it at its own first staffed rung, up to
/// this ceiling and in this band (OF-418 L9); `Local` is the first rung only where no host
/// picks one.
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
    pub(super) fn token(self) -> &'static str {
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
    /// A positive `consecutive` is the host's to set: the Vault entry points
    /// ask past `limits.detector_consecutive`. The prompt and rubric go whole
    /// at any length: past the question's text room they ride in the state
    /// (OF-418 L7), measured at `limits.maintenance_text_bytes`.
    pub(super) fn validate(&self) -> Result<()> {
        validate_token(&self.family, "detector family is not a token")?;
        validate_token(
            &format!("session_judge.{}", self.family),
            "detector id is too long",
        )?;
        if self.prompt.is_empty() || self.rubric.is_empty() || self.consecutive == 0 {
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
        Ok(self.asked(tier, examples)?.question)
    }

    /// [`Self::question`] with the wording it leaves to the state. Wording within the text
    /// room is the question's own text, as it always was, so its question and bands stand.
    /// Past the room the question is short and keyed by the wording's digest, so changed
    /// wording is still a new question, and the prompt and rubric ride whole as the state's
    /// `detector` field (OF-418 L7).
    fn asked(&self, tier: ProposedTier, examples: (usize, usize)) -> Result<Asked> {
        self.validate()?;
        let evidence_line = if examples == (0, 0) {
            String::new()
        } else {
            format!(
                "\n\nEvidence: the runs, then {} positive and {} negative reviewed findings.",
                examples.0, examples.1
            )
        };
        if self.prompt.len() + self.rubric.len() <= QUESTION_TEXT_MAX - QUESTION_FRAMING {
            let text = format!("{}\n\nRubric:\n{}{evidence_line}", self.prompt, self.rubric);
            return Ok(Asked {
                question: TELEMETRY_ANOMALY.question(
                    &[tier.token().as_bytes(), self.family.as_bytes()],
                    text,
                    AnswerContract::Noul,
                )?,
                wording: None,
            });
        }
        let mut hasher = blake3::Hasher::new();
        for part in [self.prompt.as_str(), self.rubric.as_str()] {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = hasher.finalize();
        let text = format!(
            "Does this telemetry show the anomaly the detector's prompt describes, judged by \
             its rubric? The prompt and the rubric are the state's `detector` field, whole.\
             {evidence_line}"
        );
        Ok(Asked {
            question: TELEMETRY_ANOMALY.question(
                &[
                    tier.token().as_bytes(),
                    self.family.as_bytes(),
                    digest.as_bytes().as_slice(),
                ],
                text,
                AnswerContract::Noul,
            )?,
            wording: Some(serde_json::json!({
                "prompt": self.prompt,
                "rubric": self.rubric,
            })),
        })
    }
}

/// A detector's question as asked: the typed question and, for wording past the question's
/// text room, the prompt and rubric that ride whole in every call's state (OF-418 L7).
struct Asked {
    question: DecisionQuestion,
    wording: Option<serde_json::Value>,
}

/// The shared decision path a detector's questions go through: the host's ladder, the
/// principal the answers are for, the dial and learned bands they run under, the whole
/// state the host built from the runs, and each question's anytime budget. Telemetry reaches a
/// provider only as evidence ids and that state, as untrusted data, never as instructions; an
/// answer cannot choose its own detector id, event class or tier.
pub struct DetectorDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    /// A JSON object, whole, read by every provider: its producer measures it
    /// at `limits.maintenance_text_bytes` and never cuts it.
    pub state: &'a serde_json::Value,
    /// Each question's one clock, from when it is asked.
    pub budget: Duration,
}

impl DetectorDecisions<'_> {
    /// One question over `state`, the host's or one built from it. Abstaining fails the
    /// whole call, as a failed judge call did. A person the host's dial queues keeps that
    /// ask's own receipt; nothing here waits on them.
    fn raised_with_state(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Result<(bool, DecisionReceipt)> {
        let decision = self.ladder.run(
            question,
            self.principal,
            evidence,
            state,
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

/// The host's state with the one run a question grades named as its `target` (FIX 2481):
/// its id and its whole record. The window and the reviewed examples stay whole beside it,
/// and so does the wording the question left to the state.
fn targeted(
    state: &serde_json::Value,
    run: &RetrievalRunRecord,
    wording: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    let record = serde_json::to_value(run)
        .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
    let mut state = with_wording(state, wording)?.into_owned();
    let Some(fields) = state.as_object_mut() else {
        return Err(Error::InvalidConfig("invalid decision state".into()));
    };
    fields.insert(
        "target".into(),
        serde_json::json!({ "run": run.run_id.to_hex(), "record": record }),
    );
    Ok(state)
}

/// The host's state with the wording a question left to it (OF-418 L7) as its `detector`
/// field, whole; the host's own state when the question holds its wording.
fn with_wording<'s>(
    state: &'s serde_json::Value,
    wording: Option<&serde_json::Value>,
) -> Result<Cow<'s, serde_json::Value>> {
    let Some(wording) = wording else {
        return Ok(Cow::Borrowed(state));
    };
    let mut state = state.clone();
    let Some(fields) = state.as_object_mut() else {
        return Err(Error::InvalidConfig("invalid decision state".into()));
    };
    fields.insert("detector".into(), wording.clone());
    Ok(Cow::Owned(state))
}

/// Folds one asked state's exact bytes into a window's context digest (OF-418 L3).
fn read_state(context: &mut blake3::Hasher, bytes: &[u8]) {
    context.update(&(bytes.len() as u64).to_be_bytes());
    context.update(bytes);
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

/// What a positive finding was judged on beside its runs (OF-418 L3): the revision of its
/// recipe, the pins of what it read, and a digest of the exact states its questions read. Its
/// Coach issue is keyed by the recipe; the basis rides whole in the issue's row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FindingBasis {
    /// The recipe it ran under: [`recipe_revision`].
    pub(crate) recipe_revision: [u8; 32],
    /// Engine-authored pins of what it read: `question:<id>@<version>`, `example:<id>`,
    /// `corpus:<revision>` and `centroid:<snapshot>`.
    pub(crate) source_pins: Vec<String>,
    /// blake3 over every asked part's exact state, in order, each length-prefixed; a
    /// centroid finding's snapshot hash.
    pub(crate) context_digest: [u8; 32],
}

/// The revision of the recipe a finding runs under (OF-418 L3): its tier, family, class, whole
/// prompt and rubric, consecutive count, the reviewed positive and negative examples it asks
/// with, and a T2a corpus's revision. A changed recipe is a new revision, never an equivalent.
pub(super) fn recipe_revision(
    policy: &DetectorPolicy,
    tier: ProposedTier,
    examples: (&[EntityId], &[EntityId]),
    corpus: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.self_heal.finding_recipe.v1\0");
    for part in [
        tier.token(),
        policy.family.as_str(),
        policy.class.as_str(),
        policy.prompt.as_str(),
        policy.rubric.as_str(),
    ] {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(&(policy.consecutive as u64).to_be_bytes());
    for ids in [examples.0, examples.1] {
        hash.update(&(ids.len() as u64).to_be_bytes());
        for id in ids {
            hash.update(id.as_bytes());
        }
    }
    match corpus {
        Some(revision) => {
            hash.update(&[1]);
            hash.update(revision);
        }
        None => {
            hash.update(&[0]);
        }
    }
    *hash.finalize().as_bytes()
}

/// Emits a positive finding and files its Coach issue, keyed by `basis`, in the same write
/// (OF-418 L3), then captures its failure-signal witness, an export of its own opt-in. A
/// failed intake errors, so the host leaves the window ungraded and the next pass files it.
pub(super) fn propose(
    vault: &Vault,
    tier: ProposedTier,
    policy: &DetectorPolicy,
    runs: &[RetrievalRunRecord],
    centroid: Option<([u8; 32], Vec<EntityId>)>,
    decisions: Vec<DecisionReceipt>,
    basis: FindingBasis,
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
    vault.file_model_diagnostic(ModelFinding {
        id,
        event: &event,
        tier,
        policy,
        runs,
        decisions: &decisions,
        basis,
    })?;
    vault.capture_tier1_retrieval_window(id, runs, centroid_snapshot)?;
    Ok(Some(ProposedDiagnostic {
        tier,
        event_id: id,
        event,
        decisions,
    }))
}

/// Validates the whole ordered window, every run of it: past
/// `limits.detector_window_runs` the detector asks and reads on.
pub(super) fn valid_runs(
    vault: &Vault,
    runs: &[RetrievalRunRecord],
    consecutive: usize,
) -> Result<()> {
    if runs.len() < consecutive
        || runs.windows(2).any(|w| {
            (w[0].started_at, w[0].run_id.as_bytes()) >= (w[1].started_at, w[1].run_id.as_bytes())
        })
    {
        return Err(Error::InvalidConfig(
            "invalid ordered telemetry window".into(),
        ));
    }
    let _ = vault.measure_limit(EngineLimit::DetectorWindowRuns, runs.len() as u64);
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

/// One logical window a detector grades in parts (OF-418 L6). The window is validated whole
/// when it opens, so `consecutive` and its sufficiency are the window's, not a part's. The
/// host then asks each part in turn, oldest first, over that part's state, and the window
/// has one verdict once every part is asked. A T2b streak runs on across parts; a T3 or
/// session window raises when any of its parts raised.
pub struct WindowGrade<'w> {
    policy: &'w DetectorPolicy,
    tier: ProposedTier,
    asked: Asked,
    /// The reviewed positive, then negative, findings a T2b's questions carry as evidence.
    examples: Vec<EntityId>,
    window: &'w [RetrievalRunRecord],
    /// Runs of the window asked so far, oldest first.
    graded: usize,
    /// T2b: the receipts of the raised runs in a row that end at the newest run asked.
    streak: Vec<DecisionReceipt>,
    /// T3 and session: the receipts of the parts that raised.
    raised: Vec<DecisionReceipt>,
    /// The receipt of every question asked, in order: a clean window's judgment (OF-418 L3).
    answers: Vec<DecisionReceipt>,
    /// The recipe the window is graded under (OF-418 L3).
    recipe: [u8; 32],
    /// What its questions read: the question, then each reviewed example (OF-418 L3).
    pins: Vec<String>,
    /// Every asked part's exact state, in order (OF-418 L3).
    context: blake3::Hasher,
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
        let grade = self.open_window_grade(policy, ProposedTier::PromptClassifier, runs)?;
        self.grade_in_one(grade, decisions)
    }

    /// T3 receives an oldest-first bounded trace window and finds open anomalies.
    pub fn judge_retrieval_trace(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        let grade = self.open_window_grade(policy, ProposedTier::Judge, runs)?;
        self.grade_in_one(grade, decisions)
    }

    /// Session quality is a T2/T3 model grade, never a BEAM score or auto arm.
    /// The telemetry window must be oldest-first and belong to one episode.
    pub fn judge_session_quality(
        &self,
        policy: &DetectorPolicy,
        decisions: &DetectorDecisions<'_>,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        let grade = self.open_window_grade(policy, ProposedTier::SessionJudge, runs)?;
        self.grade_in_one(grade, decisions)
    }

    /// Opens an oldest-first `window` to grade in parts at `tier`: T2b, T3 or session (one
    /// episode's runs). The whole window is validated here, every run of it.
    ///
    /// # Errors
    ///
    /// The centroid tier, which asks no model question; an invalid policy or window; a
    /// session window with a run of no session or of another one.
    pub fn open_window_grade<'w>(
        &self,
        policy: &'w DetectorPolicy,
        tier: ProposedTier,
        window: &'w [RetrievalRunRecord],
    ) -> Result<WindowGrade<'w>> {
        let _ = self.measure_limit(EngineLimit::DetectorConsecutive, policy.consecutive as u64);
        self.window_grade(policy, tier, window, (&[], &[]))
    }

    /// [`Self::open_window_grade`] asked with reviewed positive and negative `examples`,
    /// which a T2b question carries as evidence after each run.
    pub(super) fn window_grade<'w>(
        &self,
        policy: &'w DetectorPolicy,
        tier: ProposedTier,
        window: &'w [RetrievalRunRecord],
        examples: (&[EntityId], &[EntityId]),
    ) -> Result<WindowGrade<'w>> {
        let asked = match tier {
            ProposedTier::Centroid => {
                return Err(Error::InvalidConfig(
                    "a centroid window asks no question".into(),
                ));
            }
            ProposedTier::PromptClassifier => {
                policy.asked(tier, (examples.0.len(), examples.1.len()))?
            }
            ProposedTier::Judge | ProposedTier::SessionJudge => policy.asked(tier, (0, 0))?,
        };
        // The wording goes whole: past `limits.maintenance_text_bytes` it asks.
        let wording = policy.prompt.len() + policy.rubric.len();
        let _ = self.measure_limit(EngineLimit::MaintenanceTextBytes, wording as u64);
        valid_runs(self, window, policy.consecutive)?;
        if tier == ProposedTier::SessionJudge {
            let Some(turn) = window.first().and_then(|run| run.turn) else {
                return Err(Error::InvalidConfig("missing session identity".into()));
            };
            if window
                .iter()
                .any(|run| run.turn.is_none_or(|t| t.episode_id != turn.episode_id))
            {
                return Err(Error::InvalidConfig("mixed sessions".into()));
            }
        }
        let mut pins = vec![format!(
            "question:{}@{}",
            asked.question.id.to_hex(),
            asked.question.version
        )];
        pins.extend(
            examples
                .0
                .iter()
                .chain(examples.1)
                .map(|id| format!("example:{}", id.to_hex())),
        );
        Ok(WindowGrade {
            policy,
            tier,
            asked,
            examples: examples.0.iter().chain(examples.1).copied().collect(),
            window,
            graded: 0,
            streak: Vec::new(),
            raised: Vec::new(),
            answers: Vec::new(),
            recipe: recipe_revision(policy, tier, examples, None),
            pins,
            context: blake3::Hasher::new(),
        })
    }

    /// Asks the window's next `runs` runs, one part, under `decisions`, whose state the
    /// host built from that part. T2b asks each run in turn, its state naming that run as
    /// its `target`, and carries its streak on; T3 and session ask the part once.
    ///
    /// # Errors
    ///
    /// An empty part or one past the window's end, or a question that failed or abstained.
    pub fn grade_window_part(
        &self,
        grade: &mut WindowGrade<'_>,
        decisions: &DetectorDecisions<'_>,
        runs: usize,
    ) -> Result<()> {
        let end = grade
            .graded
            .checked_add(runs)
            .filter(|end| runs > 0 && *end <= grade.window.len())
            .ok_or_else(|| Error::InvalidConfig("invalid detector window part".into()))?;
        let part = &grade.window[grade.graded..end];
        let wording = grade.asked.wording.as_ref();
        match grade.tier {
            ProposedTier::PromptClassifier => {
                for run in part {
                    let mut evidence = run_ids(std::slice::from_ref(run))?;
                    evidence.extend(&grade.examples);
                    let state = targeted(decisions.state, run, wording)?;
                    // The state goes whole: past `limits.maintenance_text_bytes` it asks.
                    let bytes = serde_json::to_vec(&state).unwrap_or_default();
                    let _ =
                        self.measure_limit(EngineLimit::MaintenanceTextBytes, bytes.len() as u64);
                    read_state(&mut grade.context, &bytes);
                    let (raised, receipt) =
                        decisions.raised_with_state(&grade.asked.question, &evidence, &state)?;
                    grade.answers.push(receipt.clone());
                    if raised {
                        grade.streak.push(receipt);
                    } else {
                        grade.streak.clear();
                    }
                }
            }
            ProposedTier::Judge | ProposedTier::SessionJudge | ProposedTier::Centroid => {
                let state = with_wording(decisions.state, wording)?;
                read_state(
                    &mut grade.context,
                    &serde_json::to_vec(&*state).unwrap_or_default(),
                );
                let (raised, receipt) =
                    decisions.raised_with_state(&grade.asked.question, &run_ids(part)?, &state)?;
                grade.answers.push(receipt.clone());
                if raised {
                    grade.raised.push(receipt);
                }
            }
        }
        grade.graded = end;
        Ok(())
    }

    /// The window's one verdict once every part is asked. A T2b raises on `consecutive`
    /// raised runs in a row that end the window, across any part boundary, and its finding
    /// names those runs. A T3 or session window raises when any part raised; its finding
    /// names every run of the window and carries the raising parts' receipts. A window with no
    /// finding is a complete clean judgment, recorded for the Coach's open issues of its key
    /// before it returns (OF-418 L3).
    ///
    /// # Errors
    ///
    /// A window not asked to its end, or storage errors.
    pub fn finish_window_grade(
        &self,
        grade: WindowGrade<'_>,
    ) -> Result<Option<ProposedDiagnostic>> {
        if grade.graded != grade.window.len() {
            return Err(Error::InvalidConfig(
                "detector window not asked whole".into(),
            ));
        }
        let (runs, decisions) = match grade.tier {
            ProposedTier::PromptClassifier => {
                if grade.streak.len() < grade.policy.consecutive {
                    self.observe_clean_window(&grade)?;
                    return Ok(None);
                }
                let start = grade.window.len() - grade.streak.len();
                (&grade.window[start..], grade.streak)
            }
            ProposedTier::Judge | ProposedTier::SessionJudge | ProposedTier::Centroid => {
                if grade.raised.is_empty() {
                    self.observe_clean_window(&grade)?;
                    return Ok(None);
                }
                (grade.window, grade.raised)
            }
        };
        let basis = FindingBasis {
            recipe_revision: grade.recipe,
            source_pins: grade.pins,
            context_digest: *grade.context.finalize().as_bytes(),
        };
        propose(self, grade.tier, grade.policy, runs, None, decisions, basis)
    }

    /// OF-418 L3: `grade`'s window, asked whole with no finding, as a clean judgment.
    fn observe_clean_window(&self, grade: &WindowGrade<'_>) -> Result<()> {
        self.record_issue_observation(Observation {
            tier: grade.tier,
            policy: grade.policy,
            recipe: grade.recipe,
            runs: grade.window,
            decisions: &grade.answers,
        })
    }

    /// `grade`'s whole window asked as one part: the single-call detector doors.
    pub(super) fn grade_in_one(
        &self,
        mut grade: WindowGrade<'_>,
        decisions: &DetectorDecisions<'_>,
    ) -> Result<Option<ProposedDiagnostic>> {
        let runs = grade.window.len();
        self.grade_window_part(&mut grade, decisions, runs)?;
        self.finish_window_grade(grade)
    }
}
