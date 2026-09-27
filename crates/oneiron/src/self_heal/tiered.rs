//! Model-graded detection over ARCH-0037 runs. No signed T1 run is minted here.
use super::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body, validate_token,
};
use crate::{EntityId, Error, Result, Vault, store::RetrievalRunRecord};
use rmpv::Value;

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
            || self.prompt.len() > 16_384
            || self.rubric.len() > 16_384
        {
            return Err(Error::InvalidConfig("invalid detector policy".into()));
        }
        Ok(())
    }
}

/// Model sees telemetry as untrusted data, not as instructions or authority.
/// A returned verdict cannot choose its own detector id, event class or tier.
pub trait TelemetryJudge {
    fn assess(
        &self,
        prompt: &str,
        rubric: &str,
        runs: &[RetrievalRunRecord],
        examples: &[(Vec<RetrievalRunRecord>, bool)],
    ) -> Result<bool>;
}

/// A proposed-only output. No conversion from this type to SignedDetectorRun exists.
#[derive(Clone, Debug)]
pub struct ProposedDiagnostic {
    pub tier: ProposedTier,
    pub event_id: EntityId,
    pub event: DiagnosticEvent,
}

pub(super) fn propose(
    vault: &Vault,
    tier: ProposedTier,
    policy: &DetectorPolicy,
    runs: &[RetrievalRunRecord],
    centroid: Option<([u8; 32], Vec<EntityId>)>,
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
    let (digest, evidence) = centroid.unwrap_or((*digest.finalize().as_bytes(), evidence));
    let event = DiagnosticEvent {
        detector_id: format!("{}.{}", tier.token(), policy.family),
        event_class: policy.class,
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
        untrusted_detail: None,
        valid_from: first.started_at,
        valid_to: None,
    };
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);
    vault.emit_diagnostic_event(&id, &event)?;
    Ok(Some(ProposedDiagnostic {
        tier,
        event_id: id,
        event,
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
        judge: &impl TelemetryJudge,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        self.classify_prompt_with_examples(policy, judge, runs, &[])
    }

    pub(super) fn classify_prompt_with_examples(
        &self,
        policy: &DetectorPolicy,
        judge: &impl TelemetryJudge,
        runs: &[RetrievalRunRecord],
        examples: &[(Vec<RetrievalRunRecord>, bool)],
    ) -> Result<Option<ProposedDiagnostic>> {
        policy.validate()?;
        valid_runs(self, runs, policy.consecutive)?;
        let mut streak = 0;
        for run in runs {
            if judge.assess(
                &policy.prompt,
                &policy.rubric,
                std::slice::from_ref(run),
                examples,
            )? {
                streak += 1;
            } else {
                streak = 0;
            }
        }
        if streak < policy.consecutive {
            return Ok(None);
        }
        propose(
            self,
            ProposedTier::PromptClassifier,
            policy,
            &runs[runs.len() - streak..],
            None,
        )
    }

    /// T3 receives an oldest-first bounded trace window and finds open anomalies.
    pub fn judge_retrieval_trace(
        &self,
        policy: &DetectorPolicy,
        judge: &impl TelemetryJudge,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        policy.validate()?;
        valid_runs(self, runs, policy.consecutive)?;
        if !judge.assess(&policy.prompt, &policy.rubric, runs, &[])? {
            return Ok(None);
        }
        propose(self, ProposedTier::Judge, policy, runs, None)
    }

    /// Session quality is a T2/T3 model grade, never a BEAM score or auto arm.
    /// The telemetry window must be oldest-first and belong to one episode.
    pub fn judge_session_quality(
        &self,
        policy: &DetectorPolicy,
        judge: &impl TelemetryJudge,
        runs: &[RetrievalRunRecord],
    ) -> Result<Option<ProposedDiagnostic>> {
        policy.validate()?;
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
        if !judge.assess(&policy.prompt, &policy.rubric, runs, &[])? {
            return Ok(None);
        }
        propose(self, ProposedTier::SessionJudge, policy, runs, None)
    }
}
