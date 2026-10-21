//! A publisher's engine candidate replayed against the real failure (FIX
//! 1661, 2144, 6357): one matched pair on the host's shadow runner, dark
//! until that runner can run a candidate engine (PR-S2a).
//!
//! First the Coach's own Grant must read the failing run's scope (FIX 6357):
//! a live agent Grant whose member is the Coach, from an owner of this vault,
//! that confers read now and lists every world the run touched. With none
//! the pair does not run, and is tried again once such a Grant reads that
//! scope (FIX 7031). Then the failing call's captured executor step is
//! resolved and kept as its capsule, and read once into one descriptor: its
//! step, its request's digest (as sent, or as stored masked), its start, the
//! bodies each arm must be granted, its clock and seed, its sampling seed
//! and the model and route it went out on. The candidate's arm runs from it
//! first, bound to a sandbox, then the baseline's, trusted in the host's
//! process; only the arm id, the target and the isolation differ, and the
//! runner meters both under the Coach alike. The Grant is checked again
//! before either arm's bodies are read.
//!
//! A pair is judged only when both arms ran their step to its end on the
//! target, step, request, start and pins named, the candidate ran sandboxed,
//! every body of both reads whole, and the baseline fails the way the
//! failure did; then the question an instruction's replay asks says whether
//! the candidate fixed it. Anything else is a typed not-run, never a verdict,
//! and a runner or storage error stays an error. Every arm's lease is
//! released on every way out.

use serde_json::json;

use super::CodeFixSettled;
use super::instruction::{CoachReplay, request_conversation};
use super::publisher::{
    CodeFixShadowHost, EngineAdmission, EngineArm, EngineArmStatus, EngineArmSummary,
    EngineCandidateRun, EngineNotRun, EnginePairState,
};
use crate::code_run::shadow_runner::{
    EngineArtifactPin, SHADOW_PROTOCOL_VERSION, ShadowArmLease, ShadowBodyRef, ShadowDeterminism,
    ShadowIsolation, ShadowIsolationRequired, ShadowMeterContext, ShadowModelPin,
    ShadowRequestDigest, ShadowRunRequest, ShadowRunResult, ShadowSandboxBinding, ShadowScope,
    ShadowSource, ShadowStatus, ShadowStepIdentity, ShadowTarget, ShadowTraceEntry,
    ShadowTraceKind, ShadowUnavailable, ShadowUnavailableReason, prepare_shadow_step_source,
};
use crate::code_run::{CapsuleHost, ExecutorStepStart, StepReplayCapsule, step_replay_capsules};
use crate::failure_signals::{
    CodeFixSource, ReplayFidelity, ShadowRun, code_fix_subject_in, failed_case_in,
};
use crate::federation::ScopeId;
use crate::{ContentPart, EntityId, LlmRequest, LlmResponse, Result, Vault};

/// A pair's part, or why the pair has no verdict.
type Outcome<T> = std::result::Result<T, EngineNotRun>;

/// What an engine candidate's pair came to: the shadow result its export
/// door seals, how the step's request ran once judged, and what the work row
/// keeps of it.
pub(super) struct EnginePair {
    pub(super) shadow: ShadowRun,
    pub(super) fidelity: Option<ReplayFidelity>,
    pub(super) run: EngineCandidateRun,
}

impl CoachReplay<'_> {
    /// The engine candidate `candidate_id`, pinned at `pin`, replayed
    /// against the real failure as one matched pair. `Unavailable` beside a
    /// typed not-run whenever the pair cannot be judged.
    ///
    /// # Errors
    ///
    /// A runner or storage failure; every arm's lease is released first.
    pub(super) fn engine_pair(
        &self,
        candidate_id: &str,
        pin: EngineArtifactPin,
    ) -> Result<EnginePair> {
        let mut run = EngineCandidateRun {
            pin,
            protocol_version: SHADOW_PROTOCOL_VERSION,
            grant: None,
            step: None,
            request_digest: None,
            start_digest: None,
            arms: Vec::new(),
            state: EnginePairState::Judged,
        };
        Ok(match self.run_pair(candidate_id, pin, &mut run)? {
            Ok(shadow) => {
                let fidelity = run.request_digest.map(|digest| match digest {
                    ShadowRequestDigest::AsSent(_) => ReplayFidelity::Exact,
                    ShadowRequestDigest::AsStored(_) => ReplayFidelity::ExactMasked,
                });
                EnginePair {
                    shadow,
                    fidelity,
                    run,
                }
            }
            Err(reason) => {
                run.state = EnginePairState::NotRun { reason };
                EnginePair {
                    shadow: ShadowRun::Unavailable,
                    fidelity: None,
                    run,
                }
            }
        })
    }

    /// The pair's run, `run` filled as each part lands: its verdict, or why
    /// there is none.
    fn run_pair(
        &self,
        candidate_id: &str,
        pin: EngineArtifactPin,
        run: &mut EngineCandidateRun,
    ) -> Result<Outcome<ShadowRun>> {
        let Some(shadow) = self.host.shadow_runner() else {
            return Ok(Err(EngineNotRun::NoRunner));
        };
        let source = &self.job.origin;
        // FIX 6357: the Coach's own Grant reads the run's scope before any of
        // its source is read.
        match coach_read_grant(self.vault, source)? {
            Ok(grant) => run.grant = Some(grant),
            Err(refused) => return Ok(Err(EngineNotRun::Admission(refused))),
        }
        let Some(capsule) = failing_capsule(self.vault, source)? else {
            return Ok(Err(EngineNotRun::NoCapturedStep));
        };
        run.step = Some(ShadowStepIdentity::of(&capsule));
        let pair = match PairDescriptor::read(self.vault, &capsule, shadow.arm_meter())? {
            Ok(pair) => pair,
            Err(unavailable) => return Ok(Err(EngineNotRun::Source(unavailable))),
        };
        run.request_digest = Some(pair.request_digest);
        run.start_digest = Some(pair.start.digest);
        let mut held = ArmsHeld {
            shadow,
            leases: Vec::new(),
        };
        // The candidate's arm first: one its runner cannot run costs no
        // baseline model call and holds no lease.
        let target = ShadowTarget::Candidate {
            id: candidate_id.to_owned(),
            pin,
        };
        let candidate =
            shadow.run_arm(pair.arm(target.clone(), ShadowIsolationRequired::Sandboxed))?;
        held.hold(&candidate);
        run.arms
            .push(EngineArmSummary::of(EngineArm::Candidate, &candidate));
        if let Err(reason) = ran_step(EngineArm::Candidate, &candidate) {
            return Ok(Err(reason));
        }
        let baseline = shadow.run_arm(pair.arm(
            ShadowTarget::Baseline,
            ShadowIsolationRequired::TrustedInProcessBaseline,
        ))?;
        held.hold(&baseline);
        run.arms
            .push(EngineArmSummary::of(EngineArm::Baseline, &baseline));
        if let Err(reason) = ran_step(EngineArm::Baseline, &baseline) {
            return Ok(Err(reason));
        }
        if !pair.answers(&candidate, &target) {
            return Ok(Err(EngineNotRun::Mismatch {
                arm: EngineArm::Candidate,
            }));
        }
        if !pair.answers(&baseline, &ShadowTarget::Baseline) {
            return Ok(Err(EngineNotRun::Mismatch {
                arm: EngineArm::Baseline,
            }));
        }
        if !isolated(&candidate, pin) {
            return Ok(Err(EngineNotRun::NotIsolated));
        }
        // FIX 6357 again: the Grant still reads the run's scope before any
        // arm's body is read.
        if coach_read_grant(self.vault, source)?.is_err() {
            return Ok(Err(EngineNotRun::Admission(EngineAdmission::Lapsed)));
        }
        let after = match read_evidence(shadow, EngineArm::Candidate, &candidate)? {
            Ok(after) => after,
            Err(reason) => return Ok(Err(reason)),
        };
        let before = match read_evidence(shadow, EngineArm::Baseline, &baseline)? {
            Ok(before) => before,
            Err(reason) => return Ok(Err(reason)),
        };
        // Both arms' bodies are read: their leases go before the questions.
        drop(held);
        Ok(self.judge_pair(&pair.request, &before, &after))
    }

    /// The verdict on a pair read whole: the baseline must fail the way the
    /// failure did, then the candidate is judged against it on the question
    /// an instruction's replay asks. `before` and `after` are the arms'
    /// evidence, each whole.
    fn judge_pair(&self, request: &LlmRequest, before: &str, after: &str) -> Outcome<ShadowRun> {
        let conversation = request_conversation(request);
        match self.fails(None, &conversation, before) {
            Some(true) => {}
            Some(false) => return Err(EngineNotRun::NotReproduced),
            None => return Err(EngineNotRun::Undecided),
        }
        match self.fixed(&conversation, before, after) {
            ShadowRun::Unavailable => Err(EngineNotRun::Undecided),
            judged => Ok(judged),
        }
    }
}

/// The Coach's live Grant that reads every world of `source`'s failing run
/// now (FIX 6357): an agent Grant whose member is the Coach, that an owner of
/// this vault delegated, that confers read now and is unexpired, and whose
/// worlds include each world the run touched (its dispatch's scope and its
/// task's, or the worlds its host scoped it to). The first such Grant, in id
/// order, or why there is none; the run's worlds are read again at each
/// check. The Grant's world reach is what admits the pair: its bands,
/// sensitivity and audience are not held to each row the step's capture
/// holds.
fn coach_read_grant(
    vault: &Vault,
    source: &CodeFixSource,
) -> Result<std::result::Result<EntityId, EngineAdmission>> {
    let coach = vault.coach_authority()?.entity_ref();
    let txn = vault.store.env.read_txn()?;
    coach_read_grant_in_txn(vault, &txn, source, coach)
}

/// [`coach_read_grant`] read in `txn`, a queue's or a settlement's own
/// writer among them, for `coach`, the Coach's id resolved outside any
/// writer (FIX 7031).
pub(super) fn coach_read_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: &CodeFixSource,
    coach: EntityId,
) -> Result<std::result::Result<EntityId, EngineAdmission>> {
    let Some(subject) = code_fix_subject_in(vault, txn, source)? else {
        return Ok(Err(EngineAdmission::ScopeUnproved));
    };
    let Ok((_, worlds)) = subject.failure.read() else {
        return Ok(Err(EngineAdmission::ScopeUnproved));
    };
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let grant = vault
        .agent_grants_in_txn(txn)?
        .into_iter()
        .find(|standing| {
            let grant = &standing.grant;
            grant.member_ref == coach
                && owners.contains(&standing.delegated_by)
                && grant.confers_at(now)
                && worlds
                    .iter()
                    .all(|world| grant.authority_scope.worlds.contains(&ScopeId(*world)))
        });
    Ok(grant
        .map(|standing| standing.id)
        .ok_or(EngineAdmission::NoGrant))
}

/// Whether the Coach's Grant now admits a pair of `settled`, the failure
/// `source`'s runs, that was kept not run for want of one (FIX 7031): the
/// same admission as the pair's own, read in `txn` only when such a pair is
/// there; `false` otherwise.
pub(super) fn read_granted_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    settled: &CodeFixSettled,
    source: &CodeFixSource,
    coach: EntityId,
) -> Result<bool> {
    let waits = settled.candidates.iter().any(|run| {
        run.engine
            .as_ref()
            .is_some_and(EngineCandidateRun::waits_on_grant)
    });
    Ok(waits && coach_read_grant_in_txn(vault, txn, source, coach)?.is_ok())
}

/// The failing call's captured executor step, kept as its capsule (FIX
/// 1662's choice of call): the last step the failing attempt captured, or
/// the one whose request a blocked report names by its hash. `None` when
/// there is none, or it is a workflow step's: no other step stands in for
/// it, and a request alone is never an engine comparison.
fn failing_capsule(vault: &Vault, source: &CodeFixSource) -> Result<Option<StepReplayCapsule>> {
    let (attempt, digest) = {
        let txn = vault.store.env.read_txn()?;
        match source {
            CodeFixSource::Case { case_ref } => match failed_case_in(vault, &txn, case_ref)? {
                Some((case, _)) => (
                    EntityId::from_bytes(*case.failing_attempt_id.as_bytes())?,
                    None,
                ),
                None => return Ok(None),
            },
            CodeFixSource::Blocked {
                receipt,
                run: Some(run),
            } => {
                let digest =
                    crate::self_heal::blocked_reports::blocked_source_in(vault, &txn, receipt)?
                        .and_then(|source| source.request)
                        .and_then(|request| request.sent)
                        .map(|sent| sent.digest);
                (*run, digest)
            }
            CodeFixSource::Blocked { run: None, .. } => return Ok(None),
        }
    };
    Ok(step_replay_capsules(vault, attempt)?
        .into_iter()
        .rev()
        .find(|capsule| digest.is_none_or(|digest| capsule.request_hash == digest))
        .filter(|capsule| capsule.host == CapsuleHost::EngineStep))
}

/// The one captured step a pair runs from, read once and cloned into each
/// arm's request.
struct PairDescriptor {
    step: ShadowStepIdentity,
    request_digest: ShadowRequestDigest,
    start: ExecutorStepStart,
    /// Every body of the run before the step frozen clean, each of which an
    /// arm must be granted.
    input_refs: Vec<ShadowBodyRef>,
    determinism: ShadowDeterminism,
    /// The sampling seed the captured request carried; `None` stays `None`.
    model_seed: Option<u64>,
    model_pin: ShadowModelPin,
    meter: ShadowMeterContext,
    /// The step's request as stored, for the questions.
    request: LlmRequest,
}

impl PairDescriptor {
    /// `capsule`'s step, read through the runner's own preparation, with
    /// `meter` for both arms; or the runner's reason it cannot be read, a
    /// capture that pinned no answering model or no route among them.
    fn read(
        vault: &Vault,
        capsule: &StepReplayCapsule,
        meter: ShadowMeterContext,
    ) -> Result<std::result::Result<Self, ShadowUnavailable>> {
        let prepared = match prepare_shadow_step_source(vault, capsule)? {
            Ok(prepared) => prepared,
            Err(unavailable) => return Ok(Err(unavailable)),
        };
        let (Some(captured), Some(route)) = (prepared.binding(), prepared.route_pin()) else {
            return Ok(Err(ShadowUnavailable::new(
                ShadowUnavailableReason::RoutePinMissing,
                "capture",
            )));
        };
        let model_pin = ShadowModelPin {
            captured: captured.clone(),
            route: route.clone(),
        };
        let input_refs = prepared
            .frozen
            .iter()
            .filter(|frozen| frozen.bytes.is_some())
            .map(|frozen| ShadowBodyRef::of(&frozen.output, frozen.secret.as_deref()))
            .collect();
        Ok(Ok(Self {
            step: *prepared.step(),
            request_digest: prepared.request_digest(),
            start: prepared.start().clone(),
            input_refs,
            determinism: prepared.determinism(),
            model_seed: prepared.seed(),
            model_pin,
            meter,
            request: prepared.request().clone(),
        }))
    }

    /// One arm's request: the pair's source, with a fresh arm id, `target`
    /// and its `isolation`, its captured step alone.
    fn arm(&self, target: ShadowTarget, isolation: ShadowIsolationRequired) -> ShadowRunRequest {
        ShadowRunRequest {
            protocol_version: SHADOW_PROTOCOL_VERSION,
            arm_id: EntityId::now(),
            target,
            source: ShadowSource::Capsule {
                step: self.step,
                request_digest: self.request_digest,
                start: Some(self.start.clone()),
            },
            input_refs: self.input_refs.clone(),
            body_refs: Vec::new(),
            determinism: self.determinism,
            model_seed: self.model_seed,
            model_pin: self.model_pin.clone(),
            meter: self.meter.clone(),
            sandbox: ShadowSandboxBinding {
                isolation,
                profile_digest: None,
                backend_binding_id: None,
            },
            scope: ShadowScope::CapturedStep,
        }
    }

    /// Whether `result` answered for this pair: at its protocol, for
    /// `target`, on its step, request digest and start, with at least one
    /// model call and every call on the pins named.
    fn answers(&self, result: &ShadowRunResult, target: &ShadowTarget) -> bool {
        result.protocol_version == SHADOW_PROTOCOL_VERSION
            && result.target == *target
            && result.step == Some(self.step)
            && result.request_digest == Some(self.request_digest)
            && result.source_digest == Some(self.start.digest)
            && !result.model_receipts.is_empty()
            && result.model_receipts.iter().all(|receipt| {
                receipt.expected == self.model_pin && receipt.request_digest == self.request_digest
            })
    }
}

/// The leases of a pair's arms, each released once the pair is done with
/// it, whichever way it ends.
struct ArmsHeld<'a> {
    shadow: &'a dyn CodeFixShadowHost,
    leases: Vec<ShadowArmLease>,
}

impl ArmsHeld<'_> {
    /// Holds the lease `result` came with, if it came with one.
    fn hold(&mut self, result: &ShadowRunResult) {
        self.leases.extend(result.lease);
    }
}

impl Drop for ArmsHeld<'_> {
    fn drop(&mut self) {
        for lease in &self.leases {
            self.shadow.release_arm(lease);
        }
    }
}

/// Whether `result`, the arm `arm`'s, ran its captured step to its end; else
/// why the pair cannot be judged, the runner's reason kept whole.
fn ran_step(arm: EngineArm, result: &ShadowRunResult) -> Outcome<()> {
    match &result.status {
        ShadowStatus::StepComplete { .. } => Ok(()),
        ShadowStatus::Unavailable { unavailable } => Err(EngineNotRun::Unavailable {
            arm,
            unavailable: unavailable.clone(),
        }),
        status => Err(EngineNotRun::Ended {
            arm,
            status: EngineArmStatus::of(status),
        }),
    }
}

/// Whether the candidate's arm ran sandboxed, and ran what its pin names:
/// its build, or for a patch an executable its runner resolved. The trusted
/// in-process isolation every arm of PR-S1 reports is never a candidate's.
fn isolated(result: &ShadowRunResult, pin: EngineArtifactPin) -> bool {
    matches!(result.isolation, ShadowIsolation::Sandboxed { .. })
        && match pin.patch {
            None => result.resolved_artifact_digest == Some(pin.build),
            Some(_) => result.resolved_artifact_digest.is_some(),
        }
}

/// One arm's evidence as the questions read it, every body whole and read
/// under its lease: its model answers, the effects it proposed, the
/// recorded calls it matched, and the outputs it wrote; or why it cannot be
/// read whole.
fn read_evidence(
    shadow: &dyn CodeFixShadowHost,
    arm: EngineArm,
    result: &ShadowRunResult,
) -> Result<Outcome<String>> {
    let partial = || -> Result<Outcome<String>> { Ok(Err(EngineNotRun::PartialEvidence { arm })) };
    let (Some(lease), Some(effect_trace), Some(bridge_trace)) = (
        result.lease.as_ref(),
        result.effect_trace.as_ref(),
        result.bridge_trace.as_ref(),
    ) else {
        return partial();
    };
    let mut answers = Vec::with_capacity(result.model_receipts.len());
    for receipt in &result.model_receipts {
        let Some(response) = &receipt.response else {
            return partial();
        };
        let bytes = match read_whole(shadow, lease, arm, response)? {
            Ok(bytes) => bytes,
            Err(reason) => return Ok(Err(reason)),
        };
        let Ok(response) = serde_json::from_slice::<LlmResponse>(&bytes) else {
            return partial();
        };
        answers.push(answer_text(&response));
    }
    let effects = match read_trace(shadow, lease, arm, effect_trace)? {
        Ok(effects) => effects,
        Err(reason) => return Ok(Err(reason)),
    };
    let matched = match read_trace(shadow, lease, arm, bridge_trace)? {
        Ok(matched) => matched,
        Err(reason) => return Ok(Err(reason)),
    };
    let mut outputs = Vec::with_capacity(result.outputs.len());
    for output in &result.outputs {
        let bytes = match read_whole(shadow, lease, arm, output)? {
            Ok(bytes) => bytes,
            Err(reason) => return Ok(Err(reason)),
        };
        outputs.push(json!({
            "path": output.path,
            "text": String::from_utf8_lossy(&bytes),
        }));
    }
    let done = matches!(result.status, ShadowStatus::StepComplete { done: true });
    let effects: Vec<serde_json::Value> = effects.iter().map(trace_state).collect();
    let matched: Vec<serde_json::Value> = matched.iter().map(trace_state).collect();
    let evidence = json!({
        "done": done,
        "answers": answers,
        "proposed_effects": effects,
        "matched_calls": matched,
        "outputs": outputs,
    });
    Ok(Ok(evidence.to_string()))
}

/// The body `body` of the arm `arm`, read whole under its `lease`: one its
/// producer did not finish is partial, and one the runner cannot read now
/// says why.
fn read_whole(
    shadow: &dyn CodeFixShadowHost,
    lease: &ShadowArmLease,
    arm: EngineArm,
    body: &ShadowBodyRef,
) -> Result<Outcome<Vec<u8>>> {
    if !body.complete {
        return Ok(Err(EngineNotRun::PartialEvidence { arm }));
    }
    Ok(shadow
        .read_arm_body(lease, body.body)?
        .map_err(|unavailable| EngineNotRun::Unavailable { arm, unavailable }))
}

/// An arm's trace, read whole and decoded; one that does not decode is
/// partial.
fn read_trace(
    shadow: &dyn CodeFixShadowHost,
    lease: &ShadowArmLease,
    arm: EngineArm,
    body: &ShadowBodyRef,
) -> Result<Outcome<Vec<ShadowTraceEntry>>> {
    let bytes = match read_whole(shadow, lease, arm, body)? {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };
    Ok(rmp_serde::from_slice(&bytes).map_err(|_| EngineNotRun::PartialEvidence { arm }))
}

/// A model answer as the questions read it, every part whole: its text as
/// written, and any other part, each tool call it names included, as its
/// JSON.
fn answer_text(response: &LlmResponse) -> String {
    response
        .message
        .content
        .iter()
        .map(|part| match part {
            ContentPart::Text { text } => text.clone(),
            other => serde_json::to_string(other).unwrap_or_default(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One trace entry as the questions read it: its effect, its request, and
/// for a matched call the recorded outcome it was answered with.
fn trace_state(entry: &ShadowTraceEntry) -> serde_json::Value {
    let request = match entry.kind {
        ShadowTraceKind::Call => msgpack_state(&entry.request),
        ShadowTraceKind::TrailingSpeech => {
            serde_json::Value::String(String::from_utf8_lossy(&entry.request).into_owned())
        }
    };
    json!({
        "seq": entry.seq,
        "effect": entry.effect,
        "request": request,
        "outcome": entry.outcome.as_deref().map(msgpack_state),
    })
}

/// MessagePack `bytes` as JSON, whole; bytes that do not decode read as
/// their text.
fn msgpack_state(bytes: &[u8]) -> serde_json::Value {
    rmpv::decode::read_value(&mut &*bytes)
        .ok()
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or_else(|| serde_json::Value::String(String::from_utf8_lossy(bytes).into_owned()))
}
