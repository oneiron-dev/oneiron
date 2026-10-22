//! A publisher's engine candidate replayed against the real failure (FIX
//! 1661, 2144, 6357): one matched pair on the host's shadow runner, dark
//! until that runner can run a candidate engine (PR-S2a).
//!
//! First the Coach's own Grant must admit the failing call's capture (FIX
//! 6357, 8704, `admission`): taken where the source snapshot found it, and
//! read again here. With none the pair does not run, and is tried again once
//! such a Grant admits it (FIX 7031). Then the failing call's captured
//! executor step is resolved and kept as its capsule, and read once, under
//! that Grant, into one descriptor: its step, its request's digest (as sent,
//! or as stored masked), its start, the bodies each arm must be granted, its
//! clock and seed, its sampling seed and the model and route it went out on.
//! The candidate's arm runs from it first, bound to a sandbox, then the
//! baseline's, trusted in the host's process; only the arm id, the target
//! and the isolation differ, and the runner meters both under the Coach
//! alike. The Grant is read again before each arm is sent and before each
//! body of an arm is read.
//!
//! A pair is judged only when both arms ran their step to its end on the
//! target, step, request, start and pins named, the candidate ran sandboxed,
//! every body of both reads whole, and the baseline fails the way the
//! failure did; then the question an instruction's replay asks says whether
//! the candidate fixed it. Anything else is a typed not-run, never a verdict,
//! and a runner or storage error stays an error. Every arm's lease is
//! released on every way out.

use serde_json::json;

use super::admission::CoachReplayAdmission;
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
    ShadowTraceKind, ShadowUnavailable, ShadowUnavailableReason,
    prepare_admitted_shadow_step_source,
};
use crate::code_run::{CapsuleHost, ExecutorStepStart, StepReplayCapsule, step_replay_capsules};
use crate::failure_signals::{ReplayFidelity, ShadowRun};
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
        // FIX 6357, 8704: the Coach's own Grant admits the capture, taken
        // where the snapshot found it and read again, before any of its
        // source is read.
        let admission = match &self.snapshot.admission {
            Ok(admission) => admission,
            Err(refused) => return Ok(Err(EngineNotRun::Admission(*refused))),
        };
        // A Grant gone since the snapshot is waited for, as one never there.
        if let Err(refused) = admission.still_admits(self.vault)? {
            let refused = match refused {
                EngineAdmission::Lapsed => EngineAdmission::NoGrant,
                other => other,
            };
            return Ok(Err(EngineNotRun::Admission(refused)));
        }
        run.grant = Some(admission.grant());
        let chosen = self.snapshot.replay.capsule.as_ref();
        let Some(capsule) = failing_capsule(self.vault, chosen)? else {
            return Ok(Err(EngineNotRun::NoCapturedStep));
        };
        run.step = Some(ShadowStepIdentity::of(&capsule));
        let meter = shadow.arm_meter();
        let pair = match PairDescriptor::read(self.vault, &capsule, meter, admission)? {
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
        // The Grant is read again before each arm is sent (FIX 8704).
        if let Err(reason) = still_admitted(self.vault, admission)? {
            return Ok(Err(reason));
        }
        let candidate =
            shadow.run_arm(pair.arm(target.clone(), ShadowIsolationRequired::Sandboxed))?;
        held.hold(&candidate);
        run.arms
            .push(EngineArmSummary::of(EngineArm::Candidate, &candidate));
        if let Err(reason) = ran_step(EngineArm::Candidate, &candidate) {
            return Ok(Err(reason));
        }
        if let Err(reason) = still_admitted(self.vault, admission)? {
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
        // FIX 6357, 8704 again: the Grant still admits the capture before
        // each body of either arm is read. A pact lapse keeps its own reason
        // (FIX 7548).
        let bodies = ArmBodies {
            shadow,
            vault: self.vault,
            admission,
        };
        let after = match bodies.evidence(EngineArm::Candidate, &candidate)? {
            Ok(after) => after,
            Err(reason) => return Ok(Err(reason)),
        };
        let before = match bodies.evidence(EngineArm::Baseline, &baseline)? {
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

/// Whether the Grant `admission` holds still admits the capture now, alone
/// (FIX 8704); else why the pair cannot read on. A pact lapse keeps its own
/// reason (FIX 7548), any other is `Lapsed`.
fn still_admitted(vault: &Vault, admission: &CoachReplayAdmission) -> Result<Outcome<()>> {
    Ok(admission
        .still_admits(vault)?
        .map_err(EngineNotRun::Admission))
}

/// The failing call's captured executor step, kept as its capsule (FIX
/// 1662's choice of call): `chosen`, the one the run's source snapshot chose
/// with its request (OF-380 L1), read again under its step's identity and
/// its request's hash, never chosen again. `None` when the snapshot chose
/// none, it is a workflow step's, or it reads under that identity no more:
/// no other step stands in for it, and a request alone is never an engine
/// comparison.
fn failing_capsule(
    vault: &Vault,
    chosen: Option<&StepReplayCapsule>,
) -> Result<Option<StepReplayCapsule>> {
    let Some(chosen) = chosen.filter(|capsule| capsule.host == CapsuleHost::EngineStep) else {
        return Ok(None);
    };
    let identity = ShadowStepIdentity::of(chosen);
    Ok(step_replay_capsules(vault, chosen.attempt)?
        .into_iter()
        .find(|again| {
            ShadowStepIdentity::of(again) == identity
                && again.request_hash == chosen.request_hash
                && again.host == CapsuleHost::EngineStep
        }))
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
    /// `capsule`'s step, read through the runner's own preparation while
    /// `admission` still admits it (FIX 8704), with `meter` for both arms;
    /// or the runner's reason it cannot be read, a capture that pinned no
    /// answering model or no route among them.
    fn read(
        vault: &Vault,
        capsule: &StepReplayCapsule,
        meter: ShadowMeterContext,
        admission: &CoachReplayAdmission,
    ) -> Result<std::result::Result<Self, ShadowUnavailable>> {
        let prepared = match prepare_admitted_shadow_step_source(vault, capsule, admission)? {
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

/// What reads an arm's bodies: the host's runner, under the Coach's
/// admission to the capture they came from, read again before each body
/// (FIX 8704).
struct ArmBodies<'a> {
    shadow: &'a dyn CodeFixShadowHost,
    vault: &'a Vault,
    admission: &'a CoachReplayAdmission,
}

impl ArmBodies<'_> {
    /// One arm's evidence as the questions read it, every body whole and
    /// read under its lease: its model answers, the effects it proposed, the
    /// recorded calls it matched, and the outputs it wrote; or why it cannot
    /// be read whole.
    fn evidence(&self, arm: EngineArm, result: &ShadowRunResult) -> Result<Outcome<String>> {
        let partial =
            || -> Result<Outcome<String>> { Ok(Err(EngineNotRun::PartialEvidence { arm })) };
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
            let bytes = match self.whole(lease, arm, response)? {
                Ok(bytes) => bytes,
                Err(reason) => return Ok(Err(reason)),
            };
            let Ok(response) = serde_json::from_slice::<LlmResponse>(&bytes) else {
                return partial();
            };
            answers.push(answer_text(&response));
        }
        let effects = match self.trace(lease, arm, effect_trace)? {
            Ok(effects) => effects,
            Err(reason) => return Ok(Err(reason)),
        };
        let matched = match self.trace(lease, arm, bridge_trace)? {
            Ok(matched) => matched,
            Err(reason) => return Ok(Err(reason)),
        };
        let mut outputs = Vec::with_capacity(result.outputs.len());
        for output in &result.outputs {
            let bytes = match self.whole(lease, arm, output)? {
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

    /// The body `body` of the arm `arm`, read whole under its `lease` while
    /// the Coach's Grant still admits the capture: one its producer did not
    /// finish is partial, and one the runner cannot read now says why.
    fn whole(
        &self,
        lease: &ShadowArmLease,
        arm: EngineArm,
        body: &ShadowBodyRef,
    ) -> Result<Outcome<Vec<u8>>> {
        if !body.complete {
            return Ok(Err(EngineNotRun::PartialEvidence { arm }));
        }
        if let Err(reason) = still_admitted(self.vault, self.admission)? {
            return Ok(Err(reason));
        }
        Ok(self
            .shadow
            .read_arm_body(lease, body.body)?
            .map_err(|unavailable| EngineNotRun::Unavailable { arm, unavailable }))
    }

    /// An arm's trace, read whole and decoded; one that does not decode is
    /// partial.
    fn trace(
        &self,
        lease: &ShadowArmLease,
        arm: EngineArm,
        body: &ShadowBodyRef,
    ) -> Result<Outcome<Vec<ShadowTraceEntry>>> {
        let bytes = match self.whole(lease, arm, body)? {
            Ok(bytes) => bytes,
            Err(reason) => return Ok(Err(reason)),
        };
        Ok(rmp_serde::from_slice(&bytes).map_err(|_| EngineNotRun::PartialEvidence { arm }))
    }
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
