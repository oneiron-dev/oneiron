//! The host's shadow runner (PR-S1; FIX 1661/2144, the runner side of
//! L07-B's B2b): [`ServerShadowRunner`] runs one arm of a
//! [`ShadowRunRequest`] at a time per call, each on the server's runtime
//! whatever runtime its caller waits on.
//!
//! An arm first meets its request's protocol version, then its target (a
//! candidate engine is unavailable before any of its code is loaded, until
//! PR-S2), its scope (a captured step alone) and its sandbox (the trusted
//! in-process baseline alone). Its capsule is then read and frozen on a
//! blocking worker, and checked against what the request names (its request
//! and start digests, its clock and seed, the bodies it expects granted).
//! The model call is awaited first, strictly on the captured pins through
//! the metered gateway (`model`); the reply's healing and its program then
//! run on a blocking worker that makes the JS runtime and the bridge inside
//! it, so nothing that is not `Send` is held across an await. The arm's
//! bodies stay under a lease (`arm_store`) until the caller releases it.
//!
//! What an arm reaches: its frozen bodies, its own store, the gateway and
//! its effect collector. No vault write path, gated write, lease, auth
//! header or secret resolver reaches it, and nothing installs or promotes
//! anything.

mod arm_store;
mod model;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use oneiron::code_run::shadow_runner::{
    PreparedShadowStep, SHADOW_PROTOCOL_VERSION, ShadowArmLease, ShadowIsolationRequired,
    ShadowRequestDigest, ShadowRunFuture, ShadowRunRequest, ShadowRunResult, ShadowRunner,
    ShadowSandboxBinding, ShadowScope, ShadowSource, ShadowStatus, ShadowStepIdentity,
    ShadowStepRun, ShadowTarget, ShadowUnavailable, ShadowUnavailableReason as Reason,
    prepare_shadow_step_source,
};
use oneiron::code_run::{ExecutorStepStart, step_replay_capsules};
use oneiron::compaction::output::OutputRef;
use oneiron::engine_executor::{JsCodeModeRuntime, StepCancellation, run_shadow_step};
use oneiron::{EntityId, Error, LlmResponse, Result, Vault};

use self::arm_store::{ArmEntry, ArmRegistry};
use self::model::Gateway;
use crate::server::SyncServer;

/// Where an arm's program runs: a fresh JS runtime for each step, made on
/// the blocking worker that runs it. The host wires its checked-in
/// component's factory here.
pub type ShadowRuntimes = Arc<dyn Fn() -> Result<Box<dyn JsCodeModeRuntime + Send>> + Send + Sync>;

/// The arms running now that their callers may cancel, by arm id.
type CancelMap = HashMap<EntityId, StepCancellation>;

/// [`CancelMap`], shared by a runner and its arms' callers.
type Cancels = Arc<Mutex<CancelMap>>;

/// An arm's source, or why it has none.
type Outcome<T> = std::result::Result<T, ShadowUnavailable>;

/// The host's runner of shadow arms.
pub struct ServerShadowRunner {
    server: Weak<SyncServer>,
    /// The server's runtime, which every arm runs on.
    handle: tokio::runtime::Handle,
    runtimes: ShadowRuntimes,
    arms: Arc<ArmRegistry>,
    cancels: Cancels,
}

impl ServerShadowRunner {
    /// A runner for `server`, its arms run on `handle` (the server's
    /// runtime), each step's program on a runtime `runtimes` makes. Its
    /// scratch directory is made here, and every directory a runner that
    /// stopped left is removed.
    ///
    /// # Errors
    ///
    /// The scratch directory cannot be made or held.
    pub fn new(
        server: Weak<SyncServer>,
        handle: tokio::runtime::Handle,
        runtimes: ShadowRuntimes,
    ) -> Result<Self> {
        Ok(Self {
            server,
            handle,
            runtimes,
            arms: Arc::new(ArmRegistry::open()?),
            cancels: Cancels::default(),
        })
    }

    /// The whole body `body` of the arm `lease` holds, while it holds it:
    /// how a caller adopts an arm's evidence before it releases the lease.
    ///
    /// # Errors
    ///
    /// The arm's store failing, and a body that is not its digest.
    pub fn read_body(&self, lease: &ShadowArmLease, body: OutputRef) -> Result<Option<Vec<u8>>> {
        let Some(arm) = self.arms.get(lease) else {
            return Ok(None);
        };
        arm.store().read(body)
    }

    /// Releases `lease`: its arm's bodies go once no reader holds them.
    /// Whether it held an arm.
    pub fn release(&self, lease: &ShadowArmLease) -> bool {
        self.arms.release(lease)
    }

    /// Cancels the running arm `arm`: its model call is not sent, and its
    /// step stops at its next check. Whether one was running.
    pub fn cancel(&self, arm: EntityId) -> bool {
        let token = lock(&self.cancels).get(&arm).cloned();
        match token {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }
}

impl ShadowRunner for ServerShadowRunner {
    fn run<'a>(&'a self, request: ShadowRunRequest) -> ShadowRunFuture<'a> {
        let cancel = StepCancellation::new();
        lock(&self.cancels).insert(request.arm_id, cancel.clone());
        let running = Running {
            cancels: Arc::clone(&self.cancels),
            arm: request.arm_id,
            cancel: cancel.clone(),
        };
        let arm = Arm {
            server: self.server.clone(),
            runtimes: Arc::clone(&self.runtimes),
            arms: Arc::clone(&self.arms),
            cancel,
        };
        let task = self.handle.spawn(arm.run(request));
        Box::pin(async move {
            let _running = running;
            match task.await {
                Ok(result) => result,
                Err(error) => Err(Error::InvalidConfig(format!("shadow arm task: {error}"))),
            }
        })
    }
}

/// An arm while its caller waits on it. Once the caller is done waiting,
/// answered or not, the arm is cancelled (a finished one has nothing left
/// to stop) and no longer cancellable by its id.
struct Running {
    cancels: Cancels,
    arm: EntityId,
    cancel: StepCancellation,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
        lock(&self.cancels).remove(&self.arm);
    }
}

/// What one arm runs with, owned by its task.
struct Arm {
    server: Weak<SyncServer>,
    runtimes: ShadowRuntimes,
    arms: Arc<ArmRegistry>,
    cancel: StepCancellation,
}

impl Arm {
    /// The arm's run, to its result.
    async fn run(self, request: ShadowRunRequest) -> Result<ShadowRunResult> {
        let not_run = ShadowUnavailable::new(Reason::SourceMissing, "not_run");
        let mut result = ShadowRunResult::unavailable(&request, not_run);
        result.status = self.run_into(&request, &mut result).await?;
        Ok(result)
    }

    /// Runs `request`, filling `result` as each part lands: its final
    /// status.
    async fn run_into(
        &self,
        request: &ShadowRunRequest,
        result: &mut ShadowRunResult,
    ) -> Result<ShadowStatus> {
        if let Some(unavailable) = refused_up_front(request) {
            return Ok(ShadowStatus::Unavailable { unavailable });
        }
        let ShadowSource::Capsule {
            step,
            request_digest,
            start,
        } = &request.source
        else {
            // A captured request by ref is the frame a candidate process is
            // handed (PR-S2); the baseline runs from a capsule.
            return Ok(unavailable(
                Reason::SourceMissing,
                "captured_request_source",
            ));
        };
        let server = self
            .server
            .upgrade()
            .ok_or_else(|| Error::InvalidConfig("shadow runner: the server stopped".to_owned()))?;
        let vault = Arc::clone(server.vault());
        let prepared = match prepare_on_worker(Arc::clone(&vault), *step).await? {
            Ok(prepared) => prepared,
            Err(unavailable) => return Ok(ShadowStatus::Unavailable { unavailable }),
        };
        result.step = Some(*prepared.step());
        result.source_digest = Some(prepared.start().digest);
        result.request_digest = Some(prepared.request_digest());
        if let Err(unavailable) =
            matches_request(&prepared, request, *request_digest, start.as_ref())
        {
            return Ok(ShadowStatus::Unavailable { unavailable });
        }
        let lease = ShadowArmLease::mint();
        let arm = self.arms.open_arm(lease)?;
        result.lease = Some(lease);
        let gateway = Gateway {
            server: &server,
            vault: &vault,
            store: arm.store(),
            cancel: &self.cancel,
        };
        let called = gateway
            .call(0, &prepared, &request.model_pin, &request.meter)
            .await?;
        result.model_receipts.push(called.receipt);
        let answer = match called.answer {
            Ok(answer) => answer,
            Err(unavailable) => return Ok(ShadowStatus::Unavailable { unavailable }),
        };
        let ran = match self.run_step(prepared, answer, arm).await? {
            Ok(ran) => ran,
            Err(unavailable) => return Ok(ShadowStatus::Unavailable { unavailable }),
        };
        result.outputs = ran.outputs;
        result.effect_trace = Some(ran.effect_trace);
        result.bridge_trace = Some(ran.bridge_trace);
        result.bridge = Some(ran.bridge);
        Ok(ran.status)
    }

    /// Heals `answer` and runs its program for `prepared`'s step, on a
    /// blocking worker that makes the step's JS runtime and its bridge.
    async fn run_step(
        &self,
        prepared: PreparedShadowStep,
        answer: LlmResponse,
        arm: Arc<ArmEntry>,
    ) -> Result<Outcome<ShadowStepRun>> {
        let runtimes = Arc::clone(&self.runtimes);
        let cancel = self.cancel.clone();
        let ran = tokio::task::spawn_blocking(move || {
            let Ok(mut runtime) = runtimes.as_ref()() else {
                let resource = Reason::ResourceUnavailable {
                    resource: "js_runtime".to_owned(),
                };
                return Ok(Err(ShadowUnavailable::new(resource, "runtime")));
            };
            let runtime: &mut dyn JsCodeModeRuntime = &mut *runtime;
            run_shadow_step(&prepared, &answer, runtime, arm.store(), &cancel).map(Ok)
        })
        .await;
        ran.map_err(|error| Error::InvalidConfig(format!("shadow step worker: {error}")))?
    }
}

/// What the arm meets before anything of it is read or loaded: its
/// protocol version, then its target, its scope and its sandbox.
fn refused_up_front(request: &ShadowRunRequest) -> Option<ShadowUnavailable> {
    if request.protocol_version != SHADOW_PROTOCOL_VERSION {
        return Some(ShadowUnavailable::new(
            Reason::ProtocolUnsupported,
            "protocol_version",
        ));
    }
    candidate_refusal(&request.target)
        .or_else(|| scope_refusal(request.scope))
        .or_else(|| sandbox_refusal(&request.sandbox))
}

/// A candidate engine, a build or a patch, is unavailable before any of
/// its code is loaded until the sandboxed candidate process lands (CALLS
/// "candidate engine unsupported until PR-S2").
fn candidate_refusal(target: &ShadowTarget) -> Option<ShadowUnavailable> {
    match target {
        ShadowTarget::Baseline => None,
        ShadowTarget::Candidate { .. } => Some(ShadowUnavailable::new(
            Reason::CandidateEngineUnsupported,
            "pr_s1",
        )),
    }
}

/// An arm runs its captured step alone in PR-S1 (CALLS "S1 scope = captured
/// step only"): a whole run is unavailable.
fn scope_refusal(scope: ShadowScope) -> Option<ShadowUnavailable> {
    match scope {
        ShadowScope::CapturedStep => None,
        ShadowScope::WholeRun => Some(ShadowUnavailable::new(Reason::WholeRunUnsupported, "pr_s1")),
    }
}

/// The baseline runs in the host's own process: an arm bound to a sandboxed
/// engine process has none to run in until PR-S2.
fn sandbox_refusal(sandbox: &ShadowSandboxBinding) -> Option<ShadowUnavailable> {
    match sandbox.isolation {
        ShadowIsolationRequired::TrustedInProcessBaseline => None,
        ShadowIsolationRequired::Sandboxed => {
            Some(ShadowUnavailable::new(Reason::SandboxUnavailable, "pr_s1"))
        }
    }
}

/// Whether `prepared` is the source `request` names: its request digest
/// (which copy too), its start when named, its clock and seed, the model
/// seed, and each body it expects granted.
fn matches_request(
    prepared: &PreparedShadowStep,
    request: &ShadowRunRequest,
    request_digest: ShadowRequestDigest,
    start: Option<&ExecutorStepStart>,
) -> Outcome<()> {
    let mismatch = |cause: &str| Err(ShadowUnavailable::new(Reason::SourceDigestMismatch, cause));
    if request_digest != prepared.request_digest() {
        return mismatch("request_digest");
    }
    if start.is_some_and(|start| start != prepared.start()) {
        return mismatch("start");
    }
    if request.determinism != prepared.determinism() {
        return mismatch("determinism");
    }
    if request.model_seed != prepared.seed() {
        return mismatch("model_seed");
    }
    prepared.check_refs(&request.input_refs)?;
    prepared.check_refs(&request.body_refs)
}

/// `step`'s capsule, read and frozen on a blocking worker.
async fn prepare_on_worker(
    vault: Arc<Vault>,
    step: ShadowStepIdentity,
) -> Result<Outcome<PreparedShadowStep>> {
    let prepared = tokio::task::spawn_blocking(move || prepare_step(&vault, step)).await;
    prepared.map_err(|error| Error::InvalidConfig(format!("shadow source worker: {error}")))?
}

/// The capsule `step` names, read and frozen; unavailable when there is no
/// such capsule.
fn prepare_step(vault: &Vault, step: ShadowStepIdentity) -> Result<Outcome<PreparedShadowStep>> {
    let capsule = step_replay_capsules(vault, step.attempt)?
        .into_iter()
        .find(|capsule| {
            capsule.lease_generation == step.lease_generation
                && capsule.run == step.run
                && capsule.step == step.step
        });
    let Some(capsule) = capsule else {
        return Ok(Err(ShadowUnavailable::new(
            Reason::SourceMissing,
            "capsule",
        )));
    };
    prepare_shadow_step_source(vault, &capsule)
}

/// `reason`, caused by `cause`, as an arm's status.
fn unavailable(reason: Reason, cause: &str) -> ShadowStatus {
    ShadowStatus::Unavailable {
        unavailable: ShadowUnavailable::new(reason, cause),
    }
}

/// The arms callers may cancel now.
fn lock(cancels: &Mutex<CancelMap>) -> MutexGuard<'_, CancelMap> {
    cancels.lock().unwrap_or_else(PoisonError::into_inner)
}
