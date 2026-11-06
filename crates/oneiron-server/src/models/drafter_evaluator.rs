//! The vault's own drafter, evaluated, activated and rolled back (FIX
//! 14975, FIX 12569 slice 5): the host half of `oneiron::drafter`'s
//! evaluation doors (DRAFTER-ACTIVATE = A + revert).
//!
//! [`start_drafter_evaluations`] runs once a version has trained: the
//! nightly retrain calls it before its own corpus work. It reads the plan of
//! the newest trained version of the target this process serves a drafter
//! for (its held-out cases opened then, in this process), and evaluates it
//! on a task of the vault's drafter host. One evaluation runs per vault at a
//! time. Until a trainer returns a version, nothing runs.
//!
//! **Evaluation** (`evaluate_drafter`). Every held-out case is rebuilt as the
//! request its rung sent (the provider's own body, output cap and response
//! format), asked solo, with [`EVALUATION_SEED`] where it names no seed. It
//! is replayed on evaluator incarnations of the vault's own serving row
//! (`worker_host::launch_evaluator`): one per block of the recipe's paired
//! schedule, each with the head the block names (the incumbent or the
//! candidate), then one with no draft at all, the target alone, on the same
//! target, quant, runtime, template, settings and depth. Each incarnation
//! answers its warm-up cases unmeasured, then every case once, by the
//! evaluator op (`eval.generate`): the exact token ids of every pass, its
//! receipt (raw token counts, native prefill and generate time, queue
//! waits, first-token time, drafts proposed and accepted) and, on the
//! target alone, each position's top two raw logits. The host times each
//! call end to end.
//!
//! **Token identity.** Each case's candidate output is compared, token by
//! token and pass by pass, with the target alone's. At a divergence the
//! target alone's top two raw logits on the shared prefix must be the two
//! tokens and lie within the recipe's epsilon: the divergence is recorded as
//! an allowed tie, the target alone runs again from the candidate's prefix
//! through that token (`forced`), and the continuation is compared under
//! that actual prefix, up to [`MAX_FOLLOWED_DIVERGENCES`] times. Any other
//! divergence fails. Every candidate block must give the same ids.
//!
//! **Decision.** The engine decides from the evidence. With no rule, no
//! held-out side, too small a sample, a mismatched runtime identity, a draft
//! that is not the one given, or a case one arm answered and another did
//! not, the evaluation is unknown; nothing activates.
//!
//! **Activation.** A version that qualified and beat the incumbent with no
//! slowdown is activated by compare-and-swap on the binding's generation;
//! the serving host serves it through its one seam (a supervised restart).
//! Once the new incarnation proves the draft's identity, the first
//! observation cases are replayed on it (`observe`): any output that is not
//! the qualified one, any error, or any slowdown against the incumbent's
//! runs under the recipe's metric rolls it back, with a `rollback` event the
//! morning report shows. No traffic mix is read as a speed comparison.
//!
//! Plaintext: each head an evaluator incarnation loads is materialised into
//! the vault's `drafter-evaluation/`, removed when the evaluation starts and
//! when it ends, and by a vault lock, which also retires the incarnations.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::drafter::{
    DrafterActivation, DrafterActivationServing, DrafterArmIdentity, DrafterCaseMeasure,
    DrafterEvaluation, DrafterEvaluationArm, DrafterEvaluationDecision, DrafterEvaluationEvidence,
    DrafterEvaluationPlan, DrafterHeldOutCase, DrafterObservation, DrafterObservationVerdict,
    DrafterQualificationRule, DrafterServing, DrafterSpeedVerdict, DrafterTarget,
    DrafterTieEvidence, DrafterTokenIdentity, DrafterUnknownReason, DrafterUnservedReason,
    compare_speed,
};
use oneiron::llm::{
    CacheDigest, CacheEpoch, INFERENCE_CALLS_KEY, InferenceCallReceipt, WorkerReadiness,
};
use oneiron::world_keys::VaultKeyStatus;
use oneiron::{EntityId, Vault};
use oneiron_driver::InferenceWorker;
use oneiron_llm_openai::{OpenAiCompatConfig, build_openai_chat_request};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::catalog::catalog_entry;
use super::drafter_serving::{
    VaultLoadSet, blocking, is_stock_draft_identity, served_vault_count, vault_runtime,
};
use super::native_exl3::{OpFault, evaluator_advertised, evaluator_generate, split_request};
use super::openai::send_format;
use super::output_cap;
use super::worker_host::{
    EvaluatorDraft, EvaluatorIncarnation, EvaluatorSeat, evaluator_seat, launch_evaluator,
};
use crate::config::models::ModelRef;

/// The seed a replayed case runs under when its request names none, so
/// every arm samples the same draws.
const EVALUATION_SEED: u64 = 0x0D2A_F7E2;

/// The request field the house EXL3 server admits a call alone by (its
/// `SOLO_FIELD`): an evaluation's answers are compared, and batch
/// invariance holds only for a call that runs alone.
const SOLO_PARAM: &str = "oneiron_solo";

/// The most allowed ties one case's comparison follows, each with one
/// target-only continuation; a case with more is unresolved.
const MAX_FOLLOWED_DIVERGENCES: usize = 8;

/// How long an evaluator incarnation may take to launch and qualify.
const EVALUATOR_READY_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// How long one evaluation call may take.
const EVALUATION_CASE_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// How long an activation may take to be served before it rolls back.
const ACTIVATION_SERVED_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// How often the activation's serving is read while it waits.
const SERVED_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The vaults an evaluation runs for now.
static RUNNING: Mutex<BTreeSet<[u8; 32]>> = Mutex::new(BTreeSet::new());

/// A vault's place in [`RUNNING`], given back when it drops.
struct Running([u8; 32]);

impl Running {
    fn claim(vault: [u8; 32]) -> Option<Self> {
        RUNNING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(vault)
            .then_some(Self(vault))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        RUNNING
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Starts the evaluation of the newest trained version of the drafter
/// target this process serves, on `vault`'s drafter host, when one waits and
/// none runs. The plan, held-out cases included, is read here, before the
/// caller's night may sweep the corpora. Returns at once.
pub(crate) fn start_drafter_evaluations(vault: &Arc<Vault>) {
    let Some(target) = super::drafter_retrain_target() else {
        return;
    };
    let id = vault.vault_key_vault_id();
    let Some(runtime) = vault_runtime(&id) else {
        return;
    };
    let version = match vault.drafter_evaluation_candidate(&target) {
        Ok(Some(version)) => version,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "the drafter evaluation candidates did not read");
            return;
        }
    };
    let Some(running) = Running::claim(id) else {
        return;
    };
    let plan = match vault.drafter_evaluation_plan(&version) {
        Ok(Some(plan)) => plan,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a drafter evaluation plan did not read");
            return;
        }
    };
    let vault = Arc::clone(vault);
    runtime.spawn(async move {
        let _running = running;
        evaluate_and_activate(vault, plan).await;
    });
}

/// One replayed case, as its rung sent it.
struct PreparedCase {
    index: u32,
    conversation: JsonValue,
    params: JsonValue,
}

/// The case `case` as the seat's provider sends it, solo, under
/// [`EVALUATION_SEED`] where it names none; `None` when it is not for the
/// seat's wire model or does not build.
fn prepare_case(seat: &EvaluatorSeat, case: &DrafterHeldOutCase) -> Option<PreparedCase> {
    if case.wire_model != seat.wire_model() {
        return None;
    }
    let provider = seat.provider();
    let model = ModelRef {
        provider: seat.provider_name().to_owned(),
        model: seat.wire_model().to_owned(),
    };
    let entry = catalog_entry(&model, provider).ok()?;
    let mut request = case.request.clone();
    request.model = entry.model.clone();
    let config = OpenAiCompatConfig::from_catalog([entry]);
    let mut body = build_openai_chat_request(&config, &request, false)
        .ok()?
        .body;
    output_cap(provider).apply(&mut body);
    send_format(provider.response_format, &mut body);
    let (conversation, mut params) = split_request(&body);
    let fields = params.as_object_mut()?;
    fields.insert(SOLO_PARAM.to_owned(), JsonValue::Bool(true));
    fields
        .entry("seed")
        .or_insert_with(|| json!(EVALUATION_SEED));
    Some(PreparedCase {
        index: case.index,
        conversation,
        params,
    })
}

/// One pass of one answer.
struct PassRun {
    phase: String,
    ids: Vec<u32>,
    /// Each position's `(id1, logit1, id2, logit2)`, when the call kept
    /// evidence.
    top2: Option<Vec<Option<(u32, f64, u32, f64)>>>,
}

/// One case's answer on one incarnation.
struct CaseRun {
    passes: Vec<PassRun>,
    measure: DrafterCaseMeasure,
}

impl CaseRun {
    fn top2_at(&self, pass: usize, position: usize) -> Option<(u32, f64, u32, f64)> {
        self.passes
            .get(pass)?
            .top2
            .as_ref()?
            .get(position)
            .copied()
            .flatten()
    }
}

#[derive(Deserialize)]
struct EvalPass {
    phase: String,
    ids: Vec<u32>,
    #[serde(default)]
    top2: Option<Vec<Option<(u32, f64, u32, f64)>>>,
}

#[derive(Deserialize)]
struct EvalError {
    #[serde(default)]
    code: Option<String>,
}

#[derive(Deserialize)]
struct EvalAnswer {
    outcome: String,
    #[serde(default)]
    passes: Vec<EvalPass>,
    #[serde(default)]
    usage: JsonValue,
    #[serde(default)]
    error: Option<EvalError>,
}

/// A live incarnation an evaluation calls: its supervisor, socket, epoch and
/// the draft identity its answers must name.
struct Endpoint {
    worker: InferenceWorker,
    socket: PathBuf,
    epoch: String,
    draft_digest: Option<String>,
}

/// BLAKE3 of the canonical JSON of `passes`' phases and ids.
fn output_digest(passes: &[PassRun]) -> [u8; 32] {
    let shape: Vec<(&str, &[u32])> = passes
        .iter()
        .map(|pass| (pass.phase.as_str(), pass.ids.as_slice()))
        .collect();
    *blake3::hash(&serde_json::to_vec(&shape).unwrap_or_default()).as_bytes()
}

/// The measure of case `index` from its receipt, timed `end_to_end` by the
/// host; its arm and block are the caller's.
fn measure_of(
    index: u32,
    receipt: &InferenceCallReceipt,
    end_to_end: Duration,
    passes: &[PassRun],
) -> DrafterCaseMeasure {
    let measured = !receipt.passes.is_empty();
    let queue = &receipt.queue_wait;
    let queue_us = match (queue.worker_us, queue.engine_us) {
        (None, None) => None,
        (worker, engine) => Some(worker.unwrap_or(0) + engine.unwrap_or(0)),
    };
    DrafterCaseMeasure {
        case: index,
        arm: DrafterEvaluationArm::TargetOnly,
        block: 0,
        prompt_tokens: receipt.logical_prompt_tokens,
        output_tokens: receipt.output_tokens,
        queue_us,
        prefill_us: receipt
            .passes
            .iter()
            .map(|pass| pass.prefill_us)
            .sum::<Option<u64>>()
            .filter(|_| measured),
        generate_us: receipt
            .passes
            .iter()
            .map(|pass| pass.generate_us)
            .sum::<Option<u64>>()
            .filter(|_| measured),
        ttft_us: receipt.ttft_us,
        end_to_end_us: u64::try_from(end_to_end.as_micros()).ok(),
        drafts_proposed: receipt.drafts_proposed,
        drafts_accepted: receipt.drafts_accepted,
        output_blake3: output_digest(passes),
    }
}

/// `answer`, case `index`'s, read and checked against `endpoint`: done,
/// with exactly one receipt naming the endpoint's epoch and draft identity.
/// Otherwise the fault's code.
fn read_answer(
    index: u32,
    answer: JsonValue,
    end_to_end: Duration,
    endpoint: &Endpoint,
) -> Result<CaseRun, String> {
    let answer: EvalAnswer =
        serde_json::from_value(answer).map_err(|_| "unreadable_answer".to_owned())?;
    if answer.outcome != "done" {
        let code = answer
            .error
            .and_then(|error| error.code)
            .unwrap_or_else(|| "unknown".to_owned());
        return Err(format!("error:{code}"));
    }
    let receipts: Vec<InferenceCallReceipt> = answer
        .usage
        .get(INFERENCE_CALLS_KEY)
        .cloned()
        .and_then(|calls| serde_json::from_value(calls).ok())
        .unwrap_or_default();
    let [receipt] = receipts.as_slice() else {
        return Err("receipt_missing".to_owned());
    };
    let identity = &receipt.worker.identity;
    let epoch = identity.backend_epoch.as_ref().map(CacheEpoch::as_str);
    if epoch != Some(endpoint.epoch.as_str())
        || identity.draft_weights_digest != endpoint.draft_digest
    {
        return Err("identity_moved".to_owned());
    }
    let passes: Vec<PassRun> = answer
        .passes
        .into_iter()
        .map(|pass| PassRun {
            phase: pass.phase,
            ids: pass.ids,
            top2: pass.top2,
        })
        .collect();
    let measure = measure_of(index, receipt, end_to_end, &passes);
    Ok(CaseRun { passes, measure })
}

/// Runs `case` once on `endpoint`, under a lease of its incarnation:
/// `forced` ids first where given, the evidence kept where asked, as
/// background work where asked. The fault's code otherwise.
async fn run_case(
    endpoint: &Endpoint,
    case: &PreparedCase,
    forced: Option<JsonValue>,
    evidence: bool,
    background: bool,
) -> Result<CaseRun, String> {
    let _lease = endpoint
        .worker
        .acquire()
        .await
        .map_err(|_| "worker_unavailable".to_owned())?;
    let mut body = json!({"params": case.params, "evidence": evidence});
    if let Some(forced) = forced {
        body["forced"] = forced;
    }
    if background {
        body["work_class"] = json!("background");
    }
    let started = Instant::now();
    let answer = tokio::time::timeout(
        EVALUATION_CASE_DEADLINE,
        evaluator_generate(&endpoint.socket, &endpoint.epoch, body, &case.conversation),
    )
    .await
    .map_err(|_| "case_deadline".to_owned())?
    .map_err(|fault| match fault {
        OpFault::Refused(code) => format!("refused:{code}"),
        OpFault::Cut => "cut".to_owned(),
    })?;
    read_answer(case.index, answer, started.elapsed(), endpoint)
}

/// Where two answers first part.
enum Divergence {
    /// Nowhere: the same passes, token for token.
    None,
    /// At this pass's position.
    At { pass: usize, position: usize },
    /// Their passes differ in phase, count or length with no token between
    /// them: no tie accounts for it.
    Shape,
}

fn first_divergence(reference: &[PassRun], drafted: &[PassRun]) -> Divergence {
    for (pass, (left, right)) in reference.iter().zip(drafted).enumerate() {
        if left.phase != right.phase {
            return Divergence::Shape;
        }
        if let Some(position) = left.ids.iter().zip(&right.ids).position(|(a, b)| a != b) {
            return Divergence::At { pass, position };
        }
        if left.ids.len() != right.ids.len() {
            return Divergence::Shape;
        }
    }
    if reference.len() == drafted.len() {
        Divergence::None
    } else {
        Divergence::Shape
    }
}

/// `drafted`'s ids up to and including pass `pass`'s position `position`,
/// by phase: what a target-only continuation is forced to first.
fn forced_prefix(drafted: &[PassRun], pass: usize, position: usize) -> JsonValue {
    let mut forced = JsonMap::new();
    for (index, run) in drafted.iter().enumerate().take(pass + 1) {
        let ids = if index == pass {
            &run.ids[..=position]
        } else {
            run.ids.as_slice()
        };
        forced.insert(run.phase.clone(), json!(ids));
    }
    JsonValue::Object(forced)
}

/// How one case's comparison ended.
enum CaseVerdict {
    Exact,
    Tied,
    Mismatch,
    Unresolved,
    NoLogits,
}

/// One case's comparison: its verdict, its allowed ties and the
/// continuations it ran.
struct Followed {
    verdict: CaseVerdict,
    ties: Vec<DrafterTieEvidence>,
    continuations: u64,
}

/// Whether the reference token `reference` and the drafted `drafted` are the
/// target alone's top two, `top`, within `epsilon` of each other.
fn allowed_tie(top: (u32, f64, u32, f64), reference: u32, drafted: u32, epsilon: f64) -> bool {
    let (first, first_logit, second, second_logit) = top;
    reference != drafted
        && ((first == reference && second == drafted) || (first == drafted && second == reference))
        && (first_logit - second_logit).abs() <= epsilon
}

/// Compares `drafted` with the target alone's `reference` for `case`,
/// following each allowed tie with a target-only continuation from the
/// drafted prefix on `endpoint`.
async fn follow(
    endpoint: &Endpoint,
    case: &PreparedCase,
    reference: &CaseRun,
    drafted: &CaseRun,
    epsilon: f64,
) -> Followed {
    let mut followed = Followed {
        verdict: CaseVerdict::Exact,
        ties: Vec::new(),
        continuations: 0,
    };
    let mut continued: Option<CaseRun> = None;
    let mut last: Option<(usize, usize)> = None;
    loop {
        let now = continued.as_ref().unwrap_or(reference);
        let (pass, position) = match first_divergence(&now.passes, &drafted.passes) {
            Divergence::None => {
                if !followed.ties.is_empty() {
                    followed.verdict = CaseVerdict::Tied;
                }
                return followed;
            }
            Divergence::Shape => {
                followed.verdict = CaseVerdict::Mismatch;
                return followed;
            }
            Divergence::At { pass, position } => (pass, position),
        };
        if last.is_some_and(|seen| (pass, position) <= seen)
            || followed.ties.len() >= MAX_FOLLOWED_DIVERGENCES
        {
            followed.verdict = CaseVerdict::Unresolved;
            return followed;
        }
        let Some(top) = now.top2_at(pass, position) else {
            followed.verdict = CaseVerdict::NoLogits;
            return followed;
        };
        let reference_id = now.passes[pass].ids[position];
        let drafted_id = drafted.passes[pass].ids[position];
        if !allowed_tie(top, reference_id, drafted_id, epsilon) {
            followed.verdict = CaseVerdict::Mismatch;
            return followed;
        }
        followed.ties.push(DrafterTieEvidence {
            case: case.index,
            phase: drafted.passes[pass].phase.clone(),
            position: position as u64,
            top1_logit: top.1,
            top2_logit: top.3,
        });
        last = Some((pass, position));
        let forced = forced_prefix(&drafted.passes, pass, position);
        match run_case(endpoint, case, Some(forced), true, false).await {
            Ok(run) => {
                followed.continuations += 1;
                continued = Some(run);
            }
            Err(_) => {
                followed.verdict = CaseVerdict::Unresolved;
                return followed;
            }
        }
    }
}

/// What one arm's incarnation answered; each run's measure names its
/// block.
struct ArmRun {
    arm: DrafterEvaluationArm,
    runs: BTreeMap<u32, CaseRun>,
    failed: BTreeMap<u32, String>,
}

/// The draft identity an arm's answers must name.
enum ExpectedDraft {
    None,
    Stock,
    Vault(String),
}

impl ExpectedDraft {
    fn holds(&self, digest: Option<&str>) -> bool {
        match self {
            Self::None => digest.is_none(),
            Self::Stock => digest.is_some_and(is_stock_draft_identity),
            Self::Vault(identity) => digest == Some(identity.as_str()),
        }
    }
}

/// One version's evaluation as this host runs it.
struct Evaluation {
    vault: Arc<Vault>,
    vault_id: [u8; 32],
    plan: DrafterEvaluationPlan,
    evidence: DrafterEvaluationEvidence,
    cases: Vec<PreparedCase>,
    /// Every arm's answers, the drafted blocks first, the target alone's
    /// last.
    arms: Vec<ArmRun>,
    /// The cases every arm answered: the ones compared.
    judged: BTreeSet<u32>,
    candidate: Option<Arc<VaultLoadSet>>,
}

impl Evaluation {
    fn new(vault: Arc<Vault>, plan: DrafterEvaluationPlan) -> Self {
        let evidence = plan.evidence();
        Self {
            vault_id: vault.vault_key_vault_id(),
            vault,
            plan,
            evidence,
            cases: Vec::new(),
            arms: Vec::new(),
            judged: BTreeSet::new(),
            candidate: None,
        }
    }

    fn rule(&self) -> Option<&DrafterQualificationRule> {
        self.plan.rule.as_ref().ok()
    }

    fn locked(&self) -> bool {
        self.vault
            .vault_key_status()
            .is_ok_and(|status| status == VaultKeyStatus::Locked)
    }

    /// Why replay must stop before the next case, if it must: the vault
    /// locked, or an erase or a policy change reached the version or its
    /// incumbent ([`Vault::drafter_evaluation_watch`]). The arm's
    /// incarnation is then retired and the evaluation's plaintext removed
    /// as the evaluation ends, before any further case runs.
    fn halted(&self) -> Option<DrafterUnknownReason> {
        if self.locked() {
            return Some(DrafterUnknownReason::VaultLocked);
        }
        match self.vault.drafter_evaluation_watch(&self.plan) {
            Ok(reason) => reason,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a drafter evaluation's watch did not read; replay stops");
                Some(DrafterUnknownReason::WorkerError)
            }
        }
    }

    fn error(&mut self, code: &str) {
        *self.evidence.errors.entry(code.to_owned()).or_default() += 1;
    }

    /// `version`'s load set at `generation`, materialised for an evaluator
    /// worker.
    async fn materialize(&self, version: EntityId, generation: u64) -> Option<Arc<VaultLoadSet>> {
        let made = blocking(&self.vault, move |vault| {
            let dir = vault.new_drafter_evaluation_dir()?;
            vault.materialize_drafter_evaluation_load_set(&version, generation, &dir)
        })
        .await;
        match made {
            Ok(made) => Some(Arc::new(VaultLoadSet {
                vault: self.vault_id,
                target: self.plan.target.clone(),
                version,
                generation: self.plan.binding_generation,
                dir: made.dir,
                files: made.files,
                load_set_blake3: made.load_set_blake3,
            })),
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "a drafter load set did not open for evaluation");
                None
            }
        }
    }

    /// What needs no worker: a rule, held-out cases, the rule's sample in
    /// them at all, the seat, and each case as its rung sent it.
    fn preflight(&mut self) -> Result<EvaluatorSeat, DrafterUnknownReason> {
        let min_cases = self
            .plan
            .rule
            .as_ref()
            .map_err(|reason| *reason)?
            .sample
            .min_cases;
        if self.plan.cases.is_empty() {
            return Err(DrafterUnknownReason::NoHeldOut);
        }
        if (self.plan.cases.len() as u64) < min_cases {
            return Err(DrafterUnknownReason::InsufficientSample);
        }
        let seat = evaluator_seat(&self.plan.target, served_vault_count())
            .map_err(|_| DrafterUnknownReason::NoEvaluatorWorker)?;
        let cases: Vec<PreparedCase> = self
            .plan
            .cases
            .iter()
            .filter_map(|case| prepare_case(&seat, case))
            .collect();
        let unbuildable = self.plan.cases.len() - cases.len();
        for _ in 0..unbuildable {
            self.error("case_unbuildable");
        }
        if cases.is_empty() {
            return Err(DrafterUnknownReason::NoHeldOut);
        }
        self.cases = cases;
        Ok(seat)
    }

    /// Launches one arm's incarnation with `draft` and checks what it
    /// proved: qualified, on the target's model and tokenizer, naming the
    /// draft it was given, with a socket that answers the evaluator op.
    async fn start_arm(
        &self,
        seat: &EvaluatorSeat,
        draft: EvaluatorDraft,
        expected: &ExpectedDraft,
    ) -> Result<(EvaluatorIncarnation, Endpoint, DrafterArmIdentity), DrafterUnknownReason> {
        let incarnation = launch_evaluator(seat, self.vault_id, draft)
            .ok_or(DrafterUnknownReason::WorkerError)?;
        let ready = tokio::time::timeout(
            EVALUATOR_READY_DEADLINE,
            incarnation.worker().ensure_ready(),
        )
        .await;
        let observed = match (ready, incarnation.worker().status().readiness) {
            (Ok(Ok(())), WorkerReadiness::Ready { observed }) => observed,
            _ => {
                incarnation.retire().await;
                return Err(DrafterUnknownReason::WorkerError);
            }
        };
        let pins = observed.identity;
        let text = |digest: Option<&CacheDigest>| digest.map(|digest| digest.as_str().to_owned());
        let identity = DrafterArmIdentity {
            arm: DrafterEvaluationArm::TargetOnly,
            block: 0,
            serving: None,
            draft_digest: pins.draft_weights_digest,
            model: text(pins.model.as_ref()),
            tokenizer: text(pins.tokenizer.as_ref()),
            runtime: text(pins.runtime.as_ref()),
            template: text(pins.template.as_ref()),
            epoch: pins
                .backend_epoch
                .as_ref()
                .map(|epoch| epoch.as_str().to_owned()),
            launch_manifest: incarnation.manifest_sha256(),
        };
        let fits = identity.model.as_deref() == Some(self.plan.target.model.as_str())
            && identity.tokenizer.as_deref() == Some(self.plan.target.tokenizer.as_str())
            && expected.holds(identity.draft_digest.as_deref());
        if !fits {
            incarnation.retire().await;
            return Err(DrafterUnknownReason::RuntimeIdentityMismatch);
        }
        let (Some(socket), Some(epoch)) = (incarnation.socket(), identity.epoch.clone()) else {
            incarnation.retire().await;
            return Err(DrafterUnknownReason::WorkerError);
        };
        if !evaluator_advertised(&socket).await {
            incarnation.retire().await;
            return Err(DrafterUnknownReason::WorkerError);
        }
        let endpoint = Endpoint {
            worker: incarnation.worker().clone(),
            socket,
            epoch,
            draft_digest: identity.draft_digest.clone(),
        };
        Ok((incarnation, endpoint, identity))
    }

    /// One arm's answers on `endpoint`: its warm-up cases unmeasured, then
    /// every case once, the evidence kept where asked.
    async fn measure_arm(
        &self,
        endpoint: &Endpoint,
        arm: DrafterEvaluationArm,
        block: u32,
        evidence: bool,
    ) -> Result<ArmRun, DrafterUnknownReason> {
        let warmup = self.rule().map_or(0, |rule| {
            usize::try_from(rule.schedule.warmup_cases).unwrap_or(usize::MAX)
        });
        for case in self.cases.iter().take(warmup) {
            if let Some(reason) = self.halted() {
                return Err(reason);
            }
            let _ = run_case(endpoint, case, None, false, false).await;
        }
        let mut run = ArmRun {
            arm,
            runs: BTreeMap::new(),
            failed: BTreeMap::new(),
        };
        for case in &self.cases {
            if let Some(reason) = self.halted() {
                return Err(reason);
            }
            match run_case(endpoint, case, None, evidence, false).await {
                Ok(mut answered) => {
                    answered.measure.arm = arm;
                    answered.measure.block = block;
                    run.runs.insert(case.index, answered);
                }
                Err(code) => {
                    run.failed.insert(case.index, code);
                }
            }
        }
        Ok(run)
    }

    /// The drafted blocks of the schedule, in order, each on an incarnation
    /// of its own with the head it names; `incumbent` is the incumbent
    /// version's load set, `None` for stock.
    async fn run_blocks(
        &mut self,
        seat: &EvaluatorSeat,
        incumbent: Option<Arc<VaultLoadSet>>,
    ) -> Result<(), DrafterUnknownReason> {
        let blocks = self
            .rule()
            .map(|rule| rule.schedule.blocks.clone())
            .unwrap_or_default();
        for (block, arm) in blocks.into_iter().enumerate() {
            let block = u32::try_from(block).unwrap_or(u32::MAX);
            let head = if arm == DrafterEvaluationArm::Candidate {
                self.candidate.clone()
            } else {
                incumbent.clone()
            };
            let (draft, expected) = match head {
                Some(set) => {
                    let identity = set.identity();
                    (EvaluatorDraft::Vault(set), ExpectedDraft::Vault(identity))
                }
                None => (EvaluatorDraft::Stock, ExpectedDraft::Stock),
            };
            let serving = if arm == DrafterEvaluationArm::Candidate {
                DrafterServing::Version(self.plan.version)
            } else {
                self.plan.incumbent
            };
            let (incarnation, endpoint, mut identity) =
                self.start_arm(seat, draft, &expected).await?;
            let measured = self.measure_arm(&endpoint, arm, block, false).await;
            incarnation.retire().await;
            identity.arm = arm;
            identity.block = block;
            identity.serving = Some(serving);
            self.evidence.arms.push(identity);
            self.arms.push(measured?);
        }
        Ok(())
    }

    /// The target alone, last: every case with its evidence, then each
    /// case's comparison, on the same incarnation.
    async fn run_reference(&mut self, seat: &EvaluatorSeat) -> Result<(), DrafterUnknownReason> {
        let block = u32::try_from(self.arms.len()).unwrap_or(u32::MAX);
        let (incarnation, endpoint, mut identity) = self
            .start_arm(seat, EvaluatorDraft::TargetOnly, &ExpectedDraft::None)
            .await?;
        identity.block = block;
        self.evidence.arms.push(identity);
        let judged = match self
            .measure_arm(&endpoint, DrafterEvaluationArm::TargetOnly, block, true)
            .await
        {
            Ok(reference) => {
                let judged = self.judge(&endpoint, &reference).await;
                self.arms.push(reference);
                judged
            }
            Err(reason) => Err(reason),
        };
        incarnation.retire().await;
        judged
    }

    /// The cases every arm answered. A case no arm answered is left out,
    /// counted under its fault; one some arms answered and others did not
    /// leaves the evaluation unknown.
    fn fold(&mut self, reference: &ArmRun) -> Result<BTreeSet<u32>, DrafterUnknownReason> {
        let mut judged = BTreeSet::new();
        let mut codes = Vec::new();
        let mut partial = false;
        for case in &self.cases {
            let mut answered = 0_usize;
            let mut fault: Option<&str> = None;
            let arms = self.arms.iter().chain(std::iter::once(reference));
            let mut total = 0_usize;
            for arm in arms {
                total += 1;
                if arm.runs.contains_key(&case.index) {
                    answered += 1;
                } else {
                    fault = fault.or(arm.failed.get(&case.index).map(String::as_str));
                }
            }
            let fault = fault.unwrap_or("unanswered");
            if answered == total {
                judged.insert(case.index);
            } else if answered == 0 {
                codes.push(format!("excluded:{fault}"));
            } else {
                partial = true;
                codes.push(format!("partial:{fault}"));
            }
        }
        for code in codes {
            self.error(&code);
        }
        if partial {
            Err(DrafterUnknownReason::WorkerError)
        } else {
            Ok(judged)
        }
    }

    /// `arm`'s answers to `case`, block by block.
    fn arm_runs(&self, arm: DrafterEvaluationArm, case: u32) -> Vec<&CaseRun> {
        self.arms
            .iter()
            .filter(|run| run.arm == arm)
            .filter_map(|run| run.runs.get(&case))
            .collect()
    }

    /// Compares each case every arm answered with the target alone's
    /// `reference`: the candidate's blocks must agree with each other, and
    /// their output must be the target alone's up to allowed ties.
    async fn judge(
        &mut self,
        endpoint: &Endpoint,
        reference: &ArmRun,
    ) -> Result<(), DrafterUnknownReason> {
        let judged = self.fold(reference)?;
        let epsilon = self
            .rule()
            .map(|rule| rule.logit_epsilon)
            .ok_or(DrafterUnknownReason::NoQualificationRule)?;
        let mut identity = DrafterTokenIdentity::default();
        for case in self
            .cases
            .iter()
            .filter(|case| judged.contains(&case.index))
        {
            if let Some(reason) = self.halted() {
                return Err(reason);
            }
            let Some(target) = reference.runs.get(&case.index) else {
                continue;
            };
            identity.cases += 1;
            let incumbent = self.arm_runs(DrafterEvaluationArm::Incumbent, case.index);
            if incumbent.first().is_some_and(|run| {
                matches!(
                    first_divergence(&target.passes, &run.passes),
                    Divergence::None
                )
            }) {
                identity.incumbent_exact += 1;
            }
            let candidate = self.arm_runs(DrafterEvaluationArm::Candidate, case.index);
            let Some(first) = candidate.first() else {
                continue;
            };
            if candidate
                .iter()
                .any(|run| run.measure.output_blake3 != first.measure.output_blake3)
            {
                identity.mismatched += 1;
                continue;
            }
            let followed = follow(endpoint, case, target, first, epsilon).await;
            identity.continuations += followed.continuations;
            match followed.verdict {
                CaseVerdict::Exact => identity.exact += 1,
                CaseVerdict::Tied => {
                    identity.tied += 1;
                    identity.ties.extend(followed.ties);
                }
                CaseVerdict::Mismatch => identity.mismatched += 1,
                CaseVerdict::Unresolved => identity.unresolved += 1,
                CaseVerdict::NoLogits => identity.without_logits += 1,
            }
        }
        self.evidence.identity = identity;
        self.judged = judged;
        Ok(())
    }

    /// Every arm's measures of the compared cases, into the evidence.
    fn collect_runs(&mut self) {
        let runs: Vec<DrafterCaseMeasure> = self
            .arms
            .iter()
            .flat_map(|arm| arm.runs.iter())
            .filter(|(case, _)| self.judged.contains(*case))
            .map(|(_, run)| run.measure.clone())
            .collect();
        self.evidence.runs = runs;
    }

    /// Runs the evaluation; what left it unknown, if anything.
    async fn evaluate(&mut self) -> Option<DrafterUnknownReason> {
        let seat = match self.preflight() {
            Ok(seat) => seat,
            Err(reason) => return Some(reason),
        };
        let _ = blocking(&self.vault, |vault| {
            Ok(vault.remove_drafter_evaluation_plaintext())
        })
        .await;
        self.candidate = self
            .materialize(self.plan.version, self.plan.version_generation)
            .await;
        if self.candidate.is_none() {
            self.error("candidate_load_set");
            return Some(DrafterUnknownReason::WorkerError);
        }
        let incumbent = match (self.plan.incumbent, self.plan.incumbent_generation) {
            (DrafterServing::Stock, _) => None,
            (DrafterServing::Version(id), Some(generation)) => {
                let Some(set) = self.materialize(id, generation).await else {
                    self.error("incumbent_load_set");
                    return Some(DrafterUnknownReason::WorkerError);
                };
                Some(set)
            }
            (DrafterServing::Version(_), None) => {
                self.error("incumbent_load_set");
                return Some(DrafterUnknownReason::WorkerError);
            }
        };
        let outcome = match self.run_blocks(&seat, incumbent).await {
            Ok(()) => self.run_reference(&seat).await,
            Err(reason) => Err(reason),
        };
        self.collect_runs();
        outcome.err()
    }
}

/// Evaluates `plan`'s version, records the evidence (the engine decides),
/// and activates a version that qualified and improved, then observes it.
async fn evaluate_and_activate(vault: Arc<Vault>, plan: DrafterEvaluationPlan) {
    let mut evaluation = Evaluation::new(Arc::clone(&vault), plan);
    let fault = evaluation.evaluate().await;
    let _ = blocking(&vault, |vault| {
        Ok(vault.remove_drafter_evaluation_plaintext())
    })
    .await;
    let evidence = evaluation.evidence.clone();
    let recorded = blocking(&vault, move |vault| {
        vault.record_drafter_evaluation(evidence, fault)
    })
    .await;
    let record = match recorded {
        Ok(Some(record)) => record,
        Ok(None) => {
            tracing::info!("a drafter version moved while it was evaluated; nothing was recorded");
            return;
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a drafter evaluation was not recorded");
            return;
        }
    };
    tracing::info!(
        decision = ?record.evidence.decision,
        speed = ?record.evidence.speed,
        "a drafter version was evaluated"
    );
    if record.evidence.decision != DrafterEvaluationDecision::Qualified
        || record.evidence.speed != DrafterSpeedVerdict::Improved
    {
        return;
    }
    let Some(candidate) = evaluation.candidate.as_deref().map(VaultLoadSet::identity) else {
        return;
    };
    activate_and_observe(&vault, &record, &candidate, &evaluation.cases).await;
}

/// Activates `record`'s version and, once served, observes it; a slowdown,
/// an output violation or an error rolls it back.
async fn activate_and_observe(
    vault: &Arc<Vault>,
    record: &DrafterEvaluation,
    candidate: &str,
    cases: &[PreparedCase],
) {
    let id = record.id;
    let activation = blocking(vault, move |vault| vault.try_activate_drafter(&id)).await;
    let generation = match activation {
        Ok(DrafterActivation::Activated { binding, .. }) => binding.generation,
        Ok(DrafterActivation::Refused { reason }) => {
            tracing::info!(?reason, "a qualified drafter version was not activated");
            return;
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a drafter activation did not run");
            return;
        }
    };
    let observation = observe(vault, record, generation, candidate, cases).await;
    let verdict = observation.verdict;
    let observed = blocking(vault, move |vault| {
        vault.observe_drafter_serving(&id, observation)
    })
    .await;
    match observed {
        Ok(outcome) => tracing::info!(?verdict, ?outcome, "an activated drafter was observed"),
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a drafter observation was not recorded");
        }
    }
}

/// How the wait for an activation's serving ended.
enum ServedWait {
    Served(Option<String>),
    Moved,
    Failed,
}

/// Waits until the serving host recorded an incarnation serving `version`
/// for `target` at binding generation `generation`, the binding moved, the
/// host's apply of it failed, or [`ACTIVATION_SERVED_DEADLINE`] passed.
async fn wait_served(
    vault: &Arc<Vault>,
    target: &DrafterTarget,
    generation: u64,
    version: EntityId,
) -> ServedWait {
    let deadline = Instant::now() + ACTIVATION_SERVED_DEADLINE;
    let mut applying_seen = false;
    loop {
        let owned = target.clone();
        let read = blocking(vault, move |vault| {
            vault.drafter_activation_serving(&owned, generation, &version)
        })
        .await;
        match read {
            Ok(DrafterActivationServing::Served { draft_digest }) => {
                return ServedWait::Served(draft_digest);
            }
            Ok(DrafterActivationServing::Moved) => return ServedWait::Moved,
            Ok(DrafterActivationServing::Pending { view: Some(view) }) => {
                if view.applying {
                    applying_seen = true;
                } else if applying_seen
                    && matches!(
                        view.reason,
                        Some(
                            DrafterUnservedReason::WorkerRejected
                                | DrafterUnservedReason::LoadSetUnverified
                        )
                    )
                {
                    return ServedWait::Failed;
                }
            }
            Ok(DrafterActivationServing::Pending { view: None }) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return ServedWait::Failed;
        }
        tokio::time::sleep(SERVED_POLL_INTERVAL).await;
    }
}

/// The vault's serving incarnation of `target`, when it serves the draft
/// `candidate` names and answers the evaluator op.
async fn serving_endpoint(target: &DrafterTarget, candidate: &str) -> Option<Endpoint> {
    let seat = evaluator_seat(target, served_vault_count()).ok()?;
    let (worker, socket) = seat.serving_endpoint()?;
    let WorkerReadiness::Ready { observed } = worker.status().readiness else {
        return None;
    };
    let epoch = observed
        .identity
        .backend_epoch
        .as_ref()?
        .as_str()
        .to_owned();
    let draft_digest = observed.identity.draft_weights_digest.clone();
    if draft_digest.as_deref() != Some(candidate) || !evaluator_advertised(&socket).await {
        return None;
    }
    Some(Endpoint {
        worker,
        socket,
        epoch,
        draft_digest,
    })
}

fn note(observation: &mut DrafterObservation, code: &str) {
    *observation.errors.entry(code.to_owned()).or_default() += 1;
}

/// Replays the first `take` of `cases` the evaluation qualified on the
/// serving `endpoint`, as background work, into `observation`: `false`, its
/// verdict set, once an answer is not the qualified one or a case fails.
async fn replay_observation(
    endpoint: &Endpoint,
    observation: &mut DrafterObservation,
    qualified: &BTreeMap<u32, [u8; 32]>,
    cases: &[PreparedCase],
    take: usize,
) -> bool {
    for case in cases
        .iter()
        .filter(|case| qualified.contains_key(&case.index))
        .take(take)
    {
        let mut run = match run_case(endpoint, case, None, false, true).await {
            Ok(run) => run,
            Err(code) => {
                note(observation, &code);
                observation.verdict = DrafterObservationVerdict::WorkerError;
                return false;
            }
        };
        run.measure.arm = DrafterEvaluationArm::Served;
        let matches = qualified.get(&case.index) == Some(&run.measure.output_blake3);
        observation.runs.push(run.measure);
        if !matches {
            observation.verdict = DrafterObservationVerdict::OutputMismatch;
            return false;
        }
    }
    true
}

/// Identity-pinned reference measurements of the incarnation that serves
/// `record`'s activated version: its first observation cases replayed on
/// it, as background work, each answer the qualified one, and their speed
/// against the incumbent's runs of the evaluation under the recipe's rule.
async fn observe(
    vault: &Arc<Vault>,
    record: &DrafterEvaluation,
    generation: u64,
    candidate: &str,
    cases: &[PreparedCase],
) -> DrafterObservation {
    let evidence = &record.evidence;
    let mut observation = DrafterObservation {
        generation,
        draft_digest: None,
        epoch: None,
        runs: Vec::new(),
        comparisons: Vec::new(),
        errors: BTreeMap::new(),
        verdict: DrafterObservationVerdict::WorkerError,
        observed_at: 0,
    };
    match wait_served(vault, &evidence.target, generation, evidence.version).await {
        ServedWait::Served(digest) if digest.as_deref() == Some(candidate) => {
            observation.draft_digest = digest;
        }
        ServedWait::Served(_) => {
            note(&mut observation, "draft_identity");
            return observation;
        }
        ServedWait::Moved => {
            note(&mut observation, "binding_moved");
            return observation;
        }
        ServedWait::Failed => {
            note(&mut observation, "not_served");
            return observation;
        }
    }
    let (Some(rule), Some(endpoint)) = (
        evidence.rule.as_ref(),
        serving_endpoint(&evidence.target, candidate).await,
    ) else {
        note(&mut observation, "no_serving_endpoint");
        return observation;
    };
    observation.epoch = Some(endpoint.epoch.clone());
    let qualified: BTreeMap<u32, [u8; 32]> = evidence
        .runs
        .iter()
        .filter(|run| run.arm == DrafterEvaluationArm::Candidate)
        .map(|run| (run.case, run.output_blake3))
        .collect();
    let take = usize::try_from(rule.schedule.observation_cases).unwrap_or(usize::MAX);
    if !replay_observation(&endpoint, &mut observation, &qualified, cases, take).await {
        return observation;
    }
    let mut runs: Vec<DrafterCaseMeasure> = evidence
        .runs
        .iter()
        .filter(|run| run.arm == DrafterEvaluationArm::Incumbent)
        .cloned()
        .collect();
    runs.extend(observation.runs.iter().cloned());
    let (speed, comparisons) = compare_speed(
        &rule.slowdown,
        &runs,
        DrafterEvaluationArm::Incumbent,
        DrafterEvaluationArm::Served,
    );
    observation.comparisons = comparisons;
    observation.verdict = match speed {
        DrafterSpeedVerdict::Slowdown => DrafterObservationVerdict::Slowdown,
        DrafterSpeedVerdict::Unmeasured => DrafterObservationVerdict::WorkerError,
        DrafterSpeedVerdict::Improved | DrafterSpeedVerdict::NotImproved => {
            DrafterObservationVerdict::Clean
        }
    };
    observation
}
