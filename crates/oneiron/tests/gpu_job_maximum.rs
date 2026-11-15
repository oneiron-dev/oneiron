//! Customer GPU jobs under their declared maximum (CROSS-ARCH-0023 lifecycle,
//! C2; row L10-31): the quote reserved whole before anything is created, the
//! job told to checkpoint at 50, 80 and 95 percent, the customer's warning at
//! 95 in their inbox, the stop at the maximum only after a checkpoint taken
//! after that warning, the add-funds notice and the one resume, settlement of
//! the billed time never above the quote, and a restarted host taking a chunk
//! up again. The provider is a scripted fake that logs each call.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GPU_JOB_STOPPED_PRODUCER, GPU_JOB_WARNING_PRODUCER, GPU_QUOTE_VALID_MS, GpuConnectorError,
    GpuEndReason, GpuJob, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote, GpuJobRequest,
    GpuJobSignal, GpuJobSpec, GpuJobState, GpuJobStepReport, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination, PriceShape,
};
use oneiron::inbox::{NotificationBody, NotificationKind, decode_notification_body};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, CheckpointRef, JobSignal, JobStartRefused, KeyCustody, LeaseUnit, MemoryReceipts,
    OfferRoute, PaidConnector, Payer, ResumeRefused, RunAdmission, RunDeclaration, RunDenied,
    RunEvent,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;
const DEFAULT_MAXIMUM_SECS: u64 = 3_600;

/// What the fake provider holds and answers.
#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    created: HashMap<String, GpuResourceRef>,
    specs: Vec<GpuJobSpec>,
    signals: Vec<GpuJobSignal>,
    /// The next create makes its resource, then answers a timeout.
    create_times_out: bool,
    status: Option<GpuResourceStatus>,
    termination: Option<GpuTermination>,
}

#[derive(Default)]
struct FakeGpu(Mutex<FakeState>);

impl FakeGpu {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake provider lock")
    }

    fn running(&self, used_secs: u64, checkpoint: Option<&str>) {
        self.state().status = Some(GpuResourceStatus::Running {
            used_secs,
            checkpoint: checkpoint.map(|name| CheckpointRef(name.to_owned())),
        });
    }

    fn terminates(&self, termination: GpuTermination) {
        self.state().termination = Some(termination);
    }

    fn calls(&self) -> Vec<String> {
        self.state().calls.clone()
    }

    fn called(&self, name: &str) -> usize {
        self.calls()
            .iter()
            .filter(|call| call.starts_with(name))
            .count()
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("create {key}"));
        state.specs.push(spec.clone());
        let resource = GpuResourceRef(format!("resource-{key}"));
        state.created.insert(key.to_owned(), resource.clone());
        if std::mem::take(&mut state.create_times_out) {
            return Err(GpuConnectorError::Timeout);
        }
        Ok(resource)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("find {key}"));
        Ok(state.created.get(key).cloned())
    }

    fn status(&self, _resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(self
            .state()
            .status
            .clone()
            .unwrap_or(GpuResourceStatus::Pending))
    }

    fn signal(
        &self,
        _resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.state().signals.push(signal);
        Ok(())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push("terminate".to_owned());
        Ok(state.termination.unwrap_or(GpuTermination::Pending))
    }
}

/// A rooted vault, its owner, one offer at 2 credit-micros a second (startup
/// 10, teardown 5, rounding 5) and the fake provider.
struct Rig {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    owner_actor: EntityId,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
}

fn offer(unit_cost: u64) -> GpuOffer {
    GpuOffer {
        name: "h100-fixture".to_owned(),
        class: "h100".to_owned(),
        provider: "fixture-cloud".to_owned(),
        region: "test-1".to_owned(),
        connector: PaidConnector {
            connector: "fixture-gpu".to_owned(),
            route: OfferRoute::new("fixture-gpu", "https://gpu.example.com").expect("route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: Some("gpu-prices-1".to_owned()),
            custody: KeyCustody::T0,
            unit_cost,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 10,
        teardown_secs: 5,
        rounding_secs: 5,
    }
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    Rig {
        _dir: dir,
        vault,
        owner,
        owner_actor,
        offer: offer(2),
        gpu: FakeGpu::default(),
        permits: GpuJobPermits::new(),
    }
}

fn request(maximum_secs: Option<u64>) -> GpuJobRequest {
    GpuJobRequest {
        job_type: "fine-tune".to_owned(),
        image: "registry.example.com/trainer@sha256:00".to_owned(),
        maximum_secs,
        inputs: serde_json::json!({"dataset": "owen-notes"}),
    }
}

/// The job's own run, with one line of `limit` credit-micros.
fn admission(job: &EntityId, limit: u64) -> (RunAdmission, Arc<MemoryReceipts>) {
    let receipts = Arc::new(MemoryReceipts::default());
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: limit,
        reserve_units: limit,
        unit: LeaseUnit::new("credit-micros").expect("unit"),
    })
    .with_connector("fixture-gpu".to_owned());
    let admission = RunAdmission::new(
        GpuJob::admission_ref_of(job),
        declaration,
        None,
        Arc::clone(&receipts) as Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    );
    (admission, receipts)
}

/// The units each settled receipt charged, in order.
fn settled(receipts: &MemoryReceipts) -> Vec<u64> {
    receipts
        .rows()
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Settled { units, .. } => Some(units),
            _ => None,
        })
        .collect()
}

fn notice(vault: &Vault, id: &EntityId) -> NotificationBody {
    let body = vault.get(id).expect("notice read").expect("notice row");
    decode_notification_body(&body).expect("notice body")
}

impl Rig {
    fn quote(&self, maximum_secs: u64, resume: Option<EntityId>, now_ms: u64) -> GpuJobQuote {
        self.offer
            .quote(
                &request(Some(maximum_secs)),
                resume,
                DEFAULT_MAXIMUM_SECS,
                now_ms,
            )
            .expect("quote")
    }

    fn start(&self, quote: &GpuJobQuote, admission: &RunAdmission) -> GpuJob {
        self.vault
            .start_gpu_job(
                &self.owner,
                &self.offer,
                quote,
                None,
                admission,
                &self.permits,
                &self.gpu,
                NOW,
            )
            .expect("start")
    }

    /// The provider reports `used_secs` (and a checkpoint), then the host
    /// steps the job.
    fn step_at(
        &self,
        job: &EntityId,
        admission: &RunAdmission,
        used_secs: u64,
        checkpoint: Option<&str>,
    ) -> GpuJobStepReport {
        self.gpu.running(used_secs, checkpoint);
        self.step(job, admission)
    }

    fn step(&self, job: &EntityId, admission: &RunAdmission) -> GpuJobStepReport {
        self.vault
            .gpu_job_step(job, &self.offer, admission, &self.permits, &self.gpu, NOW)
            .expect("step")
    }

    fn job(&self, id: &EntityId) -> GpuJob {
        self.vault.gpu_job(id).expect("job read").expect("job row")
    }

    /// Runs a fresh 100-second job to its stop at the maximum: checkpoint
    /// signals at 50, 80 and 95, the warning at 95, checkpoint `ck-1` after
    /// it, the stop at 100 and a termination confirmed at 100 billed seconds.
    fn run_to_stop(
        &self,
    ) -> (
        GpuJob,
        RunAdmission,
        Arc<MemoryReceipts>,
        Vec<GpuJobStepReport>,
    ) {
        let quote = self.quote(100, None, NOW);
        let (admission, receipts) = admission(&quote.job, quote.units);
        let job = self.start(&quote, &admission);
        let mut reports = Vec::new();
        for (used, checkpoint) in [(50, None), (80, None), (95, None), (97, Some("ck-1"))] {
            reports.push(self.step_at(&job.id, &admission, used, checkpoint));
        }
        self.gpu.terminates(GpuTermination::Pending);
        reports.push(self.step_at(&job.id, &admission, 100, Some("ck-1")));
        self.gpu
            .terminates(GpuTermination::Confirmed { billed_secs: 100 });
        reports.push(self.step(&job.id, &admission));
        (self.job(&job.id), admission, receipts, reports)
    }
}

#[test]
fn a_job_warns_checkpoints_and_stops_at_its_maximum() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    assert_eq!((quote.maximum_secs, quote.overhead_secs), (100, 20));
    assert_eq!((quote.quantity, quote.units), (120, 240));
    let (job, _admission, receipts, reports) = rig.run_to_stop();

    assert_eq!(
        rig.gpu.state().signals[..3],
        [
            GpuJobSignal::CheckpointDue { percent: 50 },
            GpuJobSignal::CheckpointDue { percent: 80 },
            GpuJobSignal::CheckpointDue { percent: 95 },
        ],
        "the job is told to checkpoint at 50, 80 and 95 percent, once each and in order",
    );
    assert_eq!(rig.gpu.state().signals.len(), 3, "and nothing else");
    assert!(
        reports[2]
            .signals
            .iter()
            .any(|signal| matches!(signal, JobSignal::Warning95 { .. })),
        "the warning comes at 95 percent: {:?}",
        reports[2].signals
    );
    assert_eq!(
        reports[2].notices.len(),
        1,
        "one warning notice for the owner"
    );
    let warning = notice(&rig.vault, &reports[2].notices[0]);
    assert_eq!(warning.kind, NotificationKind::GpuJobWarning);
    assert_eq!(warning.source.producer, GPU_JOB_WARNING_PRODUCER);
    assert_eq!(warning.source.result, Some(job.id.to_hex()));
    assert_eq!(warning.recipient, Some(rig.owner_actor.to_hex()));
    assert!(reports[3].notices.is_empty(), "the warning is written once");

    assert_eq!(
        reports[4].state,
        GpuJobState::Ending {
            reason: GpuEndReason::AtMaximum
        },
        "at the maximum, after the warning and a later checkpoint, the job is terminated",
    );
    assert_eq!(rig.gpu.called("terminate"), 2, "asked until confirmed");
    assert_eq!(job.state, GpuJobState::Stopped);
    let stop = job.stop.as_ref().expect("the stop is kept");
    assert_eq!(stop.notice.checkpoint, CheckpointRef("ck-1".to_owned()));
    assert_eq!(stop.notice.used_units, 100);

    let stopped = &reports[5];
    assert_eq!(stopped.notices.len(), 1, "one add-funds notice");
    let ask = notice(&rig.vault, &stopped.notices[0]);
    assert_eq!(ask.kind, NotificationKind::Ask);
    assert_eq!(ask.source.producer, GPU_JOB_STOPPED_PRODUCER);
    assert!(
        ask.source
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("ck-1")),
        "the notice names the checkpoint the job resumes from: {:?}",
        ask.source.detail
    );
    assert_eq!(stopped.settled_units, Some(240), "(100 + 20) seconds at 2");
    assert_eq!(settled(&receipts), vec![240]);
}

#[test]
fn a_stop_waits_for_a_checkpoint_taken_after_the_warning() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.gpu.terminates(GpuTermination::Pending);
    // ck-0 is taken before the warning; ck-0b is first seen with it.
    rig.step_at(&job.id, &admission, 60, Some("ck-0"));
    rig.step_at(&job.id, &admission, 95, Some("ck-0b"));
    assert!(rig.job(&job.id).maximum.warning_delivered());
    assert_eq!(rig.job(&job.id).maximum.counted_checkpoint(), None);

    let at_maximum = rig.step_at(&job.id, &admission, 100, Some("ck-0b"));
    assert_eq!(
        at_maximum.state,
        GpuJobState::Running,
        "no stop without a checkpoint"
    );
    assert_eq!(rig.gpu.called("terminate"), 0);
    assert_eq!(
        rig.gpu.state().signals.last(),
        Some(&GpuJobSignal::CheckpointBeforeStop),
        "the job is asked for a checkpoint instead",
    );

    let checkpointed = rig.step_at(&job.id, &admission, 101, Some("ck-1"));
    assert_eq!(
        checkpointed.state,
        GpuJobState::Ending {
            reason: GpuEndReason::AtMaximum
        }
    );
    assert_eq!(rig.gpu.called("terminate"), 1);
}

#[test]
fn a_zero_maximum_or_a_reservation_that_does_not_fit_never_creates() {
    let rig = rig();
    let zero = rig
        .offer
        .quote(&request(Some(0)), None, DEFAULT_MAXIMUM_SECS, NOW);
    assert!(
        matches!(zero, Err(GpuJobError::Start(JobStartRefused::ZeroMaximum))),
        "{zero:?}"
    );

    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units - 1);
    let refused = rig.vault.start_gpu_job(
        &rig.owner,
        &rig.offer,
        &quote,
        None,
        &admission,
        &rig.permits,
        &rig.gpu,
        NOW,
    );
    assert!(
        matches!(refused, Err(GpuJobError::Denied(RunDenied::Budget { .. }))),
        "{refused:?}"
    );
    assert!(
        rig.gpu.calls().is_empty(),
        "nothing was created: {:?}",
        rig.gpu.calls()
    );
    assert!(
        rig.vault.gpu_jobs().expect("jobs").is_empty(),
        "nothing was written"
    );
}

#[test]
fn an_exited_job_settles_its_billed_time_and_returns_the_rest() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.step_at(&job.id, &admission, 20, None);
    rig.gpu.state().status = Some(GpuResourceStatus::Exited { used_secs: 40 });
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 40 });
    let ended = rig.step(&job.id, &admission);

    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    assert_eq!(ended.settled_units, Some(120), "(40 + 20) seconds at 2");
    assert_eq!(settled(&receipts), vec![120]);
    assert_eq!(admission.read().remaining_units, 120, "the rest goes back");
    assert!(ended.notices.is_empty());
}

#[test]
fn resume_runs_once_from_the_checkpoint_under_a_larger_maximum() {
    let rig = rig();
    let (job, _first, _receipts, _) = rig.run_to_stop();
    let resume = job.stop.as_ref().expect("stopped").resume.clone();

    let quote = rig.quote(100, Some(job.id), NOW);
    let (admission, receipts) = admission(&job.id, quote.units);
    let resumed = rig
        .vault
        .start_gpu_job(
            &rig.owner,
            &rig.offer,
            &quote,
            Some(&resume),
            &admission,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("resume");
    assert_eq!(resumed.state, GpuJobState::Running);
    assert_eq!(resumed.chunks.len(), 2);
    assert_eq!(
        resumed.maximum.maximum().units,
        200,
        "100 run plus 100 more"
    );
    let spec = rig
        .gpu
        .state()
        .specs
        .last()
        .cloned()
        .expect("second create");
    assert_eq!(spec.checkpoint_from, Some(CheckpointRef("ck-1".to_owned())));
    assert_eq!(spec.maximum_secs, 100);
    assert_eq!(spec.chunk, 1);

    // The new chunk gets its own signals: 160 of 200 is the next one, 80.
    let signals_before = rig.gpu.state().signals.len();
    rig.step_at(&job.id, &admission, 10, None);
    assert_eq!(
        rig.gpu.state().signals.len(),
        signals_before,
        "50 percent was reached before"
    );
    rig.step_at(&job.id, &admission, 60, None);
    assert_eq!(
        rig.gpu.state().signals.last(),
        Some(&GpuJobSignal::CheckpointDue { percent: 80 })
    );

    let again = rig.vault.start_gpu_job(
        &rig.owner,
        &rig.offer,
        &rig.quote(100, Some(job.id), NOW),
        Some(&resume),
        &admission,
        &rig.permits,
        &rig.gpu,
        NOW,
    );
    assert!(
        matches!(again, Err(GpuJobError::Resume(ResumeRefused::NotStopped))),
        "{again:?}"
    );

    // The second chunk runs to its own stop; the first stop's offer is spent.
    rig.step_at(&job.id, &admission, 95, None);
    rig.step_at(&job.id, &admission, 97, Some("ck-2"));
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 100 });
    let stopped = rig.step_at(&job.id, &admission, 100, Some("ck-2"));
    assert_eq!(stopped.state, GpuJobState::Stopped);
    assert_eq!(
        settled(&receipts),
        vec![240],
        "the chunk pays its own quote"
    );
    let stale = rig.vault.start_gpu_job(
        &rig.owner,
        &rig.offer,
        &rig.quote(100, Some(job.id), NOW),
        Some(&resume),
        &admission,
        &rig.permits,
        &rig.gpu,
        NOW,
    );
    assert!(
        matches!(stale, Err(GpuJobError::Resume(ResumeRefused::StaleOffer))),
        "{stale:?}"
    );
}

#[test]
fn a_create_timeout_finds_the_resource_and_never_creates_twice() {
    let rig = rig();
    rig.gpu.state().create_times_out = true;
    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);

    let key = format!("{}:0", job.id.to_hex());
    assert_eq!(
        rig.gpu.calls(),
        vec![format!("create {key}"), format!("find {key}")]
    );
    assert_eq!(job.state, GpuJobState::Running);
    assert_eq!(
        job.chunk().and_then(|chunk| chunk.resource.clone()),
        Some(GpuResourceRef(format!("resource-{key}")))
    );
}

#[test]
fn a_quote_on_the_host_default_maximum_starts() {
    let rig = rig();
    let quote = rig
        .offer
        .quote(&request(None), None, DEFAULT_MAXIMUM_SECS, NOW)
        .expect("quote");
    assert_eq!(quote.maximum_secs, DEFAULT_MAXIMUM_SECS);
    let (admission, _receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);

    assert_eq!(job.state, GpuJobState::Running);
    assert_eq!(rig.gpu.called("create"), 1);
    assert_eq!(
        rig.gpu.state().specs[0].maximum_secs,
        DEFAULT_MAXIMUM_SECS,
        "the chunk runs under the host's default maximum"
    );
}

#[test]
fn a_quote_from_a_changed_offer_is_refused() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units * 2);
    let start = |offer: &GpuOffer, now_ms: u64| {
        rig.vault.start_gpu_job(
            &rig.owner,
            offer,
            &quote,
            None,
            &admission,
            &rig.permits,
            &rig.gpu,
            now_ms,
        )
    };
    let changed = start(&offer(3), NOW);
    assert!(
        matches!(changed, Err(GpuJobError::QuoteChanged)),
        "{changed:?}"
    );
    assert!(
        changed
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("quote again"))
    );
    let expired = start(&rig.offer, NOW + GPU_QUOTE_VALID_MS + 1);
    assert!(
        matches!(expired, Err(GpuJobError::QuoteExpired)),
        "{expired:?}"
    );
    assert!(rig.gpu.calls().is_empty(), "nothing was created");
}

#[test]
fn cancel_ends_and_settles_without_the_maximum_conditions() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.step_at(&job.id, &admission, 30, None);
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 30 });

    let cancelled = rig
        .vault
        .cancel_gpu_job(&rig.owner, &job.id, &rig.permits, &rig.gpu, NOW)
        .expect("cancel");
    assert_eq!(
        cancelled.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(rig.gpu.called("terminate"), 1);
    assert_eq!(
        cancelled.chunk().and_then(|chunk| chunk.settled_units),
        Some(100),
        "(30 + 20) seconds at 2"
    );
    assert_eq!(settled(&receipts), vec![100]);
    assert!(cancelled.stop.is_none(), "no stop and no add-funds notice");
    assert!(!cancelled.maximum.warning_delivered(), "no warning");
}

#[test]
fn a_restarted_host_takes_up_the_chunk_and_its_new_permit_pays_the_end() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (first, first_receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &first);
    rig.step_at(&job.id, &first, 30, None);

    // The host stops: its permits are handed off, charging nothing.
    let handed = rig.permits.hand_off_all();
    assert_eq!(handed.len(), 1);
    assert_eq!(
        settled(&first_receipts).iter().sum::<u64>(),
        0,
        "a kept chunk is charged nothing"
    );
    assert_eq!(first.read().remaining_units, quote.units);

    // The restarted host's step admits the chunk again on its new run.
    let (second, second_receipts) = admission(&job.id, quote.units);
    rig.step_at(&job.id, &second, 45, None);
    assert!(rig.permits.holds(&job.id), "the chunk is taken up");
    assert!(!rig.job(&job.id).chunk().expect("chunk").admission_lost);

    rig.gpu.state().status = Some(GpuResourceStatus::Exited { used_secs: 50 });
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 50 });
    let ended = rig.step(&job.id, &second);
    assert_eq!(ended.settled_units, Some(140), "(50 + 20) seconds at 2");
    assert_eq!(
        settled(&second_receipts),
        vec![140],
        "the new permit pays the end"
    );
    assert_eq!(settled(&first_receipts).iter().sum::<u64>(), 0);
}
