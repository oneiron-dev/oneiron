//! Customer GPU jobs under their declared maximum (CROSS-ARCH-0023 lifecycle,
//! C2; row L10-31): the quote reserved whole before anything is created, the
//! job told to checkpoint at 50, 80 and 95 percent, the customer's warning at
//! 95 in their inbox, the stop at the maximum only after a checkpoint taken
//! after that warning, the add-funds notice and the one resume, settlement of
//! the billed time never above the quote, and a restarted host taking a chunk
//! up again. The provider is a scripted fake that logs each call.
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GPU_JOB_STOPPED_PRODUCER, GPU_JOB_WARNING_PRODUCER, GPU_QUOTE_VALID_MS, GpuConnectorError,
    GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits, GpuJobQuote,
    GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuJobState, GpuJobStepReport, GpuOffer,
    GpuResourceRef, GpuResourceStatus, GpuTermination, PriceShape,
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
    /// The next create answers that the provider is unavailable and makes
    /// nothing.
    create_unavailable: bool,
    status: Option<GpuResourceStatus>,
    termination: Option<GpuTermination>,
    /// The next create waits here twice before it makes its resource: once
    /// on entering, once to go on; the test's other side runs between.
    create_gate: Option<Arc<Barrier>>,
    /// The next status read waits here the same way.
    status_gate: Option<Arc<Barrier>>,
}

/// Waits at a gate taken from the fake twice, holding no lock of the fake.
fn pass_gate(gate: Option<Arc<Barrier>>) {
    if let Some(gate) = gate {
        gate.wait();
        gate.wait();
    }
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
        let gate = self.state().create_gate.take();
        pass_gate(gate);
        let mut state = self.state();
        state.calls.push(format!("create {key}"));
        state.specs.push(spec.clone());
        if std::mem::take(&mut state.create_unavailable) {
            return Err(GpuConnectorError::Unavailable {
                reason: "fixture provider down".to_owned(),
            });
        }
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
        let gate = self.state().status_gate.take();
        pass_gate(gate);
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
                GpuJobStart {
                    actor: GpuJobActor::Owner(&self.owner),
                    offer: &self.offer,
                    quote,
                    resume: None,
                    admission,
                },
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
        GpuJobStart {
            actor: GpuJobActor::Owner(&rig.owner),
            offer: &rig.offer,
            quote: &quote,
            resume: None,
            admission: &admission,
        },
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
            GpuJobStart {
                actor: GpuJobActor::Owner(&rig.owner),
                offer: &rig.offer,
                quote: &quote,
                resume: Some(&resume),
                admission: &admission,
            },
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
        GpuJobStart {
            actor: GpuJobActor::Owner(&rig.owner),
            offer: &rig.offer,
            quote: &rig.quote(100, Some(job.id), NOW),
            resume: Some(&resume),
            admission: &admission,
        },
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
        GpuJobStart {
            actor: GpuJobActor::Owner(&rig.owner),
            offer: &rig.offer,
            quote: &rig.quote(100, Some(job.id), NOW),
            resume: Some(&resume),
            admission: &admission,
        },
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
            GpuJobStart {
                actor: GpuJobActor::Owner(&rig.owner),
                offer,
                quote: &quote,
                resume: None,
                admission: &admission,
            },
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
        .cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
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

/// A cancel that lands while the provider still creates the chunk finds no
/// resource, ends the job and settles nothing; the resource that create then
/// makes is terminated, never left running for a job that ended (review of
/// #8059, round 1).
#[test]
fn a_create_that_loses_to_a_cancel_terminates_its_resource() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units);
    let gate = Arc::new(Barrier::new(2));
    rig.gpu.state().create_gate = Some(Arc::clone(&gate));
    let (started, cancelled) = std::thread::scope(|scope| {
        let cancel = scope.spawn(|| {
            gate.wait();
            let cancelled = rig.vault.cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &quote.job,
                &rig.permits,
                &rig.gpu,
                NOW,
            );
            gate.wait();
            cancelled
        });
        let started = rig.start(&quote, &admission);
        (started, cancel.join().expect("cancel thread"))
    });

    let ended = GpuJobState::Ended {
        reason: GpuEndReason::Cancelled,
    };
    let cancelled = cancelled.expect("cancel");
    assert_eq!(cancelled.state, ended);
    assert_eq!(
        cancelled.chunk().and_then(|chunk| chunk.resource.clone()),
        None,
        "the cancel found no resource"
    );
    assert_eq!(
        cancelled.chunk().and_then(|chunk| chunk.settled_units),
        Some(0)
    );
    assert_eq!(started.state, ended, "the start returns the stored job");
    assert_eq!(
        rig.gpu.called("terminate"),
        1,
        "the resource the losing create made is terminated"
    );
}

/// The same race, with a provider that does not confirm the termination at
/// once: the job keeps the resource and the host's step asks again until the
/// provider confirms it. The cancelled job stays ended, and the customer pays
/// nothing for the resource (review of #8059, round 2).
#[test]
fn a_losing_create_is_terminated_until_its_provider_confirms() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, receipts) = admission(&quote.job, quote.units);
    let gate = Arc::new(Barrier::new(2));
    rig.gpu.state().create_gate = Some(Arc::clone(&gate));
    std::thread::scope(|scope| {
        let cancel = scope.spawn(|| {
            gate.wait();
            let cancelled = rig.vault.cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &quote.job,
                &rig.permits,
                &rig.gpu,
                NOW,
            );
            gate.wait();
            cancelled
        });
        rig.start(&quote, &admission);
        cancel.join().expect("cancel thread").expect("cancel");
    });
    assert_eq!(rig.gpu.called("terminate"), 1, "asked, not confirmed");
    assert_eq!(
        rig.vault.live_gpu_jobs().expect("live jobs"),
        vec![quote.job],
        "the host steps the job until its resource's termination is confirmed"
    );

    rig.step(&quote.job, &admission);
    assert_eq!(rig.gpu.called("terminate"), 2, "the step asks again");

    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 3 });
    rig.step(&quote.job, &admission);
    assert_eq!(rig.gpu.called("terminate"), 3);
    assert!(
        rig.vault.live_gpu_jobs().expect("live jobs").is_empty(),
        "nothing is left to step"
    );
    rig.step(&quote.job, &admission);
    assert_eq!(
        rig.gpu.called("terminate"),
        3,
        "a confirmed termination is not asked again"
    );

    let job = rig.job(&quote.job);
    assert_eq!(
        job.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(job.chunk().and_then(|chunk| chunk.settled_units), Some(0));
    assert_eq!(settled(&receipts).iter().sum::<u64>(), 0);
}

/// A restarted host's step takes a reserved chunk up on a new permit, and a
/// cancel that saw no permit ends the job unpaid before the step's create
/// answers (here: a cancel on its own permits; on one host, a cancel between
/// the step's read and its take-up). The step's write then loses, and its new
/// permit is settled for nothing, not left holding the reservation (review of
/// #8059, round 2).
#[test]
fn a_permit_taken_up_by_a_losing_step_is_settled() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (first, _first_receipts) = admission(&quote.job, quote.units);
    rig.gpu.state().create_unavailable = true;
    let job = rig.start(&quote, &first);
    assert_eq!(
        job.state,
        GpuJobState::Reserved,
        "the create did not answer and the provider has nothing under its key"
    );
    // The host stops, and restarts with no permit.
    let _ = rig.permits.hand_off_all();

    let (second, second_receipts) = admission(&job.id, quote.units);
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 0 });
    let gate = Arc::new(Barrier::new(2));
    rig.gpu.state().create_gate = Some(Arc::clone(&gate));
    let elsewhere = GpuJobPermits::new();
    let report = std::thread::scope(|scope| {
        let cancel = scope.spawn(|| {
            gate.wait();
            let cancelled = rig.vault.cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &job.id,
                &elsewhere,
                &rig.gpu,
                NOW,
            );
            gate.wait();
            cancelled
        });
        let report = rig.step(&job.id, &second);
        cancel.join().expect("cancel thread").expect("cancel");
        report
    });

    assert_eq!(
        report.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert!(
        !rig.permits.holds(&job.id),
        "the permit the step took up is not left held"
    );
    assert_eq!(
        second.read().remaining_units,
        quote.units,
        "its reservation went back"
    );
    assert_eq!(settled(&second_receipts).iter().sum::<u64>(), 0);
}

/// An erase of the job's starter while a step waits on its provider: the
/// erase is a write like any other, so the step's write over the row it read
/// before loses, and the starter stays erased (review of #8059, round 1).
#[cfg(oneiron_test_support)]
#[test]
fn an_erase_during_a_step_keeps_the_starter_erased() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (admission, _receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    assert_eq!(job.started_by, Some(rig.owner_actor));
    rig.gpu.running(50, None);
    let gate = Arc::new(Barrier::new(2));
    rig.gpu.state().status_gate = Some(Arc::clone(&gate));
    let (report, scrubbed) = std::thread::scope(|scope| {
        let erase = scope.spawn(|| {
            gate.wait();
            let scrubbed = oneiron::test_doors::inquiry::erase_actor_in_tables_in_order(
                &rig.vault,
                &rig.owner_actor,
                &["GPU_JOB"],
            );
            gate.wait();
            scrubbed
        });
        let report = rig.step(&job.id, &admission);
        (report, erase.join().expect("erase thread"))
    });

    assert_eq!(scrubbed.expect("erase"), 1, "the job table's scrub ran");
    assert_eq!(report.state, GpuJobState::Running);
    assert_eq!(
        rig.job(&job.id).started_by,
        None,
        "a step that read the job before the erase never puts its starter back"
    );
}

/// A resume continues the stopped job where it ran: a quote that names
/// another offer, job type or image is refused before anything is reserved or
/// created, and the job's own terms still resume (review round 2 of #8063 and
/// #8064: the resumed job kept the first offer's routing, so the host's
/// status reads and the cancel went to that offer's backend while the new
/// resource ran on the other).
#[test]
fn a_resume_quote_for_another_offer_job_type_or_image_is_refused_before_anything_is_reserved() {
    let rig = rig();
    let (job, _first, _receipts, _) = rig.run_to_stop();
    let resume = job.stop.as_ref().expect("stopped").resume.clone();
    let creates = rig.gpu.called("create");
    let other = GpuOffer {
        name: "a100-fixture".to_owned(),
        class: "a100".to_owned(),
        provider: "other-cloud".to_owned(),
        ..offer(2)
    };
    let mut other_image = request(Some(100));
    other_image.image = "registry.example.com/other@sha256:11".to_owned();
    let mut other_type = request(Some(100));
    other_type.job_type = "inference".to_owned();
    let quote_on = |offer: &GpuOffer, request: &GpuJobRequest| {
        offer
            .quote(request, Some(job.id), DEFAULT_MAXIMUM_SECS, NOW)
            .expect("quote")
    };
    let cases = [
        (
            "another offer",
            &other,
            quote_on(&other, &request(Some(100))),
        ),
        (
            "another image",
            &rig.offer,
            quote_on(&rig.offer, &other_image),
        ),
        (
            "another job type",
            &rig.offer,
            quote_on(&rig.offer, &other_type),
        ),
    ];
    for (case, offer, quote) in cases {
        let (admission, _receipts) = admission(&job.id, quote.units);
        let refused = rig.vault.start_gpu_job(
            GpuJobStart {
                actor: GpuJobActor::Owner(&rig.owner),
                offer,
                quote: &quote,
                resume: Some(&resume),
                admission: &admission,
            },
            &rig.permits,
            &rig.gpu,
            NOW,
        );
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| error.to_string().contains("resume")),
            "{case}: {refused:?}"
        );
        assert_eq!(
            admission.read().remaining_units,
            quote.units,
            "{case}: nothing is reserved"
        );
    }
    assert_eq!(rig.gpu.called("create"), creates, "nothing is created");
    let stored = rig.job(&job.id);
    assert_eq!(stored.state, GpuJobState::Stopped);
    assert_eq!(stored.chunks.len(), 1);

    let quote = rig.quote(100, Some(job.id), NOW);
    let (admission, _receipts) = admission(&job.id, quote.units);
    let resumed = rig
        .vault
        .start_gpu_job(
            GpuJobStart {
                actor: GpuJobActor::Owner(&rig.owner),
                offer: &rig.offer,
                quote: &quote,
                resume: Some(&resume),
                admission: &admission,
            },
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("the job's own terms resume");
    assert_eq!(resumed.chunks.len(), 2);
}

/// A cancel on a host that holds no permit for the live chunk (it restarted
/// since the chunk began) leaves the chunk ending; the host's next step
/// admits the chunk again, terminates it and settles its billed time on the
/// new permit, so the cancel never skips the bill (review round 2 of #8063).
#[test]
fn a_cancel_after_a_restart_is_ended_and_paid_by_the_step_that_takes_the_chunk_up() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (first, first_receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &first);
    rig.step_at(&job.id, &first, 30, None);
    let _ = rig.permits.hand_off_all();
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 30 });

    let cancelled = rig
        .vault
        .cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("cancel");
    let (second, second_receipts) = admission(&job.id, quote.units);
    rig.step(&job.id, &second);

    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(
        ended.chunk().and_then(|chunk| chunk.settled_units),
        Some(100),
        "(30 + 20) seconds at 2"
    );
    assert_eq!(
        settled(&second_receipts),
        vec![100],
        "the new permit pays the end"
    );
    assert_eq!(settled(&first_receipts).iter().sum::<u64>(), 0);
    assert_eq!(rig.gpu.called("terminate"), 1);
    assert_eq!(
        cancelled.state,
        GpuJobState::Ending {
            reason: GpuEndReason::Cancelled
        },
        "the cancel leaves the chunk to the step that takes it up"
    );
}

/// The step that ends a chunk at its maximum settles that chunk's permit after
/// its write. A resume that starts the next chunk in between holds its own
/// permit beside it: the first chunk pays its own end, and the second chunk's
/// permit stays held for its own (review round 2 of #8063 and #8064: the
/// resume's permit replaced the first chunk's, which settled for nothing, and
/// the step then charged the first chunk's time to the second's permit).
#[cfg(oneiron_test_support)]
#[test]
fn a_resume_between_a_stop_and_its_settlement_leaves_each_chunk_its_own_permit() {
    let rig = rig();
    let quote = rig.quote(100, None, NOW);
    let (first, first_receipts) = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &first);
    for (used, checkpoint) in [(50, None), (80, None), (95, None), (97, Some("ck-1"))] {
        rig.step_at(&job.id, &first, used, checkpoint);
    }
    rig.gpu.terminates(GpuTermination::Pending);
    rig.step_at(&job.id, &first, 100, Some("ck-1"));
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 100 });
    let gate = Arc::new(Barrier::new(2));
    oneiron::test_doors::gpu_job::gate_next_end_commit(&rig.permits, job.id, Arc::clone(&gate));
    let (second, second_receipts) = admission(&job.id, quote.units);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| rig.step(&job.id, &first));
        // The step's write committed the stop; its permit is not settled yet.
        gate.wait();
        let stopped = rig.job(&job.id);
        assert_eq!(stopped.state, GpuJobState::Stopped);
        let resume = stopped.stop.as_ref().expect("stopped").resume.clone();
        let next = rig.quote(100, Some(job.id), NOW);
        rig.vault
            .start_gpu_job(
                GpuJobStart {
                    actor: GpuJobActor::Owner(&rig.owner),
                    offer: &rig.offer,
                    quote: &next,
                    resume: Some(&resume),
                    admission: &second,
                },
                &rig.permits,
                &rig.gpu,
                NOW,
            )
            .expect("resume");
        gate.wait();
        worker.join().expect("step thread");
    });
    assert_eq!(
        settled(&first_receipts),
        vec![240],
        "(100 + 20) seconds at 2: the first chunk pays its own end"
    );
    assert_eq!(
        settled(&second_receipts).iter().sum::<u64>(),
        0,
        "the second chunk's permit is charged nothing yet"
    );
    assert!(
        rig.permits.holds(&job.id),
        "the second chunk's permit stays held"
    );
}
