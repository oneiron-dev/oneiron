//! `vault.jobs.history` over plain offer jobs, from the rows the job's own lifecycle writes
//! (review round 1 of #10419): a stopped job the customer cancels keeps its last chunk's end at
//! its maximum; a chunk the provider refused before anything ran charged nothing and returned
//! its whole quote; a stop's or a cancel's occupancy is unknown, since the provider's last
//! reported run time is only a sample, while an exit reports the final one; and a resumed
//! chunk, whose starter the row does not keep, is never shown to an agent as its own.
//!
//! A chunk one of the vault's machines ran shows what the issuer's observation of its key holds
//! (pass 33, 5.1): the machine and its device, and from the end the issuer confirmed, the
//! machine's end cause, when the issuer received it, the seconds the machine measured (a stop's
//! too), a lost key's last seen run time as lost, and the meter. A key whose end the issuer
//! never confirmed names its machine only.
//!
//! The provider is a scripted fake. Fleet command:
//! `cargo test --locked -p oneiron --all-features --test job_history_offers`.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector, GpuJobEnd,
    GpuJobPermits, GpuJobQuote, GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuJobState,
    GpuJobTerminal, GpuOffer, GpuResourceRef, GpuResourceStatus, GpuTermination, MeterVerdict,
    PriceShape,
};
use oneiron::job_dispatch::{BootMark, JobObservation};
use oneiron::job_history::{
    HistoryInputs, HistoryViewer, JobHistory, JobHistoryAttempt, JobHistoryRequest, project,
    read_job_history,
};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, CheckpointRef, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector,
    Payer, RunAdmission, RunDeclaration,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;
const DEFAULT_MAXIMUM_SECS: u64 = 3_600;
/// When the issuer received a test machine's end receipt.
const ENDED_AT: u64 = NOW + 120_000;
/// The vendor's id of the GPU the test machine held.
const DEVICE: &str = "GPU-7c1d9e20";

/// The vault machine the issuer sent these tests' chunks to.
fn machine() -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x03;
    bytes[15] = 77;
    EntityId::from_bytes_unchecked(bytes)
}

/// An end the issuer confirmed on the test machine, as its billing builds the typed terminal.
fn confirmed(
    end: GpuJobEnd,
    measured: Option<u64>,
    billed: u64,
    meter: MeterVerdict,
) -> GpuJobTerminal {
    GpuJobTerminal {
        end,
        measured_secs: measured,
        billed_secs: billed,
        meter,
        machine: Some(machine()),
        device_id: Some(DEVICE.to_owned()),
        outputs: Vec::new(),
    }
}

/// What the fake provider holds and answers.
#[derive(Default)]
struct FakeState {
    created: HashMap<String, GpuResourceRef>,
    /// The next create is refused with this reason and makes nothing.
    create_refused: Option<String>,
    status: Option<GpuResourceStatus>,
    termination: Option<GpuTermination>,
}

#[derive(Default)]
struct FakeGpu(Mutex<FakeState>);

impl FakeGpu {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake provider lock")
    }

    fn reports(&self, status: GpuResourceStatus) {
        self.state().status = Some(status);
    }

    fn terminates(&self, termination: GpuTermination) {
        self.state().termination = Some(termination);
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        if let Some(reason) = state.create_refused.take() {
            return Err(GpuConnectorError::Refused { reason });
        }
        let resource = GpuResourceRef(format!("resource-{key}"));
        state.created.insert(key.to_owned(), resource.clone());
        Ok(resource)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(self.state().created.get(key).cloned())
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
        _signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        Ok(())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Ok(self.state().termination.unwrap_or(GpuTermination::Pending))
    }

    /// The provider closes the chunk for good: the owner's write-off (door 10) may proceed.
    fn write_off(&self, _job: &GpuJob, _now_ms: u64) -> Result<(), GpuConnectorError> {
        Ok(())
    }
}

/// A rooted vault, its owner, one offer at 2 credit-micros a second (startup 10, teardown 5,
/// rounding 5) and the fake provider.
struct Rig {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let offer = GpuOffer {
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
            unit_cost: 2,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 10,
        teardown_secs: 5,
        rounding_secs: 5,
    };
    Rig {
        _dir: dir,
        vault,
        owner,
        offer,
        gpu: FakeGpu::default(),
        permits: GpuJobPermits::new(),
    }
}

/// The job's own run, with one line of `limit` credit-micros.
fn admission(job: &EntityId, limit: u64) -> RunAdmission {
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: limit,
        reserve_units: limit,
        unit: LeaseUnit::new("credit-micros").expect("unit"),
    })
    .with_connector("fixture-gpu".to_owned());
    RunAdmission::new(
        GpuJob::admission_ref_of(job),
        declaration,
        None,
        Arc::new(MemoryReceipts::default()) as Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    )
}

impl Rig {
    fn quote(&self, maximum_secs: u64, resume: Option<EntityId>) -> GpuJobQuote {
        let request = GpuJobRequest {
            job_type: "fine-tune".to_owned(),
            image: "registry.example.com/trainer@sha256:00".to_owned(),
            maximum_secs: Some(maximum_secs),
            inputs: serde_json::json!({"dataset": "owen-notes"}),
        };
        self.offer
            .quote(&request, resume, DEFAULT_MAXIMUM_SECS, NOW)
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

    fn step(&self, job: &EntityId, admission: &RunAdmission) {
        self.vault
            .gpu_job_step(job, &self.offer, admission, &self.permits, &self.gpu, NOW)
            .expect("step");
    }

    fn running(&self, job: &EntityId, admission: &RunAdmission, used: u64, checkpoint: &str) {
        self.gpu.reports(GpuResourceStatus::Running {
            used_secs: used,
            checkpoint: (!checkpoint.is_empty()).then(|| CheckpointRef(checkpoint.to_owned())),
        });
        self.step(job, admission);
    }

    fn cancel(&self, job: &EntityId) -> GpuJob {
        self.vault
            .cancel_gpu_job(
                GpuJobActor::Owner(&self.owner),
                job,
                &self.permits,
                &self.gpu,
                NOW,
            )
            .expect("cancel")
    }

    fn job(&self, id: &EntityId) -> GpuJob {
        self.vault.gpu_job(id).expect("job read").expect("job row")
    }

    /// A fresh 100-second job run to its stop at the maximum: the warning at 95, checkpoint
    /// `ck-1` after it, the stop at 100 and a termination confirmed at 100 billed seconds.
    fn run_to_stop(&self) -> GpuJob {
        let quote = self.quote(100, None);
        let admission = admission(&quote.job, quote.units);
        let job = self.start(&quote, &admission);
        for (used, checkpoint) in [(50, ""), (80, ""), (95, ""), (97, "ck-1")] {
            self.running(&job.id, &admission, used, checkpoint);
        }
        self.gpu.terminates(GpuTermination::Pending);
        self.running(&job.id, &admission, 100, "ck-1");
        self.gpu
            .terminates(GpuTermination::Confirmed { billed_secs: 100 });
        self.step(&job.id, &admission);
        let stopped = self.job(&job.id);
        assert_eq!(stopped.state, GpuJobState::Stopped);
        stopped
    }

    /// Writes the issuer's observation of `job`'s chunk `index`, as the test machine's receipts
    /// leave it: the newest run time any receipt carried, and the end the issuer confirmed, if
    /// it did.
    fn observe(&self, job: &GpuJob, index: usize, last_measured: u64, end: Option<GpuJobTerminal>) {
        let end_seen = end.as_ref().map(|_| BootMark {
            boot_id: "boot-1".to_owned(),
            boot_ns: 9_000_000_000,
            wall_ms: ENDED_AT,
        });
        let meter = end.as_ref().map(|end| end.meter);
        self.vault
            .put_job_observation(&JobObservation {
                key: job.chunks[index].idempotency_key.clone(),
                machine: machine(),
                device_id: Some(DEVICE.to_owned()),
                receipt: Vec::new(),
                epoch: "epoch-1".to_owned(),
                seq: 9,
                last_measured_secs: Some(last_measured),
                observed_at_ms: ENDED_AT,
                end_seen,
                meter,
                terminal: end,
                started: true,
            })
            .expect("observation write");
    }

    /// The owner's history of the attempts on `machine`.
    fn history_on(&self, machine: EntityId) -> JobHistory {
        let request = JobHistoryRequest {
            machine: Some(machine.to_hex()),
            ..JobHistoryRequest::default()
        };
        let filter = request.filter().expect("a valid request");
        read_job_history(&self.vault, &filter, HistoryViewer::Owner).expect("history read")
    }

    /// The owner's history, read from the vault's own rows.
    fn history(&self) -> JobHistory {
        let filter = JobHistoryRequest::default()
            .filter()
            .expect("a valid request");
        read_job_history(&self.vault, &filter, HistoryViewer::Owner).expect("history read")
    }
}

fn only(history: &JobHistory) -> &JobHistoryAttempt {
    assert_eq!(history.attempts.len(), 1, "{:?}", history.attempts);
    &history.attempts[0]
}

#[test]
fn a_stopped_job_cancelled_later_keeps_its_chunk_ended_at_its_maximum() {
    let rig = rig();
    let stopped = rig.run_to_stop();
    let cancelled = rig.cancel(&stopped.id);
    assert_eq!(
        cancelled.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(
        attempt.end, "at_maximum",
        "the chunk ended at its maximum before the cancel gave up its resume"
    );
    // The stop terminated after the last reported run time: only the billed time is final.
    assert_eq!(attempt.occupied_secs, None);
    assert_eq!(attempt.billed_secs, Some(100));
    assert_eq!(history.totals.all.occupied_unknown, 1);
}

#[test]
fn a_chunk_refused_before_it_ran_charges_nothing_and_returns_its_quote() {
    let rig = rig();
    rig.gpu.state().create_refused = Some("no h100 capacity in test-1".to_owned());
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    let held = rig.start(&quote, &admission);
    assert!(
        matches!(held.state, GpuJobState::Held { .. }),
        "{:?}",
        held.state
    );

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "held");
    assert_eq!(
        attempt.end_reason.as_deref(),
        Some("no h100 capacity in test-1")
    );
    assert_eq!(attempt.charged_secs, Some(0));
    assert_eq!(attempt.returned_secs, Some(quote.quantity));
    assert_eq!(attempt.occupied_secs, Some(0), "nothing ran");
    assert_eq!(history.totals.all.returned_secs, quote.quantity);
    assert_eq!(history.totals.all.charged_secs, 0);
    assert_eq!(history.totals.all.occupied_unknown, 0);
}

#[test]
fn a_never_started_offer_attempt_has_no_charge_and_returns_its_quote() {
    let rig = rig();
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    rig.gpu.state().create_refused = Some("not available".to_owned());
    let mut job = rig.start(&quote, &admission);
    // A signed submit refusal writes this state without filling the chunk's settlement.
    job.state = GpuJobState::Ended {
        reason: GpuEndReason::NeverStarted,
    };
    let inputs = HistoryInputs {
        jobs: &[job],
        claims: &[],
        periods: &[],
        orders: &[],
        observations: &[],
        unattributed: &[],
    };
    let filter = JobHistoryRequest::default()
        .filter()
        .expect("a valid request");

    let history = project(&inputs, &filter, HistoryViewer::Owner);
    let attempt = only(&history);
    assert_eq!(attempt.end, "never_started");
    assert_eq!(attempt.end_reason, None);
    assert_eq!(attempt.occupied_secs, Some(0));
    assert_eq!(attempt.charged_secs, Some(0));
    assert_eq!(attempt.returned_secs, Some(quote.quantity));
}

#[test]
fn a_cancel_before_any_status_leaves_the_occupancy_unknown() {
    let rig = rig();
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    // The resource ran 20 seconds before the first status read; the cancel terminates it.
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 20 });
    let cancelled = rig.cancel(&job.id);
    assert_eq!(
        cancelled.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "cancelled");
    assert_eq!(attempt.billed_secs, Some(20));
    assert_eq!(
        attempt.occupied_secs, None,
        "no status reported the run time the cancel ended"
    );
    assert_eq!(history.totals.all.occupied_secs, 0);
    assert_eq!(history.totals.all.occupied_unknown, 1);
}

#[test]
fn a_written_off_chunk_settles_zero_and_leaves_the_occupancy_unknown() {
    let rig = rig();
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.running(&job.id, &admission, 30, "");
    let written = rig
        .vault
        .write_off_gpu_job(&rig.owner, &job.id, &rig.permits, &rig.gpu, NOW)
        .expect("the owner writes the job off");
    assert_eq!(
        written.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Unconfirmed
        }
    );

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "written_off");
    assert_eq!(attempt.billed_secs, None, "no end was confirmed");
    assert_eq!(attempt.settled_units, Some(0));
    assert_eq!(attempt.charged_secs, Some(0), "this host held the permit");
    assert_eq!(attempt.returned_secs, Some(quote.quantity));
    assert_eq!(
        attempt.occupied_secs, None,
        "the last reported run time is a sample"
    );
    assert_eq!(attempt.lost_secs, 0);
    assert_eq!(history.totals.all.charged_secs, 0);
    assert_eq!(history.totals.all.occupied_unknown, 1);
}

#[test]
fn a_resumed_chunk_is_never_an_agents_own() {
    let rig = rig();
    let stopped = rig.run_to_stop();
    let resume = stopped.stop.as_ref().expect("stopped").resume.clone();
    let quote = rig.quote(100, Some(stopped.id));
    let admission = admission(&stopped.id, quote.units);
    rig.vault
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
        .expect("the owner resumes");
    // The resumed chunk exits after 40 seconds, the run time its exit reports.
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 40 });
    rig.gpu.reports(GpuResourceStatus::Exited { used_secs: 40 });
    rig.step(&stopped.id, &admission);
    let mut job = rig.job(&stopped.id);
    assert_eq!(
        job.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    assert_eq!(job.chunks.len(), 2);

    // An agent's job keeps its starter as the first chunk's, whoever resumed it: a start
    // names the starter only on the job's first chunk.
    let mut agent = [0u8; 16];
    agent[0] = 0x03;
    agent[15] = 41;
    let agent = EntityId::from_bytes_unchecked(agent);
    job.started_by = Some(agent);
    let jobs = [job];
    let inputs = HistoryInputs {
        jobs: &jobs,
        claims: &[],
        periods: &[],
        orders: &[],
        observations: &[],
        unattributed: &[],
    };
    let filter = JobHistoryRequest::default()
        .filter()
        .expect("a valid request");

    let own = project(&inputs, &filter, HistoryViewer::Requester(agent));
    let attempt = only(&own);
    assert_eq!(attempt.chunk, 0);
    assert_eq!(attempt.requester, Some(agent.to_hex()));
    assert_eq!(
        own.totals.all.attempts, 1,
        "the resumed chunk is not the agent's"
    );

    let owner = project(&inputs, &filter, HistoryViewer::Owner);
    assert_eq!(owner.attempts.len(), 2);
    let resumed = owner
        .attempts
        .iter()
        .find(|attempt| attempt.chunk == 1)
        .expect("the resumed chunk is history");
    assert_eq!(resumed.requester, None, "no row keeps a resume's starter");
    assert_eq!(resumed.end, "exited");
    assert_eq!(
        resumed.occupied_secs,
        Some(40),
        "an exit reports the final run time"
    );
    let first = owner
        .attempts
        .iter()
        .find(|attempt| attempt.chunk == 0)
        .expect("the first chunk is history");
    assert_eq!(first.end, "at_maximum");
    assert_eq!(resumed.continues.as_deref(), Some(first.key.as_str()));
}

#[test]
fn a_vault_machine_chunk_shows_the_end_its_issuer_confirmed() {
    let rig = rig();
    let stopped = rig.run_to_stop();
    // The machine measured 104 seconds, above the issuer's own bracket of 100 from the first
    // send to the end receipt: the bracket was billed.
    let meter = MeterVerdict::Bracketed { billed_secs: 100 };
    let end = confirmed(GpuJobEnd::Stopped, Some(104), 100, meter);
    rig.observe(&stopped, 0, 100, Some(end));

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "at_maximum");
    assert_eq!(attempt.node_end.as_deref(), Some("stopped"));
    assert_eq!(attempt.machine, Some(machine().to_hex()));
    assert_eq!(attempt.device.as_deref(), Some(DEVICE));
    assert_eq!(attempt.ended_at_ms, Some(ENDED_AT));
    assert_eq!(
        attempt.occupied_secs,
        Some(104),
        "the machine measured what the stop occupied"
    );
    assert_eq!(attempt.billed_secs, Some(100));
    assert_eq!(attempt.meter.as_deref(), Some("bracketed"));
    assert_eq!(attempt.lost_secs, 0);
    assert_eq!(history.totals.all.occupied_secs, 104);
    assert_eq!(history.totals.all.occupied_unknown, 0);
    let by_machine = &history.totals.by_machine;
    assert_eq!(by_machine.len(), 1);
    assert_eq!(by_machine[0].machine, Some(machine().to_hex()));

    assert_eq!(rig.history_on(machine()).attempts.len(), 1);
    let elsewhere = EntityId::from_bytes_unchecked([0x03; 16]);
    assert!(rig.history_on(elsewhere).attempts.is_empty());
}

#[test]
fn a_lost_vault_machine_chunk_shows_its_last_seen_run_time_as_lost() {
    let rig = rig();
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.running(&job.id, &admission, 30, "");
    // The machine attests the key lost after a receipt that showed 34 seconds: nothing is
    // billed, and its occupancy is unknown.
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 0 });
    rig.gpu.reports(GpuResourceStatus::Gone);
    rig.step(&job.id, &admission);
    let lost = rig.job(&job.id);
    assert_eq!(
        lost.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Gone
        }
    );
    let end = GpuJobEnd::Lost {
        reason: "host_reset".to_owned(),
        last_seen_secs: 34,
    };
    let end = confirmed(end, None, 0, MeterVerdict::Unknown);
    rig.observe(&lost, 0, 34, Some(end));

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "gone");
    assert_eq!(attempt.node_end.as_deref(), Some("lost(host_reset)"));
    assert_eq!(
        attempt.lost_secs, 34,
        "the newest run time any receipt carried"
    );
    assert_eq!(
        attempt.occupied_secs, None,
        "no machine measured a lost key"
    );
    assert_eq!(attempt.billed_secs, Some(0));
    assert_eq!(attempt.meter.as_deref(), Some("unknown"));
    assert_eq!(attempt.ended_at_ms, Some(ENDED_AT));
    assert_eq!(history.totals.all.lost_secs, 34);
    assert_eq!(history.totals.all.occupied_unknown, 1);
}

#[test]
fn a_key_whose_end_the_issuer_never_confirmed_names_its_machine_only() {
    let rig = rig();
    let quote = rig.quote(100, None);
    let admission = admission(&quote.job, quote.units);
    let job = rig.start(&quote, &admission);
    rig.running(&job.id, &admission, 20, "");
    // The issuer holds the machine's running receipt and never a terminal one (the machine's
    // journal of the key was lost); the customer's cancel ended the job.
    rig.observe(&job, 0, 20, None);
    rig.gpu
        .terminates(GpuTermination::Confirmed { billed_secs: 20 });
    rig.cancel(&job.id);

    let history = rig.history();
    let attempt = only(&history);
    assert_eq!(attempt.end, "cancelled");
    assert_eq!(attempt.machine, Some(machine().to_hex()));
    assert_eq!(attempt.device.as_deref(), Some(DEVICE));
    assert_eq!(attempt.node_end, None);
    assert_eq!(attempt.ended_at_ms, None);
    assert_eq!(attempt.meter, None);
    assert_eq!(attempt.occupied_secs, None, "a running receipt is a sample");
    assert_eq!(attempt.lost_secs, 0);
}
