//! `vault.jobs.history` joined to `WORK_ORDER` (pass 34, 1.1 and section 5; row Q2): an attempt
//! the work-order loop made names its order and its number, who ordered, how long the order
//! waited for it (from the order for the first attempt, from the end of the attempt before for
//! a later one), and what the RANK, PLACE and AFTER rules decided, all read from the order's own
//! row in the history's snapshot. An agent sees only its own order among a RANK decision's
//! options, as `vault.jobs.orders.get` shows it.
//!
//! The loop runs over a scripted fake provider; the machine's facts are what the test says it
//! reported. Fleet command:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test job_history_orders`
#![cfg(oneiron_test_support)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits,
    GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination, PriceShape,
};
use oneiron::job_history::{
    HistoryInputs, HistoryViewer, JobHistory, JobHistoryAttempt, JobHistoryRequest, project,
    read_job_history,
};
use oneiron::job_workload::{NetworkMode, ResourceRequest, ScopeKind, WorkloadPin};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration,
};
use oneiron::test_doors::work_order::{put_approved_workload, put_order};
use oneiron::work_order::{
    AttemptOutcome, AttemptRefused, AttemptToMake, EndKind, MachineFacts, MachineReach,
    OrderAttemptRef, OrderCharge, OrderClass, OrderHost, OrderLimits, OrderState, OrderWishes,
    OrderedBy, Room, TemplateFact, WaitRule, WorkOrder,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;
const TEMPLATE: &str = "open-models";
const TEMPLATE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OFFER: &str = "fixture-machines";

/// What the fake provider holds and answers.
struct FakeState {
    creates: Vec<String>,
    /// The next this-many creates answer that the machine refused, before any resource.
    refuse_creates: usize,
    status: Option<GpuResourceStatus>,
    termination: GpuTermination,
}

struct FakeGpu(Mutex<FakeState>);

impl FakeGpu {
    fn new() -> Self {
        Self(Mutex::new(FakeState {
            creates: Vec::new(),
            refuse_creates: 0,
            status: None,
            termination: GpuTermination::Pending,
        }))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake provider lock")
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.creates.push(key.to_owned());
        if state.refuse_creates > 0 {
            state.refuse_creates -= 1;
            return Err(GpuConnectorError::Refused {
                reason: "device_busy".to_owned(),
            });
        }
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(self
            .state()
            .creates
            .iter()
            .any(|made| made == key)
            .then(|| GpuResourceRef(format!("resource-{key}"))))
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
        Ok(self.state().termination)
    }
}

fn offer() -> GpuOffer {
    GpuOffer {
        name: OFFER.to_owned(),
        class: "machine".to_owned(),
        provider: "vault-machines".to_owned(),
        region: "home".to_owned(),
        connector: PaidConnector {
            connector: "fixture-machines".to_owned(),
            route: OfferRoute::new("fixture-machines", "https://machines.example.com")
                .expect("route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: Some("machines-1".to_owned()),
            custody: KeyCustody::T0,
            unit_cost: 1,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 0,
        teardown_secs: 0,
        rounding_secs: 0,
    }
}

/// A vault, its owner, the offer and the fake provider.
struct Rig {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_actor: EntityId,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Rig {
        _dir: dir,
        vault,
        owner_actor,
        offer: offer(),
        gpu: FakeGpu::new(),
        permits: GpuJobPermits::new(),
    }
}

/// Eight threads' worth of memory and disk, no device.
fn request() -> ResourceRequest {
    ResourceRequest {
        cpu_threads: 0,
        memory_mib: 8_192,
        disk_mib: 1_024,
        devices: Vec::new(),
        maximum_secs: 600,
    }
}

fn pin() -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: TEMPLATE_DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/arm.json".to_owned(),
        entry: "tools/units/run_arm.sh".to_owned(),
        args: vec!["arm=d2".to_owned()],
        request: request(),
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: Vec::new(),
    }
}

/// A machine that answered, holds the template, and has room for several attempts.
fn machine(id: EntityId) -> MachineFacts {
    MachineFacts {
        machine: id,
        reach: MachineReach::Answered { at_ms: NOW },
        enabled: true,
        refusal: None,
        paused: None,
        drained: None,
        templates: Some(vec![TemplateFact {
            name: TEMPLATE.to_owned(),
            digest: TEMPLATE_DIGEST.to_owned(),
        }]),
        room: Room {
            threads_total: Some(32),
            threads_free: Some(32),
            memory_total_mib: Some(65_536),
            memory_free_mib: Some(65_536),
            disk_free_mib: Some(100_000),
            frees_at_ms: None,
        },
        devices: None,
        window: None,
        keep_headroom_pct: None,
        roles: Vec::new(),
        warm: Vec::new(),
    }
}

impl Rig {
    /// Pins and approves the workload on `machines`; its digest.
    fn workload(&self, machines: &[EntityId]) -> String {
        put_approved_workload(
            &self.vault,
            pin(),
            self.owner_actor,
            machines.to_vec(),
            Vec::new(),
            NOW + 86_400_000,
            NOW,
        )
    }

    /// An open order of `workload` by the owner at `NOW`, as the order door writes it.
    fn order(&self, workload: &str, class: OrderClass) -> WorkOrder {
        let order = WorkOrder {
            id: EntityId::now(),
            ordered_by: OrderedBy::Owner {
                owner: Some(self.owner_actor),
            },
            workload: workload.to_owned(),
            request: request(),
            charge: OrderCharge::Offer {
                name: OFFER.to_owned(),
            },
            limits: OrderLimits::default(),
            wishes: OrderWishes::default(),
            class,
            wait: WaitRule::Open,
            retry_on: Vec::new(),
            state: OrderState::Open {
                blocked: Vec::new(),
                looked_at_ms: NOW,
                earliest_ms: None,
            },
            cancel: None,
            retry_not_before_ms: None,
            attempts: Vec::new(),
            result: None,
            intent_key: None,
            after: None,
            group: None,
            ordered_at_ms: NOW,
            updated_at_ms: NOW,
            revision: 0,
        };
        put_order(&self.vault, &order);
        order
    }

    fn stored(&self, order: &WorkOrder) -> WorkOrder {
        self.vault
            .work_order(&order.id)
            .expect("order read")
            .expect("order row")
    }

    /// The history `viewer` reads for `request`, from the vault's own rows.
    fn history(&self, request: &JobHistoryRequest, viewer: HistoryViewer) -> JobHistory {
        let filter = request.filter().expect("a valid request");
        read_job_history(&self.vault, &filter, viewer).expect("history read")
    }
}

/// The job's own run, with one line of `limit` credit-micros.
fn admission(job: &EntityId, limit: u64) -> RunAdmission {
    let declaration = RunDeclaration::declared(BudgetLine {
        limit_units: limit,
        reserve_units: limit,
        unit: LeaseUnit::new("credit-micros").expect("unit"),
    })
    .with_connector("fixture-machines".to_owned());
    RunAdmission::new(
        GpuJob::admission_ref_of(job),
        declaration,
        None,
        Arc::new(MemoryReceipts::default()) as Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    )
}

/// The loop's host: the machines' facts as given, and the built quote and start with the fake
/// provider, at the time of the pass that asks.
struct TestHost<'a> {
    rig: &'a Rig,
    facts: Vec<MachineFacts>,
    now_ms: Cell<u64>,
    admissions: RefCell<HashMap<EntityId, RunAdmission>>,
}

impl<'a> TestHost<'a> {
    fn new(rig: &'a Rig, facts: Vec<MachineFacts>) -> Self {
        Self {
            rig,
            facts,
            now_ms: Cell::new(NOW),
            admissions: RefCell::new(HashMap::new()),
        }
    }

    /// One pass of the loop at `now_ms`.
    fn pass(&self, now_ms: u64) {
        self.now_ms.set(now_ms);
        self.rig.vault.work_order_pass(self, now_ms).expect("pass");
    }

    /// Steps `job` once at `now_ms`, as the job worker does.
    fn step(&self, job: &EntityId, now_ms: u64) {
        let admissions = self.admissions.borrow();
        let run = admissions.get(job).expect("the job's run");
        self.rig
            .vault
            .gpu_job_step(
                job,
                &self.rig.offer,
                run,
                &self.rig.permits,
                &self.rig.gpu,
                now_ms,
            )
            .expect("step");
    }
}

impl OrderHost for TestHost<'_> {
    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts> {
        self.facts
            .iter()
            .filter(|facts| machines.contains(&facts.machine))
            .cloned()
            .collect()
    }

    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome {
        let now_ms = self.now_ms.get();
        let quote = self
            .rig
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: TEMPLATE.to_owned(),
                    image: attempt.order.workload.clone(),
                    maximum_secs: Some(attempt.order.request.maximum_secs),
                    inputs: serde_json::json!({ "machine": attempt.machine.to_hex() }),
                },
                Some(attempt.job),
                600,
                now_ms,
            )
            .expect("quote");
        let run = admission(&attempt.job, 1_000_000);
        let reference = attempt.reference();
        let started = self.rig.vault.start_gpu_job(
            GpuJobStart {
                actor: GpuJobActor::Order(&reference),
                offer: &self.rig.offer,
                quote: &quote,
                resume: None,
                admission: &run,
            },
            &self.rig.permits,
            &self.rig.gpu,
            now_ms,
        );
        self.admissions.borrow_mut().insert(attempt.job, run);
        match started {
            Ok(_) => AttemptOutcome::Made,
            Err(GpuJobError::Order(AttemptRefused::OrderChanged)) => AttemptOutcome::OrderChanged,
            Err(GpuJobError::Order(AttemptRefused::Blocked(blocker))) => {
                AttemptOutcome::Refused(vec![blocker])
            }
            // The machine's refusal comes after the start's write: the attempt is made, and its
            // job's end tells the loop.
            Err(other) => {
                let made = self
                    .rig
                    .vault
                    .work_order(&attempt.order.id)
                    .expect("order read")
                    .is_some_and(|order| order.attempts.len() >= usize::from(attempt.n));
                assert!(made, "the start failed before its write: {other}");
                AttemptOutcome::Made
            }
        }
    }

    fn stop_attempt(&self, order: &WorkOrder, job: &EntityId) -> Result<(), String> {
        let last = order.last_attempt().ok_or("no attempt")?;
        let reference = OrderAttemptRef {
            order: order.id,
            revision: order.revision,
            n: last.n,
            machine: last.machine,
            ranked: last.ranked.clone(),
            placed: last.placed.clone(),
        };
        self.rig
            .vault
            .cancel_gpu_job(
                GpuJobActor::Order(&reference),
                job,
                &self.rig.permits,
                &self.rig.gpu,
                self.now_ms.get(),
            )
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

/// The attempt of `history` whose job is `job`.
fn attempt_of<'h>(history: &'h JobHistory, job: &EntityId) -> &'h JobHistoryAttempt {
    history
        .attempts
        .iter()
        .find(|attempt| attempt.job == job.to_hex())
        .unwrap_or_else(|| panic!("no attempt of job {job:?} in {:?}", history.attempts))
}

#[test]
fn history_names_the_order_and_attempt_of_each_job_with_the_time_the_order_waited_for_it() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(&[free]);
    let order = rig.order(&digest, OrderClass::Normal);
    let host = TestHost::new(&rig, vec![machine(free)]);

    // The machine refuses attempt 1 before anything runs. The order waited 5 s for it.
    rig.gpu.state().refuse_creates = 1;
    host.pass(NOW + 5_000);
    host.pass(NOW + 6_000);
    let waiting = rig.stored(&order);
    assert_eq!(waiting.attempts.len(), 1);
    let first_end = waiting.attempts[0]
        .end
        .clone()
        .expect("the pass settled attempt 1's end");
    assert_eq!(first_end.kind, EndKind::NeverStarted);
    let retry_at = waiting
        .retry_not_before_ms
        .expect("a zero-second end is retried after a backoff");

    // Attempt 2 after the backoff; it runs 30 s and exits.
    let made_at = retry_at + 2_000;
    host.pass(made_at);
    let running = rig.stored(&order);
    assert_eq!(running.attempts.len(), 2, "{:?}", running.state);
    let second_job = running.attempts[1].job;
    {
        let mut provider = rig.gpu.state();
        provider.status = Some(GpuResourceStatus::Exited { used_secs: 30 });
        provider.termination = GpuTermination::Confirmed { billed_secs: 30 };
    }
    host.step(&second_job, made_at + 31_000);
    host.pass(made_at + 32_000);
    let done = rig.stored(&order);
    assert!(matches!(done.state, OrderState::Done), "{:?}", done.state);

    let history = rig.history(&JobHistoryRequest::default(), HistoryViewer::Owner);
    assert_eq!(history.attempts.len(), 2, "{:?}", history.attempts);

    let first = attempt_of(&history, &done.attempts[0].job);
    assert_eq!(first.end, "held");
    let first_order = first.order.as_ref().expect("attempt 1 names its order");
    assert_eq!(first_order.order, order.id.to_hex());
    assert_eq!(first_order.attempt, 1);
    assert_eq!(
        first_order.ordered_by,
        OrderedBy::Owner {
            owner: Some(rig.owner_actor)
        }
    );
    assert_eq!(first_order.class, OrderClass::Normal);
    assert_eq!(first_order.ordered_at_ms, NOW);
    assert_eq!(first_order.made_at_ms, NOW + 5_000);
    assert_eq!(
        first_order.queued_ms,
        Some(5_000),
        "the first attempt waited from the order"
    );
    assert_eq!(first_order.started_at_ms, None, "nothing ran");
    assert_eq!(first_order.machine, Some(free.to_hex()));
    assert_eq!(first_order.placed.pick, free.to_hex());
    assert_eq!(first_order.ranked.pick, order.id.to_hex());
    assert_eq!(first_order.end.as_ref(), Some(&first_end));

    let second = attempt_of(&history, &second_job);
    assert_eq!(second.end, "exited");
    assert_eq!(second.occupied_secs, Some(30));
    let second_order = second.order.as_ref().expect("attempt 2 names its order");
    assert_eq!(second_order.order, order.id.to_hex());
    assert_eq!(second_order.attempt, 2);
    assert_eq!(second_order.made_at_ms, made_at);
    let second_wait = made_at - first_end.at_ms;
    assert!(second_wait > 0);
    assert_eq!(
        second_order.queued_ms,
        Some(second_wait),
        "a later attempt waited from the end of the one before"
    );
    assert!(second_order.started_at_ms.is_some(), "the exit says it ran");
    assert_eq!(
        second_order.end.as_ref().map(|end| end.kind),
        Some(EndKind::Exited { code: 0 })
    );
    assert_eq!(
        second_order.end.as_ref().map(|end| end.after.pick.as_str()),
        Some("done")
    );

    assert_eq!(history.totals.all.queued_attempts, 2);
    assert_eq!(history.totals.all.queued_ms, 5_000 + second_wait);

    // `order` narrows the list and the totals to one order's attempts.
    let one = rig.history(
        &JobHistoryRequest {
            order: Some(order.id.to_hex()),
            ..JobHistoryRequest::default()
        },
        HistoryViewer::Owner,
    );
    assert_eq!(one.attempts.len(), 2);
    let other = rig.history(
        &JobHistoryRequest {
            order: Some(EntityId::now().to_hex()),
            ..JobHistoryRequest::default()
        },
        HistoryViewer::Owner,
    );
    assert!(other.attempts.is_empty());
    assert_eq!(other.totals.all.attempts, 0);
}

#[test]
fn an_agent_sees_only_its_own_order_among_the_rank_options_of_its_attempt() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(&[free]);
    let first = rig.order(&digest, OrderClass::Interactive);
    let second = rig.order(&digest, OrderClass::Normal);
    let host = TestHost::new(&rig, vec![machine(free)]);

    // Both orders are runnable in one pass, so each attempt's RANK decision lists both. The
    // machine refuses both before anything runs, which ends them.
    rig.gpu.state().refuse_creates = 2;
    host.pass(NOW + 1_000);
    host.pass(NOW + 2_000);
    let both = vec![first.id.to_hex(), second.id.to_hex()];
    for order in [&first, &second] {
        let stored = rig.stored(order);
        assert_eq!(stored.attempts.len(), 1, "{:?}", stored.state);
        assert_eq!(stored.attempts[0].ranked.options, both);
        assert!(stored.attempts[0].end.is_some());
    }

    // The second order is an agent's: its row names the agent, and its job the agent's start.
    let mut agent = [0u8; 16];
    agent[0] = 0x03;
    agent[15] = 41;
    let agent = EntityId::from_bytes_unchecked(agent);
    let mut orders = rig.vault.work_orders().expect("orders read");
    let mut jobs = rig.vault.gpu_jobs().expect("jobs read");
    let agents_job = rig.stored(&second).attempts[0].job;
    for order in &mut orders {
        if order.id == second.id {
            order.ordered_by = OrderedBy::Agent {
                actor: Some(agent),
                class: EdgeActorClass::Agent,
                grant: EntityId::now(),
            };
        }
    }
    for job in &mut jobs {
        if job.id == agents_job {
            job.started_by = Some(agent);
        }
    }
    let inputs = HistoryInputs {
        jobs: &jobs,
        claims: &[],
        periods: &[],
        orders: &orders,
        observations: &[],
        unattributed: &[],
    };
    let filter = JobHistoryRequest::default()
        .filter()
        .expect("a valid request");

    let own = project(&inputs, &filter, HistoryViewer::Requester(agent));
    assert_eq!(own.attempts.len(), 1, "{:?}", own.attempts);
    let made = own.attempts[0]
        .order
        .as_ref()
        .expect("the agent's attempt names its order");
    assert_eq!(made.order, second.id.to_hex());
    assert_eq!(made.ranked.pick, second.id.to_hex());
    assert_eq!(
        made.ranked.options,
        vec![second.id.to_hex()],
        "the other caller's order is not shown to the agent"
    );

    let owner = project(&inputs, &filter, HistoryViewer::Owner);
    assert_eq!(owner.attempts.len(), 2);
    for attempt in &owner.attempts {
        let made = attempt.order.as_ref().expect("an order's attempt");
        assert_eq!(
            made.ranked.options, both,
            "the owner sees the whole decision"
        );
    }
}
