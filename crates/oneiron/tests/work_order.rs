//! Work orders and their loop (pass 34, `34-compute-general/DESIGN.md` sections 0, 1.1-1.3,
//! 4.3, 4.5, 4.7; row Q1; rulings EM-18, EM-19, EM-22 = A). An order waits holding nothing and
//! names each reason; the loop places it through the built quote and start, whose own write
//! checks the order's authority and revision and writes its attempt entry beside the job; a
//! retry is a new attempt under a new job id. The provider is a scripted fake; the machines'
//! facts are what the test says they reported.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test work_order`
#![cfg(oneiron_test_support)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::gpu_job::{
    GpuConnectorError, GpuJob, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits,
    GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination, PriceShape,
};
use oneiron::job_workload::{
    DeviceClaim, DeviceKind, NetworkMode, ResourceRequest, ScopeKind, Sharing, WorkloadPin,
};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration,
};
use oneiron::test_doors::work_order::{put_approved_workload, put_order, settled_order_wait};
use oneiron::work_order::{
    AfterPick, AttemptOutcome, AttemptRefused, AttemptToMake, Blocker, CancelWhy, DeviceFact,
    EndKind, GiveUpWhy, MachineFacts, MachineReach, OrderCharge, OrderClass, OrderHost,
    OrderLimits, OrderState, OrderWishes, OrderedBy, RetryPolicy, Room, TemplateFact, WaitRule,
    WaitUntil, WindowFact, WorkOrder, WorkOrderWaitAnswer, after_rule, attempt_job_id, fit, place,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;
const TEMPLATE: &str = "open-models";
const TEMPLATE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OFFER: &str = "fixture-machines";

/// What the fake provider holds and answers.
#[derive(Default)]
struct FakeState {
    creates: Vec<String>,
    terminates: usize,
    /// The next create answers that the provider refused, before any resource.
    create_refused: bool,
    status: Option<GpuResourceStatus>,
}

#[derive(Default)]
struct FakeGpu(Mutex<FakeState>);

impl FakeGpu {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake provider lock")
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.creates.push(key.to_owned());
        if std::mem::take(&mut state.create_refused) {
            return Err(GpuConnectorError::Refused {
                reason: "device_busy".to_owned(),
            });
        }
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        let state = self.state();
        Ok(state
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
        self.state().terminates += 1;
        Ok(GpuTermination::Confirmed { billed_secs: 0 })
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

/// A vault, its owner, the offer, the fake provider, and the machines' facts.
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
        gpu: FakeGpu::default(),
        permits: GpuJobPermits::new(),
    }
}

/// A request of `gpus` CUDA GPUs of at least 20,000 MiB each (none for 0).
fn request(gpus: u32) -> ResourceRequest {
    let devices = if gpus == 0 {
        Vec::new()
    } else {
        vec![DeviceClaim {
            kind: DeviceKind::Gpu,
            count: gpus,
            memory_mib: 20_000,
            features: vec!["cuda".to_owned()],
            sharing: Sharing::Exclusive,
        }]
    };
    ResourceRequest {
        cpu_threads: 0,
        memory_mib: 8_192,
        disk_mib: 1_024,
        devices,
        maximum_secs: 600,
    }
}

fn pin(gpus: u32) -> WorkloadPin {
    WorkloadPin {
        template: TEMPLATE.to_owned(),
        template_digest: TEMPLATE_DIGEST.to_owned(),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contracts/arm.json".to_owned(),
        entry: "tools/units/run_arm.sh".to_owned(),
        args: vec!["arm=d2".to_owned()],
        request: request(gpus),
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: Vec::new(),
    }
}

/// A machine that answered, holds the template, and reports `devices`.
fn machine(id: EntityId, devices: Option<Vec<DeviceFact>>) -> MachineFacts {
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
        devices,
        window: None,
        keep_headroom_pct: None,
        roles: Vec::new(),
        warm: Vec::new(),
        warm_absent: Vec::new(),
    }
}

fn gpu(id: &str, busy_until_ms: Option<u64>) -> DeviceFact {
    DeviceFact {
        id: id.to_owned(),
        kind: "gpu".to_owned(),
        memory_mib: 24_576,
        features: vec!["cuda".to_owned()],
        busy_until_ms,
    }
}

impl Rig {
    /// Pins and approves a workload of `gpus` GPUs on `machines`; its digest.
    fn workload(&self, gpus: u32, machines: &[EntityId]) -> String {
        put_approved_workload(
            &self.vault,
            pin(gpus),
            self.owner_actor,
            machines.to_vec(),
            Vec::new(),
            NOW + 86_400_000,
            NOW,
        )
    }

    /// An open order of `workload` by the owner, as the order door writes it.
    fn order(&self, workload: &str, gpus: u32, wait: WaitRule) -> WorkOrder {
        self.order_by(
            workload,
            gpus,
            wait,
            OrderedBy::Owner {
                owner: Some(self.owner_actor),
            },
            OrderClass::Normal,
        )
    }

    fn order_by(
        &self,
        workload: &str,
        gpus: u32,
        wait: WaitRule,
        ordered_by: OrderedBy,
        class: OrderClass,
    ) -> WorkOrder {
        let order = WorkOrder {
            id: EntityId::now(),
            ordered_by,
            workload: workload.to_owned(),
            request: request(gpus),
            charge: OrderCharge::Offer {
                name: OFFER.to_owned(),
            },
            limits: OrderLimits::default(),
            wishes: OrderWishes::default(),
            class,
            wait,
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

    fn jobs(&self) -> Vec<GpuJob> {
        self.vault.gpu_jobs().expect("jobs read")
    }
}

/// The job's own run with one line of `limit` credit-micros.
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

/// What the test's host does before it calls the built start.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BeforeStart {
    /// Calls the start.
    Start,
    /// Dies before the start's write: nothing reaches the store.
    CrashBefore,
    /// Calls the start, then dies before the loop hears the outcome.
    CrashAfter,
    /// Cancels the order first, as a cancel door racing the dispatch would.
    CancelFirst,
}

/// The loop's host in the tests: the machines' facts as given, and the built quote and start
/// with the fake provider.
struct TestHost<'a> {
    rig: &'a Rig,
    facts: Vec<MachineFacts>,
    before: Cell<BeforeStart>,
    admissions: RefCell<HashMap<EntityId, RunAdmission>>,
    asked: Cell<usize>,
}

impl<'a> TestHost<'a> {
    fn new(rig: &'a Rig, facts: Vec<MachineFacts>) -> Self {
        Self {
            rig,
            facts,
            before: Cell::new(BeforeStart::Start),
            admissions: RefCell::new(HashMap::new()),
            asked: Cell::new(0),
        }
    }

    fn start(&self, attempt: &AttemptToMake<'_>) -> Result<GpuJob, GpuJobError> {
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
                NOW,
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
            NOW,
        );
        self.admissions.borrow_mut().insert(attempt.job, run);
        started
    }

    /// Steps `job` once, as the job worker does.
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
        self.asked.set(self.asked.get() + 1);
        match self.before.get() {
            BeforeStart::CrashBefore => return AttemptOutcome::OrderChanged,
            BeforeStart::CancelFirst => {
                self.rig
                    .vault
                    .cancel_work_order(&attempt.order.id, Some(self.rig.owner_actor), NOW)
                    .expect("cancel write")
                    .expect("cancelled");
            }
            BeforeStart::Start | BeforeStart::CrashAfter => {}
        }
        let started = self.start(attempt);
        if self.before.get() == BeforeStart::CrashAfter {
            return AttemptOutcome::OrderChanged;
        }
        match started {
            Ok(_) => AttemptOutcome::Made,
            Err(GpuJobError::Order(AttemptRefused::OrderChanged)) => AttemptOutcome::OrderChanged,
            Err(GpuJobError::Order(AttemptRefused::Blocked(blocker))) => {
                AttemptOutcome::Refused(vec![blocker])
            }
            // A failure after the start's write (the provider's create) leaves the attempt
            // made: its job's end tells the loop.
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
        let reference = oneiron::work_order::OrderAttemptRef {
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
                NOW,
            )
            .map(drop)
            .map_err(|error| error.to_string())
    }
}

fn blockers(order: &WorkOrder) -> Vec<(Option<String>, Blocker)> {
    match &order.state {
        OrderState::Open { blocked, .. } => blocked
            .iter()
            .map(|on| (on.machine.clone(), on.blocker.clone()))
            .collect(),
        other => panic!("the order is not open: {other:?}"),
    }
}

#[test]
fn an_order_that_cannot_run_now_waits_and_names_each_blocker() {
    let rig = rig();
    let (paused, busy) = (EntityId::now(), EntityId::now());
    let digest = rig.workload(1, &[paused, busy]);
    let order = rig.order(&digest, 1, WaitRule::Open);
    let mut paused_facts = machine(paused, Some(vec![gpu("GPU-a", None)]));
    paused_facts.paused = Some("maintenance".to_owned());
    let free_at = NOW + 300_000;
    let host = TestHost::new(
        &rig,
        vec![
            paused_facts,
            machine(busy, Some(vec![gpu("GPU-b", Some(free_at))])),
        ],
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let stored = rig.stored(&order);
    let named = blockers(&stored);
    assert!(named.contains(&(
        Some(paused.to_hex()),
        Blocker::Paused {
            why: "maintenance".to_owned()
        }
    )));
    assert!(named.contains(&(
        Some(busy.to_hex()),
        Blocker::DeviceBusy {
            device: "GPU-b".to_owned(),
            free_at_ms: Some(free_at)
        }
    )));
    match stored.state {
        OrderState::Open { earliest_ms, .. } => assert_eq!(earliest_ms, Some(free_at)),
        other => panic!("open expected: {other:?}"),
    }
    assert!(stored.attempts.is_empty());
}

#[test]
fn a_waiting_order_holds_no_device_and_no_wallet_hold() {
    let rig = rig();
    let busy = EntityId::now();
    let digest = rig.workload(1, &[busy]);
    let order = rig.order(&digest, 1, WaitRule::Open);
    let host = TestHost::new(
        &rig,
        vec![machine(busy, Some(vec![gpu("GPU-b", Some(NOW + 1))]))],
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert!(matches!(rig.stored(&order).state, OrderState::Open { .. }));
    // No start was asked, so no quote was reserved and no job row or permit exists.
    assert_eq!(host.asked.get(), 0);
    assert!(rig.jobs().is_empty());
    assert!(host.admissions.borrow().is_empty());
}

#[test]
fn an_order_whose_requesters_grant_is_revoked_before_dispatch_makes_no_attempt() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    // An agent with no live Grant naming vault.jobs.order: the read a revoked Grant gives.
    let agent = OrderedBy::Agent {
        actor: Some(EntityId::now()),
        class: EdgeActorClass::Agent,
        grant: EntityId::now(),
    };
    let order = rig.order_by(&digest, 0, WaitRule::Open, agent, OrderClass::Normal);
    // The start's own write refuses the attempt on its own, before anything is held.
    let reference = oneiron::work_order::OrderAttemptRef {
        order: order.id,
        revision: order.revision,
        n: 1,
        machine: Some(free),
        ranked: oneiron::work_order::SlotDecision {
            slot: oneiron::work_order::SlotName::Rank,
            options: Vec::new(),
            pick: order.id.to_hex(),
            by: oneiron::work_order::DecidedBy::Rule {
                name: "test".to_owned(),
            },
            why: String::new(),
        },
        placed: oneiron::work_order::SlotDecision {
            slot: oneiron::work_order::SlotName::Place,
            options: vec![free.to_hex()],
            pick: free.to_hex(),
            by: oneiron::work_order::DecidedBy::Rule {
                name: "test".to_owned(),
            },
            why: String::new(),
        },
    };
    let job = attempt_job_id(&order.id, 1).expect("job id");
    let quote = rig
        .offer
        .quote(
            &GpuJobRequest {
                job_type: TEMPLATE.to_owned(),
                image: digest.clone(),
                maximum_secs: Some(600),
                inputs: serde_json::json!({ "machine": free.to_hex() }),
            },
            Some(job),
            600,
            NOW,
        )
        .expect("quote");
    let refused = rig.vault.start_gpu_job(
        GpuJobStart {
            actor: GpuJobActor::Order(&reference),
            offer: &rig.offer,
            quote: &quote,
            resume: None,
            admission: &admission(&job, 1_000_000),
        },
        &rig.permits,
        &rig.gpu,
        NOW,
    );
    assert!(matches!(
        refused,
        Err(GpuJobError::Order(AttemptRefused::Blocked(
            Blocker::GrantNotLive
        )))
    ));
    assert!(rig.jobs().is_empty());
    // The loop cancels the order with the reason and asks for no attempt.
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(host.asked.get(), 0);
    assert_eq!(
        rig.stored(&order).state,
        OrderState::Cancelled {
            why: CancelWhy::AuthorityEnded
        }
    );
    assert!(rig.jobs().is_empty());
}

#[test]
fn a_cancel_and_a_dispatch_of_one_order_never_both_win() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    // The cancel writes between the loop's read and the start's write: the start refuses.
    let first = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    host.before.set(BeforeStart::CancelFirst);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert!(matches!(
        rig.stored(&first).state,
        OrderState::Cancelled { .. }
    ));
    assert!(rig.stored(&first).attempts.is_empty());
    assert!(rig.jobs().is_empty());
    assert!(rig.gpu.state().creates.is_empty());
    // The dispatch writes first: the cancel stops its attempt, and the order ends cancelled
    // once the attempt's end is in, never dispatched again.
    let second = rig.order(&digest, 0, WaitRule::Open);
    host.before.set(BeforeStart::Start);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert!(matches!(
        rig.stored(&second).state,
        OrderState::Running { attempt: 1 }
    ));
    rig.vault
        .cancel_work_order(&second.id, Some(rig.owner_actor), NOW)
        .expect("cancel write")
        .expect("cancel");
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = rig.stored(&second).attempts[0].job;
    host.step(&job, NOW + 1_000);
    assert!(rig.gpu.state().terminates >= 1);
    rig.vault.work_order_pass(&host, NOW + 2_000).expect("pass");
    let ended = rig.stored(&second);
    assert!(matches!(ended.state, OrderState::Cancelled { .. }));
    assert_eq!(ended.attempts.len(), 1);
}

#[test]
fn a_written_off_attempt_is_not_followed_by_another_unless_someone_orders_again() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = rig.stored(&order).attempts[0].job;
    let wrote = rig
        .vault
        .with_write_txn_grouped(|txn| rig.vault.order_attempt_written_off_in_txn(txn, &job, NOW))
        .expect("write-off");
    assert!(wrote);
    assert_eq!(
        rig.stored(&order).state,
        OrderState::GivenUp {
            why: GiveUpWhy::WrittenOff
        }
    );
    rig.vault
        .work_order_pass(&host, NOW + 60_000)
        .expect("pass");
    assert_eq!(host.asked.get(), 1);
    assert_eq!(rig.stored(&order).attempts.len(), 1);
}

#[test]
fn a_crash_between_any_two_steps_of_making_an_attempt_leaves_one_attempt_or_none() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    // Before the start's write: none.
    host.before.set(BeforeStart::CrashBefore);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert!(rig.stored(&order).attempts.is_empty());
    assert!(rig.jobs().is_empty());
    // After the write, before the loop hears: one, under the job id the order fixes.
    host.before.set(BeforeStart::CrashAfter);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = attempt_job_id(&order.id, 1).expect("job id");
    let stored = rig.stored(&order);
    assert_eq!(stored.attempts.len(), 1);
    assert_eq!(stored.attempts[0].job, job);
    assert_eq!(rig.jobs().len(), 1);
    assert_eq!(rig.jobs()[0].id, job);
    // A second pass after the crash makes nothing more.
    host.before.set(BeforeStart::Start);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(rig.stored(&order).attempts.len(), 1);
    assert_eq!(rig.jobs().len(), 1);
    assert_eq!(rig.gpu.state().creates.len(), 1);
}

#[test]
fn an_order_with_an_unconfirmed_attempt_gets_no_second_attempt() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::No);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    // The attempt's job row is gone from this issuer's view (a restore): its end is unknown.
    let mut lost = rig.stored(&order);
    lost.attempts[0].job = EntityId::now();
    put_order(&rig.vault, &lost);
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");
    rig.vault.work_order_pass(&host, NOW + 2_000).expect("pass");
    let stored = rig.stored(&order);
    assert_eq!(host.asked.get(), 1);
    assert_eq!(stored.attempts.len(), 1);
    // Unknown is never read as ended, and `wait: no` does not give it up.
    assert!(matches!(
        blockers(&stored).as_slice(),
        [(_, Blocker::AttemptUnconfirmed { .. })]
    ));
}

#[test]
fn a_blocker_that_no_wait_can_clear_refuses_the_order_at_once() {
    let rig = rig();
    let (a, b) = (EntityId::now(), EntityId::now());
    let digest = rig.workload(0, &[a, b]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let mut without = machine(a, None);
    without.templates = Some(Vec::new());
    let mut changed = machine(b, None);
    if let Some(templates) = changed.templates.as_mut() {
        templates[0].digest = "2".repeat(64);
    }
    let host = TestHost::new(&rig, vec![without, changed]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    match rig.stored(&order).state {
        OrderState::GivenUp {
            why: GiveUpWhy::NeverFits { blocked },
        } => {
            let codes: Vec<&str> = blocked.iter().map(|on| on.blocker.code()).collect();
            assert!(codes.contains(&"template_not_offered"));
            assert!(codes.contains(&"template_changed"));
        }
        other => panic!("refused at once expected: {other:?}"),
    }
    assert_eq!(host.asked.get(), 0);
}

#[test]
fn a_retry_is_a_new_key_and_the_old_key_is_never_sent_again() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    // The machine refuses the first attempt before anything runs: zero seconds.
    rig.gpu.state().create_refused = true;
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");
    let waiting = rig.stored(&order);
    assert_eq!(waiting.attempts.len(), 1);
    assert_eq!(
        waiting.attempts[0].end.as_ref().map(|end| end.kind),
        Some(EndKind::NeverStarted)
    );
    assert!(matches!(
        blockers(&waiting).as_slice(),
        [(None, Blocker::RetryNotBefore { .. })]
    ));
    // After the backoff, attempt 2 under its own job id.
    rig.vault
        .work_order_pass(&host, NOW + 32_000)
        .expect("pass");
    let stored = rig.stored(&order);
    assert_eq!(stored.attempts.len(), 2);
    let (first, second) = (stored.attempts[0].job, stored.attempts[1].job);
    assert_ne!(first, second);
    assert_eq!(second, attempt_job_id(&order.id, 2).expect("job id"));
    let creates = rig.gpu.state().creates.clone();
    assert_eq!(creates.len(), 2);
    assert_ne!(creates[0], creates[1]);
}

#[test]
fn a_deterministic_failure_is_not_retried_by_default() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let mut order = rig.order(&digest, 0, WaitRule::Open);
    let policy = RetryPolicy::default();
    for end in [
        EndKind::Exited { code: 1 },
        EndKind::MemoryLimit,
        EndKind::DiskLimit,
        EndKind::TimeLimit,
        EndKind::Lost,
    ] {
        let (pick, decision) = after_rule(&order, end, &policy, NOW);
        assert_eq!(pick, AfterPick::GiveUp, "{end:?}");
        assert_eq!(decision.pick, "give_up");
    }
    // The order's own retry_on asks for it, once.
    order.retry_on = vec![EndKind::Exited { code: 1 }];
    let (pick, _) = after_rule(&order, EndKind::Exited { code: 1 }, &policy, NOW);
    assert_eq!(pick, AfterPick::RetryAt(NOW + 30_000));
    // A zero-second end is the queue working: retried.
    let (pick, _) = after_rule(&order, EndKind::NeverStarted, &policy, NOW);
    assert_eq!(pick, AfterPick::RetryAt(NOW + 30_000));
}

#[test]
fn a_job_without_a_device_claim_is_not_placed_on_a_device_machine_when_another_fits() {
    let rig = rig();
    let (with_gpus, without) = (EntityId::now(), EntityId::now());
    let digest = rig.workload(0, &[with_gpus, without]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let device_machine = machine(
        with_gpus,
        Some(vec![gpu("GPU-a", None), gpu("GPU-b", None)]),
    );
    let cpu_machine = machine(without, Some(Vec::new()));
    let (picked, decision) = place(&order, &[&device_machine, &cpu_machine]).expect("a pick");
    assert_eq!(picked.machine, without);
    assert_eq!(decision.why, "keeps devices free");
    assert_eq!(decision.options, vec![without.to_hex(), with_gpus.to_hex()]);
    // Through the loop: the attempt goes to the machine without devices.
    let host = TestHost::new(&rig, vec![device_machine, cpu_machine]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(rig.stored(&order).attempts[0].machine, Some(without));
}

#[test]
fn a_machine_outside_its_window_or_inside_its_kept_headroom_is_not_a_candidate() {
    let rig = rig();
    let (closed, tight, open) = (EntityId::now(), EntityId::now(), EntityId::now());
    let digest = rig.workload(0, &[closed, tight, open]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let opens = NOW + 3_600_000;
    let mut closed_facts = machine(closed, None);
    closed_facts.window = Some(WindowFact {
        open: false,
        opens_ms: Some(opens),
    });
    let mut tight_facts = machine(tight, None);
    tight_facts.keep_headroom_pct = Some(90);
    let template = (TEMPLATE, TEMPLATE_DIGEST);
    assert_eq!(
        fit(&order, template, &closed_facts),
        vec![Blocker::OutsideWindow {
            opens_ms: Some(opens)
        }]
    );
    assert_eq!(
        fit(&order, template, &tight_facts),
        vec![Blocker::KeepHeadroom]
    );
    let host = TestHost::new(&rig, vec![closed_facts, tight_facts, machine(open, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let stored = rig.stored(&order);
    assert_eq!(stored.attempts[0].machine, Some(open));
    assert_eq!(stored.attempts[0].placed.options, vec![open.to_hex()]);
}

#[test]
fn two_runnable_orders_of_two_lines_start_in_the_order_rule_and_neither_spends_the_others_room() {
    let rig = rig();
    let one = EntityId::now();
    let digest = rig.workload(1, &[one]);
    let owner = OrderedBy::Owner {
        owner: Some(rig.owner_actor),
    };
    // The background order is older; the interactive one still goes first.
    let background = rig.order_by(
        &digest,
        1,
        WaitRule::Open,
        owner.clone(),
        OrderClass::Background,
    );
    let interactive = rig.order_by(&digest, 1, WaitRule::Open, owner, OrderClass::Interactive);
    let host = TestHost::new(&rig, vec![machine(one, Some(vec![gpu("GPU-a", None)]))]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let first = rig.stored(&interactive);
    assert!(matches!(first.state, OrderState::Running { attempt: 1 }));
    assert_eq!(first.attempts[0].ranked.pick, interactive.id.to_hex());
    // The other waits on the device the first holds, and holds nothing itself.
    let second = rig.stored(&background);
    assert!(second.attempts.is_empty());
    assert!(matches!(
        blockers(&second).as_slice(),
        [(_, Blocker::DeviceBusy { .. })]
    ));
    // One job, reserved on its own run: the waiting order's room was never touched.
    let jobs = rig.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, first.attempts[0].job);
    assert_eq!(host.admissions.borrow().len(), 1);
}

/// A decision of `slot` by a test rule that picks `pick`.
fn test_decision(
    slot: oneiron::work_order::SlotName,
    pick: String,
) -> oneiron::work_order::SlotDecision {
    oneiron::work_order::SlotDecision {
        slot,
        options: vec![pick.clone()],
        pick,
        by: oneiron::work_order::DecidedBy::Rule {
            name: "test".to_owned(),
        },
        why: String::new(),
    }
}

/// The first attempt of `order` on `machine`, as a pass would ask for it.
fn first_attempt<'a>(
    order: &'a WorkOrder,
    machine: EntityId,
    pin: &'a WorkloadPin,
) -> AttemptToMake<'a> {
    AttemptToMake {
        order,
        n: 1,
        job: attempt_job_id(&order.id, 1).expect("job id"),
        machine,
        devices: Vec::new(),
        pin,
        ranked: test_decision(oneiron::work_order::SlotName::Rank, order.id.to_hex()),
        placed: test_decision(oneiron::work_order::SlotName::Place, machine.to_hex()),
    }
}

#[test]
fn an_order_whose_wait_ran_out_makes_no_attempt_even_where_it_fits() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Until { ms: NOW });
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    // The start's own write refuses an attempt at or after the order's time.
    let pin = pin(0);
    let started = host.start(&first_attempt(&order, free, &pin));
    assert!(matches!(
        started,
        Err(GpuJobError::Order(AttemptRefused::OrderChanged))
    ));
    assert!(rig.jobs().is_empty());
    // The loop gives it up on a machine that fits, and asks for no attempt.
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(host.asked.get(), 0);
    assert!(rig.jobs().is_empty());
    assert!(matches!(
        rig.stored(&order).state,
        OrderState::GivenUp {
            why: GiveUpWhy::WaitEnded { .. }
        }
    ));
}

#[test]
fn a_refusal_that_reports_no_templates_waits_instead_of_refusing_the_order() {
    let rig = rig();
    let paused = EntityId::now();
    let digest = rig.workload(0, &[paused]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    // A node's refusal carries no template inventory: the template is not known missing.
    let mut facts = machine(paused, None);
    facts.templates = None;
    facts.refusal = Some(Blocker::Paused {
        why: "maintenance".to_owned(),
    });
    let host = TestHost::new(&rig, vec![facts]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(host.asked.get(), 0);
    let stored = rig.stored(&order);
    let reasons = blockers(&stored);
    let codes: Vec<&str> = reasons.iter().map(|(_, blocker)| blocker.code()).collect();
    assert_eq!(codes, vec!["paused"]);
}

#[test]
fn an_order_whose_limits_allow_no_scope_of_its_pin_is_never_placed() {
    let rig = rig();
    let free = EntityId::now();
    // The pin runs in the host scope; the order allows containers only.
    let digest = rig.workload(0, &[free]);
    let mut order = rig.order(&digest, 0, WaitRule::Open);
    order.limits.scopes = vec!["container".to_owned()];
    put_order(&rig.vault, &order);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    let pin = pin(0);
    let started = host.start(&first_attempt(&order, free, &pin));
    match started {
        Err(GpuJobError::Order(AttemptRefused::Blocked(blocker))) => {
            assert_eq!(blocker.code(), "scope_not_allowed");
        }
        other => panic!("the start's write let a host pin past a container-only order: {other:?}"),
    }
    assert!(rig.jobs().is_empty());
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert_eq!(host.asked.get(), 0);
    match rig.stored(&order).state {
        OrderState::GivenUp {
            why: GiveUpWhy::NeverFits { blocked },
        } => {
            let codes: Vec<&str> = blocked.iter().map(|on| on.blocker.code()).collect();
            assert_eq!(codes, vec!["scope_not_allowed"]);
        }
        other => panic!("the order is not refused at once: {other:?}"),
    }
}

#[test]
fn a_cancel_of_an_order_whose_attempt_is_unconfirmed_waits_for_that_attempts_end() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    // The attempt's job row is gone from this issuer's view: the order shows open, on an
    // unconfirmed attempt.
    let job = EntityId::now();
    let mut lost = rig.stored(&order);
    lost.attempts[0].job = job;
    put_order(&rig.vault, &lost);
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");
    assert!(matches!(rig.stored(&order).state, OrderState::Open { .. }));
    // The cancel is recorded and the order stays where the attempt's end can still land.
    rig.vault
        .cancel_work_order(&order.id, Some(rig.owner_actor), NOW + 2_000)
        .expect("cancel write")
        .expect("cancel");
    let cancelled = rig.stored(&order);
    assert!(!cancelled.state.is_terminal());
    assert!(cancelled.cancel.is_some());
    rig.vault.work_order_pass(&host, NOW + 3_000).expect("pass");
    assert_eq!(host.asked.get(), 1);
    // The owner's write-off of that attempt lands on the order, which ends cancelled.
    let wrote = rig
        .vault
        .with_write_txn_grouped(|txn| {
            rig.vault
                .order_attempt_written_off_in_txn(txn, &job, NOW + 4_000)
        })
        .expect("write-off");
    assert!(wrote);
    let ended = rig.stored(&order);
    assert!(matches!(ended.state, OrderState::Cancelled { .. }));
    assert_eq!(
        ended.attempts[0].end.as_ref().map(|end| end.kind),
        Some(EndKind::WrittenOff)
    );
}

/// The answer the order's writer settled the wait on `order` until `until` with: what every
/// run parked on it is delivered, and what a run that parks later is answered at once.
fn settled(rig: &Rig, order: &WorkOrder, until: WaitUntil) -> Option<WorkOrderWaitAnswer> {
    settled_order_wait(&rig.vault, &order.id, until)
        .map(|reply| serde_json::from_value(reply).expect("a wait answer"))
}

#[test]
fn a_started_wait_answers_at_the_first_started_attempt_or_at_an_end_with_no_start() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = rig.stored(&order).attempts[0].job;
    // The attempt is made and its resource exists, but the provider holds it pending: its
    // clock has not started, so neither has the attempt.
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");
    assert_eq!(rig.stored(&order).attempts[0].started_at_ms, None);
    assert!(settled(&rig, &order, WaitUntil::Started).is_none());
    rig.gpu.state().status = Some(GpuResourceStatus::Running {
        used_secs: 3,
        checkpoint: None,
    });
    host.step(&job, NOW + 2_000);
    rig.vault.work_order_pass(&host, NOW + 3_000).expect("pass");
    let started = settled(&rig, &order, WaitUntil::Started).expect("the started wait settled");
    assert!(started.reached);
    assert_eq!(
        started.view.order.attempts[0].started_at_ms,
        Some(NOW + 3_000)
    );
    assert!(matches!(
        started.view.order.state,
        OrderState::Running { attempt: 1 }
    ));
    assert!(settled(&rig, &order, WaitUntil::Terminal).is_none());
    // An order cancelled while open, before any attempt, reaches both at its end: the view's
    // state says it ended, with no attempt.
    let never = rig.order(&digest, 0, WaitRule::Open);
    rig.vault
        .cancel_work_order(&never.id, Some(rig.owner_actor), NOW + 4_000)
        .expect("cancel write")
        .expect("cancel");
    let ended =
        settled(&rig, &never, WaitUntil::Started).expect("the started wait settled at the end");
    assert!(ended.view.order.attempts.is_empty());
    assert!(matches!(
        ended.view.order.state,
        OrderState::Cancelled { .. }
    ));
    assert_eq!(settled(&rig, &never, WaitUntil::Terminal), Some(ended));
}

#[test]
fn a_terminal_wait_settles_in_the_write_that_ends_the_order_with_its_view() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = rig.stored(&order).attempts[0].job;
    assert!(settled(&rig, &order, WaitUntil::Terminal).is_none());
    // The job ends before any pass saw it run: its end is the provider's word that it ran.
    rig.gpu.state().status = Some(GpuResourceStatus::Exited { used_secs: 7 });
    host.step(&job, NOW + 1_000);
    rig.vault.work_order_pass(&host, NOW + 2_000).expect("pass");
    let done = rig.stored(&order);
    assert_eq!(done.state, OrderState::Done);
    let answer = settled(&rig, &order, WaitUntil::Terminal).expect("the terminal wait settled");
    assert!(answer.reached);
    assert_eq!(answer.view.order, done);
    assert_eq!(
        answer.view.order.attempts[0].started_at_ms,
        Some(NOW + 2_000)
    );
    // An offer's provider signs no receipt.
    assert_eq!(answer.view.receipt, None);
    // The started wait settled in the same write, with the same answer.
    assert_eq!(settled(&rig, &order, WaitUntil::Started), Some(answer));
}

#[test]
fn a_pending_cancel_does_not_end_the_wait_until_the_attempt_ends() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open);
    let host = TestHost::new(&rig, vec![machine(free, None)]);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let job = rig.stored(&order).attempts[0].job;
    rig.vault
        .cancel_work_order(&order.id, Some(rig.owner_actor), NOW + 1_000)
        .expect("cancel write")
        .expect("cancel");
    let cancelling = rig.stored(&order);
    assert!(cancelling.cancel.is_some());
    assert!(!cancelling.state.is_terminal());
    assert!(settled(&rig, &order, WaitUntil::Terminal).is_none());
    // The owner writes the attempt off: the order ends cancelled, and the wait settles then.
    let wrote = rig
        .vault
        .with_write_txn_grouped(|txn| {
            rig.vault
                .order_attempt_written_off_in_txn(txn, &job, NOW + 2_000)
        })
        .expect("write-off");
    assert!(wrote);
    let answer = settled(&rig, &order, WaitUntil::Terminal).expect("settled at the end");
    assert!(matches!(
        answer.view.order.state,
        OrderState::Cancelled { .. }
    ));
}
