//! Slot deciders (pass 34, `34-compute-general/DESIGN.md` sections 1.2, 4.4, 4.5, 4.7 and 10;
//! row P1): the Grant the owner names in `policy.slots.decider` answers RANK, PLACE or AFTER
//! among the options the engine lists. An answer outside them, or none inside the slot's
//! deadline, keeps the rule's pick (I9), and the decision is stored on the row it decides. One
//! pass waits about one deadline on its deciders, and an order a decider holds is asked again
//! only once its wait ends (Engine F1 and F3, 25 Nov 20:4x). The host's decision ladder is a
//! scripted decider here; the provider is a scripted fake.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test work_order_deciders`
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::{
    AtMaximum, GpuConnectorError, GpuJobActor, GpuJobConnector, GpuJobError, GpuJobPermits,
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
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::derive::expire_agent_grant;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::work_order::{put_approved_workload, put_order};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::work_order::decider::{
    DECIDER_VERB, DeciderMiss, DeciderReceipt, DeciderReply, PLACE_WAIT,
    PLACE_WAIT_REASK_MS_DEFAULT, SlotAsk, SlotAskWindow,
};
use oneiron::work_order::{
    AttemptOutcome, AttemptRefused, AttemptToMake, Blocker, DecidedBy, DeviceFact, EndKind,
    GiveUpWhy, MachineFacts, MachineReach, OrderCharge, OrderClass, OrderHost, OrderLimits,
    OrderState, OrderWishes, OrderedBy, PLACE_RULE, RANK_RULE, Room, SlotName, TemplateFact,
    WaitRule, WorkOrder,
};
use oneiron::{EntityId, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 1_800_000_000_000;
const TEMPLATE: &str = "open-models";
const TEMPLATE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OFFER: &str = "fixture-machines";

/// What the fake provider holds and answers.
#[derive(Default)]
struct FakeState {
    creates: Vec<String>,
    /// The next create answers that the provider refused, before any resource.
    create_refused: bool,
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
        Ok(self
            .state()
            .creates
            .iter()
            .any(|made| made == key)
            .then(|| GpuResourceRef(format!("resource-{key}"))))
    }

    fn status(&self, _resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(GpuResourceStatus::Pending)
    }

    fn signal(
        &self,
        _resource: &GpuResourceRef,
        _signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        Ok(())
    }

    fn terminate(&self, _resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
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
        at_maximum: AtMaximum::Stop,
    }
}

/// A vault with an installed owner who can mint Grants, the offer, and the fake provider.
struct Rig {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner_actor: EntityId,
    proof: AuthenticatedOwner,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("enroll the install");
    // The handle holds the host's root, as a serving host does: the owner's
    // setting acts this install carries are then proven, and land.
    vault.hold_checkpoint_root_signer(Arc::new(issuer));
    let (owner_actor, proof) = embedded_owner(&vault).expect("embedded owner proof");
    Rig {
        _dir: dir,
        vault,
        owner_actor,
        proof,
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
    }
}

fn gpu(id: &str) -> DeviceFact {
    DeviceFact {
        id: id.to_owned(),
        kind: "gpu".to_owned(),
        memory_mib: 24_576,
        features: vec!["cuda".to_owned()],
        busy_until_ms: None,
    }
}

/// Two machines that fit a CPU order equally: the rule picks the lower id.
fn two_machines() -> (EntityId, EntityId) {
    let (a, b) = (EntityId::now(), EntityId::now());
    (a.min(b), a.max(b))
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
    fn order(&self, workload: &str, gpus: u32, wait: WaitRule, class: OrderClass) -> WorkOrder {
        let order = WorkOrder {
            id: EntityId::now(),
            ordered_by: OrderedBy::Owner {
                owner: Some(self.owner_actor),
            },
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

    /// A Grant the owner mints for a new agent `name`, naming `verbs`; its id.
    fn grant(&self, name: &str, verbs: &[&str]) -> EntityId {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("named agent");
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: Default::default(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("mint the agent's Grant")
        .grant;
        assert!(minted.confers, "FIXTURE: the Grant confers");
        minted.grant_ref
    }

    /// A decider Grant: it names `read` and the decision read.
    fn decider(&self) -> EntityId {
        self.grant("slot-decider", &["read", DECIDER_VERB])
    }

    /// The owner sets `key` for `slot` to `value` at the vault.
    fn set_slot(&self, key: &str, slot: &str, value: serde_json::Value) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.proof),
                SetSetting {
                    key: key.to_owned(),
                    item: Some(slot.to_owned()),
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: Some(value),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                    weight_runs: None,
                    surface: None,
                },
            )
            .expect("the owner's change");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "FIXTURE: the owner's change did not apply: {outcome:?}"
        );
    }

    /// The owner names `grant` to decide `slot`.
    fn name_decider(&self, slot: &str, grant: EntityId) {
        self.set_slot("policy.slots.decider", slot, json!(grant.to_hex()));
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
        oneiron::gpu_job::GpuJob::admission_ref_of(job),
        declaration,
        None,
        Arc::new(MemoryReceipts::default()) as Arc<dyn oneiron::llm::run_admission::RunReceiptSink>,
    )
}

/// What the scripted decider answers an ask.
type Script = Box<dyn Fn(&SlotAsk) -> DeciderReply>;

/// The loop's host: the machines' facts as given, the built quote and start with the fake
/// provider, and a scripted decider in place of the decision ladder.
struct TestHost<'a> {
    rig: &'a Rig,
    facts: Vec<MachineFacts>,
    script: Script,
    asks: RefCell<Vec<SlotAsk>>,
    admissions: RefCell<Vec<RunAdmission>>,
}

impl<'a> TestHost<'a> {
    fn new(rig: &'a Rig, facts: Vec<MachineFacts>, script: Script) -> Self {
        Self {
            rig,
            facts,
            script,
            asks: RefCell::new(Vec::new()),
            admissions: RefCell::new(Vec::new()),
        }
    }

    fn asked(&self, slot: SlotName) -> Vec<SlotAsk> {
        self.asks
            .borrow()
            .iter()
            .filter(|ask| ask.slot == slot)
            .cloned()
            .collect()
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
        let quote = self
            .rig
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: TEMPLATE.to_owned(),
                    image: attempt.order.workload.clone(),
                    maximum_secs: Some(attempt.order.request.maximum_secs),
                    inputs: json!({ "machine": attempt.machine.to_hex() }),
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
        self.admissions.borrow_mut().push(run);
        match started {
            Ok(_) => AttemptOutcome::Made,
            Err(GpuJobError::Order(AttemptRefused::OrderChanged)) => AttemptOutcome::OrderChanged,
            Err(GpuJobError::Order(AttemptRefused::Blocked(blocker))) => {
                AttemptOutcome::Refused(vec![blocker])
            }
            // A failure after the start's write (the provider's create) leaves the attempt
            // made: its job's end tells the loop.
            Err(_) => AttemptOutcome::Made,
        }
    }

    fn stop_attempt(&self, _order: &WorkOrder, _job: &EntityId) -> Result<(), String> {
        Ok(())
    }

    fn decide(&self, ask: &SlotAsk) -> DeciderReply {
        self.asks.borrow_mut().push(ask.clone());
        (self.script)(ask)
    }
}

/// The receipt the scripted decider's read leaves, with probability `p`.
fn receipt(p: f64) -> DeciderReceipt {
    DeciderReceipt::of_read(
        "0".repeat(32),
        vec!["big:fixture-model@1".to_owned()],
        Some("big".to_owned()),
        Some(p),
        Some(0.002),
    )
}

/// A scripted decider that answers `label` to every ask.
fn answers(label: &str) -> Script {
    let label = label.to_owned();
    Box::new(move |_| DeciderReply::Answered {
        label: label.clone(),
        receipt: receipt(0.8),
    })
}

/// A decider no test expects to be asked.
fn never() -> Script {
    Box::new(|ask| panic!("the decider was asked: {ask:?}"))
}

/// A decider whose every read takes the whole deadline it is given and answers nothing, as a
/// read whose clock ran out.
fn slow() -> Script {
    Box::new(|ask| {
        // testkit-lint: allow(sleep) the pass's ask budget is real time (Instant), which no fake clock reaches
        std::thread::sleep(Duration::from_millis(ask.deadline_ms));
        DeciderReply::Silent { receipt: None }
    })
}

fn blockers(order: &WorkOrder) -> Vec<Blocker> {
    match &order.state {
        OrderState::Open { blocked, .. } => blocked.iter().map(|on| on.blocker.clone()).collect(),
        other => panic!("the order is not open: {other:?}"),
    }
}

#[test]
fn a_slot_answer_outside_the_listed_options_keeps_the_default() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    // A machine the order may not run on: not among the options.
    let elsewhere = EntityId::now().to_hex();
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(&elsewhere),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    let asked = host.asked(SlotName::Place);
    assert_eq!(asked.len(), 1, "one ask for the one placement");
    assert_eq!(asked[0].grant, grant);
    assert_eq!(
        asked[0].options,
        vec![low.to_hex(), high.to_hex(), PLACE_WAIT.to_owned()]
    );
    let stored = rig.stored(&order);
    assert_eq!(stored.attempts.len(), 1);
    let attempt = &stored.attempts[0];
    assert_eq!(attempt.machine, Some(low), "the rule's pick stands");
    assert_eq!(attempt.placed.pick, low.to_hex());
    assert_eq!(
        attempt.placed.by,
        DecidedBy::RuleKept {
            name: PLACE_RULE.to_owned(),
            decider: grant,
            miss: DeciderMiss::Outside,
            receipt: Some(receipt(0.8)),
        }
    );
}

#[test]
fn a_silent_decider_keeps_the_default_inside_the_deadline() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    // A deadline no answer meets: the decider's answer, though listed, comes after it.
    rig.set_slot("policy.slots.deadline_ms", "place", json!(0));
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(&high.to_hex()),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    let asked = host.asked(SlotName::Place);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].deadline_ms, 0,
        "the slot's own deadline reaches the host"
    );
    let stored = rig.stored(&order);
    let attempt = &stored.attempts[0];
    assert_eq!(attempt.machine, Some(low), "the rule's pick stands");
    assert!(
        matches!(
            &attempt.placed.by,
            DecidedBy::RuleKept { decider, miss: DeciderMiss::Silent, .. } if *decider == grant
        ),
        "{:?}",
        attempt.placed.by
    );

    // A read whose own clock ran out is silent too.
    let second = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    rig.set_slot("policy.slots.deadline_ms", "place", json!(5_000));
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        Box::new(|_| DeciderReply::Silent { receipt: None }),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let stored = rig.stored(&second);
    assert_eq!(stored.attempts[0].machine, Some(low));
    assert_eq!(
        stored.attempts[0].placed.by,
        DecidedBy::RuleKept {
            name: PLACE_RULE.to_owned(),
            decider: grant,
            miss: DeciderMiss::Silent,
            receipt: None,
        }
    );
}

#[test]
fn the_placement_decision_and_its_reason_are_stored_on_the_attempt() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(&high.to_hex()),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    // The decider saw the candidates' facts and the rule's pick, and nothing of the workload.
    let asked = host.asked(SlotName::Place);
    assert_eq!(asked.len(), 1);
    let candidates = asked[0].facts["candidates"]
        .as_array()
        .expect("the candidates' facts");
    assert_eq!(candidates.len(), 2);
    assert_eq!(asked[0].facts["rule_pick"]["pick"], json!(low.to_hex()));
    assert!(asked[0].facts.get("workload").is_none());

    // "Why here?" is a read of the stored order.
    let stored = rig.stored(&order);
    assert!(matches!(stored.state, OrderState::Running { attempt: 1 }));
    let attempt = &stored.attempts[0];
    assert_eq!(
        attempt.machine,
        Some(high),
        "the decider's pick is the machine"
    );
    assert_eq!(attempt.placed.slot, SlotName::Place);
    assert_eq!(attempt.placed.pick, high.to_hex());
    assert_eq!(
        attempt.placed.options,
        vec![low.to_hex(), high.to_hex(), PLACE_WAIT.to_owned()]
    );
    assert_eq!(
        attempt.placed.by,
        DecidedBy::Grant {
            grant,
            receipt: receipt(0.8),
        }
    );
    assert_eq!(
        attempt.placed.why,
        "the decider the owner named picked it (p 0.800)"
    );
    let jobs = rig.vault.gpu_jobs().expect("jobs read");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].id, attempt.job);
}

#[test]
fn a_decider_is_asked_only_where_two_options_are_lawful() {
    let rig = rig();
    let only = EntityId::now();
    let digest = rig.workload(0, &[only]);
    // One machine and no wait: one lawful place. One runnable order: one lawful rank.
    let order = rig.order(&digest, 0, WaitRule::No, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    rig.name_decider("rank", grant);
    let host = TestHost::new(&rig, vec![machine(only, None)], never());
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    assert!(host.asks.borrow().is_empty());
    let stored = rig.stored(&order);
    let attempt = &stored.attempts[0];
    assert_eq!(attempt.machine, Some(only));
    assert_eq!(
        attempt.placed.by,
        DecidedBy::Rule {
            name: PLACE_RULE.to_owned()
        }
    );
    assert_eq!(
        attempt.ranked.by,
        DecidedBy::Rule {
            name: RANK_RULE.to_owned()
        }
    );
}

#[test]
fn a_decider_whose_grant_is_revoked_is_not_asked() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    expire_agent_grant(&rig.vault, grant).expect("the Grant ends");
    let host = TestHost::new(&rig, vec![machine(low, None), machine(high, None)], never());
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    assert!(host.asks.borrow().is_empty());
    let stored = rig.stored(&order);
    assert_eq!(stored.attempts[0].machine, Some(low));
    assert_eq!(
        stored.attempts[0].placed.by,
        DecidedBy::RuleKept {
            name: PLACE_RULE.to_owned(),
            decider: grant,
            miss: DeciderMiss::NotLive,
            receipt: None,
        }
    );

    // A Grant that does not name the decision read does not stand as a decider either.
    let reader = rig.grant("reader-only", &["read"]);
    rig.name_decider("place", reader);
    let second = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    assert!(host.asks.borrow().is_empty());
    assert!(matches!(
        &rig.stored(&second).attempts[0].placed.by,
        DecidedBy::RuleKept {
            miss: DeciderMiss::NotLive,
            ..
        }
    ));
}

#[test]
fn a_rank_decider_picks_which_runnable_order_goes_first() {
    let rig = rig();
    let one = EntityId::now();
    let digest = rig.workload(1, &[one]);
    // The rule puts the interactive order first; the decider picks the background one.
    let background = rig.order(&digest, 1, WaitRule::Open, OrderClass::Background);
    let interactive = rig.order(&digest, 1, WaitRule::Open, OrderClass::Interactive);
    let grant = rig.decider();
    rig.name_decider("rank", grant);
    let host = TestHost::new(
        &rig,
        vec![machine(one, Some(vec![gpu("GPU-a")]))],
        answers(&background.id.to_hex()),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    let asked = host.asked(SlotName::Rank);
    assert_eq!(asked.len(), 1, "one rank ask per pass");
    assert_eq!(
        asked[0].options,
        vec![interactive.id.to_hex(), background.id.to_hex()]
    );
    // The decider sees each order's class, charge and age, not its workload or arguments.
    let shown = asked[0].facts["orders"][0]
        .as_object()
        .expect("an order's facts");
    assert!(shown.contains_key("class") && shown.contains_key("age_ms"));
    assert!(!shown.contains_key("workload") && !shown.contains_key("args"));

    let first = rig.stored(&background);
    assert!(matches!(first.state, OrderState::Running { attempt: 1 }));
    assert_eq!(first.attempts[0].ranked.pick, background.id.to_hex());
    assert!(matches!(
        &first.attempts[0].ranked.by,
        DecidedBy::Grant { grant: by, .. } if *by == grant
    ));
    // The other waits on the device the first holds.
    let second = rig.stored(&interactive);
    assert!(second.attempts.is_empty());
    assert!(matches!(
        blockers(&second).as_slice(),
        [Blocker::DeviceBusy { .. }]
    ));
}

#[test]
fn an_after_decider_gives_up_where_the_rule_would_retry() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("after", grant);
    let host = TestHost::new(&rig, vec![machine(free, None)], answers("give_up"));
    // The machine refuses the first attempt before anything runs: the rule would retry it.
    rig.gpu.state().create_refused = true;
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");

    let asked = host.asked(SlotName::After);
    assert_eq!(asked.len(), 1);
    assert_eq!(
        asked[0].options,
        vec![
            "retry_now".to_owned(),
            "retry_at".to_owned(),
            "give_up".to_owned()
        ]
    );
    assert_eq!(asked[0].facts["rule_pick"]["pick"], json!("retry_at"));
    let stored = rig.stored(&order);
    assert_eq!(
        stored.state,
        OrderState::GivenUp {
            why: GiveUpWhy::Ended {
                end: EndKind::NeverStarted
            }
        }
    );
    let end = stored.attempts[0].end.as_ref().expect("the attempt's end");
    assert_eq!(end.after.pick, "give_up");
    assert!(matches!(
        &end.after.by,
        DecidedBy::Grant { grant: by, .. } if *by == grant
    ));
    // Nothing starts again.
    rig.vault
        .work_order_pass(&host, NOW + 120_000)
        .expect("pass");
    assert_eq!(rig.stored(&order).attempts.len(), 1);
    assert_eq!(rig.gpu.state().creates.len(), 1);
}

#[test]
fn only_a_decider_waits_while_a_machine_fits() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(PLACE_WAIT),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    let stored = rig.stored(&order);
    assert!(stored.attempts.is_empty(), "nothing starts while it waits");
    assert_eq!(
        blockers(&stored),
        vec![Blocker::DeciderWait {
            decider: grant.to_hex(),
            until_ms: NOW + PLACE_WAIT_REASK_MS_DEFAULT,
        }]
    );
    assert!(rig.vault.gpu_jobs().expect("jobs read").is_empty());

    // An order that may not wait is never offered the wait.
    let now_only = rig.order(&digest, 0, WaitRule::No, OrderClass::Normal);
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(&high.to_hex()),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let offered: Vec<Vec<String>> = host
        .asked(SlotName::Place)
        .into_iter()
        .map(|ask| ask.options)
        .collect();
    assert!(offered.contains(&vec![low.to_hex(), high.to_hex()]));
    assert_eq!(rig.stored(&now_only).attempts[0].machine, Some(high));
}

#[test]
fn a_decider_that_waits_is_asked_again_only_once_its_wait_ends() {
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let order = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    let grant = rig.decider();
    rig.name_decider("place", grant);
    let host = TestHost::new(
        &rig,
        vec![machine(low, None), machine(high, None)],
        answers(PLACE_WAIT),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");
    let held = vec![Blocker::DeciderWait {
        decider: grant.to_hex(),
        until_ms: NOW + PLACE_WAIT_REASK_MS_DEFAULT,
    }];
    assert_eq!(blockers(&rig.stored(&order)), held);

    // Inside the wait the order is held with no ask, so it spends none of the hour's ceiling.
    rig.vault
        .work_order_pass(&host, NOW + PLACE_WAIT_REASK_MS_DEFAULT - 1)
        .expect("pass");
    assert_eq!(host.asked(SlotName::Place).len(), 1);
    assert_eq!(blockers(&rig.stored(&order)), held);

    // Once it ends, the loop places the order again and asks again; the owner's
    // policy.slots.wait_reask_ms sets the next wait.
    rig.set_slot("policy.slots.wait_reask_ms", "place", json!(5_000));
    let again = NOW + PLACE_WAIT_REASK_MS_DEFAULT;
    rig.vault.work_order_pass(&host, again).expect("pass");
    assert_eq!(host.asked(SlotName::Place).len(), 2);
    let stored = rig.stored(&order);
    assert_eq!(
        blockers(&stored),
        vec![Blocker::DeciderWait {
            decider: grant.to_hex(),
            until_ms: again + 5_000,
        }]
    );
    assert!(
        matches!(stored.state, OrderState::Open { earliest_ms: Some(ms), .. } if ms == again + 5_000),
        "the open state says when the wait ends: {:?}",
        stored.state
    );
    assert!(stored.attempts.is_empty());
}

#[test]
fn the_orders_after_a_rank_pick_keep_the_rule_s_own_decisions() {
    let rig = rig();
    let free = EntityId::now();
    let digest = rig.workload(0, &[free]);
    // The rule ranks interactive, normal, background; the decider picks background.
    let background = rig.order(&digest, 0, WaitRule::No, OrderClass::Background);
    let normal = rig.order(&digest, 0, WaitRule::No, OrderClass::Normal);
    let interactive = rig.order(&digest, 0, WaitRule::No, OrderClass::Interactive);
    let grant = rig.decider();
    rig.name_decider("rank", grant);
    let host = TestHost::new(
        &rig,
        vec![machine(free, None)],
        answers(&background.id.to_hex()),
    );
    rig.vault.work_order_pass(&host, NOW).expect("pass");

    let rule_order: Vec<String> = [&interactive, &normal, &background]
        .iter()
        .map(|order| order.id.to_hex())
        .collect();
    assert_eq!(host.asked(SlotName::Rank)[0].options, rule_order);
    let ranked = |order: &WorkOrder| rig.stored(order).attempts[0].ranked.clone();
    assert!(matches!(
        ranked(&background).by,
        DecidedBy::Grant { grant: by, .. } if by == grant
    ));
    // Each other order keeps the rule's own decision about it: its place in the rule's order
    // and the rule's why, not a place in the order the decider's pick made.
    for (order, why) in [
        (
            &interactive,
            "first by class, then the fewest running in its family, then the oldest",
        ),
        (&normal, "place 2 by class, running in its family, then age"),
    ] {
        let decision = ranked(order);
        assert_eq!(decision.pick, order.id.to_hex());
        assert_eq!(decision.why, why);
        assert_eq!(decision.options, rule_order);
        assert_eq!(
            decision.by,
            DecidedBy::Rule {
                name: RANK_RULE.to_owned()
            }
        );
    }
}

#[test]
fn a_pass_waits_about_one_deadline_on_its_deciders() {
    const DEADLINE_MS: u64 = 500;
    let rig = rig();
    let (low, high) = two_machines();
    let digest = rig.workload(0, &[low, high]);
    let facts = vec![machine(low, None), machine(high, None)];
    // An order whose first attempt the provider refused before anything ran: the next pass
    // settles its end, and the rule retries it.
    let retried = rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal);
    rig.gpu.state().create_refused = true;
    let quiet = TestHost::new(&rig, facts.clone(), never());
    rig.vault.work_order_pass(&quiet, NOW).expect("pass");
    assert_eq!(
        rig.stored(&retried).attempts.len(),
        1,
        "FIXTURE: one attempt"
    );
    // Three runnable orders, each with two machines and the wait to pick from.
    let runnable: Vec<WorkOrder> = (0..3)
        .map(|_| rig.order(&digest, 0, WaitRule::Open, OrderClass::Normal))
        .collect();
    let grant = rig.decider();
    for slot in ["rank", "place", "after"] {
        rig.name_decider(slot, grant);
        rig.set_slot("policy.slots.deadline_ms", slot, json!(DEADLINE_MS));
    }
    let host = TestHost::new(&rig, facts, slow());
    // testkit-lint: allow(wall-clock) measures the pass against the real-time ask budget
    let started = Instant::now();
    rig.vault.work_order_pass(&host, NOW + 1_000).expect("pass");
    let took = started.elapsed();

    // AFTER, RANK and three PLACEs name the slow decider; only the pass's first ask is made.
    assert_eq!(
        host.asks.borrow().len(),
        1,
        "one ask: the one that spent the budget"
    );
    assert_eq!(host.asked(SlotName::After).len(), 1);
    assert!(
        took < Duration::from_millis(DEADLINE_MS + 1_500),
        "the pass took {took:?}, past one deadline and a margin"
    );
    let end = rig.stored(&retried).attempts[0]
        .end
        .clone()
        .expect("the attempt's end");
    assert!(
        matches!(
            end.after.by,
            DecidedBy::RuleKept {
                miss: DeciderMiss::Silent,
                ..
            }
        ),
        "{:?}",
        end.after.by
    );
    // The later slots keep the rule's pick, recorded as a ceiling miss: each order starts on the
    // rule's machine, and the first in the rule's order keeps its rank as the rule had it.
    let kept = |name: &str| DecidedBy::RuleKept {
        name: name.to_owned(),
        decider: grant,
        miss: DeciderMiss::Ceiling,
        receipt: None,
    };
    let mut rank_kept = 0;
    for order in &runnable {
        let stored = rig.stored(order);
        let attempt = &stored.attempts[0];
        assert_eq!(attempt.machine, Some(low));
        assert_eq!(attempt.placed.by, kept(PLACE_RULE));
        if attempt.ranked.by == kept(RANK_RULE) {
            rank_kept += 1;
        } else {
            assert_eq!(
                attempt.ranked.by,
                DecidedBy::Rule {
                    name: RANK_RULE.to_owned()
                }
            );
        }
    }
    assert_eq!(
        rank_kept, 1,
        "the rank slot's one decision is kept on the first order"
    );
}

#[test]
fn the_ask_window_refuses_past_its_hourly_ceiling() {
    let mut window = SlotAskWindow::default();
    let (decider, other) = (EntityId::now(), EntityId::now());
    assert!(window.admit(SlotName::Place, decider, 2, NOW));
    assert!(window.admit(SlotName::Place, decider, 2, NOW + 1));
    assert!(
        !window.admit(SlotName::Place, decider, 2, NOW + 2),
        "a third ask in the hour is refused"
    );
    // Each slot and each decider counts apart.
    assert!(window.admit(SlotName::Rank, decider, 2, NOW + 3));
    assert!(window.admit(SlotName::Place, other, 2, NOW + 4));
    // The next hour opens a new window.
    let next_hour = (NOW / 3_600_000 + 1) * 3_600_000;
    assert!(window.admit(SlotName::Place, decider, 2, next_hour));
    // A ceiling of 0 never asks.
    assert!(!window.admit(SlotName::After, decider, 0, NOW));
}
