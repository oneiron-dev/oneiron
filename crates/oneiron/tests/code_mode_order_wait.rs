//! A real QuickJS guest parks on its agent's work order. Ending the fake
//! provider's job settles the wait; re-entering the same run finishes with
//! the terminal order and its first attempt's signed receipt.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test code_mode_order_wait`
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use base64::Engine as _;
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::code_run::{
    CodeRunDeterminism, GatedActorWrite, SelfDurableWaitReason, SelfEffect, read_host_output,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::{
    AtMaximum, GpuConnectorError, GpuJob, GpuJobActor, GpuJobConnector, GpuJobPermits,
    GpuJobRequest, GpuJobSignal, GpuJobSpec, GpuJobStart, GpuOffer, GpuResourceRef,
    GpuResourceStatus, GpuTermination, PriceShape,
};
use oneiron::job_dispatch::JobObservation;
use oneiron::job_workload::{NetworkMode, ResourceRequest, ScopeKind, WorkloadPin};
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration,
};
use oneiron::test_doors::code_run_answer::install_actor_ceiling;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::summarize_note_set::observation_text;
use oneiron::test_doors::work_order::{put_approved_workload, settled_order_wait};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::work_order::{
    AttemptOutcome, AttemptToMake, MachineFacts, MachineReach, OrderCharge, OrderClass, OrderHost,
    OrderState, OrderedBy, Room, TemplateFact, WaitRule, WaitUntil, WorkOrder, WorkOrderRequest,
    order_wait_id, order_work_as,
};
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000_000;
const MAX_SECS: u64 = 600;
const TEMPLATE: &str = "open-models";
const TEMPLATE_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OFFER: &str = "fixture-machines";
const RECEIPT: &[u8] = b"signed receipt fixture";

#[derive(Default)]
struct FakeGpu {
    exited: AtomicBool,
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        Ok(GpuResourceRef(format!("resource-{key}")))
    }

    fn find(&self, _: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        Ok(None)
    }

    fn status(&self, _: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        Ok(if self.exited.load(Ordering::SeqCst) {
            GpuResourceStatus::Exited { used_secs: 7 }
        } else {
            GpuResourceStatus::Running {
                used_secs: 1,
                checkpoint: None,
            }
        })
    }

    fn signal(&self, _: &GpuResourceRef, _: GpuJobSignal) -> Result<(), GpuConnectorError> {
        Ok(())
    }

    fn terminate(&self, _: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        Ok(GpuTermination::Confirmed { billed_secs: 0 })
    }
}

struct TestHost<'a> {
    vault: &'a Vault,
    facts: MachineFacts,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
    admission: RefCell<Option<RunAdmission>>,
}

impl TestHost<'_> {
    fn step(&self, job: &EntityId, now_ms: u64) {
        let admission = self.admission.borrow();
        self.vault
            .gpu_job_step(
                job,
                &self.offer,
                admission.as_ref().expect("the job's run admission"),
                &self.permits,
                &self.gpu,
                now_ms,
            )
            .expect("step the job");
    }
}

impl OrderHost for TestHost<'_> {
    fn machine_facts(&self, machines: &[EntityId]) -> Vec<MachineFacts> {
        assert_eq!(machines, &[self.facts.machine]);
        vec![self.facts.clone()]
    }

    fn make_attempt(&self, attempt: &AttemptToMake<'_>) -> AttemptOutcome {
        let quote = self
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: TEMPLATE.to_owned(),
                    image: attempt.order.workload.clone(),
                    maximum_secs: Some(MAX_SECS),
                    inputs: json!({ "machine": attempt.machine.to_hex() }),
                },
                Some(attempt.job),
                MAX_SECS,
                NOW,
            )
            .expect("quote the attempt");
        let admission = RunAdmission::new(
            GpuJob::admission_ref_of(&attempt.job),
            RunDeclaration::declared(BudgetLine {
                limit_units: 1_000_000,
                reserve_units: 1_000_000,
                unit: self.offer.connector.cost_unit.clone(),
            })
            .with_connector(OFFER.to_owned()),
            None,
            Arc::new(MemoryReceipts::default()),
        );
        self.vault
            .start_gpu_job(
                GpuJobStart {
                    actor: GpuJobActor::Order(&attempt.reference()),
                    offer: &self.offer,
                    quote: &quote,
                    resume: None,
                    admission: &admission,
                },
                &self.permits,
                &self.gpu,
                NOW,
            )
            .expect("start the ordered job");
        assert!(
            self.admission.replace(Some(admission)).is_none(),
            "only one attempt"
        );
        AttemptOutcome::Made
    }

    fn stop_attempt(&self, _: &WorkOrder, _: &EntityId) -> Result<(), String> {
        panic!("the order should end through its provider, not a cancel")
    }
}

fn order_fixture(vault: &Vault) -> (EntityId, WorkOrder, TestHost<'_>) {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("enroll the install");
    let (owner, proof) = embedded_owner(vault).expect("embedded owner proof for the mint");
    let agent = vault
        .ensure_agent_principal("order-wait-fixture")
        .expect("named agent");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(
        [
            "read",
            "vault.jobs.order",
            "vault.gpu.jobs.start",
            "vault.jobs.orders.wait",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    );
    let grant = mint_agent_grant_as(
        vault,
        &proof,
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
    assert!(grant.confers);
    vault
        .allow_gpu_jobs(&proof, &grant.grant_ref, MAX_SECS, NOW)
        .expect("set the Grant's per-job maximum")
        .expect("allowance row");
    install_actor_ceiling(vault, &agent, "auto").expect("auto ceiling for code mode");

    let machine = EntityId::now();
    let workload = put_approved_workload(
        vault,
        WorkloadPin {
            template: TEMPLATE.to_owned(),
            template_digest: TEMPLATE_DIGEST.to_owned(),
            commit: "a".repeat(40),
            contract_sha256: "b".repeat(64),
            contract_path: "contracts/arm.json".to_owned(),
            entry: "tools/units/run_arm.sh".to_owned(),
            args: Vec::new(),
            request: ResourceRequest {
                cpu_threads: 0,
                memory_mib: 8_192,
                disk_mib: 1_024,
                devices: Vec::new(),
                maximum_secs: MAX_SECS,
            },
            scope: ScopeKind::Host,
            network: NetworkMode::None,
            outputs: Vec::new(),
        },
        owner,
        vec![machine],
        vec![grant.grant_ref],
        NOW + 86_400_000,
        NOW,
    );
    let order = order_work_as(
        &vault.memory(agent, EdgeActorClass::Agent),
        None,
        &WorkOrderRequest {
            workload,
            charge: OrderCharge::Offer {
                name: OFFER.to_owned(),
            },
            limits: Default::default(),
            wishes: Default::default(),
            class: OrderClass::Normal,
            wait: WaitRule::Open,
            retry_on: Vec::new(),
            result: None,
            intent_key: None,
            after: None,
            group: None,
        },
        NOW,
    )
    .expect("the agent orders the approved workload")
    .order;
    assert_eq!(
        order.ordered_by,
        OrderedBy::Agent {
            actor: Some(agent),
            class: EdgeActorClass::Agent,
            grant: grant.grant_ref,
        }
    );
    let host = TestHost {
        vault,
        facts: MachineFacts {
            machine,
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
        },
        offer: GpuOffer {
            name: OFFER.to_owned(),
            class: "machine".to_owned(),
            provider: "vault-machines".to_owned(),
            region: "home".to_owned(),
            connector: PaidConnector {
                connector: OFFER.to_owned(),
                route: OfferRoute::new(OFFER, "https://machines.example.com").expect("offer route"),
                locality: ModelLocality::ThirdParty,
                payer: Payer::Local,
                credential_binding: None,
                catalog_revision: Some("machines-1".to_owned()),
                custody: KeyCustody::T0,
                unit_cost: 1,
                cost_unit: LeaseUnit::new("credit-micros").expect("offer unit"),
                rates: Vec::new(),
            },
            price_shape: PriceShape::AtOneironList,
            list_cost_per_second: None,
            startup_secs: 0,
            teardown_secs: 0,
            rounding_secs: 0,
            at_maximum: AtMaximum::Stop,
        },
        gpu: FakeGpu::default(),
        permits: GpuJobPermits::new(),
        admission: RefCell::new(None),
    };
    (agent, order, host)
}

struct ScriptedModel {
    program: String,
    calls: AtomicUsize,
}

impl LlmBackend for ScriptedModel {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: self.program.clone(),
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn quickjs_factory() -> QuickJsRuntimeFactory {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm"))
        .expect("pinned QuickJS component");
    QuickJsRuntimeFactory::from_component(
        &bytes,
        Sha256::digest(&bytes).into(),
        ComponentBudget::default(),
    )
    .expect("QuickJS readiness probe")
}

#[test]
fn a_code_mode_run_parks_on_an_order_and_resumes_with_its_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(NOW / 1_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("open the vault");
    let (agent, order, host) = order_fixture(&vault);
    vault
        .work_order_pass(&host, NOW)
        .expect("place and start the order");
    let stored = vault
        .work_order(&order.id)
        .expect("read order")
        .expect("order row");
    assert_eq!(stored.state, OrderState::Running { attempt: 1 });
    let job_id = stored.attempts[0].job;
    let job = vault.gpu_job(&job_id).expect("read job").expect("job row");
    vault
        .put_job_observation(&JobObservation {
            key: job.chunk().expect("live chunk").idempotency_key.clone(),
            machine: host.facts.machine,
            device_id: None,
            receipt: RECEIPT.to_vec(),
            epoch: "fixture".to_owned(),
            seq: 1,
            last_measured_secs: Some(1),
            observed_at_ms: NOW + 1_000,
            end_seen: None,
            meter: None,
            terminal: None,
            started: true,
        })
        .expect("write the attempt's receipt");

    let factory = quickjs_factory();
    let backend = ScriptedModel {
        program: format!(
            r#"const answer = await vault.jobs.orders.wait({{order:"{}"}}); finish(JSON.stringify(answer));"#,
            order.id.to_hex(),
        ),
        calls: AtomicUsize::new(0),
    };
    let run_id = EntityId::now();
    let config = EngineExecutorConfig {
        run_id,
        task: "Wait for the order and return its receipt".to_owned(),
        caller_source_digest: None,
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("test prompt package"),
        model: ModelId::new("test/executor@v1").expect("fixture model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(NOW, [0xAB; 32]),
        limits: EngineExecutorLimits::default(),
        wake: None,
    };
    let lease = BudgetLease::for_test("code-mode-order-wait");
    let execute = || -> EngineExecutorOutcome {
        let gated = GatedActorWrite::new(
            &vault,
            WriteActor::new(agent, EdgeActorClass::Agent),
            run_id.to_hex(),
        )
        .expect("bind the run to the ordering agent");
        let mut runtime = factory.runtime().expect("fresh QuickJS guest");
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
        block_on_ready(executor.run(&config)).expect("execute the run")
    };
    let first = execute();
    let EngineExecutorStatus::Waiting(wait) = &first.status else {
        panic!("expected an order wait, got {:?}", first.status);
    };
    assert_eq!(
        wait.wait_id,
        order_wait_id(&order.id, WaitUntil::Terminal).expect("terminal wait id")
    );
    assert_eq!(wait.effect, SelfEffect::JobsOrdersWait);
    assert_eq!(wait.reason, SelfDurableWaitReason::PeerResult);
    // GAP: The fresh-run executor gets its initial program from the scripted
    // model. Re-entry while the wait is outstanding must ask it nothing.
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "only the program turn"
    );
    assert_eq!(execute().status, first.status);
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "no model turn while parked"
    );

    host.gpu.exited.store(true, Ordering::SeqCst);
    host.step(&job_id, NOW + 7_000);
    vault
        .work_order_pass(&host, NOW + 8_000)
        .expect("end the order and settle its wait");
    let settled =
        settled_order_wait(&vault, &order.id, WaitUntil::Terminal).expect("terminal wait settled");

    let resumed = execute();
    assert_eq!(resumed.status, EngineExecutorStatus::Complete);
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        2,
        "one program turn after delivery"
    );
    let binding = resumed
        .replay_record
        .bindings
        .iter()
        .find(|b| b.name == "wait0")
        .expect("parked step's delivered answer");
    let bytes = read_host_output(&vault, run_id, &binding.path)
        .expect("read the delivered reply")
        .expect("stored delivery");
    let delivery: Value = serde_json::from_slice(&bytes).expect("delivery JSON");
    assert_eq!(delivery["reply"], settled);
    let text = observation_text(&vault, &run_id, 1).expect("resumed step's finish output");
    let answer: Value = serde_json::from_str(&text).expect("finish output JSON");
    assert_eq!(answer, settled);
    assert_eq!(answer["reached"], true);
    assert_eq!(answer["view"]["order"]["state"]["kind"], "done");
    assert_eq!(
        answer["view"]["receipt"]["signed"],
        base64::engine::general_purpose::STANDARD.encode(RECEIPT)
    );
    assert_eq!(answer["view"]["receipt"]["attempt"], 1);
}
