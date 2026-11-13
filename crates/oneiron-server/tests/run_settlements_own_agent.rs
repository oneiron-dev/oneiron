#![cfg(oneiron_test_support)]
//! RUN-SETTLEMENTS-OWN-AGENT-READ: `vault.budgets.settlements` over the
//! facade. The owner reads every settlement of a served run; an agent on a
//! verified slip of its own reads the run's settlements stamped with its own
//! agent id, and a person, whom no settlement names, reads none.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test run_settlements_own_agent`.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::agent_dispatch::DEFAULT_BASE_LOGICAL_ID;
use oneiron::agent_dispatch::budget_doors::{
    RunSettlementsRequest, RunSettlementsView, UsageEventOrigin,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::run_admission::Payer;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::usage::{
    UsageEvent, UsageEventType, UsageLedger, UsageMode, UsageRun, UsageTokenCounts,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const VERB_PATH: &str = "/v1/core/facade/vault.budgets.settlements";
/// The served run whose settlements are read.
const RUN: &str = "served-run-settlements";
/// Another served run, whose settlement no read of `RUN` serves.
const OTHER_RUN: &str = "served-run-elsewhere";
/// A second seeded agent definition, beside the default one.
const SECOND_AGENT_LOGICAL_ID: &str = "sys.scout";

/// Who signs a request: the self-hosted root (the owner), or a holder key.
enum Caller<'a> {
    Owner,
    Holder(&'a CapabilitySlip, &'a SigningKey),
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    first_agent: EntityId,
    second_agent: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A metered server whose ledger holds four engine settlements: on `RUN`
    /// one stamped with each agent and one unbound, on `OTHER_RUN` one
    /// stamped with the first agent.
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let (first_agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or("the default agent is seeded")?;
        let (second_agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(SECOND_AGENT_LOGICAL_ID)?
            .ok_or("a second agent is seeded")?;
        let server = SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("run-settlements-own-agent".into()),
                ..Default::default()
            },
        )?
        .with_usage_metering("billing-owner")?;
        let usage = server.vault_usage().ok_or("the server meters its usage")?;
        let ledger = UsageLedger::new(vault.clone());
        for (call, run, agent) in [
            ("first-agent-call", RUN, Some(first_agent)),
            ("second-agent-call", RUN, Some(second_agent)),
            ("unbound-call", RUN, None),
            ("first-agent-elsewhere", OTHER_RUN, Some(first_agent)),
        ] {
            let event = settled_call(usage.owner(), usage.vault_id(), call, run, agent);
            let recorded =
                ledger.record_event(event, UsageMode::Local, UsageEventOrigin::Engine)?;
            assert!(recorded.recorded, "the ledger records {call}");
        }
        Ok(Self {
            app: build_app(Arc::new(server)),
            vault,
            issuer,
            root,
            first_agent,
            second_agent,
            _dir: dir,
        })
    }

    /// An unrestricted `core:read` slip of `holder`, an actor of `class`.
    fn slip(
        &self,
        holder: EntityId,
        class: &str,
        seed: u8,
    ) -> TestResult<(CapabilitySlip, SigningKey)> {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [seed; 32];
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        Ok((self.vault.mint_capability_slip(&self.issuer, claims)?, key))
    }

    /// A person of the vault on a slip of its own: no owner, and no
    /// settlement names it.
    fn person(&self) -> TestResult<(CapabilitySlip, SigningKey)> {
        let person = EntityId::now();
        self.vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person whom no call served",
        )?;
        self.slip(person, "human", 0x73)
    }

    async fn read(&self, caller: &Caller<'_>, run: &str) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (slip, signature) = match caller {
            Caller::Owner => (
                &self.root,
                self.issuer.binding_proof(&self.root, &challenge)?,
            ),
            Caller::Holder(slip, key) => (
                *slip,
                key.sign(&slip.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let input = serde_json::to_value(RunSettlementsRequest {
            run: run.to_owned(),
        })?;
        let request = Request::post(VERB_PATH)
            .header("authorization", format!("Bearer {}", slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }
}

/// One engine settlement of a physical service call on `run`, stamped with
/// `agent` when the run was bound to one.
fn settled_call(
    owner: &str,
    vault_id: &str,
    call: &str,
    run: &str,
    agent: Option<EntityId>,
) -> UsageEvent {
    UsageEvent {
        owner: owner.to_owned(),
        vault_id: vault_id.to_owned(),
        idempotency_key: format!("run:{call}"),
        source: Some(UsageMode::Local),
        event_type: UsageEventType::Service,
        role: None,
        occurred_at: Some(1),
        agent_id: agent.map(|agent| agent.to_hex()),
        model: None,
        service: Some("search".to_owned()),
        token_counts: UsageTokenCounts::default(),
        cost_rates: None,
        unpriced: None,
        service_amount: 0,
        run: Some(UsageRun {
            instance: EntityId::now().to_hex(),
            run: run.to_owned(),
            revision: 0,
            lease: call.to_owned(),
            offer: "search-offer".to_owned(),
            route: "search-route".to_owned(),
            catalog_revision: None,
            payer: Payer::Host,
            payer_person: None,
            payer_scope: None,
            payer_ask: None,
            purpose: None,
            cycle: None,
            item: None,
            spend_scope: None,
            reserved_units: 10,
            settled_units: 7,
            unit: "units".to_owned(),
            usage_reported: true,
            service_quantity: None,
            service_cost: None,
            allocation: None,
            settlement_refused: false,
        }),
    }
}

/// The served read's settlements, by the agent each names, in the order
/// served, after the view's own run and metering are checked.
fn served_agents(body: Value) -> TestResult<Vec<Option<String>>> {
    let view: RunSettlementsView = serde_json::from_value(body)?;
    assert_eq!(view.run, RUN, "the view names the run it read");
    assert!(view.metering_enabled, "the server meters its usage");
    Ok(view
        .settlements
        .into_iter()
        .map(|settlement| {
            assert_eq!(
                settlement.run, RUN,
                "a settlement of another run was served"
            );
            settlement.agent
        })
        .collect())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too. The generated facade dispatch's poll frame does not fit a test
/// thread's default stack (`ENGINE_THREAD_STACK_BYTES`).
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn the_owner_reads_every_settlement_of_a_served_run() -> TestResult {
    on_engine_stack(owner_reads_every_settlement)
}

async fn owner_reads_every_settlement() -> TestResult {
    let fixture = Fixture::new()?;
    let (status, body) = fixture.read(&Caller::Owner, RUN).await?;
    assert_eq!(status, 200, "the owner reads the run's settlements: {body}");
    let mut agents = served_agents(body)?;
    agents.sort();
    let mut expected = vec![
        Some(fixture.first_agent.to_hex()),
        Some(fixture.second_agent.to_hex()),
        None,
    ];
    expected.sort();
    assert_eq!(
        agents, expected,
        "the owner reads each settlement of the run"
    );
    Ok(())
}

#[test]
fn an_agent_reads_only_the_settlements_stamped_with_its_own_id() -> TestResult {
    on_engine_stack(agents_read_their_own_settlements)
}

async fn agents_read_their_own_settlements() -> TestResult {
    let fixture = Fixture::new()?;
    for (agent, seed) in [(fixture.first_agent, 0x71), (fixture.second_agent, 0x72)] {
        let (slip, key) = fixture.slip(agent, "agent", seed)?;
        let (status, body) = fixture.read(&Caller::Holder(&slip, &key), RUN).await?;
        assert_eq!(
            status, 200,
            "an agent reads its own settlements of the run: {body}"
        );
        assert_eq!(
            served_agents(body)?,
            vec![Some(agent.to_hex())],
            "an agent reads the run's settlements stamped with its own id, and no other"
        );
    }
    Ok(())
}

#[test]
fn a_person_whom_no_settlement_names_reads_none() -> TestResult {
    on_engine_stack(person_reads_no_settlement)
}

async fn person_reads_no_settlement() -> TestResult {
    let fixture = Fixture::new()?;
    let (slip, key) = fixture.person()?;
    let (status, body) = fixture.read(&Caller::Holder(&slip, &key), RUN).await?;
    assert_eq!(
        status, 200,
        "a person on its own slip reads the run: {body}"
    );
    assert_eq!(
        served_agents(body)?,
        Vec::<Option<String>>::new(),
        "a person reads no settlement of the run"
    );
    Ok(())
}
