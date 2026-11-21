//! FIX 4208: a workflow step whose attempt carries a dialed landing reserve
//! meters its ordinary calls on the dial less the reserve, so no ordinary
//! call reaches the slice kept for its landing.
//!
//! * `a_dialed_leaf_holds_before_its_first_paid_call`: one-step workflow,
//!   step budget exactly one reservation (8,000 units), leaf dialed at 8,000
//!   with the default 10% reserve before the pump claims it. The ordinary
//!   limit is 7,200, below the first paid call's reservation: on the head the
//!   step holds at its cap and the provider sees nothing; on main the call
//!   goes out and the workflow completes, so both asserts fail (red).
//! * `an_undialed_leaf_sends_its_first_paid_call`: the same workflow without
//!   a dial sends its call on both main and the head: the fence must not
//!   starve steps that carry no reserve.
//!
//! Public doors plus the `oneiron` test doors only, so the file compiles
//! against main too: red on main is a failed assert, never a compile error.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test workflow_step_landing_reserve`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_def::workflow::WorkflowDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, BudgetHoldState, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState, DialLandingReserve};
use oneiron::authority::MachineRole;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// One paid call's reservation (`oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS`),
/// and the step budget: exactly one reservation, the config minimum.
const RESERVE_UNITS: u64 = oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS;
/// The dial: the whole reservation, so it fits the dial but not the dial
/// less the default 10% reserve.
const DIAL_UNITS: u64 = RESERVE_UNITS;
/// The dial less 10%: what the step's meter must be built with once dialed.
const ORDINARY_UNITS: u64 = DIAL_UNITS - DIAL_UNITS / 10;
/// How long a workflow may take to hold or stop before the test gives up.
const WAIT_CAP: Duration = Duration::from_secs(60);
/// How often the workflow's rows are read while waiting.
const POLL: Duration = Duration::from_millis(50);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

/// One paid model for every seat: provider `paid` is FakeLlm keyed
/// (`key_env`), so its calls are paid work settled against the step's meter;
/// a keyless seat would be free work and prove nothing. The Dreamer stays
/// off; the workflow pump runs with a one-reservation step budget.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"paid:step-model\"\n\
         [dreamer]\nenabled = false\n\
         [workflows]\nenabled = true\nretry_backoff_secs = 0\nstep_budget_units = {RESERVE_UNITS}\n\
         [providers.paid]\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\n\
         key_env = \"HOME\"\nrevision = \"r1\"\nlocality = \"own_server\"\n"
    )
}

/// A custom agent definition the pump can dispatch: the seeded default's
/// shape with its own instructions.
fn saved_agent(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or("the default agent is seeded")?;
    definition.logical_id = None;
    definition.agent_id = format!("test.reserve.{name}");
    definition.instructions = Some("Say one word to yuki@example.com.".to_owned());
    definition.skills.clear();
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// The in-crate `workflow_is_held_for_budget` on public doors only: the
/// root's saved hold is `Held`, names parked attempts, and every parked
/// attempt sits `Paused`.
fn held_for_budget(vault: &Vault, root: AttemptId) -> TestResult<bool> {
    let dispatcher = AgentDispatcher::new(vault);
    let queue = AttemptQueue::new(vault);
    let Some(hold) = dispatcher.plan_hold(root)? else {
        return Ok(false);
    };
    if hold.state != BudgetHoldState::Held || hold.held.is_empty() {
        return Ok(false);
    }
    for held in &hold.held {
        let row = queue
            .get(held.attempt)?
            .ok_or("a held attempt row exists")?;
        if row.state != AttemptState::Paused {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Until the workflow holds at its cap or stops: true when it held, false
/// when its roots drained first (it completed).
async fn wait_done(vault: &Vault, root: AttemptId) -> TestResult<bool> {
    let started = std::time::Instant::now();
    loop {
        if held_for_budget(vault, root)? {
            return Ok(true);
        }
        if AgentDispatcher::new(vault)
            .open_workflow_roots()?
            .is_empty()
        {
            return Ok(false);
        }
        if started.elapsed() >= WAIT_CAP {
            return Err("the workflow neither held at its cap nor stopped within 60 s".into());
        }
        tokio::time::sleep(POLL).await;
    }
}

/// A served vault with one one-step workflow dispatched; the leaf is dialed
/// before the host (and its pump) exists when `dial` is set, so the pump can
/// only ever claim an already-dialed leaf.
struct Fixture {
    vault: Arc<Vault>,
    host: AiHost,
    model: FakeLlm,
    root: AttemptId,
    leaf: AttemptId,
    _server: SyncServer,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new(name: &str, script: Vec<Reply>, dial: bool) -> TestResult<Self> {
        let model = FakeLlm::start(script, None).await;
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _proof) = embedded_owner(&vault)?;
        vault.ensure_host_root_slip(&issuer)?;
        let agent = saved_agent(&vault, name)?;
        let workflow = EntityId::now();
        vault.save_workflow(&workflow, &WorkflowDefinition::new(name, vec![agent])?, 2)?;
        let leaf = match AgentDispatcher::new(&vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some(name.to_owned()),
            run_id: Some(name.to_owned()),
            now: unix_now(),
        })? {
            AgentDispatchOutcome::WorkflowDispatched(status) => status.active_step,
            other => {
                return Err(format!(
                    "a fresh one-step workflow dispatch releases its first leaf, got {other:?}"
                )
                .into());
            }
        };
        let [root] = AgentDispatcher::new(&vault).open_workflow_roots()?[..] else {
            return Err("expected the one dispatched workflow".into());
        };
        if dial {
            let record = AttemptQueue::new(&vault).dial_landing_reserve(DialLandingReserve {
                id: leaf,
                limit_units: DIAL_UNITS,
                reserve_percent: None,
                now: unix_now(),
            })?;
            assert!(
                record.landing_reserve().is_dialed(),
                "the dial marks the leaf's landing reserve before the pump claims it"
            );
            assert_eq!(
                record.ordinary_budget_limit_units(),
                ORDINARY_UNITS,
                "the dialed leaf's ordinary limit is the dial less the default 10% reserve"
            );
        }
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("owen-landing-reserve".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        Ok(Self {
            vault,
            host,
            model,
            root,
            leaf,
            _server: server,
            _dir: dir,
        })
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }
}

#[test]
fn a_dialed_leaf_holds_before_its_first_paid_call() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new("owen", vec![Reply::text("word")], true).await?;
        let held = wait_done(&fixture.vault, fixture.root).await?;
        let seen = fixture.model.seen().len();
        let leaf = AttemptQueue::new(&fixture.vault)
            .get(fixture.leaf)?
            .map(|row| row.state);
        fixture.finish().await;
        assert!(
            held,
            "the dialed leaf holds at its ordinary cap (7,200 units admit no 8,000-unit \
             reservation); leaf state {leaf:?}, provider saw {seen} request(s)"
        );
        assert_eq!(
            seen, 0,
            "no ordinary call reaches the provider once the dial's reserve is fenced"
        );
        Ok(())
    })
}

#[test]
fn an_undialed_leaf_sends_its_first_paid_call() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new("yuki", vec![Reply::text("word")], false).await?;
        let held = wait_done(&fixture.vault, fixture.root).await?;
        let seen = fixture.model.seen().len();
        let leaf = AttemptQueue::new(&fixture.vault)
            .get(fixture.leaf)?
            .map(|row| row.state);
        fixture.finish().await;
        assert!(
            !held,
            "an undialed leaf carries no reserve to fence, so it never holds; \
             leaf state {leaf:?}, provider saw {seen} request(s)"
        );
        assert_eq!(
            seen, 1,
            "the undialed leaf's first paid call goes out on its step budget"
        );
        Ok(())
    })
}
