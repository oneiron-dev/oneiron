//! Census L9-37 PR 2 (ARCH-0051 #decision-r9-bench: "The typed verbs are the
//! seeded default and the mount is one arm the bandit may pick per model"):
//! a pumped resident run picks the shape it reads memory through when it
//! wakes, for the model its settled config runs on, stamps its attempt with
//! it before any pack loads, and its self brief, on the run's first model
//! request, names that shape.
//!
//! The server is the one `serve` builds for a vault with code mode on (the
//! checked-in QuickJS component, the fixture prompt package, a local fake
//! model that answers every call with a 500), and the test door starts its
//! pump as `serve` does, as `resident_pump_claim_latency` does. The owner
//! pins the exploration share: at 0 a model with no evidence reads through
//! the seeded verbs; at 1 the exploration share sends it to the mount.
//!
//! On the PR 1 head both tests fail: the wake stamps nothing, and the brief
//! carries no read shape.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! resident_wake_read_shape`.
#![cfg(oneiron_test_support)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fake_llm::{FakeLlm, Reply};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::authority::MachineRole;
use oneiron::edge::EdgeActorClass;
use oneiron::learning_setting::{SettingMode, SettingRow, put_setting_row};
use oneiron::store::read_shape_policy::READ_SHAPE_EXPLORE_SHARE;
use oneiron::store::{ReadShape, ReadShapeStamp, ReadShapeTier};
use oneiron::write_envelope::WriteActor;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::test_doors::resident_pump::spawn_resident_pump;
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, server::SyncServer};
use serde_json::Value;

/// How long the pump may take to claim, wake and stamp the run.
const STAMP_CAP: Duration = Duration::from_secs(60);
/// How long the woken run may take to send its first model request.
const REQUEST_CAP: Duration = Duration::from_secs(60);
/// How often the run's rows and the fake's requests are read.
const POLL: Duration = Duration::from_millis(20);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

/// Code mode on, the Dreamer and the workflow pump off, and the type check
/// off, as `resident_pump_claim_latency` runs it.
fn models_text(base_url: &str) -> String {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n[code_mode.check]\nmode = \"off\"\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n",
        prompts = prompts.display().to_string(),
    )
}

/// Runs `test` on an engine-sized stack and runtime. The woken run goes on
/// on its own thread after the test's last read, so the runtime's shutdown
/// does not wait for it.
fn on_engine_stack<F, Fut>(name: &str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime");
            runtime.block_on(test());
            runtime.shutdown_timeout(Duration::from_secs(10));
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

/// The owner pins the share of wakes the exploration share sends to the
/// mount while a model has too little mount evidence.
fn pin_explore_share(vault: &Vault, value: f64) {
    let owner = WriteActor::new(
        vault.ensure_embedded_owner_actor().expect("owner"),
        EdgeActorClass::Human,
    );
    put_setting_row(
        vault,
        &owner,
        &SettingRow {
            key: READ_SHAPE_EXPLORE_SHARE.key.to_owned(),
            mode: SettingMode::Pin,
            value,
            weight_runs: None,
            at: 10,
            why: "the test fixes the exploration share".to_owned(),
        },
    )
    .expect("the owner's pin on the exploration share");
}

/// Polls until the run's attempt holds a read-shape stamp.
async fn stamp_of(vault: &Vault, id: AttemptId) -> ReadShapeStamp {
    let start = Instant::now();
    loop {
        if let Some(stamp) = vault.read_shape_stamp(id).expect("read the stamp") {
            return stamp;
        }
        if start.elapsed() > STAMP_CAP {
            let row = AttemptQueue::new(vault)
                .get(id)
                .expect("read the run's attempt")
                .expect("the run's attempt exists");
            panic!(
                "the run's wake stamped no read shape within {STAMP_CAP:?}; its attempt is {:?}",
                row.state
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Every string a request body holds, its messages' text among them.
fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| strings(item, out)),
        Value::Object(fields) => fields.values().for_each(|field| strings(field, out)),
        _ => {}
    }
}

/// Polls until the fake has a request carrying the run's self brief, and
/// answers that brief's text.
async fn first_brief(model: &FakeLlm) -> String {
    let start = Instant::now();
    loop {
        for seen in model.seen() {
            let mut texts = Vec::new();
            strings(&seen.body, &mut texts);
            if let Some(brief) = texts.into_iter().find(|text| text.contains("<identity>")) {
                return brief;
            }
        }
        assert!(
            start.elapsed() < REQUEST_CAP,
            "the run sent no request carrying its self brief within {REQUEST_CAP:?}; the fake saw {} requests",
            model.seen().len()
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Serves a vault whose owner pinned the exploration share to
/// `explore_share`, dispatches the seeded default agent to its pump, and
/// answers the run's stamp, its attempt's executor model and its first
/// brief.
async fn wake_one_run(explore_share: f64) -> (ReadShapeStamp, Option<String>, String) {
    let model = FakeLlm::start(Vec::new(), Some(Reply::Status(500))).await;
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in BEFORE the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("resident-wake-read-shape".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let _owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    pin_explore_share(&vault, explore_share);
    let models =
        ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
    let (server, host) = AiHost::attach(server, Some(&models)).await;
    let server = Arc::new(server);
    let pump = spawn_resident_pump(&server)
        .expect("code mode binds an engine-native code host, so the pump starts");

    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("read the seeded agents")
        .expect("the default agent is seeded");
    let dispatched = AgentDispatcher::new(&vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some("resident-wake-read-shape".to_owned()),
                now: unix_now(),
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )
        .expect("dispatch the default agent");
    let AgentDispatchOutcome::Dispatched(status) = dispatched else {
        panic!("the dispatch queues one fresh run");
    };
    let stamp = stamp_of(&vault, status.attempt.id).await;
    let brief = first_brief(&model).await;
    let executor_model = AttemptQueue::new(&vault)
        .get(status.attempt.id)
        .expect("read the run's attempt")
        .expect("the run's attempt exists")
        .executor_model;

    pump.abort();
    host.shutdown().await;
    (stamp, executor_model, brief)
}

#[test]
fn a_wake_with_no_mount_evidence_reads_through_the_seeded_verbs() {
    on_engine_stack("resident-wake-read-shape-verbs", || async {
        let (stamp, executor_model, brief) = wake_one_run(0.0).await;
        assert_eq!(stamp.shape, ReadShape::Verbs, "{stamp:?}");
        assert_eq!(stamp.tier, ReadShapeTier::Seed, "{stamp:?}");
        if let Some(executor_model) = executor_model {
            assert_eq!(
                stamp.model.as_str(),
                executor_model,
                "the pick is for the model the run's executor stamp names"
            );
        }
        assert!(
            brief.contains(
                r#""read_shape":{"shape":"verbs","read_through":"read memory through the typed memory verbs"#
            ),
            "the run's first brief names the verbs: {brief}"
        );
    });
}

#[test]
fn a_wake_the_exploration_share_sends_to_the_mount_reads_through_it() {
    on_engine_stack("resident-wake-read-shape-mount", || async {
        let (stamp, executor_model, brief) = wake_one_run(1.0).await;
        assert_eq!(stamp.shape, ReadShape::Mount, "{stamp:?}");
        assert_eq!(stamp.tier, ReadShapeTier::Explore, "{stamp:?}");
        if let Some(executor_model) = executor_model {
            assert_eq!(stamp.model.as_str(), executor_model);
        }
        assert!(
            brief.contains(
                r#""read_shape":{"shape":"mount","read_through":"read memory through the graph_fs mount at / with graph_fs.ls"#
            ),
            "the run's first brief names the mount: {brief}"
        );
    });
}
