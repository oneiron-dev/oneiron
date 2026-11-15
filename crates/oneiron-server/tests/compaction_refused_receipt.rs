#![cfg(oneiron_test_support)]
//! FIX 7745: a self-written call refused after it went out keeps its receipt.
//!
//! Test 1 sends the compaction call to a 500 fake. The call went out,
//! so the pass records a refused execution that names the writer and the
//! admitted model. Main drops it, so `self_writer` is missing (RED).
//! Head keeps it, so `self_writer` is present (GREEN).
//!
//! Test 2 caps the compaction purpose to zero. The meter refuses before
//! the send, so no execution is recorded on either tree (guard).
//!
//! Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron-server --test compaction_refused_receipt --features oneiron/test-support`.

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use fake_llm::{FakeLlm, Reply};
use oneiron::llm::{ModelLocality, SelfCompactionSource};
use oneiron::{CompactionOwnership, EntityId, MemoryProfile, ModelTierRef, TimeRange, Vault};
use serde_json::{Value, json};

const SECRET: &str = "compaction-refused-receipt-key";
const WINDOW_TOKENS: u64 = 350_000;
const STEP_TOKENS: u64 = WINDOW_TOKENS / 10;
const SUMMARY_FACT: &str = "yuki keeps the deploy checklist";
const CONTEXT_TOKENS: u64 = 500_000;
const FILLER: &str = "alpha beta gamma delta ";
const CONSOLE_FRAME: &str = "Console after durable step";

/// Saves agent `owen` with a memory profile that names backend `self`.
///
/// It clones the seeded default, so all required fields stay valid.
/// It clears `logical_id`, sets `agent_id` to `test.self.owen`,
/// sets instructions that mention `yuki` and `example.com`,
/// and sets `memory_profile` to a self writer with `window` and `hot_steps`.
/// It returns the new agent id.
///
/// # Errors
///
/// Missing seeded default and vault write errors.
fn save_self_agent(
    vault: &Vault,
    window_token_budget: u64,
    hot_steps: u64,
) -> anyhow::Result<EntityId> {
    let (_, mut definition) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .ok_or_else(|| anyhow::anyhow!("seeded default agent is missing"))?;
    definition.logical_id = None;
    definition.agent_id = "test.self.owen".to_owned();
    definition.instructions =
        Some("Summarize for owen. Keep what yuki needs. Keep example.com verbatim.".to_owned());
    definition.compaction_model = None;
    definition.memory_profile = Some(MemoryProfile {
        window_token_budget,
        budget_split: None,
        compaction_backend: ModelTierRef("self".to_owned()),
        compaction: CompactionOwnership::Engine,
        hot_steps: Some(hot_steps),
        output_decay: None,
        verbatim_pins: vec!["example.com".to_owned()],
    });
    debug_assert!(
        definition
            .memory_profile
            .as_ref()
            .is_some_and(|profile| profile.writes_as_self())
    );
    let id = EntityId::now();
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

/// Sets the self-compaction row to retained turns.
///
/// A retained row forces the cold writer and skips the live fork.
/// The default cheap model is not served in the test, so the writer
/// falls back to the house compaction model.
///
/// # Errors
///
/// Vault read and write errors.
fn retain_self_compaction(vault: &Vault) -> anyhow::Result<()> {
    let mut table = vault.purpose_default_table()?;
    table.self_compaction.source = SelfCompactionSource::RetainedTurns;
    table.self_compaction.locality = ModelLocality::OwnServer;
    vault.set_purpose_default_table(&table)?;
    Ok(())
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn oneiron(args: &[&str], config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
    command
        .args(args)
        .arg("--config")
        .arg(config)
        .env("ONEIRON_AUTH_SECRET", SECRET)
        .env_remove("ONEIRON_VAULT_PATH")
        .env_remove("ONEIRON_URL")
        .env_remove("ONEIRON_SECRET")
        .env_remove("ONEIRON_BINDING_KEY");
    command
}

fn stdout(mut command: Command) -> String {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn content(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect(),
        _ => String::new(),
    }
}

fn answer(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let texts: Vec<String> = messages.iter().map(content).collect();
    if texts
        .first()
        .is_some_and(|system| system.contains("You compact"))
    {
        let input: Value = serde_json::from_str(texts.last().unwrap()).unwrap();
        let mut summary = format!(
            "Steps {} to {} checked example.com; {SUMMARY_FACT}.",
            input["from"], input["through"]
        );
        for pin in input["pins"].as_array().unwrap() {
            summary.push('\n');
            summary.push_str(pin.as_str().unwrap());
        }
        return json!({"from": input["from"], "through": input["through"], "summary": summary})
            .to_string();
    }
    let request = texts.join("\n");
    if request.contains("<compacted") {
        return "finish('done');".to_owned();
    }
    let step = request.matches(CONSOLE_FRAME).count();
    let filler = oneiron::count_context_pack_tokens(FILLER).max(1) as u64;
    let repeats = usize::try_from(STEP_TOKENS / filler + 1).unwrap();
    format!(
        "console.log('step-console-{step}');\n// {}",
        FILLER.repeat(repeats)
    )
}

struct Bridge {
    _child: Running,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Bridge {
    fn spawn(origin: &str, credential_file: &Path, stderr: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["mcp", "--surface", "primary", "--url", origin])
            .arg("--credential-file")
            .arg(credential_file)
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
            .env_remove("ONEIRON_AUTH_SECRET")
            .env_remove("ONEIRON_URL")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(stderr).unwrap())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let stdin = child.stdin.take().unwrap();
        Self {
            _child: Running(child),
            stdin,
            lines,
        }
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{message}").unwrap();
        self.stdin.flush().unwrap();
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(180))
            .unwrap_or_else(|_| panic!("no answer to {method} from oneiron mcp"));
        let answer: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(answer["id"], json!(id), "{answer:#}");
        answer
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_healthy(origin: &str, server: &mut Running, log: &Path) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!(
                "oneiron serve exited during startup ({status}): {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        if let Ok(response) = reqwest::blocking::get(format!("{origin}/api/health"))
            && response.status().is_success()
        {
            let health: Value = response.json().unwrap();
            if health["status"] == "ok" {
                return health;
            }
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became healthy"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn run_self_task(
    dir: &Path,
    step_url: &str,
    compact_url: &str,
    cap_compaction: bool,
) -> (Value, Vec<Value>, String, Value) {
    let vault_path = dir.join("vault");
    let config = dir.join("oneiron.toml");
    stdout(oneiron(
        &["init", vault_path.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let prompts =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oneiron/tests/fixtures/prompts");
    let models = format!(
        "\n[models]\ndefault = \"step:test-model\"\n\
         [models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n\
         [models.code_mode]\nprompt_package = {prompts:?}\n\
         [models.code_mode.compaction]\nwindow_tokens = {WINDOW_TOKENS}\nhot_steps = 1\ntries = 1\nrole = \"checker\"\n\
         [models.roles.checker]\nrungs = [{{ model = \"compact:test-model\" }}]\n\
         [models.providers.step]\nkind = \"local-openai-compat\"\nbase_url = \"{step_url}\"\n\
         context_tokens = {CONTEXT_TOKENS}\n\
         [models.providers.compact]\nkind = \"local-openai-compat\"\nbase_url = \"{compact_url}\"\n\
         context_tokens = {CONTEXT_TOKENS}\n",
        prompts = prompts.canonicalize().unwrap().display().to_string(),
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&config)
        .unwrap()
        .write_all(models.as_bytes())
        .unwrap();
    let owen = {
        let vault = oneiron::Vault::open(&vault_path, oneiron::VaultConfig::device()).unwrap();
        let agent = save_self_agent(&vault, WINDOW_TOKENS, 1).unwrap();
        retain_self_compaction(&vault).unwrap();
        if cap_compaction {
            let owner = vault.ensure_embedded_owner_actor().unwrap();
            oneiron::conversation_dag::test_support::put_test_policy_manifest(
                &vault,
                oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
                oneiron::EntityId::now(),
                &json!({
                    "schema_version": "1.2", "pack_id": "owen-cap", "pack_version": "1",
                    "min_engine_version": "0.0.0", "defaults": {}, "rules": [], "actor_ceilings": [],
                    "budget_policy": [{"purpose": "engine_native_executor_compaction", "cap": 0}],
                }),
            )
            .unwrap();
        }
        agent
    };
    let owen_json = serde_json::to_value(&owen).unwrap();
    let credential_file = dir.join("owen.cred");
    stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "owen",
            "--tier",
            "full-access",
            "--out",
            credential_file.to_str().unwrap(),
        ],
        &config,
    ));

    let port = free_port().to_string();
    let origin = format!("http://127.0.0.1:{port}");
    let log = dir.join("serve.log");
    let lines = dir.join("serve.out");
    let mut server = Running(
        oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], &config)
            .env("RUST_LOG", "warn,oneiron::run_receipt=info")
            .env("NO_COLOR", "1")
            .stdout(std::fs::File::create(&lines).unwrap())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let health = wait_healthy(&origin, &mut server, &log);

    let mut bridge = Bridge::spawn(&origin, &credential_file, &dir.join("mcp.stderr"));
    bridge.call(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "owen-agent", "version": "1"},
        }),
    );
    let listed = bridge.call(2, "tools/list", json!({}));
    let tool = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "execute_code")
        .unwrap_or_else(|| panic!("execute_code is not listed: {listed:#}"))
        .clone();
    let version = tool["inputSchema"]["properties"]["schema_version"]["const"].clone();

    let mut results = Vec::new();
    for id in 3..20 {
        let answer = bridge.call(
            id,
            "tools/call",
            json!({
                "name": "execute_code",
                "arguments": {
                    "schema_version": version,
                    "consent": {"policy_ref": "policy:agent-session", "purpose": "owen checks example.com step by step"},
                    "run_ref": "owen-long-run",
                    "task": "check example.com step by step for yuki",
                },
            }),
        );
        let result = answer["result"]["structuredContent"].clone();
        assert!(
            result.is_object(),
            "{answer:#}\n{}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        let status = result["result"]["status"].as_str().unwrap().to_owned();
        results.push(result);
        match status.as_str() {
            "complete" => break,
            "yielded" | "window_full" => std::thread::sleep(Duration::from_millis(300)),
            other => panic!("unexpected status {other}: {:#}", results.last().unwrap()),
        }
    }
    drop(bridge);
    drop(server);
    (
        health,
        results,
        std::fs::read_to_string(&lines).unwrap(),
        owen_json,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compaction_call_refused_after_it_went_out_keeps_its_receipt() {
    let step = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(answer)))).await;
    let compact = FakeLlm::start(Vec::new(), Some(Reply::Status(500))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let step_url = step.base_url.clone();
    let compact_url = compact.base_url.clone();
    let (health, results, log, owen) =
        tokio::task::spawn_blocking(move || run_self_task(&path, &step_url, &compact_url, false))
            .await
            .unwrap();

    assert_eq!(
        health["ai"]["compaction"], "on",
        "compaction stays on for owen: {health:#}"
    );
    let seen: Vec<String> = compact
        .seen()
        .iter()
        .map(|request| {
            request.body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(content)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .collect();
    assert!(
        seen.iter().any(|text| text.contains("You compact")),
        "no compaction call reached the 500 fake; step calls only: {seen:?}"
    );
    assert!(
        log.lines()
            .any(|line| line.contains("\"run\":\"code-mode-compaction\"")
                && line.contains("\"event\":\"dispatched\"")),
        "billing shows no dispatched compaction call, so nothing went out:\n{log}"
    );
    let writer = results.iter().find_map(|result| {
        result
            .get("compaction")
            .and_then(|value| value.get("self_writer"))
            .cloned()
    });
    let writer = writer.expect("main drops the refused call, so self_writer is missing");
    assert_eq!(
        writer.get("writer"),
        Some(&owen),
        "the refused receipt names another writer, not owen: {writer:#}"
    );
    let admitted = writer
        .get("admitted_model")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        admitted.contains("test-model"),
        "the refused receipt names another model, not the compact fake: {writer:#}"
    );
    assert_eq!(
        writer.get("source").and_then(Value::as_str),
        Some("retained_turns"),
        "the refused receipt names another source, not retained turns: {writer:#}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_compaction_call_refused_before_it_went_out_keeps_no_receipt() {
    let step = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(answer)))).await;
    let compact = FakeLlm::start(Vec::new(), Some(Reply::Status(500))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let step_url = step.base_url.clone();
    let compact_url = compact.base_url.clone();
    let (_health, results, _log, _owen) =
        tokio::task::spawn_blocking(move || run_self_task(&path, &step_url, &compact_url, true))
            .await
            .unwrap();

    assert!(
        compact.seen().is_empty(),
        "the capped compaction call went out, so the meter did not refuse it first"
    );
    assert!(
        results.iter().all(|result| {
            result
                .get("compaction")
                .and_then(|value| value.get("self_writer"))
                .is_none()
        }),
        "an unsent call recorded a receipt it must not keep: {results:#?}"
    );
}
