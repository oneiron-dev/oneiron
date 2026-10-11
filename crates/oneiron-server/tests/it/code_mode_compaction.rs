#![allow(clippy::unwrap_used)]
//! A long code-mode run served by the shipped binary compacts by itself
//! (agent-runtime-v1 §d7; Wave 9b compaction host done-means).
//!
//! `oneiron serve` runs `execute_code` for an agent that reaches it through
//! `oneiron mcp`. Each step's program carries a tenth of the run's window
//! (programs, unlike consoles, never decay), so the run crosses its threshold
//! within a few steps, or parks at its window with the pass in flight: its
//! oldest steps are summarized by the compaction seat in the background, the
//! summary passes the engine's gate, and the next step's request carries it in
//! place of those steps; the run then finishes. `/api/health` says compaction
//! is on.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::fake_llm::{FakeLlm, Reply};

const SECRET: &str = "code-mode-compaction-issuer-key";
/// The window a run parks at; it starts compacting at half of it or later.
const WINDOW_TOKENS: u64 = 80_000;
/// What each step's program adds to the run's request.
const STEP_TOKENS: u64 = WINDOW_TOKENS / 10;
const SUMMARY_FACT: &str = "the deploy checklist has four items";
const FILLER: &str = "alpha beta gamma delta ";
const CONSOLE_FRAME: &str = "Console after durable step";

/// A running process; dropping it kills the process.
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

/// The text of one chat message, whichever content form the request used.
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

/// The fake model. A compaction call (the compaction prompt's system
/// message) gets a summary of exactly its span with every pin kept. A step
/// call gets a program of [`STEP_TOKENS`] that prints its step; once a
/// request carries a compacted epoch, the program finishes the run.
fn answer(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let texts: Vec<String> = messages.iter().map(content).collect();
    if texts
        .first()
        .is_some_and(|system| system.contains("You compact"))
    {
        let input: Value = serde_json::from_str(texts.last().unwrap()).unwrap();
        let mut summary = format!(
            "Steps {} to {} printed filler while checking the deploy notes; {SUMMARY_FACT}.",
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

/// `oneiron mcp` on the code-mode surface, one JSON-RPC message per line.
struct Bridge {
    /// Killed when the bridge drops.
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
            return response.json().unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became healthy"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// The served run, end to end: returns the health answer, every
/// `execute_code` result and the server's log. Blocking; the fake model runs
/// on the test's runtime.
fn run_long_task(dir: &Path, model_url: &str) -> (Value, Vec<Value>, String) {
    let vault = dir.join("vault");
    let config = dir.join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let prompts =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oneiron/tests/fixtures/prompts");
    let models = format!(
        "\n[models]\ndefault = \"local:test-model\"\n\
         [models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n\
         [models.code_mode]\nprompt_package = {prompts:?}\n\
         [models.code_mode.compaction]\nwindow_tokens = {WINDOW_TOKENS}\nhot_steps = 1\n\
         [models.providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{model_url}\"\n\
         context_tokens = 200000\n",
        prompts = prompts.canonicalize().unwrap().display().to_string(),
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&config)
        .unwrap()
        .write_all(models.as_bytes())
        .unwrap();
    let credential_file = dir.join("runner.cred");
    stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "runner",
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
    let mut server = Running(
        oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], &config)
            .env("RUST_LOG", "warn,oneiron::run_receipt=info")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
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
            "clientInfo": {"name": "long-run-agent", "version": "1"},
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
                    "consent": {"policy_ref": "policy:agent-session", "purpose": "a long task"},
                    "run_ref": "long-run",
                    "task": "check the deploy notes step by step",
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
    (health, results, std::fs::read_to_string(&log).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_served_run_compacts_by_itself_and_finishes() {
    let fake = FakeLlm::start(Vec::new(), Some(Reply::Computed(Arc::new(answer)))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let url = fake.base_url.clone();
    let (health, results, log) = tokio::task::spawn_blocking(move || run_long_task(&path, &url))
        .await
        .unwrap();

    assert_eq!(health["ai"]["compaction"], "on", "{health:#}");
    let last = results.last().unwrap();
    assert_eq!(last["result"]["status"], "complete", "{results:#?}");
    // The run reports its swap.
    assert!(
        results
            .iter()
            .any(|result| result["compaction"]["last_swap"]["epoch"] == 1),
        "{results:#?}"
    );

    let seen = fake.seen();
    let texts: Vec<String> = seen
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
    let compaction = texts
        .iter()
        .position(|text| text.contains("You compact"))
        .expect("a compaction call reached the model");
    assert!(
        texts[compaction].contains("step-console-0"),
        "the oldest step is compacted"
    );
    assert!(seen[compaction].body.get("response_format").is_some());
    let swapped = texts
        .iter()
        .position(|text| text.contains("<compacted epoch=\"1\""))
        .expect("a step after the swap carries the summary");
    assert!(swapped > compaction);
    let swapped = &texts[swapped];
    assert!(swapped.contains(SUMMARY_FACT));
    assert!(
        !swapped.contains("step-console-0"),
        "the compacted step left the window"
    );
    assert!(
        swapped.contains("sandbox.fs.read_file"),
        "its output stays reachable"
    );

    // Each pass's model call is a run like every other server model call:
    // admitted on a one-use permit, dispatched through the run's gate and
    // settled, each step in the server's run receipts.
    let events: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("\"run\":\"code-mode-compaction\""))
        .filter_map(|line| {
            ["admitted", "denied", "dispatched", "settled", "revised"]
                .into_iter()
                .find(|event| line.contains(&format!("\"event\":\"{event}\"")))
        })
        .collect();
    assert!(
        !events.is_empty()
            && events
                .chunks(3)
                .all(|call| call == ["admitted", "dispatched", "settled"]),
        "every compaction call is admitted, dispatched and settled: {events:?}\n{log}"
    );
}
