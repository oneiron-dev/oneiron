#![cfg(oneiron_test_support)]
//! FIX 7745: a self-written call refused after it went out keeps its receipt.
//!
//! Test 1 sends the compaction call to a 400 fake. The 400 is a terminal
//! provider refusal, so the pass records a refused execution that names the
//! writer and the admitted model. Main drops it, so `self_writer` is missing
//! (RED). Head keeps it, so `self_writer` is present (GREEN).
//!
//! Test 2 keeps the self-compaction row from serving any route: the flight is
//! refused before any byte goes out, so no execution is recorded on either
//! tree, and the report names the refusal (guard).
//!
//! Both runs authenticate as the AGENT_DEF their self profile is saved under:
//! the credential is minted in-test for that definition with the full-access
//! tier's verbs, the way `oneiron token agent` mints one, minus only the
//! PERSON-only binding an AGENT_DEF never takes.
//!
//! Each test reads the first result whose compaction holds a refusal with no
//! pass in flight: the call that collected the refused pass. A pass is
//! collected at the next model turn, often inside the call that started it,
//! so no result need ever show it in flight.
//!
//! Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron-server --test compaction_refused_receipt --features oneiron/test-support`.

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use fake_llm::{FakeLlm, Reply};
use oneiron::llm::{ModelLocality, SelfCompactionSource};
use oneiron::{
    CompactionOwnership, EdgeActorClass, EntityId, MemoryProfile, ModelTierRef, TimeRange, Vault,
    VaultConfig, WriteActor,
};
use serde_json::{Value, json};

const SECRET: &str = "compaction-refused-receipt-key";
const WINDOW_TOKENS: u64 = 350_000;
const STEP_TOKENS: u64 = WINDOW_TOKENS / 10;
const SUMMARY_FACT: &str = "yuki keeps the deploy checklist";
const CONTEXT_TOKENS: u64 = 500_000;
const FILLER: &str = "alpha beta gamma delta ";
const CONSOLE_FRAME: &str = "Console after durable step";
/// The credential's lifetime, as `oneiron token agent` defaults it.
const CREDENTIAL_LIFETIME_SECS: u64 = 30 * 24 * 60 * 60;
/// The self-writer frame the prompt package must hold (FIX 4575): without it a
/// run whose profile names `self` compacts nowhere, and no pass is attempted.
const SELF_WRITER_FRAME: &str =
    "Write the summary as the agent whose run this is, in its own voice.\n";
/// How long the settle loop waits for the refused pass to be collected.
const SETTLE_DEADLINE_SECS: u64 = 180;
/// How many `execute_code` calls the settle loop makes at most.
const SETTLE_MAX_CALLS: u64 = 40;

/// Saves agent `owen` with a memory profile that names backend `self`.
///
/// It clones the seeded default, so all required fields (including the `auto`
/// ceiling) stay valid. It clears `logical_id`, sets `agent_id` to
/// `test.self.owen`, sets instructions that mention `yuki` and `example.com`,
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
    // `MemoryProfile` is `#[non_exhaustive]`: built through its constructor.
    definition.memory_profile = Some(
        MemoryProfile::new(
            window_token_budget,
            ModelTierRef("self".to_owned()),
            CompactionOwnership::Engine,
        )
        .with_hot_steps(hot_steps)
        .with_verbatim_pins(vec!["example.com".to_owned()]),
    );
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

/// Anchors `agent` to the vault's embedded owner PERSON, so the run's
/// compaction can load the home it wears: an AGENT_DEF with no subject anchor
/// has no identity to write as, and its flight is refused before it is sent.
///
/// Runs before the vault is rooted, where the writer needs only store-truth
/// owner semantics.
///
/// # Errors
///
/// Vault read and write errors.
fn anchor_agent_to_owner(vault: &Vault, agent: &EntityId) -> anyhow::Result<()> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let writer = WriteActor::new(owner, EdgeActorClass::Human);
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    oneiron::subject_model::anchor_actor_subject(vault, *agent, owner, writer, at)?;
    Ok(())
}

/// Sets the self-compaction row to retained turns, served at most at
/// `locality`.
///
/// A retained row forces the cold writer and skips the live fork. The default
/// cheap model is not served in the test, so the writer falls back to the
/// house compaction model. `on_device` serves no test route, so the flight is
/// refused before anything is sent.
///
/// # Errors
///
/// Vault read and write errors.
fn retain_self_compaction(vault: &Vault, locality: ModelLocality) -> anyhow::Result<()> {
    let mut table = vault.purpose_default_table()?;
    table.self_compaction.source = SelfCompactionSource::RetainedTurns;
    table.self_compaction.locality = locality;
    vault.set_purpose_default_table(&table)?;
    Ok(())
}

/// The local owner, as `oneiron token agent` binds them: this process holds
/// the vault's writer lease and acts as its embedded owner.
///
/// # Errors
///
/// A lease held elsewhere, a missing owner actor, or a refused proof.
fn local_owner(vault: &Vault) -> anyhow::Result<oneiron::consent::AuthenticatedOwner> {
    anyhow::ensure!(
        vault
            .writer_lease()
            .is_some_and(oneiron::VaultWriterLease::held_by_current_process),
        "owner actions need this process to hold the vault's writer lease"
    );
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(|error| anyhow::anyhow!("vault owner unavailable: {error}"))?;
    let owner = vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        oneiron::store::GateDecisionId::now(),
    )?;
    anyhow::ensure!(
        vault.is_live_vault_owner(&owner)?,
        "the embedded owner is not this vault's owner"
    );
    Ok(owner)
}

/// Mints the credential the run authenticates with: a paired slip for the
/// AGENT_DEF `agent`, of class `agent`, carrying the full-access tier's verbs,
/// the way `oneiron token agent` mints one, minus only the PERSON-only binding
/// an AGENT_DEF never takes. The agent's grant and ceiling land first, so the
/// credential resolves and the run's writes are judged.
///
/// The vault is already rooted (a `token agent` run rooted it under this
/// install's issuer seed), so this process installs the same platform
/// keystore `serve` installs and loads that issuer; nothing here roots
/// anything.
///
/// Returns the one-string credential form the bridge's `--credential-file`
/// holds.
///
/// # Errors
///
/// Issuer, grant, link, redemption and slip-encoding errors.
fn mint_agent_definition_credential(
    vault: &Vault,
    vault_path: &Path,
    agent: &EntityId,
) -> anyhow::Result<String> {
    oneiron_server::config::KeystoreConfig::default().install_on(vault, vault_path);
    let issuer = vault.load_host_slip_issuer()?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = local_owner(vault)?;
    vault.ensure_serving_install_profile_at_start(Some(&issuer), "compaction-refused-receipt");
    let principal = agent.to_hex();
    vault.grant_agent_principal(
        &owner,
        &principal,
        oneiron::authority::AgentTier::FullAccess.ceiling(),
    )?;
    let verbs: BTreeSet<String> = oneiron::authority::AgentTier::FullAccess
        .core_scopes()
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect();
    let mut scope = oneiron::federation::Scope::top();
    scope.verbs = oneiron::federation::ScopeAxis::Some(verbs);
    let link = vault.issue_owner_pairing_link(
        &issuer,
        &owner,
        scope,
        CREDENTIAL_LIFETIME_SECS,
        oneiron::authority::PairingPrincipal {
            holder_ref: Some(principal.clone()),
            actor_class: Some("agent".to_owned()),
            org_ref: None,
            write_facet: None,
            comm: None,
        },
    )?;
    let key = SigningKey::generate(&mut rand_core::OsRng);
    let binding_key = key.verifying_key().to_bytes();
    let transcript = oneiron::authority::pairing_binding_transcript_pinned(
        &link.code,
        &binding_key,
        &principal,
        link.pin.as_ref(),
    )?;
    let slip = vault.redeem_pairing_link(
        &issuer,
        &link.code,
        &principal,
        binding_key,
        &key.sign(&transcript).to_bytes(),
    )?;
    let token = slip.to_token()?;
    let seed: String = key
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(format!(
        "v2.cred.{}.{}",
        token.strip_prefix("v2.slip.").unwrap_or(&token),
        seed
    ))
}

/// Writes `credential` to a new owner-only file, as the bridge's
/// `--credential-file` requires: a file another user can read is a credential
/// they hold too, and the bridge refuses it.
///
/// # Errors
///
/// File creation and write errors.
fn write_credential_file(path: &Path, credential: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(credential.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// Copies the code-mode prompt package into `dir` and adds the self-writer
/// frame, which the shared fixture lacks. Returns the package root.
///
/// # Errors
///
/// File copy and write errors.
fn prompt_package_with_self_writer_frame(dir: &Path) -> anyhow::Result<PathBuf> {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../oneiron/tests/fixtures/prompts");
    let package = dir.join("prompts");
    let blocks = package.join("blocks");
    std::fs::create_dir_all(&blocks)?;
    for name in ["engine-executor-compaction.md", "engine-executor-wire.md"] {
        std::fs::copy(source.join("blocks").join(name), blocks.join(name))?;
    }
    std::fs::write(blocks.join("compaction-self-writer.md"), SELF_WRITER_FRAME)?;
    Ok(package)
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

/// The first result whose compaction holds a refusal (`suppressed`) with no
/// pass in flight: the call that collected a refused pass. A refused pass
/// holds the turn, and only a collected pass sets that hold, so this result
/// reads the settled pass. `None` when no refused pass was collected.
fn settled_verdict(results: &[Value]) -> Option<&Value> {
    results.iter().find(|result| {
        let Some(compaction) = result.get("compaction") else {
            return false;
        };
        let in_flight = compaction
            .get("in_flight")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        compaction.get("suppressed").is_some() && !in_flight
    })
}

fn run_self_task(
    dir: &Path,
    step_url: &str,
    compact_url: &str,
    locality: ModelLocality,
) -> (Value, Vec<Value>, String, Value) {
    let vault_path = dir.join("vault");
    let config = dir.join("oneiron.toml");
    stdout(oneiron(
        &["init", vault_path.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let prompts = prompt_package_with_self_writer_frame(dir).unwrap();
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
        let vault = Vault::open_owned(&vault_path, VaultConfig::server()).unwrap();
        let agent = save_self_agent(&vault, WINDOW_TOKENS, 1).unwrap();
        anchor_agent_to_owner(&vault, &agent).unwrap();
        retain_self_compaction(&vault, locality).unwrap();
        agent
    };
    // Roots the vault and installs this install's keystore and machine
    // profile, as shipped code does; the PERSON credential it writes is not
    // the run's. The run authenticates as the AGENT_DEF, minted below.
    let unused_credential = dir.join("owen-unused.cred");
    stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "owen",
            "--tier",
            "full-access",
            "--out",
            unused_credential.to_str().unwrap(),
        ],
        &config,
    ));
    let credential_file = dir.join("owen.cred");
    {
        let vault = Vault::open_owned(&vault_path, VaultConfig::server()).unwrap();
        let credential = mint_agent_definition_credential(&vault, &vault_path, &owen).unwrap();
        write_credential_file(&credential_file, &credential).unwrap();
    }
    let owen_json = serde_json::to_value(&owen).unwrap();

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

    // The settle loop: every model turn lands a pass that finished since the
    // last one, so a refused pass is collected inside the call that started
    // it or at the next call's first turn. The loop stops at the first result
    // that holds the refusal with nothing in flight: the call that collected
    // it. Stopping earlier would read a pass that has not finished.
    let mut results = Vec::new();
    let mut id = 3u64;
    let deadline = Instant::now() + Duration::from_secs(SETTLE_DEADLINE_SECS);
    loop {
        assert!(
            Instant::now() < deadline,
            "the refused pass never settled within {SETTLE_DEADLINE_SECS}s: {results:#?}"
        );
        assert!(
            id < 3 + SETTLE_MAX_CALLS,
            "the refused pass never settled within {SETTLE_MAX_CALLS} calls: {results:#?}"
        );
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
        id += 1;
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
            "yielded" | "window_full" => {
                if settled_verdict(&results).is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
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
    let compact = FakeLlm::start(Vec::new(), Some(Reply::Status(400))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let step_url = step.base_url.clone();
    let compact_url = compact.base_url.clone();
    let (health, results, log, owen) = tokio::task::spawn_blocking(move || {
        run_self_task(&path, &step_url, &compact_url, ModelLocality::OwnServer)
    })
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
        "no compaction call reached the 400 fake; step calls only: {seen:?}"
    );
    assert!(
        log.lines()
            .any(|line| line.contains("\"run\":\"code-mode-compaction\"")
                && line.contains("\"event\":\"dispatched\"")),
        "billing shows no dispatched compaction call, so nothing went out:\n{log}"
    );
    let verdict = settled_verdict(&results)
        .unwrap_or_else(|| panic!("no refused compaction pass was collected: {results:#?}"));
    // A refusal at prepare records `self_unavailable` and no execution on both
    // trees; only a refusal after the send makes a missing `self_writer` main's.
    assert!(
        verdict["compaction"].get("self_unavailable").is_none(),
        "the refused pass never went out, so this is not the 400 receipt: {verdict:#}"
    );
    let writer = verdict
        .get("compaction")
        .and_then(|value| value.get("self_writer"))
        .cloned();
    let writer = writer.unwrap_or_else(|| {
        panic!("main drops the refused call, so self_writer is missing: {verdict:#}")
    });
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
    let compact = FakeLlm::start(Vec::new(), Some(Reply::Status(400))).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_owned();
    let step_url = step.base_url.clone();
    let compact_url = compact.base_url.clone();
    let (_health, results, _log, _owen) = tokio::task::spawn_blocking(move || {
        run_self_task(&path, &step_url, &compact_url, ModelLocality::OnDevice)
    })
    .await
    .unwrap();

    assert!(
        compact.seen().is_empty(),
        "the refused compaction call went out, so the row did not refuse it first"
    );
    let verdict = settled_verdict(&results)
        .unwrap_or_else(|| panic!("no refused compaction flight was collected: {results:#?}"));
    assert_eq!(
        verdict
            .get("compaction")
            .and_then(|value| value.get("self_unavailable"))
            .and_then(Value::as_str),
        Some("route_wider_than_policy"),
        "the settled flight names another refusal, not the row's locality bound: {verdict:#}"
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
