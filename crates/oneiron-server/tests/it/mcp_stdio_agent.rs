//! An agent that spawns a command (Claude Code, Codex) reaches a running vault
//! over MCP with a scoped, revocable agent slip, through the shipped binary.
//!
//! `oneiron token agent` mints the credential on the stopped vault and
//! `oneiron mcp` speaks stdio MCP to the agent, signing every request it
//! forwards. Done-means (Wave 9b, MCP stdio bridge): `initialize`,
//! `tools/list`, one write and a recall that returns it, all with the agent
//! slip; the slip keeps working across a restart; a revoked slip is refused
//! on the next call; the agent command never mints an owner-grade slip; and
//! no slip or seed appears in argv, logs or error text. Review repros
//! (#1346): a tier holds at every write door and the latest mint replaces
//! the earlier slips; the bridge bounds every request in time and size and
//! keeps the credential out of curl's environment.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron_remote::unix_seconds_now;
use serde_json::{Value, json};

const SECRET: &str = "mcp-stdio-issuer-key-not-a-bearer";
const TEXT: &str = "The Vellichor ferry to Ost Marren leaves pier nine at a quarter past six.";

/// The bridge's limits on one client message and one server answer.
const FRAME_LIMIT: usize = 2 * 1024 * 1024;
const REPLY_LIMIT: usize = 16 * 1024 * 1024;

/// A running `oneiron serve`; dropping it kills the process.
struct Server(Child);

impl Drop for Server {
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
    let output = command.output().expect("run oneiron");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

/// Starts `oneiron serve` and waits until a protected route refuses an
/// anonymous call, which means the router is up.
fn serve(config: &Path, port: u16, log: &Path) -> Server {
    let port = port.to_string();
    let mut command = oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], config);
    command
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log).expect("server log file"));
    let mut server = Server(command.spawn().expect("spawn oneiron serve"));
    let url = format!("http://127.0.0.1:{port}/v1/core/facade/receipts");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = server.0.try_wait().expect("poll oneiron serve") {
            panic!(
                "oneiron serve exited during startup ({status}): {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
        }
        let answered = reqwest::blocking::Client::new()
            .post(&url)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .map(|response| response.status().as_u16());
        if matches!(answered, Ok(401 | 403)) {
            return server;
        }
        assert!(
            Instant::now() < deadline,
            "oneiron serve never became ready: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn sigterm(mut server: Server) {
    let pid = libc::pid_t::try_from(server.0.id()).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory; `pid` is a
    // child this test spawned and has not yet reaped.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM could not be sent");
    let deadline = Instant::now() + Duration::from_secs(30);
    while server.0.try_wait().expect("poll oneiron serve").is_none() {
        assert!(Instant::now() < deadline, "oneiron serve ignored SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A `curl` first on the bridge's PATH that records its argv, then runs the
/// host's curl. The script is written by a shell, never by this process, so
/// no other test thread's fork can hold it open for writing when it runs.
fn argv_recording_curl(dir: &Path, argv_log: &Path) -> PathBuf {
    recording_curl(dir, argv_log, None)
}

/// [`argv_recording_curl`], also appending the environment curl inherits to
/// `env_log`.
fn recording_curl(dir: &Path, argv_log: &Path, env_log: Option<&Path>) -> PathBuf {
    let real = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("curl"))
        .find(|candidate| candidate.is_file())
        .expect("the bridge needs the host's curl");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let env = env_log.map_or_else(String::new, |log| format!("env >> '{}'\n", log.display()));
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{env}exec '{}' \"$@\"\n",
        argv_log.display(),
        real.display()
    );
    let wrote = Command::new("sh")
        .arg("-c")
        .arg("cat > \"$1\" && chmod 755 \"$1\"")
        .arg("sh")
        .arg(bin.join("curl"))
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .expect("sh stdin")
                .write_all(script.as_bytes())?;
            child.wait()
        })
        .expect("write the recording curl");
    assert!(wrote.success());
    bin
}

/// `oneiron mcp` as an agent spawns it: one JSON-RPC message per line.
struct Bridge {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Bridge {
    fn spawn(origin: &str, credential_file: &Path, curl_dir: &Path, stderr: &Path) -> Self {
        let file = credential_file.to_str().unwrap();
        Self::spawn_with(
            &["--url", origin, "--credential-file", file],
            &[],
            curl_dir,
            stderr,
        )
    }

    /// `oneiron mcp` with `args`, and only `env` of the credential variables.
    fn spawn_with(args: &[&str], env: &[(&str, &str)], curl_dir: &Path, stderr: &Path) -> Self {
        let path = std::env::join_paths(
            std::iter::once(curl_dir.to_path_buf()).chain(
                std::env::var_os("PATH")
                    .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .unwrap_or_default(),
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["mcp", "--surface", "tool-first"])
            .args(args)
            .env("PATH", path)
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
            .env_remove("ONEIRON_AUTH_SECRET")
            .env_remove("ONEIRON_URL")
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(stderr).unwrap())
            .spawn()
            .expect("spawn oneiron mcp");
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
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            lines,
            seen: Vec::new(),
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("bridge stdin open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    fn next(&mut self) -> Value {
        self.next_within(Duration::from_secs(120))
    }

    fn next_within(&mut self, wait: Duration) -> Value {
        let line = self
            .lines
            .recv_timeout(wait)
            .unwrap_or_else(|_| panic!("no answer from oneiron mcp; so far: {:#?}", self.seen));
        let answer = serde_json::from_str(&line)
            .unwrap_or_else(|_| panic!("not one JSON line: {line:.200}"));
        self.seen.push(line);
        answer
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let answer = self.next();
        assert_eq!(answer["id"], json!(id), "answers: {:#?}", self.seen);
        answer
    }

    /// Closing stdin is how an agent ends the session; the bridge then exits.
    fn close(self) -> Vec<String> {
        self.close_within(Duration::from_secs(120))
    }

    /// [`Bridge::close`], failing if the bridge takes longer than `wait` to
    /// exit. Answers it wrote on the way out are kept.
    fn close_within(mut self, wait: Duration) -> Vec<String> {
        drop(self.stdin.take());
        let deadline = Instant::now() + wait;
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                panic!("oneiron mcp still running {wait:?} after stdin closed");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success(), "oneiron mcp exited {status}");
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.seen.push(line);
        }
        std::mem::take(&mut self.seen)
    }
}

/// A test that fails mid-session leaves no bridge behind.
impl Drop for Bridge {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn tool_call(id: u64, tool: &str, version: &Value, arguments: Value) -> (u64, Value) {
    (
        id,
        json!({
            "name": tool,
            "arguments": {
                "schema_version": version,
                "consent": { "policy_ref": "policy:agent-session", "purpose": "remember for the owner" },
                "arguments": arguments,
            },
        }),
    )
}

fn recall(bridge: &mut Bridge, id: u64, version: &Value) -> Value {
    let (id, params) = tool_call(
        id,
        "recall",
        version,
        json!({ "spec": { "query": "Vellichor ferry pier nine", "limit": 10 } }),
    );
    bridge.call(id, "tools/call", params)
}

#[test]
fn an_agent_reaches_the_vault_over_stdio_mcp_with_a_scoped_revocable_slip() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let config = dir.path().join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    let owner: Value = serde_json::from_str(&stdout(oneiron(
        &["whoami", vault.to_str().unwrap()],
        &config,
    )))
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let origin = format!("http://127.0.0.1:{port}");

    // The agent command keeps owner powers for the owner.
    let refused = oneiron(
        &["token", "agent", "--name", "claude-code", "--tier", "owner"],
        &config,
    )
    .output()
    .unwrap();
    assert!(
        !refused.status.success(),
        "an owner tier was minted for an agent"
    );

    // Minted on the stopped vault into an owner-only file; nothing secret printed.
    let credential_file = dir.path().join("claude-code.cred");
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "claude-code",
            "--tier",
            "full-access",
            "--out",
            credential_file.to_str().unwrap(),
        ],
        &config,
    )))
    .unwrap();
    for secret_field in ["credential", "token", "binding_key"] {
        assert!(minted.get(secret_field).is_none(), "printed {secret_field}");
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&credential_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "credential file mode {mode:o}");
    }
    // Minted with write, the agent is ARCH-0028's full-access tier.
    assert_eq!(minted["ceiling"], json!("auto"), "{minted:#}");
    let principal = minted["principal_ref"].as_str().unwrap().to_owned();
    let slip_id = minted["slip_id"].as_str().unwrap().to_owned();
    let stored = std::fs::read_to_string(&credential_file).unwrap();
    let (slip_hex, seed) = stored
        .trim()
        .strip_prefix("v2.cred.")
        .and_then(|rest| rest.rsplit_once('.'))
        .expect("a paired v2 credential");
    let token = format!("v2.slip.{slip_hex}");

    // Never owner-grade: the agent's own principal, class `agent`, three verbs.
    let slip = CapabilitySlip::from_token(&token).unwrap();
    assert_eq!(slip.claims.holder_ref, principal);
    assert_ne!(Some(principal.as_str()), owner["owner_principal"].as_str());
    assert_eq!(slip.claims.actor_class.as_deref(), Some("agent"));
    assert_ne!(slip.claims.scope, Scope::top());
    assert_eq!(
        slip.claims.scope.verbs,
        ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:propose".to_owned(),
            "core:write".to_owned()
        ]))
    );
    // ARCH-0028's propose-only tier: write capability at ceiling `proposed`.
    let reviewer_file = dir.path().join("reviewer.cred");
    let reviewer: Value = serde_json::from_str(&stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "reviewer",
            "--tier",
            "propose-only",
            "--out",
            reviewer_file.to_str().unwrap(),
        ],
        &config,
    )))
    .unwrap();
    assert_eq!(reviewer["ceiling"], json!("proposed"), "{reviewer:#}");

    let argv_log = dir.path().join("curl-argv.log");
    let curl_dir = argv_recording_curl(dir.path(), &argv_log);
    let first = serve(&config, port, &dir.path().join("serve-1.log"));
    let mut bridge = Bridge::spawn(
        &origin,
        &credential_file,
        &curl_dir,
        &dir.path().join("mcp.stderr"),
    );

    let initialized = bridge.call(
        1,
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "e2e-agent", "version": "1" },
        }),
    );
    assert_eq!(
        initialized["result"]["actor"]["actor_ref"],
        json!(principal),
        "{initialized:#}"
    );
    assert_eq!(
        initialized["result"]["actor"]["actor_class"],
        json!("agent")
    );
    // A notification is forwarded and never answered: the next line is the
    // answer to the next request.
    bridge.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    let listed = bridge.call(2, "tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().expect("tools");
    let names: BTreeSet<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(
        names.contains("witness") && names.contains("recall"),
        "{names:?}"
    );
    for tool in tools {
        let schema = &tool["inputSchema"];
        assert!(schema["properties"].get("actor").is_none(), "{tool:#}");
        assert!(
            !schema["required"]
                .as_array()
                .unwrap()
                .contains(&json!("actor"))
        );
    }
    let witness = tools.iter().find(|tool| tool["name"] == "witness").unwrap();
    let version = witness["inputSchema"]["properties"]["schema_version"]["const"].clone();

    let (id, params) = tool_call(
        3,
        "witness",
        &version,
        json!({ "spec": {
            "conversation_ref": "45454545454545454545454545454545",
            "messages": [{
                "author": "user", "message_type": "dialogue", "content": TEXT,
                "is_visible": true, "order": 0,
            }],
            "occurred_at": unix_seconds_now(),
        }}),
    );
    let wrote = bridge.call(id, "tools/call", params);
    assert!(wrote.get("error").is_none(), "{wrote:#}");
    assert_ne!(wrote["result"]["isError"], json!(true), "{wrote:#}");
    let recalled = recall(&mut bridge, 4, &version);
    assert!(recalled.to_string().contains(TEXT), "{recalled:#}");

    // A propose-only agent's write reaches the write gate and its ceiling;
    // its credential is not what refuses it.
    let mut reviewer_bridge = Bridge::spawn(
        &origin,
        &reviewer_file,
        &curl_dir,
        &dir.path().join("reviewer.stderr"),
    );
    let (id, params) = tool_call(
        1,
        "witness",
        &version,
        json!({ "spec": {
            "conversation_ref": "47474747474747474747474747474747",
            "messages": [{
                "author": "user", "message_type": "dialogue", "content": "reviewer draft",
                "is_visible": true, "order": 0,
            }],
            "occurred_at": unix_seconds_now(),
        }}),
    );
    let drafted = reviewer_bridge.call(id, "tools/call", params);
    assert_ne!(drafted["error"]["code"], json!(-32001), "{drafted:#}");
    assert_ne!(
        drafted["error"]["data"]["kind"],
        json!("mcp_auth_required"),
        "{drafted:#}"
    );
    let seen_by_reviewer = reviewer_bridge.close().join("\n");

    // The slip opens no owner-grade door, and a proposal against a subject
    // that is not there says what to do about it.
    let key = SigningKey::from_bytes(
        &(0..seed.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    let signed = |request: reqwest::blocking::RequestBuilder| {
        request
            .bearer_auth(&token)
            .header(
                "x-oneiron-binding",
                holder_proof(&slip, &key, unix_seconds_now())
                    .unwrap()
                    .to_string(),
            )
            .send()
            .unwrap()
    };
    let owner_door = signed(
        reqwest::blocking::Client::new().get(format!("{origin}/api/search/text?query=Vellichor")),
    );
    assert!(
        matches!(owner_door.status().as_u16(), 401 | 403),
        "{}",
        owner_door.status()
    );
    let proposed = signed(
        reqwest::blocking::Client::new()
            .post(format!("{origin}/v1/core/propose"))
            .json(&json!({
                "subject": "46464646464646464646464646464646",
                "predicate": "profile.name",
                "value": "candidate",
            })),
    );
    assert_eq!(proposed.status().as_u16(), 403);
    let refusal = proposed.text().unwrap();
    assert!(
        refusal.contains("subject not found or not readable"),
        "{refusal}"
    );

    // A restart forgets nothing the agent needs: the same bridge, same slip.
    sigterm(first);
    let second = serve(&config, port, &dir.path().join("serve-2.log"));
    let recalled = recall(&mut bridge, 5, &version);
    assert!(recalled.to_string().contains(TEXT), "{recalled:#}");

    // Revoked on the stopped vault: the next call is refused, and says why.
    sigterm(second);
    let revoked: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "revoke", "--jti", &slip_id],
        &config,
    )))
    .unwrap();
    assert_eq!(revoked, json!({ "revoked": true }));
    let _third = serve(&config, port, &dir.path().join("serve-3.log"));
    let refused = recall(&mut bridge, 6, &version);
    assert_eq!(refused["error"]["code"], json!(-32001), "{refused:#}");
    assert!(!refused.to_string().contains(TEXT), "{refused:#}");

    // No slip or seed in what any process printed, logged or ran.
    let mut seen = bridge.close().join("\n");
    seen.push_str(&seen_by_reviewer);
    for log in [
        "mcp.stderr",
        "reviewer.stderr",
        "serve-1.log",
        "serve-2.log",
        "serve-3.log",
    ] {
        seen.push_str(&std::fs::read_to_string(dir.path().join(log)).unwrap());
    }
    let argv = std::fs::read_to_string(&argv_log).expect("curl ran through the wrapper");
    assert!(argv.contains("--config -"), "{argv}");
    seen.push_str(&argv);
    seen.push_str(&minted.to_string());
    for secret in [slip_hex, seed] {
        assert!(!seen.contains(secret), "a credential leaked");
    }
}

/// A fresh vault with no embedder, and the config file every command shares.
fn init_vault(dir: &Path) -> PathBuf {
    let vault = dir.join("vault");
    let config = dir.join("oneiron.toml");
    stdout(oneiron(
        &["init", vault.to_str().unwrap(), "--embedder", "none"],
        &config,
    ));
    config
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn verbs(names: &[&str]) -> ScopeAxis<String> {
    ScopeAxis::Some(names.iter().map(|name| (*name).to_owned()).collect())
}

/// One minted agent credential: what `token agent --out` printed, its file,
/// and the slip and key a holder signs with.
struct Minted {
    printed: Value,
    file: PathBuf,
    token: String,
    slip: CapabilitySlip,
    key: SigningKey,
}

impl Minted {
    fn new(config: &Path, file: PathBuf, name: &str, tier: &str) -> Self {
        let printed: Value = serde_json::from_str(&stdout(oneiron(
            &[
                "token",
                "agent",
                "--name",
                name,
                "--tier",
                tier,
                "--out",
                file.to_str().unwrap(),
            ],
            config,
        )))
        .unwrap();
        let stored = std::fs::read_to_string(&file).unwrap();
        let (slip_hex, seed) = stored
            .trim()
            .strip_prefix("v2.cred.")
            .and_then(|rest| rest.rsplit_once('.'))
            .expect("a paired v2 credential");
        let token = format!("v2.slip.{slip_hex}");
        let key = SigningKey::from_bytes(
            &(0..seed.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&seed[at..at + 2], 16).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        Self {
            printed,
            file,
            slip: CapabilitySlip::from_token(&token).unwrap(),
            token,
            key,
        }
    }

    /// `request` with this slip and a fresh holder proof; the HTTP status.
    fn send(&self, request: reqwest::blocking::RequestBuilder) -> u16 {
        request
            .bearer_auth(&self.token)
            .header(
                "x-oneiron-binding",
                holder_proof(&self.slip, &self.key, unix_seconds_now())
                    .unwrap()
                    .to_string(),
            )
            .send()
            .unwrap()
            .status()
            .as_u16()
    }

    /// The raw batch door: one PERSON put at `id`, committed at once.
    fn batch(&self, origin: &str, id: &str) -> u16 {
        self.send(
            reqwest::blocking::Client::new()
                .post(format!("{origin}/v1/core/batch"))
                .json(&json!({ "entities": [{
                    "id": id, "entity_type": 10, "body": { "name": "unreviewed person" },
                }]})),
        )
    }

    /// The proposal door, against subject `id`. It answers 403 for a subject
    /// that is not there, so it also says whether a batch landed.
    fn propose(&self, origin: &str, id: &str) -> u16 {
        self.send(
            reqwest::blocking::Client::new()
                .post(format!("{origin}/v1/core/propose"))
                .json(&json!({ "subject": id, "predicate": "profile.name", "value": "candidate" })),
        )
    }
}

fn create_task(bridge: &mut Bridge, id: u64, version: &Value) -> Value {
    let (id, params) = tool_call(
        id,
        "tasks.create",
        version,
        json!({ "spec": { "kind": "review" } }),
    );
    bridge.call(id, "tools/call", params)
}

/// A tier holds at every write door, not only at the MCP one, and a name's
/// latest mint is its one credential. Review repros: a propose-only slip
/// committed through `/v1/core/batch` (Astra F1, P1), and a full-access slip
/// stayed live after its name was re-minted read-only (Astra F2, Greptile P1).
#[test]
fn an_agent_holds_its_latest_tier_at_every_write_door() {
    const UNREVIEWED: &str = "48484848484848484848484848484848";
    const REVIEWED: &str = "49494949494949494949494949494949";
    let dir = tempfile::tempdir().unwrap();
    let config = init_vault(dir.path());
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let mint = |name: &str, tier: &str, file: &str| {
        Minted::new(&config, dir.path().join(file), name, tier)
    };
    let writer = mint("writer", "full-access", "writer.cred");
    let reviewer = mint("reviewer", "propose-only", "reviewer.cred");
    let scout = mint("scout", "full-access", "scout-1.cred");

    let curl_dir = argv_recording_curl(dir.path(), &dir.path().join("curl-argv.log"));
    let first = serve(&config, port, &dir.path().join("serve-1.log"));

    // A propose-only agent commits nothing through the raw batch door; a
    // full-access one still does, and the reviewer can still propose.
    assert_eq!(reviewer.batch(&origin, UNREVIEWED), 403);
    assert_eq!(
        writer.propose(&origin, UNREVIEWED),
        403,
        "the refused batch landed"
    );
    assert_eq!(writer.batch(&origin, REVIEWED), 200);
    assert_eq!(reviewer.propose(&origin, REVIEWED), 200);
    // Propose-only proposes; `core:write`, which every unbound write door
    // requires, is full-access's alone.
    assert_eq!(
        reviewer.slip.claims.scope.verbs,
        verbs(&["core:read", "core:propose"])
    );

    // The scout writes at every door while it is full-access.
    let mut scout_bridge = Bridge::spawn(
        &origin,
        &scout.file,
        &curl_dir,
        &dir.path().join("scout.stderr"),
    );
    let listed = scout_bridge.call(1, "tools/list", json!({}));
    let version =
        listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "tasks.create")
            .unwrap_or_else(|| panic!("no tasks.create: {listed:#}"))["inputSchema"]["properties"]
            ["schema_version"]["const"]
            .clone();
    let created = create_task(&mut scout_bridge, 2, &version);
    assert_ne!(created["error"]["code"], json!(-32001), "{created:#}");
    assert_eq!(
        scout.batch(&origin, "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a"),
        200
    );
    assert_eq!(scout.propose(&origin, REVIEWED), 200);

    // Re-minted read-only on the stopped vault, then served again: the
    // full-access slip is refused at every write door, and on the session
    // that held it.
    sigterm(first);
    let downgraded = mint("scout", "read-only", "scout-2.cred");
    let _second = serve(&config, port, &dir.path().join("serve-2.log"));
    let refused = create_task(&mut scout_bridge, 3, &version);
    assert_eq!(refused["error"]["code"], json!(-32001), "{refused:#}");
    assert!(
        matches!(scout.propose(&origin, REVIEWED), 401 | 403),
        "the replaced slip proposed"
    );
    assert!(
        matches!(
            scout.batch(&origin, "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"),
            401 | 403
        ),
        "the replaced slip wrote"
    );
    assert_eq!(
        downgraded.printed["revoked_slip_ids"],
        json!([scout.printed["slip_id"]]),
        "{:#}",
        downgraded.printed
    );
    assert_eq!(downgraded.slip.claims.scope.verbs, verbs(&["core:read"]));
    scout_bridge.close();
}

/// One fake MCP endpoint per test: it records each request and answers by
/// the request's JSON-RPC method, stalling or flooding where told to.
fn fake_mcp_server(seen: Arc<Mutex<Vec<Value>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = Arc::clone(&seen);
            std::thread::spawn(move || answer_fake(stream, &seen));
        }
    });
    port
}

fn answer_fake(mut stream: TcpStream, seen: &Mutex<Vec<Value>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 {
            return;
        }
        let Some((name, value)) = header.trim_end().split_once(':') else {
            break;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().unwrap();
        }
        if name.eq_ignore_ascii_case("expect") {
            stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    seen.lock().unwrap().push(request.clone());
    let head = |length: usize| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n"
        )
    };
    let reply = match request["method"].as_str() {
        // The headers, then nothing.
        Some("stall/headers") => head(64),
        // The headers and the start of a body, then nothing.
        Some("stall/body") => format!("{}{{\"jsonrpc\":", head(64)),
        // A whole answer to the request, past the bridge's reply limit.
        Some("oversized") => {
            let answer = json!({
                "jsonrpc": "2.0", "id": request["id"],
                "result": { "pad": "x".repeat(REPLY_LIMIT) },
            })
            .to_string();
            format!("{}{answer}", head(answer.len()))
        }
        _ => {
            let answer = json!({ "jsonrpc": "2.0", "id": request["id"], "result": {} }).to_string();
            format!("{}{answer}", head(answer.len()))
        }
    };
    // The bridge may hang up mid-answer; that is what is under test.
    let _ = stream
        .write_all(reply.as_bytes())
        .and_then(|()| stream.flush());
    if request["method"]
        .as_str()
        .is_some_and(|method| method.starts_with("stall/"))
    {
        std::thread::sleep(Duration::from_secs(600));
    }
}

/// The start of an answer, for a failure message: an oversized one is 16 MiB.
fn head(answer: &Value) -> String {
    answer.to_string().chars().take(300).collect()
}

/// Sends request `id` with no params; its answer and how long it took.
fn ask(bridge: &mut Bridge, id: u64, method: &str) -> (Value, Duration) {
    bridge.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": {} }));
    let started = Instant::now();
    let answer = bridge.next_within(Duration::from_secs(30));
    assert_eq!(answer["id"], json!(id), "{}", head(&answer));
    (answer, started.elapsed())
}

/// A stalled, truncated or oversized answer, or an oversized message, costs
/// the agent one typed error for that request and nothing more; closing stdin
/// never waits on a stalled request; and a credential taken from the
/// environment never reaches curl's. Review repros: Astra F3, F4 and F5
/// (= Greptile P2).
#[test]
fn the_bridge_bounds_every_request_and_keeps_its_credential_from_curl() {
    let dir = tempfile::tempdir().unwrap();
    let config = init_vault(dir.path());
    let printed: Value = serde_json::from_str(&stdout(oneiron(
        &["token", "agent", "--name", "codex"],
        &config,
    )))
    .unwrap();
    let token = printed["token"].as_str().unwrap().to_owned();
    let seed = printed["binding_key"].as_str().unwrap().to_owned();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let origin = format!("http://127.0.0.1:{}", fake_mcp_server(Arc::clone(&seen)));
    let env_log = dir.path().join("curl-env.log");
    let curl_dir = recording_curl(
        dir.path(),
        &dir.path().join("curl-argv.log"),
        Some(&env_log),
    );
    let mut bridge = Bridge::spawn_with(
        &[
            "--url",
            &origin,
            "--secret-env",
            "AGENT_SLIP",
            "--binding-key-env",
            "AGENT_SEED",
            "--request-timeout-secs",
            "4",
            "--idle-timeout-secs",
            "1",
        ],
        &[
            ("AGENT_SLIP", &token),
            ("AGENT_SEED", &seed),
            ("ONEIRON_SECRET", &token),
            ("ONEIRON_BINDING_KEY", &seed),
        ],
        &curl_dir,
        &dir.path().join("mcp.stderr"),
    );
    // Headers and no body: the request's deadline ends it.
    let (stalled, took) = ask(&mut bridge, 1, "stall/headers");
    assert_eq!(
        stalled["error"]["data"]["kind"],
        json!("server_unreachable"),
        "{stalled:#}"
    );
    assert!(
        stalled["error"]["message"]
            .as_str()
            .unwrap()
            .contains("within 4s"),
        "{stalled:#}"
    );
    assert!(took < Duration::from_secs(15), "took {took:?}");
    // A body that stops: the idle limit ends it, before the deadline.
    let (truncated, took) = ask(&mut bridge, 2, "stall/body");
    assert_eq!(
        truncated["error"]["data"]["kind"],
        json!("server_unreachable"),
        "{truncated:#}"
    );
    assert!(
        truncated["error"]["message"]
            .as_str()
            .unwrap()
            .contains("stalled"),
        "{truncated:#}"
    );
    assert!(took < Duration::from_secs(4), "took {took:?}");
    // An answer past the reply limit is dropped, with an error for its id.
    let (flooded, _) = ask(&mut bridge, 3, "oversized");
    assert_eq!(
        flooded["error"]["data"]["kind"],
        json!("reply_too_large"),
        "{}",
        head(&flooded)
    );

    // A message past the frame limit is refused unsent, by its id.
    let pad = "x".repeat(FRAME_LIMIT);
    bridge.send(&json!({ "jsonrpc": "2.0", "id": 4, "method": "ping", "params": { "pad": pad } }));
    let refused = bridge.next_within(Duration::from_secs(30));
    assert_eq!(refused["id"], json!(4), "{}", head(&refused));
    assert_eq!(
        refused["error"]["data"]["kind"],
        json!("frame_too_large"),
        "{}",
        head(&refused)
    );
    assert!(
        !seen
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["id"] == json!(4))
    );

    // The session is whole: the next request is answered.
    let (answered, _) = ask(&mut bridge, 5, "ping");
    assert_eq!(answered["result"], json!({}), "{answered:#}");

    // Closing stdin with a request stalled does not wait past its deadline.
    bridge.send(&json!({ "jsonrpc": "2.0", "id": 6, "method": "stall/headers", "params": {} }));
    let seen_lines = bridge.close_within(Duration::from_secs(30));
    let last: Value = serde_json::from_str(seen_lines.last().unwrap()).unwrap();
    assert_eq!(last["id"], json!(6), "{last:#}");
    assert_eq!(
        last["error"]["data"]["kind"],
        json!("server_unreachable"),
        "{last:#}"
    );

    // curl inherited no variable the credential was in, under either name.
    let env = std::fs::read_to_string(&env_log).expect("curl ran through the wrapper");
    for name in [
        "AGENT_SLIP=",
        "AGENT_SEED=",
        "ONEIRON_SECRET=",
        "ONEIRON_BINDING_KEY=",
    ] {
        assert!(!env.contains(name), "curl inherited {name}");
    }
    assert!(
        !env.contains(&seed) && !env.contains(&token),
        "a credential reached curl"
    );
}
