//! An agent that spawns a command (Claude Code, Codex) reaches a running vault
//! over MCP with a scoped, revocable agent slip, through the shipped binary.
//!
//! `oneiron token agent` mints the credential on the stopped vault and
//! `oneiron mcp` speaks stdio MCP to the agent, signing every request it
//! forwards. Done-means (Wave 9b, MCP stdio bridge): `initialize`,
//! `tools/list`, one write and a recall that returns it, all with the agent
//! slip; the slip keeps working across a restart; a revoked slip is refused
//! on the next call; the agent command never mints an owner-grade slip; and
//! no slip or seed appears in argv, logs or error text.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron_remote::unix_seconds_now;
use serde_json::{Value, json};

const SECRET: &str = "mcp-stdio-issuer-key-not-a-bearer";
const TEXT: &str = "The Vellichor ferry to Ost Marren leaves pier nine at a quarter past six.";

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
    let real = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|dir| dir.join("curl"))
        .find(|candidate| candidate.is_file())
        .expect("the bridge needs the host's curl");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
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
        let path = std::env::join_paths(
            std::iter::once(curl_dir.to_path_buf()).chain(
                std::env::var_os("PATH")
                    .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .unwrap_or_default(),
            ),
        )
        .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["mcp", "--url", origin, "--surface", "tool-first"])
            .arg("--credential-file")
            .arg(credential_file)
            .env("PATH", path)
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
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
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(120))
            .unwrap_or_else(|_| panic!("no answer from oneiron mcp; so far: {:#?}", self.seen));
        self.seen.push(line.clone());
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("not one JSON line: {line}"))
    }

    fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let answer = self.next();
        assert_eq!(answer["id"], json!(id), "answers: {:#?}", self.seen);
        answer
    }

    /// Closing stdin is how an agent ends the session; the bridge then exits.
    fn close(mut self) -> Vec<String> {
        drop(self.stdin.take());
        let status = self.child.wait().unwrap();
        assert!(status.success(), "oneiron mcp exited {status}");
        self.seen
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
        &["token", "agent", "--name", "claude-code", "--scope", "core:read,core:auth"],
        &config,
    )
    .output()
    .unwrap();
    assert!(!refused.status.success(), "core:auth was minted for an agent");

    // Minted on the stopped vault into an owner-only file; nothing secret printed.
    let credential_file = dir.path().join("claude-code.cred");
    let minted: Value = serde_json::from_str(&stdout(oneiron(
        &[
            "token",
            "agent",
            "--name",
            "claude-code",
            "--scope",
            "core:read,core:write",
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
        let mode = std::fs::metadata(&credential_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "credential file mode {mode:o}");
    }
    let principal = minted["principal_ref"].as_str().unwrap().to_owned();
    let slip_id = minted["slip_id"].as_str().unwrap().to_owned();
    let stored = std::fs::read_to_string(&credential_file).unwrap();
    let (slip_hex, seed) = stored
        .trim()
        .strip_prefix("v2.cred.")
        .and_then(|rest| rest.rsplit_once('.'))
        .expect("a paired v2 credential");
    let token = format!("v2.slip.{slip_hex}");

    // Never owner-grade: the agent's own principal, class `agent`, two verbs.
    let slip = CapabilitySlip::from_token(&token).unwrap();
    assert_eq!(slip.claims.holder_ref, principal);
    assert_ne!(Some(principal.as_str()), owner["owner_principal"].as_str());
    assert_eq!(slip.claims.actor_class.as_deref(), Some("agent"));
    assert_ne!(slip.claims.scope, Scope::top());
    assert_eq!(
        slip.claims.scope.verbs,
        ScopeAxis::Some(BTreeSet::from(["core:read".to_owned(), "core:write".to_owned()]))
    );

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
        initialized["result"]["actor"]["actor_ref"], json!(principal),
        "{initialized:#}"
    );
    assert_eq!(initialized["result"]["actor"]["actor_class"], json!("agent"));
    // A notification is forwarded and never answered: the next line is the
    // answer to the next request.
    bridge.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));

    let listed = bridge.call(2, "tools/list", json!({}));
    let tools = listed["result"]["tools"].as_array().expect("tools");
    let names: BTreeSet<&str> = tools.iter().filter_map(|tool| tool["name"].as_str()).collect();
    assert!(
        names.contains("witness") && names.contains("recall"),
        "{names:?}"
    );
    for tool in tools {
        let schema = &tool["inputSchema"];
        assert!(schema["properties"].get("actor").is_none(), "{tool:#}");
        assert!(!schema["required"].as_array().unwrap().contains(&json!("actor")));
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
                holder_proof(&slip, &key, unix_seconds_now()).unwrap().to_string(),
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
    for log in ["mcp.stderr", "serve-1.log", "serve-2.log", "serve-3.log"] {
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
