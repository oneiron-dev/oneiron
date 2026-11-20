//! `oneiron hook --host <host> hand-over` with a hosted vault selected (H41,
//! ARCH-0028 `#plugin-first-run` step 3; FIX-LIST
//! HOOK-HOSTED-HAND-OVER-TRANSCRIPT; REVIEW-9834). Where every
//! `session-start` of the session bound the selected hosted vault, and it is
//! still the one selected, a Claude Code session's log and its subagents'
//! logs, a workflow run's included, go to that vault through
//! `vault.imports.hook_transcript`, over `oneiron mcp` as the credential the
//! selection names, in its own auth mode, read below Claude Code's
//! `projects` folder through no link, in calls the sign-in's carrier takes.
//! A session that bound a pin, a session with no start, a config named and
//! a host whose log the verb does not read each keep the local queue, as
//! before. A session whose starts bound a hosted vault no longer selected,
//! or more than one vault, sends its log nowhere (review round 2).
//!
//! The shipped binary runs the hook. The `oneiron` it runs for the bridge
//! and the import is a stand-in that records its arguments and, as `oneiron
//! mcp`, answers the import and records the call it was sent, as
//! `agent_plugins_hooks.rs` does for the recall. How the vault lands the
//! session is `hook_transcript_import_served.rs`'s.
//!
//! Run with: `cargo test --locked -p oneiron-server --test hook_hosted_hand_over`.
#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use serde_json::{Value, json};

/// A selected hosted vault's origin that answers no probe. The stand-in
/// bridge never reaches an origin.
const ORIGIN: &str = "https://vault.example";
/// The selected hosted vault's id.
const VAULT_ID: &str = "4f6e6569726f6e2d686f737465642d68616e642d6f7665722d7465737430303031";
/// Another hosted vault's id, selected after a session bound the first.
const OTHER_VAULT_ID: &str = "4f6e6569726f6e2d686f737465642d68616e642d6f7665722d7465737430303032";
/// The Claude Code session the hand-over sends.
const SESSION: &str = "0b5e55e0-3333-4444-8555-a66677778888";
/// Its one subagent's log stem, in its `subagents` folder.
const SUBAGENT: &str = "agent-a1b2c3";
/// A workflow run's subagent's log stem, in the run's folder there.
const WORKFLOW_SUBAGENT: &str = "agent-d4e5f6";
/// What a server's `GET /.well-known/oneiron` answers, for a probe.
const DESCRIPTOR: &str = r#"{"protocol":"oneiron-pairing","slip_version":2,"binding":"ed25519","pairing_endpoint":"/v1/core/pairing/redeem"}"#;
/// The conversation the stand-in answers the import with.
const CONVERSATION: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

/// The bridge and import a hook runs, stood in by a script that writes its
/// arguments to `@RECORD@/argv` and, as `oneiron mcp`, answers the
/// handshake and each import, and writes each `tools/call` it was sent to
/// `@RECORD@/call-<id>` and the last to `@RECORD@/call`.
const STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@" > '@RECORD@/argv'
[ "$1" = mcp ] || exit 0
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stand-in","version":"1"}}}'
read -r line
id=1
while read -r line; do
    id=$((id + 1))
    printf '%s\n' "$line" > "@RECORD@/call-$id"
    printf '%s\n' "$line" > '@RECORD@/call'
    printf '{"jsonrpc":"2.0","id":%s,"result":{"structuredContent":{"output":{"conversation":"@CONVERSATION@","conversations":[]}}}}\n' "$id"
done
"#;

/// A bridge that answers the handshake, writes its pid to `@RECORD@/pid`,
/// then stops reading (suspended, say) for a minute.
const STALLED_STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@" > '@RECORD@/argv'
printf '%s\n' "$$" > '@RECORD@/pid'
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stand-in","version":"1"}}}'
read -r line
sleep 60
"#;

/// A home with nothing in it but what a test writes, so no hook sees the
/// host's vaults, runtime files, pin or hosted selection, and the stand-in
/// `oneiron` it runs.
struct Bench {
    dir: tempfile::TempDir,
}

impl Bench {
    fn new() -> Self {
        let bench = Self {
            dir: tempfile::tempdir().expect("test fixture"),
        };
        for dir in ["home", "config", "runtime", "record", "outside"] {
            std::fs::create_dir(bench.path(dir)).expect("test fixture");
        }
        std::fs::create_dir_all(bench.projects()).expect("test fixture");
        bench.write_stand_in(STAND_IN);
        bench
    }

    /// Makes `script` the `oneiron` the hooks run.
    fn write_stand_in(&self, script: &str) {
        let script = script
            .replace(
                "@RECORD@",
                self.path("record").to_str().expect("UTF-8 path"),
            )
            .replace("@CONVERSATION@", CONVERSATION);
        let _ = std::fs::remove_file(self.stand_in());
        // A child writes the script, so this process never holds it open for
        // writing while another test's child starts (ETXTBSY).
        let written = Command::new("sh")
            .args(["-c", r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#, "sh"])
            .arg(&script)
            .arg(self.stand_in())
            .status()
            .expect("run sh");
        assert!(written.success(), "write the stand-in");
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn stand_in(&self) -> PathBuf {
        self.path("oneiron-stand-in")
    }

    /// Claude Code's config folder, where `CLAUDE_CONFIG_DIR` points.
    fn claude_config(&self) -> PathBuf {
        self.path("claude")
    }

    /// Claude Code's folder of project folders.
    fn projects(&self) -> PathBuf {
        self.claude_config().join("projects")
    }

    /// The per-user oneiron folder, where `hosted.json` and `hook.toml` live.
    fn user_dir(&self) -> PathBuf {
        self.path("config").join("oneiron")
    }

    /// The folder runtime files are in, where `XDG_RUNTIME_DIR` points.
    fn run_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.user_dir().join("run")
        } else {
            self.path("runtime").join("oneiron")
        }
    }

    /// Records one hosted vault at `origin` with id `vault_id` signed in to
    /// here in `mode`, selected, as `oneiron hosted` publishes it:
    /// owner-only, naming the credential file and never a value in it. It
    /// replaces any selection made before.
    fn select_hosted(&self, origin: &str, vault_id: &str, mode: &str, credential: &Path) {
        let selection = json!({
            "vaults": [{
                "origin": origin,
                "vault_id": vault_id,
                "auth_mode": mode,
                "credential_file": credential,
                "verified_at_ms": 1_790_000_000_000_u64,
            }],
            "selected": vault_id,
        });
        let file = self.user_dir().join("hosted.json");
        let _ = std::fs::remove_file(&file);
        owner_only_file(&file, &selection.to_string());
    }

    /// A runtime file as `serve` writes it, for a server whose pid lives
    /// (this test's own) and which read `config`.
    fn running_local_vault(&self, config: &Path) {
        let runtime = json!({
            "vault_id": null,
            "url": "http://local.vault.example",
            "pid": std::process::id(),
            "state_dir": self.path("vault"),
            "config": config,
            "settings_file": null,
            "started_at_ms": 1_790_000_000_000_u64,
        });
        owner_only_file(&self.run_dir().join("local.json"), &runtime.to_string());
    }

    /// A Claude Code session log and its subagent's, in Claude Code's own
    /// layout, every line a whole record: the session's log path.
    fn session_log(&self) -> PathBuf {
        let folder = self.projects().join("-tmp-heron-lantern");
        let log = folder.join(format!("{SESSION}.jsonl"));
        let subagents = folder.join(SESSION).join("subagents");
        std::fs::create_dir_all(&subagents).expect("test fixture");
        std::fs::write(&log, turns(false)).expect("test fixture");
        std::fs::write(subagents.join(format!("{SUBAGENT}.jsonl")), turns(true))
            .expect("test fixture");
        log
    }

    /// Runs `oneiron hook --host <host> <event> <args>` with `payload` on
    /// stdin and `env` set, which exits 0; what it printed.
    fn hook(&self, host: &str, event: &[&str], env: &[(&str, &str)], payload: &Value) -> String {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(["hook", "--host", host])
            .args(event)
            .arg("--oneiron")
            .arg(self.stand_in())
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("CLAUDE_CONFIG_DIR", self.claude_config())
            .env_remove("ONEIRON_CONFIG")
            .env_remove("ONEIRON_URL")
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY");
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn oneiron hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write the hook event");
        let output = child.wait_with_output().expect("run oneiron hook");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{host} {event:?}: a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 stdout")
    }

    /// Runs `oneiron hook --host <host> hand-over <args>` with `payload` on
    /// stdin and `env` set, which exits 0 and prints nothing.
    fn hand_over(&self, host: &str, args: &[&str], env: &[(&str, &str)], payload: &Value) {
        let mut event = vec!["hand-over"];
        event.extend(args);
        let said = self.hook(host, &event, env, payload);
        assert!(said.is_empty(), "{host}: a hand-over prints nothing");
    }

    /// Starts the Claude Code session whose log is at `log`, with `args`
    /// and no recall: the vault it binds, as its first line names it.
    fn session_start(&self, args: &[&str], log: &Path) -> String {
        self.session_start_from("startup", args, log)
    }

    /// Starts the Claude Code session whose log is at `log` as Claude Code
    /// does for `source` (`startup`, `resume`, `compact`), with `args` and
    /// no recall: the vault it binds, as its first line names it.
    fn session_start_from(&self, source: &str, args: &[&str], log: &Path) -> String {
        let mut event = vec!["session-start", "--query", ""];
        event.extend(args);
        let payload = json!({
            "hook_event_name": "SessionStart",
            "session_id": SESSION,
            "transcript_path": log,
            "cwd": "/tmp/heron-lantern",
            "source": source,
        });
        self.hook("claude-code", &event, &[], &payload)
    }

    /// Forgets what the stand-in recorded, so a later look sees only what
    /// ran after.
    fn forget_runs(&self) {
        for entry in std::fs::read_dir(self.path("record")).expect("test fixture") {
            std::fs::remove_file(entry.expect("test fixture").path()).expect("test fixture");
        }
    }

    /// Whether no `oneiron` ran since [`Bench::forget_runs`]: no bridge, no
    /// import queued.
    fn ran_nothing(&self) -> bool {
        !self.path("record").join("argv").exists()
    }

    /// What the stand-in wrote to `name`.
    fn recorded(&self, name: &str) -> String {
        std::fs::read_to_string(self.path("record").join(name))
            .unwrap_or_else(|error| panic!("the stand-in wrote no {name}: {error}"))
    }

    /// The arguments the stand-in was last run with.
    fn argv(&self) -> Vec<String> {
        self.recorded("argv").lines().map(str::to_owned).collect()
    }

    /// Whether the stand-in bridge was sent a call.
    fn called(&self) -> bool {
        self.path("record").join("call").exists()
    }

    /// The `vault.imports.hook_transcript` spec the stand-in bridge was
    /// sent.
    fn sent_spec(&self) -> Value {
        self.spec_in("call")
    }

    /// The `vault.imports.hook_transcript` spec of the call the stand-in
    /// wrote to `name`.
    fn spec_in(&self, name: &str) -> Value {
        let call: Value = serde_json::from_str(&self.recorded(name)).expect("one JSON-RPC call");
        assert_eq!(call["params"]["name"], "vault.imports.hook_transcript");
        call["params"]["arguments"]["arguments"]["spec"].clone()
    }
}

/// A listener that answers every request as a server's
/// `GET /.well-known/oneiron` does, for a probe of a pinned or selected
/// vault: its origin.
fn answering_vault() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test fixture");
    let url = format!("http://{}", listener.local_addr().expect("test fixture"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => break,
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{DESCRIPTOR}",
                DESCRIPTOR.len()
            );
        }
    });
    url
}

/// `body` at `path`, owner-only, in an owner-only folder.
fn owner_only_file(path: &Path, body: &str) {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path.parent().expect("a folder"))
        .expect("test fixture");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .expect("test fixture");
}

/// Two whole Claude Code log lines, a user turn then an assistant turn: the
/// session's own, or its subagent's.
fn turns(sidechain: bool) -> String {
    let (said, answered) = if sidechain {
        (
            "Find where the heron lantern timetable is kept.",
            "It is kept beside the pier nine ledger.",
        )
    } else {
        (
            "For the heron lantern project, keep the ferry timetable in pier nine order.",
            "Noted: the heron lantern timetable stays in pier nine order.",
        )
    };
    let user = json!({
        "parentUuid": null,
        "isSidechain": sidechain,
        "userType": "external",
        "cwd": "/tmp/heron-lantern",
        "sessionId": SESSION,
        "version": "2.1.0",
        "type": "user",
        "uuid": "d2000000-0000-4000-8000-000000000001",
        "timestamp": "2026-11-20T01:00:00.000Z",
        "message": {"role": "user", "content": said},
    });
    let assistant = json!({
        "parentUuid": "d2000000-0000-4000-8000-000000000001",
        "isSidechain": sidechain,
        "userType": "external",
        "cwd": "/tmp/heron-lantern",
        "sessionId": SESSION,
        "version": "2.1.0",
        "type": "assistant",
        "uuid": "d2000000-0000-4000-8000-000000000002",
        "timestamp": "2026-11-20T01:00:05.000Z",
        "message": {
            "id": "msg_0002",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [{"type": "text", "text": answered}],
        },
    });
    format!("{user}\n{assistant}\n")
}

/// The Claude Code `Stop` event for the session log at `log`.
fn claude_code_stop(log: &Path) -> Value {
    json!({
        "hook_event_name": "Stop",
        "session_id": SESSION,
        "transcript_path": log,
        "cwd": "/tmp/heron-lantern",
        "stop_hook_active": false,
    })
}

/// The bytes a log travels as, gzip-compressed in standard base64.
fn inflated(encoded: &Value) -> Vec<u8> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_str().expect("a base64 string"))
        .expect("standard base64");
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut bytes)
        .expect("gzip");
    bytes
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|word| (*word).to_owned()).collect()
}

/// `len` characters gzip barely shrinks: a base64 rendering of a xorshift
/// stream from `seed`, so a log's encoded length is about its own.
fn noise(len: usize, seed: u64) -> String {
    let mut state = seed | 1;
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() * 4 / 3 < len + 8 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    let mut text = base64::engine::general_purpose::STANDARD.encode(bytes);
    text.truncate(len);
    text
}

/// One whole Claude Code log line, a user turn of the session saying
/// `len` characters of [`noise`] from `seed`.
fn noisy_turn(len: usize, seed: u64) -> String {
    let user = json!({
        "parentUuid": null,
        "isSidechain": false,
        "userType": "external",
        "cwd": "/tmp/heron-lantern",
        "sessionId": SESSION,
        "version": "2.1.0",
        "type": "user",
        "uuid": "d2000000-0000-4000-8000-000000000003",
        "timestamp": "2026-11-20T01:00:00.000Z",
        "message": {"role": "user", "content": noise(len, seed)},
    });
    format!("{user}\n")
}

/// The stems of the subagent logs a spec carries.
fn stems(spec: &Value) -> Vec<String> {
    spec["subagents"]
        .as_array()
        .expect("subagent logs")
        .iter()
        .map(|subagent| subagent["stem"].as_str().expect("a stem").to_owned())
        .collect()
}

#[test]
fn a_claude_code_hand_over_sends_its_log_to_the_selected_hosted_vault_in_its_own_auth_mode() {
    for (mode, flags) in [
        ("slip", &["--credential-file"][..]),
        (
            "owner",
            &["--auth-mode", "owner", "--owner-upgrade-headers-file"][..],
        ),
        ("oauth", &["--auth-mode", "oauth", "--oauth-token-file"][..]),
    ] {
        let bench = Bench::new();
        let origin = answering_vault();
        let credential = bench.path(&format!("{mode}-credential"));
        let credential_arg = credential.to_str().expect("UTF-8 path");
        bench.select_hosted(&origin, VAULT_ID, mode, &credential);
        let log = bench.session_log();
        let said = bench.session_start(&[], &log);
        assert!(
            said.contains("uses your hosted vault") && said.contains(&origin),
            "{mode}: the session binds the selected hosted vault: {said}"
        );
        bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));

        // One bridge to the selected vault as its own credential, in its
        // own mode; nothing queued here.
        let mut bridge = words(&["mcp", "--url", &origin, "--surface", "tool-first"]);
        bridge.extend(words(flags));
        bridge.push(credential_arg.to_owned());
        assert_eq!(bench.argv(), bridge, "{mode}");

        // Its one call is the import of the session's log and its
        // subagent's, byte for byte, under the hooks' consent.
        let call: Value = serde_json::from_str(&bench.recorded("call")).expect("one JSON-RPC call");
        assert_eq!(call["method"], "tools/call", "{mode}");
        assert_eq!(
            call["params"]["name"], "vault.imports.hook_transcript",
            "{mode}"
        );
        let arguments = &call["params"]["arguments"];
        assert_eq!(arguments["schema_version"], "mcp_tool_args.v1", "{mode}");
        assert_eq!(
            arguments["consent"],
            json!({
                "policy_ref": "policy:claude-code-hooks",
                "purpose": "land this session's log in the selected vault",
            }),
            "{mode}"
        );
        let spec = &arguments["arguments"]["spec"];
        assert_eq!(spec["session"], SESSION, "{mode}");
        assert_eq!(
            inflated(&spec["transcript_gzip_base64"]),
            std::fs::read(&log).expect("the session log"),
            "{mode}"
        );
        let subagents = spec["subagents"].as_array().expect("subagent logs");
        assert_eq!(subagents.len(), 1, "{mode}: {spec}");
        assert_eq!(subagents[0]["stem"], SUBAGENT, "{mode}");
        assert_eq!(
            inflated(&subagents[0]["transcript_gzip_base64"]),
            turns(true).into_bytes(),
            "{mode}"
        );
    }
}

#[test]
fn a_pin_a_running_local_vault_a_named_config_or_another_hosts_log_keeps_the_local_queue() {
    let bench = Bench::new();
    bench.select_hosted(ORIGIN, VAULT_ID, "slip", &bench.path("slip-credential"));
    let log = bench.session_log();
    let log_arg = log.to_str().expect("UTF-8 path");
    let local_queue = words(&["import", "claude-code", log_arg, "--queue"]);

    // A session whose start recorded nothing (it started before the
    // record): the local queue, as every hand-over did before.
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert_eq!(bench.argv(), local_queue, "no session start");

    // A config named here is a local queue's.
    let config = bench.path("oneiron.toml");
    let config_arg = config.to_str().expect("UTF-8 path");
    bench.hand_over(
        "claude-code",
        &["--config", config_arg],
        &[],
        &claude_code_stop(&log),
    );
    let mut queued = local_queue.clone();
    queued.extend(words(&["--config", config_arg]));
    assert_eq!(bench.argv(), queued, "a config named");

    // A pin is never swapped for the hosted vault: with no vault running at
    // it, the default config's queue, as before.
    bench.hand_over(
        "claude-code",
        &[],
        &[("ONEIRON_URL", "http://pinned.vault.example")],
        &claude_code_stop(&log),
    );
    assert_eq!(bench.argv(), local_queue, "a pin");

    // The verb reads only a Claude Code log: a Codex session's log is queued
    // for the import that reads it.
    let codex_log = bench.path("rollout.jsonl");
    let codex_log_arg = codex_log.to_str().expect("UTF-8 path");
    bench.hand_over(
        "codex",
        &[],
        &[],
        &json!({
            "session_id": "thr_heron",
            "transcript_path": codex_log,
            "cwd": "/tmp/heron-lantern",
            "hook_event_name": "Stop",
            "model": "gpt-5",
            "turn_id": "turn_1",
            "stop_hook_active": false,
            "last_assistant_message": "Done.",
        }),
    );
    assert_eq!(
        bench.argv(),
        words(&["import", "codex", codex_log_arg, "--queue"]),
        "a Codex log"
    );

    // A running local vault comes before the hosted one, as a session binds:
    // its own config's queue.
    let running = bench.path("running.toml");
    let running_arg = running.to_str().expect("UTF-8 path");
    bench.running_local_vault(&running);
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    let mut queued = local_queue;
    queued.extend(words(&["--config", running_arg]));
    assert_eq!(bench.argv(), queued, "a running local vault");
    assert!(
        !bench.path("record").join("call").exists(),
        "no case called the hosted vault"
    );
}

#[test]
fn a_session_that_bound_a_pin_or_another_hosted_vault_never_sends_its_log_to_the_selected_one() {
    // REVIEW-9834 P1 bind.rs:250: a session pinned by its hook's `--url`
    // binds the pin, which its hand-over never sees; the selected hosted
    // vault answers, and no local vault runs.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    let log_arg = log.to_str().expect("UTF-8 path");
    let local_queue = words(&["import", "claude-code", log_arg, "--queue"]);
    let pin = answering_vault();
    let said = bench.session_start(&["--url", &pin], &log);
    assert!(
        said.contains("pinned by --url") && said.contains(&pin),
        "the session binds its pin: {said}"
    );
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert!(
        !bench.called(),
        "the pinned session's log went to the hosted vault"
    );
    assert_eq!(bench.argv(), local_queue, "a session that bound a pin");

    // A session that bound one hosted vault, which another selection then
    // replaced: its log goes to neither, and to no local vault that starts
    // running after (review round 2, bind.rs:255).
    let bench = Bench::new();
    let credential = bench.path("slip-credential");
    bench.select_hosted(&answering_vault(), VAULT_ID, "slip", &credential);
    let log = bench.session_log();
    let said = bench.session_start(&[], &log);
    assert!(
        said.contains("uses your hosted vault"),
        "the session binds the selected hosted vault: {said}"
    );
    bench.select_hosted(&answering_vault(), OTHER_VAULT_ID, "slip", &credential);
    bench.forget_runs();
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert!(
        bench.ran_nothing(),
        "the log of a session whose hosted vault is no longer selected went somewhere: {:?}",
        bench.recorded("argv")
    );
    bench.running_local_vault(&bench.path("running.toml"));
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert!(
        bench.ran_nothing(),
        "a hosted session's log was queued to a local vault it never bound: {:?}",
        bench.recorded("argv")
    );
}

#[test]
fn a_session_that_bound_the_hosted_vault_past_a_silent_local_one_sends_its_log_there() {
    // REVIEW-9834 P1 bind.rs:254: a local `serve` that keeps its pid and
    // runtime file but answers no probe (stopped, say) is passed over at
    // session start, which binds the selected hosted vault; the hand-over
    // sends there, not to the silent vault's queue.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID, "slip", &bench.path("slip-credential"));
    bench.running_local_vault(&bench.path("silent.toml"));
    let log = bench.session_log();
    let said = bench.session_start(&[], &log);
    assert!(
        said.contains("uses your hosted vault") && said.contains(&origin),
        "the session passes the silent local vault over: {said}"
    );
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert_eq!(
        bench.argv().get(..3),
        Some(&words(&["mcp", "--url", &origin])[..]),
        "the hand-over goes to the vault the session bound"
    );
    assert_eq!(bench.sent_spec()["session"], SESSION);
}

#[test]
fn a_hand_over_sends_a_workflow_runs_subagent_logs_and_follows_no_link() {
    // REVIEW-9834 P1 transcript.rs:71: a workflow run's subagent log, one
    // folder down in `subagents`, goes with the session's.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    let run = log
        .with_extension("")
        .join("subagents")
        .join("workflow-run-1");
    std::fs::create_dir(&run).expect("test fixture");
    std::fs::write(run.join(format!("{WORKFLOW_SUBAGENT}.jsonl")), turns(true))
        .expect("test fixture");
    bench.session_start(&[], &log);
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    let spec = bench.sent_spec();
    let stems: Vec<&str> = spec["subagents"]
        .as_array()
        .expect("subagent logs")
        .iter()
        .map(|subagent| subagent["stem"].as_str().expect("a stem"))
        .collect();
    assert_eq!(stems, [SUBAGENT, WORKFLOW_SUBAGENT], "{spec}");

    // REVIEW-9834 P1 continue_command.rs:439: a `subagents` folder that is a
    // link to logs outside the session's folders is not followed; the
    // session's own log still goes.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    let subagents = log.with_extension("").join("subagents");
    std::fs::remove_dir_all(&subagents).expect("test fixture");
    std::fs::write(
        bench.path("outside").join("agent-outside.jsonl"),
        turns(true),
    )
    .expect("test fixture");
    std::os::unix::fs::symlink(bench.path("outside"), &subagents).expect("test fixture");
    bench.session_start(&[], &log);
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    let spec = bench.sent_spec();
    assert_eq!(spec["session"], SESSION);
    assert_eq!(
        spec["subagents"],
        json!([]),
        "a log behind a link went with the session"
    );
}

#[test]
fn a_session_whose_starts_bound_different_vaults_sends_its_log_nowhere() {
    // Review round 2, hook.rs:144: a session started on hosted A, then
    // resumed or compacted with hosted B selected, holds turns from A: its
    // log goes to neither, even once A is selected again.
    for source in ["resume", "compact"] {
        let bench = Bench::new();
        let credential = bench.path("slip-credential");
        let first = answering_vault();
        bench.select_hosted(&first, VAULT_ID, "slip", &credential);
        let log = bench.session_log();
        bench.session_start(&[], &log);
        let second = answering_vault();
        bench.select_hosted(&second, OTHER_VAULT_ID, "slip", &credential);
        let said = bench.session_start_from(source, &[], &log);
        assert!(
            said.contains("uses your hosted vault") && said.contains(&second),
            "{source}: the start binds the vault selected now: {said}"
        );
        bench.forget_runs();
        bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
        assert!(
            bench.ran_nothing(),
            "{source}: turns from the first vault went with the log: {:?}",
            bench.recorded("argv")
        );
        bench.select_hosted(&first, VAULT_ID, "slip", &credential);
        bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
        assert!(
            bench.ran_nothing(),
            "{source}: turns from the second vault went with the log: {:?}",
            bench.recorded("argv")
        );
    }

    // A resumed session with no record of its earlier turns: their vault is
    // not known, so its log goes nowhere.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    bench.session_start_from("resume", &[], &log);
    bench.forget_runs();
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert!(
        bench.ran_nothing(),
        "a resumed session's earlier turns went to a vault: {:?}",
        bench.recorded("argv")
    );

    // A session compacted and resumed with the one vault it started on still
    // selected sends its log there.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID, "slip", &bench.path("slip-credential"));
    let log = bench.session_log();
    bench.session_start(&[], &log);
    bench.session_start_from("compact", &[], &log);
    bench.session_start_from("resume", &[], &log);
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert_eq!(
        bench.argv().get(..3),
        Some(&words(&["mcp", "--url", &origin])[..]),
        "a session that bound one vault throughout sends its log there"
    );
    assert_eq!(bench.sent_spec()["session"], SESSION);
}

#[test]
fn a_hand_over_sends_only_the_log_of_its_own_session() {
    // Review round 2, hook.rs:278: an event of the session that bound the
    // vault, naming another session's log, sends nothing.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    bench.session_start(&[], &log);
    let other = log.with_file_name("1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b.jsonl");
    std::fs::write(&other, turns(false)).expect("test fixture");
    bench.forget_runs();
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&other));
    assert!(
        bench.ran_nothing(),
        "another session's log went where this session bound: {:?}",
        bench.recorded("argv")
    );
}

#[test]
fn a_hand_over_sends_only_calls_the_sign_ins_carrier_takes() {
    // Review round 2, continue_command.rs:441: the owner's calls go over the
    // vault's socket alone, whose frame is about 8 MiB. A session log whose
    // encoding is longer is not sent at all: no bridge starts.
    let long_log = |bench: &Bench| {
        let log = bench.session_log();
        std::fs::write(&log, noisy_turn(9 * 1024 * 1024, 7)).expect("test fixture");
        log
    };
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "owner",
        &bench.path("owner-credential"),
    );
    let log = long_log(&bench);
    bench.session_start(&[], &log);
    bench.forget_runs();
    bench.hand_over(
        "claude-code",
        &["--timeout", "120"],
        &[],
        &claude_code_stop(&log),
    );
    assert!(
        bench.ran_nothing(),
        "a log too long for the owner's socket was sent: {:?}",
        bench.recorded("argv")
    );

    // A slip's calls go over HTTP past the socket's frame: the same log goes
    // in one call.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = long_log(&bench);
    bench.session_start(&[], &log);
    bench.hand_over(
        "claude-code",
        &["--timeout", "120"],
        &[],
        &claude_code_stop(&log),
    );
    let spec = bench.spec_in("call-2");
    assert_eq!(
        inflated(&spec["transcript_gzip_base64"]),
        std::fs::read(&log).expect("the session log"),
        "the slip's call carries the whole log"
    );
    assert!(!bench.path("record").join("call-3").exists(), "one call");

    // Subagents' logs that do not fit one owner's call with the session's
    // log go in further calls, in name order, each with the session's log.
    let bench = Bench::new();
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "owner",
        &bench.path("owner-credential"),
    );
    let log = bench.session_log();
    let subagents = log.with_extension("").join("subagents");
    for (stem, seed) in [("agent-noise1", 11), ("agent-noise2", 13)] {
        std::fs::write(
            subagents.join(format!("{stem}.jsonl")),
            noisy_turn(4_400_000, seed),
        )
        .expect("test fixture");
    }
    bench.session_start(&[], &log);
    bench.hand_over(
        "claude-code",
        &["--timeout", "120"],
        &[],
        &claude_code_stop(&log),
    );
    let first = bench.spec_in("call-2");
    let second = bench.spec_in("call-3");
    assert!(!bench.path("record").join("call-4").exists(), "two calls");
    assert_eq!(stems(&first), [SUBAGENT, "agent-noise1"], "the first call");
    assert_eq!(stems(&second), ["agent-noise2"], "the second call");
    for spec in [&first, &second] {
        assert_eq!(spec["session"], SESSION);
        assert_eq!(
            inflated(&spec["transcript_gzip_base64"]),
            std::fs::read(&log).expect("the session log"),
            "each call carries the session's log"
        );
    }
    assert_eq!(
        inflated(&second["subagents"][0]["transcript_gzip_base64"]),
        std::fs::read(subagents.join("agent-noise2.jsonl")).expect("the subagent log"),
    );
}

#[test]
fn a_bridge_that_stops_reading_is_ended_at_the_deadline() {
    // Review round 2, continue_command.rs:441: a bridge that answered its
    // handshake, then stopped reading, never holds the hand-over past its
    // deadline; the bridge is ended and reaped.
    let bench = Bench::new();
    bench.write_stand_in(STALLED_STAND_IN);
    bench.select_hosted(
        &answering_vault(),
        VAULT_ID,
        "slip",
        &bench.path("slip-credential"),
    );
    let log = bench.session_log();
    // More than a pipe holds, so the write itself waits on the bridge.
    std::fs::write(&log, noisy_turn(1024 * 1024, 17)).expect("test fixture");
    bench.session_start(&[], &log);
    let (ended, done) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            bench.hand_over(
                "claude-code",
                &["--timeout", "3"],
                &[],
                &claude_code_stop(&log),
            );
            let _ = ended.send(());
        });
        assert!(
            done.recv_timeout(std::time::Duration::from_secs(30))
                .is_ok(),
            "the hand-over outlived its 3 s deadline by far"
        );
    });
    let pid = bench.recorded("pid");
    let alive = Command::new("kill")
        .args(["-0", pid.trim()])
        .stderr(Stdio::null())
        .status()
        .expect("run kill");
    assert!(!alive.success(), "the stalled bridge {pid} still runs");
}

#[test]
fn a_start_never_undoes_another_starts_record() {
    // Review round 2, session_binding.rs:122: a start whose record fails
    // never removes the record another start of the session made. Here the
    // other start's staging file holds the name a shared staging path would
    // use.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID, "slip", &bench.path("slip-credential"));
    let log = bench.session_log();
    bench.session_start(&[], &log);
    std::fs::create_dir(
        bench
            .run_dir()
            .join("hook-sessions")
            .join(format!(".{SESSION}.json.tmp")),
    )
    .expect("test fixture");
    bench.session_start_from("compact", &[], &log);
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert_eq!(
        bench.argv().get(..3),
        Some(&words(&["mcp", "--url", &origin])[..]),
        "the session's record went with a failed start"
    );

    // Starts of one session at once each leave the record.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID, "slip", &bench.path("slip-credential"));
    let log = bench.session_log();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| bench.session_start(&[], &log));
        }
    });
    bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));
    assert_eq!(
        bench.argv().get(..3),
        Some(&words(&["mcp", "--url", &origin])[..]),
        "starts at once removed the session's record"
    );
}
