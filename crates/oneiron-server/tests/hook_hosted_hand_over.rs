//! `oneiron hook --host <host> hand-over` with a hosted vault selected (H41,
//! ARCH-0028 `#plugin-first-run` step 3; FIX-LIST
//! HOOK-HOSTED-HAND-OVER-TRANSCRIPT). Where a session binds the selected
//! hosted vault (no pin is set and no local vault runs), a Claude Code
//! session's log and its subagents' logs go to that vault through
//! `vault.imports.hook_transcript`, over `oneiron mcp` as the credential the
//! selection names, in its own auth mode. A pin, a running local vault, a
//! config named and a host whose log the verb does not read each keep the
//! local queue, as before.
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
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine as _;
use serde_json::{Value, json};

/// The selected hosted vault's origin. The stand-in bridge never reaches it.
const ORIGIN: &str = "https://vault.example";
/// The selected hosted vault's id.
const VAULT_ID: &str = "4f6e6569726f6e2d686f737465642d68616e642d6f7665722d7465737430303031";
/// The Claude Code session the hand-over sends.
const SESSION: &str = "0b5e55e0-3333-4444-8555-a66677778888";
/// Its one subagent's log stem.
const SUBAGENT: &str = "agent-a1b2c3";
/// The conversation the stand-in answers the import with.
const CONVERSATION: &str = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0";

/// The bridge and import a hook runs, stood in by a script that writes its
/// arguments to `@RECORD@/argv` and, as `oneiron mcp`, answers the
/// handshake and one import and writes the `tools/call` it was sent to
/// `@RECORD@/call`.
const STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@" > '@RECORD@/argv'
[ "$1" = mcp ] || exit 0
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stand-in","version":"1"}}}'
read -r line
read -r line
printf '%s\n' "$line" > '@RECORD@/call'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"output":{"conversation":"@CONVERSATION@","conversations":[]}}}}'
read -r line
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
        for dir in ["home", "config", "runtime", "record", "projects"] {
            std::fs::create_dir(bench.path(dir)).expect("test fixture");
        }
        let script = STAND_IN
            .replace(
                "@RECORD@",
                bench.path("record").to_str().expect("UTF-8 path"),
            )
            .replace("@CONVERSATION@", CONVERSATION);
        // A child writes the script, so this process never holds it open for
        // writing while another test's child starts (ETXTBSY).
        let written = Command::new("sh")
            .args(["-c", r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#, "sh"])
            .arg(&script)
            .arg(bench.stand_in())
            .status()
            .expect("run sh");
        assert!(written.success(), "write the stand-in");
        bench
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn stand_in(&self) -> PathBuf {
        self.path("oneiron-stand-in")
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

    /// Records one hosted vault signed in to here in `mode`, selected, as
    /// `oneiron hosted` publishes it: owner-only, naming the credential file
    /// and never a value in it.
    fn select_hosted(&self, mode: &str, credential: &Path) {
        let selection = json!({
            "vaults": [{
                "origin": ORIGIN,
                "vault_id": VAULT_ID,
                "auth_mode": mode,
                "credential_file": credential,
                "verified_at_ms": 1_790_000_000_000_u64,
            }],
            "selected": VAULT_ID,
        });
        owner_only_file(&self.user_dir().join("hosted.json"), &selection.to_string());
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
        let folder = self.path("projects").join("-tmp-heron-lantern");
        let log = folder.join(format!("{SESSION}.jsonl"));
        let subagents = folder.join(SESSION).join("subagents");
        std::fs::create_dir_all(&subagents).expect("test fixture");
        std::fs::write(&log, turns(false)).expect("test fixture");
        std::fs::write(subagents.join(format!("{SUBAGENT}.jsonl")), turns(true))
            .expect("test fixture");
        log
    }

    /// Runs `oneiron hook --host <host> hand-over <args>` with `payload` on
    /// stdin and `env` set, which exits 0 and prints nothing.
    fn hand_over(&self, host: &str, args: &[&str], env: &[(&str, &str)], payload: &Value) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(["hook", "--host", host, "hand-over"])
            .args(args)
            .arg("--oneiron")
            .arg(self.stand_in())
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
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
            "{host} hand-over: a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "{host}: a hand-over prints nothing"
        );
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
        let credential = bench.path(&format!("{mode}-credential"));
        let credential_arg = credential.to_str().expect("UTF-8 path");
        bench.select_hosted(mode, &credential);
        let log = bench.session_log();
        bench.hand_over("claude-code", &[], &[], &claude_code_stop(&log));

        // One bridge to the selected vault as its own credential, in its
        // own mode; nothing queued here.
        let mut bridge = words(&["mcp", "--url", ORIGIN, "--surface", "tool-first"]);
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
    bench.select_hosted("slip", &bench.path("slip-credential"));
    let log = bench.session_log();
    let log_arg = log.to_str().expect("UTF-8 path");
    let local_queue = words(&["import", "claude-code", log_arg, "--queue"]);

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
