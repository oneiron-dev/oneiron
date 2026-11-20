//! `oneiron hook --host codex session-start` for a Codex fork (FIX-LIST
//! HOOK-HAND-OVER-CODEX-FORK-PARENT-TURNS; REVIEW-9914 round 1). Codex
//! starts a fork (`codex fork`, `/fork`, `/side`, an edited earlier prompt)
//! with `source` `startup`, as a new session, and names no parent in the
//! event; its rollout's own `session_meta` line names the session it was
//! forked from as `forked_from_id`, then holds a copy of that session's
//! turns, all written before the hook runs (Codex rust-v0.153.3,
//! core/src/session/session.rs: `InitialHistory::Forked` starts as
//! `Startup`). A hand-over sends that whole rollout, so the fork's first
//! start records the binding of the session it was forked from before its
//! own: a fork of a session that bound the selected hosted vault sends its
//! log there, and a fork of a session that bound another vault, a pin, more
//! than one binding or nothing sends it nowhere; its record is one file,
//! so no write that fails leaves the copied turns' binding alone (REVIEW-9973
//! round 1). A rollout whose first line is not a whole `session_meta`, with
//! an object payload, holds turns no start can place: its log goes nowhere
//! too. A record that is a FIFO never holds a start up.
//!
//! The shipped binary runs the hook; the `oneiron` it runs for the bridge
//! and the import is a stand-in that records its arguments and, as `oneiron
//! mcp`, answers the import, as in `hook_hosted_hand_over.rs`.
//!
//! Run with: `cargo test --locked -p oneiron-server --test hook_codex_fork_binding`.
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
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};

/// The hosted vault the tests select.
const VAULT_ID: &str = "4f6e6569726f6e2d636f6465782d666f726b2d62696e64696e672d7465737431";
/// Another hosted vault, selected before it.
const OTHER_VAULT_ID: &str = "4f6e6569726f6e2d636f6465782d666f726b2d62696e64696e672d7465737432";
/// The Codex session a fork is made from.
const PARENT: &str = "019a7c2e-1111-4222-8333-444455556666";
/// The fork of [`PARENT`].
const FORK: &str = "019a7c2e-2222-4333-8444-555566667777";
/// The fork of [`FORK`].
const FORK_OF_FORK: &str = "019a7c2e-3333-4444-8555-666677778888";
/// How long one hook may run before a test calls it stuck.
const HOOK_LIMIT: Duration = Duration::from_secs(120);
/// What the probed origin answers as `GET /.well-known/oneiron`.
const DESCRIPTOR: &str = r#"{"protocol":"oneiron-pairing","slip_version":2,"binding":"ed25519","pairing_endpoint":"/v1/core/pairing/redeem"}"#;

/// The bridge and import a hook runs, stood in by a script that writes its
/// arguments to `@RECORD@/argv` and, as `oneiron mcp`, answers the
/// handshake and each import, and writes the last `tools/call` it was sent
/// to `@RECORD@/call`.
const STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@" > '@RECORD@/argv'
[ "$1" = mcp ] || exit 0
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stand-in","version":"1"}}}'
read -r line
id=1
while read -r line; do
    id=$((id + 1))
    printf '%s\n' "$line" > '@RECORD@/call'
    printf '{"jsonrpc":"2.0","id":%s,"result":{"structuredContent":{"output":{"conversation":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0","conversations":[]}}}}\n' "$id"
done
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
        for dir in ["home", "config", "runtime", "record"] {
            std::fs::create_dir(bench.path(dir)).expect("test fixture");
        }
        let script = STAND_IN.replace(
            "@RECORD@",
            bench.path("record").to_str().expect("UTF-8 path"),
        );
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

    /// The folder runtime files are in, where `XDG_RUNTIME_DIR` points.
    fn run_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.path("config").join("oneiron").join("run")
        } else {
            self.path("runtime").join("oneiron")
        }
    }

    /// The record of the Codex session `session`: the folder of the files
    /// its starts wrote.
    fn record(&self, session: &str) -> PathBuf {
        self.run_dir().join("hook-sessions-codex").join(session)
    }

    /// The names of the files in the record of the Codex session `session`,
    /// sorted.
    fn record_files(&self, session: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.record(session))
            .expect("the session's record")
            .map(|entry| {
                entry
                    .expect("test fixture")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect();
        names.sort();
        names
    }

    /// Selects the hosted vault `vault_id` at `origin`, signed in to here
    /// with a slip, as `oneiron hosted` publishes it, in place of any
    /// selection made before.
    fn select_hosted(&self, origin: &str, vault_id: &str) {
        let selection = json!({
            "vaults": [{
                "origin": origin,
                "vault_id": vault_id,
                "auth_mode": "slip",
                "credential_file": self.path("slip-credential"),
                "verified_at_ms": 1_790_000_000_000_u64,
            }],
            "selected": vault_id,
        });
        let file = self.path("config").join("oneiron").join("hosted.json");
        let _ = std::fs::remove_file(&file);
        owner_only_file(&file, &selection.to_string());
    }

    /// The rollout of the Codex session `session` below `~/.codex/sessions`.
    fn rollout(&self, session: &str) -> PathBuf {
        self.path("home")
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("11")
            .join("21")
            .join(format!("rollout-2026-11-21T01-00-00-{session}.jsonl"))
    }

    /// Writes `lines` as the rollout of `session`, its folders made.
    fn write_rollout(&self, session: &str, lines: &[Value]) {
        let rollout = self.rollout(session);
        std::fs::create_dir_all(rollout.parent().expect("a folder")).expect("test fixture");
        let text: String = lines.iter().map(|line| format!("{line}\n")).collect();
        std::fs::write(rollout, text).expect("test fixture");
    }

    /// Runs `oneiron hook --host codex <event>` with `payload` on stdin,
    /// which exits 0 within [`HOOK_LIMIT`]; what it printed.
    fn hook(&self, event: &[&str], payload: &Value) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["hook", "--host", "codex"])
            .args(event)
            .arg("--oneiron")
            .arg(self.stand_in())
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env_remove("CODEX_HOME")
            .env_remove("ONEIRON_CONFIG")
            .env_remove("ONEIRON_URL")
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
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
        let pid = child.id().to_string();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(child.wait_with_output());
        });
        let Ok(output) = receiver.recv_timeout(HOOK_LIMIT) else {
            let _ = Command::new("kill").args(["-KILL", &pid]).status();
            panic!("{event:?}: the hook is still running after {HOOK_LIMIT:?}");
        };
        let output = output.expect("run oneiron hook");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{event:?}: a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8 stdout")
    }

    /// Starts the Codex session `session` as Codex starts a new one or a
    /// fork, its rollout named, with `args` and no recall: what it said.
    fn start(&self, session: &str, args: &[&str]) -> String {
        let mut event = vec!["session-start", "--query", ""];
        event.extend(args);
        let payload = json!({
            "session_id": session,
            "transcript_path": self.rollout(session),
            "cwd": "/tmp/heron-lantern",
            "hook_event_name": "SessionStart",
            "model": "gpt-5",
            "permission_mode": "default",
            "source": "startup",
        });
        self.hook(&event, &payload)
    }

    /// Runs the hand-over of the Codex session `session`'s turn end, after
    /// forgetting what the stand-in recorded before.
    fn hand_over(&self, session: &str) {
        for entry in std::fs::read_dir(self.path("record")).expect("test fixture") {
            std::fs::remove_file(entry.expect("test fixture").path()).expect("test fixture");
        }
        let payload = json!({
            "session_id": session,
            "transcript_path": self.rollout(session),
            "cwd": "/tmp/heron-lantern",
            "hook_event_name": "Stop",
            "model": "gpt-5",
            "turn_id": "turn_1",
            "stop_hook_active": false,
            "last_assistant_message": "Done.",
        });
        let said = self.hook(&["hand-over"], &payload);
        assert!(said.is_empty(), "a hand-over prints nothing");
    }

    /// Whether the last hand-over ran no `oneiron`: no bridge, no import
    /// queued.
    fn ran_nothing(&self) -> bool {
        !self.path("record").join("argv").exists()
    }

    /// What the stand-in wrote to `name`.
    fn recorded(&self, name: &str) -> String {
        std::fs::read_to_string(self.path("record").join(name))
            .unwrap_or_else(|error| panic!("the stand-in wrote no {name}: {error}"))
    }

    /// Asserts that the last hand-over sent `session`'s whole rollout to
    /// the selected hosted vault at `origin`, and queued nothing here.
    fn assert_sent(&self, origin: &str, session: &str, case: &str) {
        let argv: Vec<String> = self.recorded("argv").lines().map(str::to_owned).collect();
        assert_eq!(
            argv[..3],
            ["mcp", "--url", origin],
            "{case}: one bridge to the vault"
        );
        let call: Value = serde_json::from_str(&self.recorded("call")).expect("one JSON-RPC call");
        assert_eq!(
            call["params"]["name"], "vault.imports.hook_transcript",
            "{case}"
        );
        let spec = &call["params"]["arguments"]["arguments"]["spec"];
        assert_eq!(spec["source"], "codex", "{case}: {spec}");
        assert_eq!(
            inflated(&spec["transcript_gzip_base64"]),
            std::fs::read(self.rollout(session)).expect("the rollout"),
            "{case}: the rollout goes byte for byte"
        );
    }

    /// Asserts that the last hand-over sent `session`'s rollout nowhere.
    fn assert_sent_nowhere(&self, case: &str) {
        assert!(
            self.ran_nothing(),
            "{case}: the fork's log went somewhere: {:?}",
            self.recorded("argv")
        );
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

/// The `session_meta` line Codex writes first in `session`'s rollout,
/// naming the session it was forked from, if any.
fn meta(session: &str, forked_from: Option<&str>) -> Value {
    let mut payload = json!({
        "session_id": session,
        "id": session,
        "timestamp": "2026-11-21T01:00:00.000Z",
        "cwd": "/tmp/heron-lantern",
        "originator": "codex_cli_rs",
        "cli_version": "0.153.3",
        "source": "cli",
        "base_instructions": {"text": "You are Codex."},
        "history_mode": "legacy",
    });
    if let Some(parent) = forked_from {
        payload["forked_from_id"] = json!(parent);
    }
    json!({"timestamp": "2026-11-21T01:00:00.000Z", "type": "session_meta", "payload": payload})
}

/// A user message and its answer, as `session`'s own turn `step`.
fn turn(session: &str, step: u32) -> Vec<Value> {
    vec![
        json!({"timestamp": "2026-11-21T01:00:01.000Z", "type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": format!("Heron lantern step {step} of {session}.")}]}}),
        json!({"timestamp": "2026-11-21T01:00:05.000Z", "type": "response_item", "payload": {"type": "message", "role": "assistant", "id": format!("msg_{step}_{session}"), "content": [{"type": "output_text", "text": "Noted."}]}}),
    ]
}

/// The rollout of a session with one turn of its own.
fn new_rollout(session: &str) -> Vec<Value> {
    let mut lines = vec![meta(session, None)];
    lines.extend(turn(session, 1));
    lines
}

/// The rollout of `fork` as Codex writes it before the fork's start: its
/// own meta naming `parent`, then a copy of `parent`'s whole rollout.
fn fork_rollout(fork: &str, parent: &str, parent_lines: &[Value]) -> Vec<Value> {
    let mut lines = vec![meta(fork, Some(parent))];
    lines.extend_from_slice(parent_lines);
    lines
}

/// Starts `fork`, forked from `parent` whose rollout is `parent_lines`,
/// then adds a turn of the fork's own and ends it: the fork's rollout.
fn run_fork(bench: &Bench, fork: &str, parent: &str, parent_lines: &[Value]) -> Vec<Value> {
    let mut lines = fork_rollout(fork, parent, parent_lines);
    bench.write_rollout(fork, &lines);
    let said = bench.start(fork, &[]);
    assert!(
        said.contains("uses your hosted vault"),
        "the fork binds the selected vault: {said}"
    );
    lines.extend(turn(fork, 2));
    bench.write_rollout(fork, &lines);
    bench.hand_over(fork);
    lines
}

#[test]
fn a_codex_fork_of_a_session_bound_to_the_selected_vault_sends_its_log_there() {
    // A new session, its rollout already written as Codex writes it before
    // the hook, sends its log to the vault it bound, as before.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID);
    let parent = new_rollout(PARENT);
    bench.write_rollout(PARENT, &parent);
    let said = bench.start(PARENT, &[]);
    assert!(
        said.contains("uses your hosted vault"),
        "the session binds the vault: {said}"
    );
    bench.hand_over(PARENT);
    bench.assert_sent(&origin, PARENT, "a new session");

    // Its fork, and the fork of that fork, each bound the same vault as the
    // turns they copy: each sends its whole rollout there.
    let fork = run_fork(&bench, FORK, PARENT, &parent);
    bench.assert_sent(
        &origin,
        FORK,
        "a fork of a session bound to the selected vault",
    );
    run_fork(&bench, FORK_OF_FORK, FORK, &fork);
    bench.assert_sent(&origin, FORK_OF_FORK, "a fork of that fork");
}

#[test]
fn a_codex_fork_of_a_session_that_bound_another_vault_a_pin_or_nothing_sends_its_log_nowhere() {
    // On the PR's base the fork's start reads `startup` as a new session,
    // binds the selected vault alone, and its hand-over sends the parent's
    // copied turns there.
    type Parent = fn(&Bench) -> Vec<Value>;
    let cases: [(&str, Parent); 3] = [
        ("a parent that bound another hosted vault", |bench| {
            bench.select_hosted(&answering_vault(), OTHER_VAULT_ID);
            let parent = new_rollout(PARENT);
            bench.write_rollout(PARENT, &parent);
            let said = bench.start(PARENT, &[]);
            assert!(
                said.contains("uses your hosted vault"),
                "the parent binds it: {said}"
            );
            parent
        }),
        ("a parent pinned by its hook's --url", |bench| {
            let parent = new_rollout(PARENT);
            bench.write_rollout(PARENT, &parent);
            let pin = answering_vault();
            let said = bench.start(PARENT, &["--url", &pin]);
            assert!(said.contains(&pin), "the parent binds its pin: {said}");
            parent
        }),
        ("a parent no start recorded", |_| new_rollout(PARENT)),
    ];
    for (case, parent) in cases {
        let bench = Bench::new();
        let parent = parent(&bench);
        let origin = answering_vault();
        bench.select_hosted(&origin, VAULT_ID);
        let fork = run_fork(&bench, FORK, PARENT, &parent);
        bench.assert_sent_nowhere(case);
        // One file for the whole log: no write that fails after the first
        // could leave the parent's binding recorded alone.
        assert_eq!(bench.record_files(FORK), ["unknown"], "{case}");

        // A fork of that fork copies the same turns, and more: its log goes
        // nowhere either, though its parent bound the selected vault.
        run_fork(&bench, FORK_OF_FORK, FORK, &fork);
        bench.assert_sent_nowhere(&format!("{case}, forked again"));
        assert_eq!(
            bench.record_files(FORK_OF_FORK),
            ["unknown"],
            "{case}, forked again"
        );
    }
}

#[test]
fn a_codex_fork_of_a_session_whose_record_is_a_fifo_starts_and_sends_its_log_nowhere() {
    // A FIFO with no writer in place of the parent's record: the fork's
    // start reads it as a record no vault takes, without waiting on it. On
    // the PR's base the start never reads it, and the fork's log goes to the
    // selected vault.
    let bench = Bench::new();
    let origin = answering_vault();
    bench.select_hosted(&origin, VAULT_ID);
    let parent = new_rollout(PARENT);
    bench.write_rollout(PARENT, &parent);
    let said = bench.start(PARENT, &[]);
    assert!(
        said.contains("uses your hosted vault"),
        "the parent binds the vault: {said}"
    );
    let files = bench.record_files(PARENT);
    let [file] = &files[..] else {
        panic!("one record file: {files:?}");
    };
    let file = bench.record(PARENT).join(file);
    std::fs::remove_file(&file).expect("test fixture");
    let made = Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&file)
        .status()
        .expect("run mkfifo");
    assert!(made.success(), "make the FIFO");

    run_fork(&bench, FORK, PARENT, &parent);
    bench.assert_sent_nowhere("a fork of a session whose record is a FIFO");
    assert_eq!(bench.record_files(FORK), ["unknown"]);
}

#[test]
fn a_codex_start_whose_rollout_begins_with_no_whole_meta_line_sends_its_log_nowhere() {
    // A rollout that holds lines but no whole `session_meta` first may hold
    // another session's turns: its log goes nowhere. On the PR's base each
    // goes to the selected vault.
    let parent = new_rollout(PARENT);
    let cut_meta = meta(FORK, Some(PARENT)).to_string();
    let cut_meta = &cut_meta[..cut_meta.len() / 2];
    // A meta line whose payload is no object, or whose parent is neither a
    // session id nor null: Codex writes neither, and the engine's importer
    // refuses the first.
    let odd_meta = |payload: Value| {
        std::iter::once(
            json!({"timestamp": "2026-11-21T01:00:00.000Z", "type": "session_meta", "payload": payload}),
        )
        .chain(parent.iter().cloned())
        .map(|line| format!("{line}\n"))
        .collect::<String>()
    };
    let cases: [(&str, String); 5] = [
        (
            "a first line that is a turn",
            turn(PARENT, 1)
                .iter()
                .map(|line| format!("{line}\n"))
                .collect(),
        ),
        (
            "a meta line cut short",
            std::iter::once(format!("{cut_meta}\n"))
                .chain(parent.iter().map(|line| format!("{line}\n")))
                .collect(),
        ),
        ("a meta line whose payload is null", odd_meta(Value::Null)),
        (
            "a meta line whose parent is a number",
            odd_meta(json!({"id": FORK, "forked_from_id": 7})),
        ),
        (
            "a meta line whose parent is empty",
            odd_meta(json!({"id": FORK, "forked_from_id": ""})),
        ),
    ];
    for (case, text) in cases {
        let bench = Bench::new();
        let origin = answering_vault();
        bench.select_hosted(&origin, VAULT_ID);
        let rollout = bench.rollout(FORK);
        std::fs::create_dir_all(rollout.parent().expect("a folder")).expect("test fixture");
        std::fs::write(&rollout, text).expect("test fixture");
        let said = bench.start(FORK, &[]);
        assert!(
            said.contains("uses your hosted vault"),
            "{case}: binds the vault: {said}"
        );
        bench.hand_over(FORK);
        bench.assert_sent_nowhere(case);
    }

    // A rollout not written yet, or written empty, when the start ran holds
    // no turn from before it: the session sends its log to the vault it
    // bound, as before.
    for written in [false, true] {
        let bench = Bench::new();
        let origin = answering_vault();
        bench.select_hosted(&origin, VAULT_ID);
        if written {
            bench.write_rollout(FORK, &[]);
        }
        let said = bench.start(FORK, &[]);
        assert!(
            said.contains("uses your hosted vault"),
            "binds the vault: {said}"
        );
        bench.write_rollout(FORK, &new_rollout(FORK));
        bench.hand_over(FORK);
        let case = if written {
            "a rollout written empty"
        } else {
            "a rollout not written yet"
        };
        bench.assert_sent(&origin, FORK, case);
    }
}
