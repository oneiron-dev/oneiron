//! The session hook lanes of Codex, Cursor and GitHub Copilot (ARCH-0028
//! #plugin-agent-plugins: "Hooks stay per host"; #plugin-build-plan step 3,
//! owner ruling OF-442 = A).
//!
//! Agent Plugins 1.0 defines no hooks: a client's own files go under the
//! top-level folder named for its namespace (spec §8.2; 1.0.0.md sha256
//! 97a658b7dca3ce1b…, read 2026-11-15). Codex and Copilot read their hooks
//! from such a folder of the shared package (`com.openai/`, which the
//! manifest's `extensions.com.openai.hooks` names, and `com.github.copilot/`),
//! so the package's root carries none. Cursor reads hooks only from a Cursor
//! plugin, so its lanes are `plugins/cursor/`. Each lane runs `oneiron hook
//! --host <client>` at the events that match the Claude Code lanes, and the
//! binary answers each client in its own format and queues its log for the
//! import that reads it (`docs/ops/client-session-hooks.md`).
//!
//! Run with: `cargo test --locked -p oneiron-server --test agent_plugins_hooks`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use clap::Parser as _;
use oneiron_server::cli::Cli;
use serde_json::{Value, json};

/// What `$HOME` stands for in the parse checks.
const TEST_HOME: &str = "/home/plugin-test";
/// `oneiron hook`'s own `--timeout` when a command names none.
const HOOK_DEFAULT_TIMEOUT_SECS: f64 = 8.0;
/// The most Codex gives a `SessionEnd` hook.
const CODEX_SESSION_END_MAX_SECS: f64 = 3.0;
const DESCRIPTOR: &str = r#"{"protocol":"oneiron-pairing","slip_version":2,"binding":"ed25519","pairing_endpoint":"/v1/core/pairing/redeem"}"#;
/// The one hit the stand-in bridge answers a recall with.
const RECALLED: &str = "Keep the ferry timetable in pier nine order.";
/// The project a session runs in; its folder is no git repository.
const PROJECT: &str = "heron-lantern";

/// One client's hook file, and where its format puts an entry's parts.
struct Lanes {
    /// The `--host` its commands name.
    host: &'static str,
    /// The file, under the repository root.
    file: &'static str,
    /// The client's event names, each with the `oneiron hook` event it runs.
    events: &'static [(&'static str, &'static str)],
    /// Whether an event holds matcher groups of hooks (Codex, as Claude
    /// Code) rather than the hooks themselves (Copilot, Cursor).
    grouped: bool,
    /// The field that holds the command.
    command: &'static str,
    /// The field that holds the client's timeout, in seconds.
    timeout: &'static str,
}

const LANES: [Lanes; 3] = [
    Lanes {
        host: "codex",
        file: "plugins/agent-plugins/com.openai/hooks/hooks.json",
        events: &[
            ("PreCompact", "hand-over"),
            ("SessionEnd", "hand-over"),
            ("SessionStart", "session-start"),
            ("Stop", "hand-over"),
        ],
        grouped: true,
        command: "command",
        timeout: "timeout",
    },
    Lanes {
        host: "copilot",
        file: "plugins/agent-plugins/com.github.copilot/hooks/hooks.json",
        // The VS Code compatible event names, whose payloads are snake_case.
        // `SessionEnd` carries no transcript path, so no hand-over runs there.
        events: &[
            ("PreCompact", "hand-over"),
            ("SessionStart", "session-start"),
            ("Stop", "hand-over"),
        ],
        grouped: false,
        command: "bash",
        timeout: "timeoutSec",
    },
    Lanes {
        host: "cursor",
        file: "plugins/cursor/hooks/hooks.json",
        events: &[
            ("preCompact", "hand-over"),
            ("sessionEnd", "hand-over"),
            ("sessionStart", "session-start"),
            ("stop", "hand-over"),
        ],
        grouped: false,
        command: "command",
        timeout: "timeout",
    },
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&read_text(path))
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// The shell words of one command: whitespace splits words outside double
/// quotes, and the quotes go. A command holding any other shell syntax is
/// refused, so this split is the shell's.
fn shell_words(command: &str) -> Vec<String> {
    for forbidden in [
        '\'', '\\', '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?',
    ] {
        assert!(
            !command.contains(forbidden),
            "{command:?} holds {forbidden:?}, more shell than the hooks' commands use"
        );
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut in_word = false;
    for c in command.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                word.push(c);
                in_word = true;
            }
        }
    }
    assert!(!quoted, "unbalanced quote in {command:?}");
    if in_word {
        words.push(word);
    }
    words
}

fn parse(argv: &[String]) -> Result<(), String> {
    Cli::try_parse_from(argv)
        .map(drop)
        .map_err(|error| error.to_string())
}

/// The value after `flag` in `argv`, when `flag` is there.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    let at = argv.iter().position(|word| word == flag)?;
    Some(
        argv.get(at + 1)
            .unwrap_or_else(|| panic!("{flag} has no value"))
            .as_str(),
    )
}

fn words(argv: &[&str]) -> Vec<String> {
    argv.iter().copied().map(String::from).collect()
}

fn names<const N: usize>(names: [&str; N]) -> BTreeSet<String> {
    names.into_iter().map(String::from).collect()
}

/// The names in `folder`.
fn entries(folder: &Path) -> BTreeSet<String> {
    std::fs::read_dir(folder)
        .unwrap_or_else(|error| panic!("read {}: {error}", folder.display()))
        .map(|entry| {
            entry
                .expect("a folder entry")
                .file_name()
                .into_string()
                .expect("a UTF-8 name")
        })
        .collect()
}

/// Every file below `folder`, as a `/`-joined path under it.
fn files_under(folder: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut open = vec![PathBuf::new()];
    while let Some(relative) = open.pop() {
        for name in entries(&folder.join(&relative)) {
            let path = relative.join(&name);
            if folder.join(&path).is_dir() {
                open.push(path);
            } else {
                found.insert(path.to_str().expect("a UTF-8 path").to_owned());
            }
        }
    }
    found
}

#[test]
fn every_client_hook_command_parses_with_the_oneiron_cli() {
    for lanes in &LANES {
        let host = lanes.host;
        let file = read_json(&repo_root().join(lanes.file));
        let events = file["hooks"]
            .as_object()
            .unwrap_or_else(|| panic!("{}: hooks is an object", lanes.file));
        // The built lanes: each event and the `oneiron hook` event it runs.
        // A new event is added here on purpose.
        let expected: BTreeMap<&str, &str> = lanes.events.iter().copied().collect();
        assert_eq!(
            events.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected.keys().copied().collect::<BTreeSet<_>>(),
            "{host}"
        );
        for (event, hook_event) in expected {
            let listed = events[event].as_array().expect("an event holds a list");
            let hooks: Vec<&Value> = if lanes.grouped {
                listed
                    .iter()
                    .flat_map(|group| group["hooks"].as_array().expect("a group holds hooks"))
                    .collect()
            } else {
                listed.iter().collect()
            };
            assert_eq!(hooks.len(), 1, "{host}: {event} runs one oneiron hook");
            let hook = hooks[0];
            assert_eq!(hook["type"], "command", "{host}: {event}");
            let command = hook[lanes.command]
                .as_str()
                .unwrap_or_else(|| panic!("{host}: {event} has no {}", lanes.command));
            // `${...}` is each client's own placeholder syntax (Cursor puts
            // its plugin variables there); `$HOME` is left to the shell.
            assert!(!command.contains("${"), "{host}: {event}: {command:?}");
            let argv = shell_words(&command.replace("$HOME", TEST_HOME));
            assert_eq!(
                argv[..5],
                words(&["oneiron", "hook", "--host", host, hook_event]),
                "{host}: {event}"
            );
            if let Err(error) = parse(&argv) {
                panic!("{host}: {event}: {argv:?} does not parse: {error}");
            }
            // The hook gives up before the client would stop it, so it always
            // exits 0 on its own and never shows as a hook error.
            let host_timeout = hook[lanes.timeout]
                .as_f64()
                .unwrap_or_else(|| panic!("{host}: {event} names its {}", lanes.timeout));
            let own_timeout = flag_value(&argv, "--timeout")
                .map_or(HOOK_DEFAULT_TIMEOUT_SECS, |secs| {
                    secs.parse().expect("seconds")
                });
            assert!(
                own_timeout < host_timeout,
                "{host}: {event}: oneiron's {own_timeout} s is not under the client's {host_timeout} s"
            );
            if host == "codex" && event == "SessionEnd" {
                assert!(
                    host_timeout <= CODEX_SESSION_END_MAX_SECS,
                    "codex: SessionEnd asks {host_timeout} s"
                );
            }
            let credential = flag_value(&argv, "--credential-file");
            if hook_event == "session-start" {
                // The client's own read-only hooks credential, as Claude
                // Code's lanes read `claude-code-hooks.cred`.
                assert_eq!(
                    credential,
                    Some(format!("{TEST_HOME}/.config/oneiron/{host}-hooks.cred").as_str()),
                    "{host}: {event}"
                );
            } else {
                // A hand-over needs no credential (it writes one queue file).
                assert_eq!(credential, None, "{host}: {event}");
            }
        }
    }

    // The checks above can fail: a host or an event the CLI does not know
    // is refused by the same parse.
    for argv in [
        ["oneiron", "hook", "--host", "codex-cli", "session-start"],
        ["oneiron", "hook", "--host", "copilot", "sessionStart"],
    ] {
        assert!(parse(&words(&argv)).is_err(), "{argv:?}");
    }
}

#[test]
fn hooks_stay_per_host_and_the_shared_root_carries_none() {
    let shared = repo_root().join("plugins/agent-plugins");

    // The shared root holds the manifest, the MCP configuration, the skills
    // and one folder per client namespace (spec §8.2): no hooks file a client
    // finds there by default (Codex's `hooks/hooks.json`, Copilot's
    // `hooks.json`), so no client runs another's hooks.
    assert_eq!(
        entries(&shared),
        names([
            "com.github.copilot",
            "com.openai",
            "mcp.json",
            "plugin.json",
            "skills"
        ])
    );
    for namespace in ["com.github.copilot", "com.openai"] {
        assert_eq!(
            files_under(&shared.join(namespace)),
            names(["hooks/hooks.json"]),
            "{namespace} holds its client's hooks alone"
        );
    }
    // Codex finds its file by the manifest: an explicit `hooks` replaces its
    // default discovery. Copilot reads its folder by its namespace alone.
    let manifest = read_json(&shared.join("plugin.json"));
    assert_eq!(
        manifest["extensions"],
        json!({"com.openai": {"hooks": "./com.openai/hooks/hooks.json"}})
    );

    // Cursor reads hooks only from a Cursor plugin: a folder of its own with
    // its manifest and its hooks, the same plugin's name aside.
    let cursor = repo_root().join("plugins/cursor");
    assert_eq!(
        files_under(&cursor),
        names([".cursor-plugin/plugin.json", "hooks/hooks.json"])
    );
    let cursor_manifest = read_json(&cursor.join(".cursor-plugin/plugin.json"));
    assert_eq!(cursor_manifest["hooks"], "./hooks/hooks.json");
    for key in ["author", "homepage", "repository", "license"] {
        assert_eq!(cursor_manifest[key], manifest[key], "{key}");
    }

    // Each client's file runs its own host's hooks alone.
    for lanes in &LANES {
        let text = read_text(&repo_root().join(lanes.file));
        for other in ["claude-code", "codex", "copilot", "cursor", "hermes"] {
            assert_eq!(
                text.contains(&format!("--host {other} ")),
                other == lanes.host,
                "{}: --host {other}",
                lanes.file
            );
        }
    }

    // The shared skill no longer tells the agent the package runs no hooks.
    let skill = read_text(&shared.join("skills/oneiron/SKILL.md"));
    assert!(!skill.contains("runs no hooks"), "{skill}");
}

/// The bridge and import a hook runs, stood in by a script that writes its
/// arguments to `@RECORD@/argv` and, as `oneiron mcp`, answers one recall
/// with one hit and writes the `tools/call` it was sent to `@RECORD@/call`.
const STAND_IN: &str = r#"#!/bin/sh
printf '%s\n' "$@" > '@RECORD@/argv'
[ "$1" = mcp ] || exit 0
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stand-in","version":"1"}}}'
read -r line
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"vault.recall","inputSchema":{"type":"object"}}]}}'
read -r line
printf '%s\n' "$line" > '@RECORD@/call'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"structuredContent":{"items":[{"kind":"MESSAGE","value_text":"@RECALLED@"}]}}}'
read -r line
"#;

/// A home with nothing in it, so no hook sees the host's vaults, runtime
/// files, pin or hosted selection, and the stand-in `oneiron` it runs.
struct Bench {
    dir: tempfile::TempDir,
}

impl Bench {
    fn new() -> Self {
        let bench = Self {
            dir: tempfile::tempdir().expect("test fixture"),
        };
        for dir in ["home", "config", "runtime", "record", "plugin-install"] {
            std::fs::create_dir(bench.path(dir)).expect("test fixture");
        }
        let script = STAND_IN
            .replace(
                "@RECORD@",
                bench.path("record").to_str().expect("UTF-8 path"),
            )
            .replace("@RECALLED@", RECALLED);
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

    /// The folder the session runs in. It is never made, so no git
    /// repository holds it and its own name is the project's.
    fn project(&self) -> PathBuf {
        self.path(PROJECT)
    }

    /// Runs `oneiron hook --host <host> <event> <args>` with `payload` on
    /// stdin, from a folder that is not the project's, as Cursor runs a
    /// plugin's hook from the plugin's own folder.
    fn hook(&self, host: &str, event: &str, args: &[&str], payload: &Value) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(["hook", "--host", host, event])
            .args(args)
            .arg("--oneiron")
            .arg(self.stand_in())
            .current_dir(self.path("plugin-install"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
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
        let output = child.wait_with_output().expect("run oneiron hook");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{host} {event}: a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// What the stand-in wrote to `name`.
    fn recorded(&self, name: &str) -> String {
        read_text(&self.path("record").join(name))
    }

    /// The arguments the stand-in was last run with.
    fn argv(&self) -> Vec<String> {
        self.recorded("argv").lines().map(str::to_owned).collect()
    }
}

/// A listener that answers every request as a server's
/// `GET /.well-known/oneiron` does, for a pin to name.
fn answering_vault() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test fixture");
    let url = format!("http://{}", listener.local_addr().expect("test fixture"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                match std::io::Read::read(&mut stream, &mut byte) {
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

/// The text a session hook's stdout adds to `host`'s context: plain text for
/// Claude Code and Codex, else the one field of the one JSON object the
/// client reads.
fn context(host: &str, output: &Output) -> String {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    let field = match host {
        "copilot" => "additionalContext",
        "cursor" => "additional_context",
        _ => {
            assert!(
                !stdout.starts_with('{'),
                "{host} reads plain text: {stdout:?}"
            );
            return stdout.trim_end_matches('\n').to_owned();
        }
    };
    let reply: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{host} reads one JSON object, not {stdout:?}: {error}"));
    let fields: Vec<&String> = reply.as_object().expect("an object").keys().collect();
    assert_eq!(fields, [field], "{host}: {stdout}");
    reply[field]
        .as_str()
        .expect("the context is text")
        .to_owned()
}

/// A `SessionStart` event as `host` sends it, from its own docs. Cursor's
/// names no `cwd`: the project is the first of its `workspace_roots`.
fn session_start_event(host: &str, project: &Path) -> Value {
    match host {
        "claude-code" => json!({
            "hook_event_name": "SessionStart",
            "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
            "source": "startup",
            "cwd": project,
            "transcript_path": "/dev/null",
        }),
        "codex" => json!({
            "session_id": "thr_heron",
            "transcript_path": null,
            "cwd": project,
            "hook_event_name": "SessionStart",
            "model": "gpt-5",
            "permission_mode": "default",
            "source": "startup",
        }),
        "copilot" => json!({
            "hook_event_name": "SessionStart",
            "session_id": "8f6c1d2e-3333-4444-8555-666677778888",
            "timestamp": "2026-11-15T13:00:00.000Z",
            "cwd": project,
            "source": "startup",
        }),
        "cursor" => json!({
            "conversation_id": "c0ffee00-1111-4222-8333-444455556666",
            "generation_id": "9e000000-1111-4222-8333-444455556666",
            "model": "default",
            "hook_event_name": "sessionStart",
            "cursor_version": "3.0.0",
            "workspace_roots": [project],
            "user_email": null,
            "transcript_path": null,
            "session_id": "c0ffee00-1111-4222-8333-444455556666",
            "is_background_agent": false,
            "composer_mode": "agent",
        }),
        _ => unreachable!("{host}"),
    }
}

/// A turn's end as `host` sends it, naming the session's log.
fn stop_event(host: &str, project: &Path, transcript: &Path) -> Value {
    match host {
        "claude-code" => json!({
            "hook_event_name": "Stop",
            "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
            "transcript_path": transcript,
            "cwd": project,
            "stop_hook_active": false,
        }),
        "codex" => json!({
            "session_id": "thr_heron",
            "transcript_path": transcript,
            "cwd": project,
            "hook_event_name": "Stop",
            "model": "gpt-5",
            "turn_id": "turn_1",
            "stop_hook_active": false,
            "last_assistant_message": "Done.",
        }),
        "copilot" => json!({
            "hook_event_name": "Stop",
            "session_id": "8f6c1d2e-3333-4444-8555-666677778888",
            "timestamp": "2026-11-15T13:05:00.000Z",
            "cwd": project,
            "transcript_path": transcript,
            "stop_reason": "end_turn",
            "stop_hook_active": false,
        }),
        "cursor" => json!({
            "conversation_id": "c0ffee00-1111-4222-8333-444455556666",
            "generation_id": "9e000000-1111-4222-8333-444455556666",
            "model": "default",
            "hook_event_name": "stop",
            "cursor_version": "3.0.0",
            "workspace_roots": [project],
            "user_email": null,
            "transcript_path": transcript,
            "status": "completed",
            "loop_count": 0,
        }),
        _ => unreachable!("{host}"),
    }
}

#[test]
fn each_client_hears_its_session_start_in_its_own_format() {
    let vault = answering_vault();
    for (host, product) in [
        ("claude-code", "Claude Code"),
        ("codex", "Codex"),
        ("copilot", "GitHub Copilot"),
        ("cursor", "Cursor"),
    ] {
        let bench = Bench::new();
        let credential = bench.path(&format!("{host}-hooks.cred"));
        let credential_arg = credential.to_str().expect("UTF-8 path");
        let output = bench.hook(
            host,
            "session-start",
            &["--url", &vault, "--credential-file", credential_arg],
            &session_start_event(host, &bench.project()),
        );

        // The line naming the vault, then the recall for the project.
        let said = context(host, &output);
        let lines: Vec<&str> = said.lines().collect();
        assert_eq!(lines.len(), 3, "{host}: {said:?}");
        assert!(lines[0].contains(&vault), "{host}: {said:?}");
        assert_eq!(
            lines[1],
            "From your Oneiron vault, for \"heron lantern\" (recalled at session start; may be dated):",
            "{host}"
        );
        assert_eq!(lines[2], format!("- {RECALLED}"), "{host}");

        // The bridge ran as the hooks' credential, and its call names the
        // client the session runs in and recalls the project's name.
        assert_eq!(
            bench.argv(),
            words(&[
                "mcp",
                "--url",
                &vault,
                "--surface",
                "tool-first",
                "--credential-file",
                credential_arg
            ]),
            "{host}"
        );
        let call: Value = serde_json::from_str(&bench.recorded("call")).expect("one JSON-RPC call");
        assert_eq!(call["method"], "tools/call", "{host}");
        let arguments = &call["params"]["arguments"];
        assert_eq!(
            arguments["consent"],
            json!({
                "policy_ref": format!("policy:{host}-hooks"),
                "purpose": format!("recall context for a new {product} session"),
            }),
            "{host}"
        );
        assert_eq!(
            arguments["arguments"]["spec"]["query"], "heron lantern",
            "{host}"
        );
    }
}

#[test]
fn each_client_hands_its_log_to_the_import_that_reads_it() {
    for (host, source) in [
        ("claude-code", "claude-code"),
        ("codex", "codex"),
        ("copilot", "hook-transcript"),
        ("cursor", "hook-transcript"),
    ] {
        let bench = Bench::new();
        let transcript = bench.path("session.jsonl");
        let output = bench.hook(
            host,
            "hand-over",
            &[],
            &stop_event(host, &bench.project(), &transcript),
        );
        assert!(output.stdout.is_empty(), "{host}: hand-over prints nothing");
        assert_eq!(
            bench.argv(),
            words(&[
                "import",
                source,
                transcript.to_str().expect("UTF-8 path"),
                "--queue"
            ]),
            "{host}"
        );
    }
}
