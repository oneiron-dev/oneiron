//! `oneiron hook --host claude-code`, through the shipped binary.
//!
//! Which vault a session binds (ARCH-0028 `#plugin-first-run`, owner ruling
//! PLUGIN-FIRSTRUN = D): a pin first, then the newest running local vault a
//! runtime file names, else a server started from the config; the one line
//! that names it; and the flow `examples/claude-code-hooks/check.sh` checks: a
//! `Stop` queues the session while the vault is down, `serve` imports it, and
//! the next session recalls it.
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const SECRET: &str = "hook-check-issuer-key-not-a-bearer";
const DESCRIPTOR: &str = r#"{"protocol":"oneiron-pairing","slip_version":2,"binding":"ed25519","pairing_endpoint":"/v1/core/pairing/redeem"}"#;

/// A user's home with its own config and runtime folders, so nothing a test
/// runs sees the host's vaults, runtime files or pin.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        let home = Self {
            dir: tempfile::tempdir().expect("test fixture"),
        };
        for dir in ["home", "config", "runtime"] {
            std::fs::create_dir(home.dir.path().join(dir)).expect("test fixture");
        }
        home
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The per-user oneiron folder: the default config, the pin and, where
    /// the platform has no runtime folder, `run/`.
    fn user_dir(&self) -> PathBuf {
        self.path("config").join("oneiron")
    }

    fn run_dir(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.user_dir().join("run")
        } else {
            self.path("runtime").join("oneiron")
        }
    }

    fn oneiron(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(args)
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("ONEIRON_AUTH_SECRET", SECRET)
            .env_remove("ONEIRON_CONFIG")
            .env_remove("ONEIRON_HOST")
            .env_remove("ONEIRON_PORT")
            .env_remove("ONEIRON_ARTIFACT_PORT")
            .env_remove("ONEIRON_VAULT_PATH")
            .env_remove("ONEIRON_URL")
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY");
        command
    }

    /// Creates a vault and its config at `config`.
    fn init(&self, vault: &Path, config: &Path) {
        std::fs::create_dir_all(config.parent().expect("config folder")).expect("test fixture");
        let output = self
            .oneiron(&["init"])
            .arg(vault)
            .arg("--config")
            .arg(config)
            .args(["--embedder", "none"])
            .output()
            .expect("run oneiron init");
        assert!(
            output.status.success(),
            "init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Any free port, so parallel tests never meet on 9090. A top-level
        // key goes before the file's first table.
        let body = std::fs::read_to_string(config).expect("test fixture");
        std::fs::write(config, format!("port = 0\n{body}")).expect("test fixture");
    }

    /// Runs one hook with `event` on stdin.
    fn hook(&self, event: &str, args: &[&str], payload: &Value) -> Output {
        let mut child = self
            .oneiron(&["hook", "--host", "claude-code", event])
            .args(args)
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
            "a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn session_start(&self, args: &[&str]) -> Vec<String> {
        let event = json!({
            "hook_event_name": "SessionStart",
            "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
            "source": "startup",
            "cwd": "/tmp/heron-lantern",
            "transcript_path": "/dev/null",
        });
        lines(&self.hook("session-start", args, &event))
    }

    /// Writes a runtime file the way `serve` does, for a server at `url`.
    fn runtime_file(&self, name: &str, url: &str, pid: u32, started_at_ms: u64) -> PathBuf {
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let dir = self.run_dir();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .expect("test fixture");
        let path = dir.join(format!("{name}.json"));
        let body = json!({
            "vault_id": null,
            "url": url,
            "pid": pid,
            "state_dir": self.path(name),
            "config": null,
            "started_at_ms": started_at_ms,
        });
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut file| file.write_all(body.to_string().as_bytes()))
            .expect("test fixture");
        path
    }

    /// The runtime files in the run folder, each read.
    fn runtime_files(&self) -> Vec<Value> {
        let Ok(entries) = std::fs::read_dir(self.run_dir()) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.expect("read the run folder").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .map(|path| {
                serde_json::from_slice(&std::fs::read(&path).expect("read a runtime file"))
                    .expect("a runtime file is JSON")
            })
            .collect()
    }

    /// Waits for the runtime file of the server whose pid is `pid`.
    fn wait_for_runtime_file(&self, pid: u32, log: &Path) -> Value {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(file) = self
                .runtime_files()
                .into_iter()
                .find(|file| file["pid"] == json!(pid))
            {
                return file;
            }
            assert!(
                Instant::now() < deadline,
                "serve never wrote its runtime file: {}",
                std::fs::read_to_string(log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_for_no_runtime_file(&self, pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self
            .runtime_files()
            .iter()
            .any(|file| file["pid"] == json!(pid))
        {
            assert!(
                Instant::now() < deadline,
                "a cleanly stopped serve left its runtime file"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn lines(output: &Output) -> Vec<String> {
    String::from_utf8(output.stdout.clone())
        .expect("UTF-8 stdout")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A listener that answers every request as a server's
/// `GET /.well-known/oneiron` does, for a runtime file or a pin to name.
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

/// A loopback origin nothing listens on.
fn silent_origin() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test fixture");
    format!("http://{}", listener.local_addr().expect("test fixture"))
}

/// The pid of a process that has exited and been reaped.
fn dead_pid() -> u32 {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    child.wait().expect("reap true");
    pid
}

/// A server this test started. Dropping it kills the process, so a failed
/// assertion never leaves one holding the vault.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sigterm(pid: u32) {
    let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory; `pid` is a
    // server this test started.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0, "SIGTERM could not be sent");
}

#[test]
fn a_session_binds_the_running_vault_the_newest_of_several_or_the_pinned_one() {
    let home = Home::new();
    let me = std::process::id();
    let (first, second) = (answering_vault(), answering_vault());

    // One running vault: the line names it.
    home.runtime_file("first", &first, me, 1_000);
    let said = home.session_start(&[]);
    assert_eq!(said.len(), 1, "one line names the vault: {said:?}");
    assert!(said[0].contains(&first), "{said:?}");

    // Two: the newest is bound, and a second line says how to keep it.
    home.runtime_file("second", &second, me, 2_000);
    let said = home.session_start(&[]);
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(
        said[0].contains(&second) && !said[0].contains(&first),
        "{said:?}"
    );
    let pin = home.user_dir().join("hook.toml");
    assert!(
        said[1].contains(&second) && said[1].contains(pin.to_str().expect("UTF-8 path")),
        "the second line pins the bound vault: {said:?}"
    );

    // A pin decides between them, even for the older one.
    std::fs::create_dir_all(home.user_dir()).expect("test fixture");
    std::fs::write(&pin, format!("url = \"{first}\"\n")).expect("test fixture");
    let said = home.session_start(&[]);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains(&first) && !said[0].contains(&second),
        "{said:?}"
    );

    // The hook's own `--url` comes before the pin file.
    let said = home.session_start(&["--url", &second]);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains(&second) && !said[0].contains(&first),
        "{said:?}"
    );
}

#[test]
fn a_stale_runtime_file_is_dropped_and_a_session_with_no_vault_is_told_how_to_set_one_up() {
    let home = Home::new();
    let gone = home.runtime_file("gone", &answering_vault(), dead_pid(), 2_000);
    // A live pid whose server does not answer is not bound, but its file
    // stays: it may be a server still starting.
    let quiet = home.runtime_file("quiet", &silent_origin(), std::process::id(), 1_000);

    let said = home.session_start(&[]);

    assert!(
        !gone.exists(),
        "a runtime file whose pid is gone is removed"
    );
    assert!(quiet.exists(), "a live pid's runtime file stays");
    assert_eq!(said.len(), 1, "one line, even with no vault: {said:?}");
    assert!(
        said[0].contains("oneiron init"),
        "it names the setup step: {said:?}"
    );
}

#[test]
fn with_no_vault_running_the_session_starts_the_configured_one() {
    let home = Home::new();
    let vault = home.path("vault");
    // The config every command reads when none is named.
    let config = home.user_dir().join("oneiron.toml");
    home.init(&vault, &config);

    let said = home.session_start(&["--timeout", "120"]);

    let files = home.runtime_files();
    assert_eq!(files.len(), 1, "the started server registered: {files:?}");
    let started = &files[0];
    let pid = u32::try_from(started["pid"].as_u64().expect("pid")).expect("pid fits u32");
    let url = started["url"].as_str().expect("url").to_owned();
    sigterm(pid);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains(&url),
        "the line names the started vault: {said:?}"
    );
    assert_eq!(
        Path::new(started["state_dir"].as_str().expect("state_dir")),
        vault,
        "the runtime file names the vault's folder"
    );
    home.wait_for_no_runtime_file(pid);
}

#[test]
fn a_stopped_session_is_queued_then_imported_and_recalled_by_the_next_session() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.path("oneiron.toml");
    home.init(&vault, &config);
    let projects = home.path("projects");
    let queue = home.path("queue");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&config)
        .expect("test fixture");
    write!(
        file,
        "\n[import]\nqueue = true\nqueue_dir = \"{}\"\nclaude_code_root = \"{}\"\n",
        queue.display(),
        projects.display()
    )
    .expect("test fixture");
    let credential = home.path("claude-code-hooks.cred");
    let minted = home
        .oneiron(&[
            "token",
            "agent",
            "--name",
            "claude-code-hooks",
            "--tier",
            "read-only",
        ])
        .arg("--out")
        .arg(&credential)
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run oneiron token agent");
    assert!(
        minted.status.success(),
        "token agent: {}",
        String::from_utf8_lossy(&minted.stderr)
    );

    // An invented session in Claude Code's own log layout.
    let session = "0b5e55e0-1111-4222-8333-944455556666";
    let log = projects
        .join("-tmp-heron-lantern")
        .join(format!("{session}.jsonl"));
    std::fs::create_dir_all(log.parent().expect("log folder")).expect("test fixture");
    let first = "d1000000-0000-4000-8000-000000000001";
    let second = "d1000000-0000-4000-8000-000000000002";
    append_turns(
        &log,
        session,
        &[
            (
                first,
                None,
                "For the heron lantern project, keep the ferry timetable in pier nine order.",
            ),
            (
                second,
                Some(first),
                "Noted: the heron lantern timetable stays in pier nine order.",
            ),
        ],
    );

    // 1. Stop while the vault is down: the session waits in the queue.
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": session,
        "transcript_path": log,
        "cwd": "/tmp/heron-lantern",
        "stop_hook_active": false,
    });
    let config_arg = config.to_str().expect("UTF-8 path");
    let output = home.hook("hand-over", &["--config", config_arg], &stop);
    assert!(output.stdout.is_empty(), "hand-over prints nothing");
    assert_eq!(
        std::fs::read_dir(&queue).expect("the queue folder").count(),
        1,
        "one queue entry"
    );

    // 2. serve starts, registers itself and imports the queued session.
    let log_path = home.path("serve.log");
    let serve_log = std::fs::File::create(&log_path).expect("server log file");
    let server = Server(
        home.oneiron(&["serve", "--host", "127.0.0.1", "--config", config_arg])
            .stdout(serve_log.try_clone().expect("server log file"))
            .stderr(serve_log)
            .spawn()
            .expect("spawn oneiron serve"),
    );
    let registered = home.wait_for_runtime_file(server.0.id(), &log_path);
    let url = registered["url"].as_str().expect("url").to_owned();
    assert!(
        !url.ends_with(":0"),
        "the runtime file names the bound port: {url}"
    );
    wait_for_empty(&queue, &log_path);

    // 3. A new session in the same project binds it with no `--url` and
    // recalls what the last one said.
    let credential_arg = credential.to_str().expect("UTF-8 path");
    let said = home.session_start(&["--credential-file", credential_arg, "--timeout", "60"]);
    assert!(
        said[0].contains(&url),
        "the first line names the vault: {said:?}"
    );
    assert!(
        said.iter().any(|line| line.contains("pier nine order")),
        "the session was recalled: {said:?}"
    );

    // 4. The session goes on; a hand-over with no `--config` queues to the
    // running vault's own queue, and a prompt recalls the new turn.
    let third = "d1000000-0000-4000-8000-000000000003";
    append_turns(
        &log,
        session,
        &[(
            third,
            Some(second),
            "The heron lantern ferry bell rings twice at the slipway.",
        )],
    );
    home.hook("hand-over", &[], &stop);
    wait_for_empty(&queue, &log_path);
    let prompt = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": session,
        "cwd": "/tmp/heron-lantern",
        "prompt": "heron lantern ferry bell",
    });
    let said = lines(&home.hook(
        "prompt",
        &["--credential-file", credential_arg, "--timeout", "60"],
        &prompt,
    ));
    assert!(
        said.iter().any(|line| line.contains("rings twice")),
        "the prompt recalled the new turn: {said:?}"
    );

    // 5. A clean stop removes the runtime file.
    let pid = server.0.id();
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
}

#[test]
fn a_mistyped_hook_command_exits_1_so_it_never_blocks_the_host() {
    let home = Home::new();
    let output = home
        .oneiron(&[
            "hook",
            "--host",
            "claude-code",
            "session-start",
            "--no-such-flag",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run oneiron hook");
    assert_eq!(output.status.code(), Some(1));
}

/// Appends Claude Code log lines, one per `(uuid, parent, text)`: a user turn
/// then an assistant turn, alternating.
fn append_turns(log: &Path, session: &str, turns: &[(&str, Option<&str>, &str)]) {
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .expect("test fixture");
    let already = std::fs::read_to_string(log)
        .expect("test fixture")
        .lines()
        .count();
    for (index, (uuid, parent, text)) in turns.iter().enumerate() {
        let user = (already + index).is_multiple_of(2);
        let message = if user {
            json!({ "role": "user", "content": text })
        } else {
            json!({
                "id": format!("msg_{}", &uuid[uuid.len() - 4..]),
                "type": "message",
                "role": "assistant",
                "model": "claude-test",
                "content": [{ "type": "text", "text": text }],
            })
        };
        let line = json!({
            "parentUuid": parent,
            "isSidechain": false,
            "userType": "external",
            "cwd": "/tmp/heron-lantern",
            "sessionId": session,
            "version": "2.1.0",
            "type": if user { "user" } else { "assistant" },
            "uuid": uuid,
            "timestamp": format!("2026-10-10T01:00:{:02}.000Z", (already + index) * 5),
            "message": message,
        });
        writeln!(out, "{line}").expect("test fixture");
    }
}

fn wait_for_empty(queue: &Path, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while std::fs::read_dir(queue).expect("the queue folder").count() > 0 {
        assert!(
            Instant::now() < deadline,
            "the queue was not drained: {}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}
