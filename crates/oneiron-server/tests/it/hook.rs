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

use oneiron::authority::ActSurface;
use oneiron::claim::{base_world_id, substrate_facet_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    PROJECT_PROPOSAL_MINT_ACTION_ID, ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, WitnessTurn,
};
use oneiron::session_project::WorkspaceBindRequest;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::config::KeystoreConfig;
use oneiron_server::workspace_identity::WorkspaceIdentity;

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

    /// Mints the agent credential the hooks read, for the vault at `config`.
    fn credential(&self, config: &Path) -> PathBuf {
        let credential = self.path("claude-code-hooks.cred");
        let minted = self
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
            .arg(config)
            .output()
            .expect("run oneiron token agent");
        assert!(
            minted.status.success(),
            "token agent: {}",
            String::from_utf8_lossy(&minted.stderr)
        );
        credential
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
        self.session_start_in(Path::new("/tmp/heron-lantern"), args)
    }

    /// A session start whose event names `cwd` as the session's folder.
    fn session_start_in(&self, cwd: &Path, args: &[&str]) -> Vec<String> {
        let event = json!({
            "hook_event_name": "SessionStart",
            "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
            "source": "startup",
            "cwd": cwd,
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
    signal(pid, libc::SIGTERM);
}

/// Stops a server this test started, and waits until it has stopped.
fn stop(pid: u32) {
    signal(pid, libc::SIGSTOP);
    let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");
    let mut status = 0;
    // SAFETY: `waitpid` writes only `status`; `pid` is this test's child,
    // and a stopped child is not reaped.
    let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WUNTRACED) };
    assert!(
        waited == pid && libc::WIFSTOPPED(status),
        "the server did not stop (status {status})"
    );
}

fn signal(pid: u32, signal: libc::c_int) {
    let pid = libc::pid_t::try_from(pid).expect("pid fits pid_t");
    // SAFETY: `kill` takes plain integers and touches no memory; `pid` is a
    // server this test started.
    let sent = unsafe { libc::kill(pid, signal) };
    assert_eq!(sent, 0, "signal {signal} could not be sent");
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
    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(
        said[1],
        "Oneiron: started local; no hosted vault is signed in to \
         here (`oneiron hosted login`); pin one with --url, \
         ONEIRON_URL or hook config.",
        "{said:?}"
    );
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
fn a_session_whose_started_server_cannot_open_the_vault_binds_the_one_that_holds_it() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.user_dir().join("oneiron.toml");
    home.init(&vault, &config);

    // A server another session started: it holds the vault but does not
    // answer yet (stopped once it has registered).
    let log_path = home.path("first-serve.log");
    let serve_log = std::fs::File::create(&log_path).expect("server log file");
    let first = Server(
        home.oneiron(&["serve", "--host", "127.0.0.1"])
            .arg("--config")
            .arg(&config)
            .stdout(serve_log.try_clone().expect("server log file"))
            .stderr(serve_log)
            .spawn()
            .expect("spawn oneiron serve"),
    );
    let registered = home.wait_for_runtime_file(first.0.id(), &log_path);
    let url = registered["url"].as_str().expect("url").to_owned();
    stop(first.0.id());

    // This session passes it over and starts its own `serve`, which cannot
    // open the vault and exits; the first server then goes on.
    let said = std::thread::scope(|scope| {
        let session = scope.spawn(|| home.session_start(&["--timeout", "120"]));
        // The hook opens the run folder's `serve.log` as it starts its own.
        let deadline = Instant::now() + Duration::from_secs(60);
        while !home.run_dir().join("serve.log").exists() {
            assert!(
                Instant::now() < deadline,
                "the session never started a server of its own"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        signal(first.0.id(), libc::SIGCONT);
        session.join().expect("the session start")
    });

    assert_eq!(said.len(), 2, "{said:?}");
    assert_eq!(
        said[1],
        "Oneiron: started local; no hosted vault is signed in to \
         here (`oneiron hosted login`); pin one with --url, \
         ONEIRON_URL or hook config.",
        "{said:?}"
    );
    assert!(
        said[0].contains(&url),
        "the session binds the server that holds the vault: {said:?}"
    );
    let files = home.runtime_files();
    assert_eq!(
        files.len(),
        1,
        "only the first server registered: {files:?}"
    );
    sigterm(first.0.id());
    home.wait_for_no_runtime_file(first.0.id());
}

#[test]
fn a_prompt_pinned_to_a_vault_that_does_not_answer_gives_up_after_one_probe() {
    let home = Home::new();
    let config = home.path("oneiron.toml");
    home.init(&home.path("vault"), &config);
    let credential = home.credential(&config);
    // A pinned origin that takes the connection and never answers.
    let hung = TcpListener::bind("127.0.0.1:0").expect("test fixture");
    let url = format!("http://{}", hung.local_addr().expect("test fixture"));
    let prompt = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "0b5e55e0-3333-4444-8555-a66677778888",
        "cwd": "/tmp/heron-lantern",
        "prompt": "heron lantern ferry bell",
    });

    let asked = Instant::now();
    let output = home.hook(
        "prompt",
        &[
            "--url",
            &url,
            "--credential-file",
            credential.to_str().expect("UTF-8 path"),
            "--timeout",
            "30",
        ],
        &prompt,
    );
    let took = asked.elapsed();

    assert!(output.stdout.is_empty(), "{:?}", lines(&output));
    assert!(
        took < Duration::from_secs(10),
        "the prompt waited {took:?} on a pinned vault that does not answer"
    );
}

#[test]
fn a_stopped_session_is_queued_then_imported_and_the_next_sessions_hooks_push_only_above_the_bar() {
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
    let credential = home.credential(&config);

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

    // 3. A new session in the same folder binds it with no `--url`. Keyed on nothing but the
    // folder's name, its start recalls nothing (RECALL-CARRIER-THRESHOLD): no relevance bar
    // separates true lines from traps on a folder's name. Given the task's words, it asks the
    // owner's start bar, and in a folder with no project bound nothing clears it.
    let credential_arg = credential.to_str().expect("UTF-8 path");
    let said = home.session_start(&["--credential-file", credential_arg, "--timeout", "60"]);
    assert!(
        said[0].contains(&url),
        "the first line names the vault: {said:?}"
    );
    assert_eq!(
        said.len(),
        1,
        "a start keyed on the folder recalls nothing: {said:?}"
    );
    let said = home.session_start(&[
        "--credential-file",
        credential_arg,
        "--query",
        "heron lantern pier nine order",
        "--timeout",
        "60",
    ]);
    assert_eq!(
        said.len(),
        1,
        "a push outside any project is quiet, and says nothing by default: {said:?}"
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
        said.is_empty(),
        "the prompt's lines ride the owner's carrier bar, and outside any project none clears \
         it: {said:?}"
    );

    // 5. A clean stop removes the runtime file.
    let pid = server.0.id();
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
}

/// RECALL-SESSION-PROJECT (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov: Q2 = A): in a
/// folder with no project bound, a read that names no project reads no claims, so the quiet
/// start's one vault line gives the owner's bind command; a folder the bridge attaches nothing
/// for (the home directory) gets no such words. Red on the base: the line names no command.
#[test]
fn a_session_in_a_folder_with_no_project_bound_is_told_the_bind_command() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.path("oneiron.toml");
    home.init(&vault, &config);
    let credential = home.credential(&config);
    let config_arg = config.to_str().expect("UTF-8 path");
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
    let credential_arg = credential.to_str().expect("UTF-8 path");
    // The plugin's quiet start: it binds the vault and recalls nothing.
    let quiet = [
        "--credential-file",
        credential_arg,
        "--query",
        " ",
        "--timeout",
        "60",
    ];

    let folder = home.path("work").join("heron-lantern");
    std::fs::create_dir_all(&folder).expect("test fixture");
    let said = home.session_start_in(&folder, &quiet);
    assert_eq!(said.len(), 1, "one line, no recall: {said:?}");
    assert!(said[0].contains(&url), "the line names the vault: {said:?}");
    assert!(
        said[0].contains("No project is bound to this folder")
            && said[0].contains(&format!(
                "`oneiron project bind <project-ref> --base-url {url}`"
            )),
        "the vault line gives the bind command, naming its vault (review round 1 of #10559): \
         {said:?}"
    );

    let said = home.session_start_in(&home.path("home"), &quiet);
    assert_eq!(said.len(), 1, "{said:?}");
    assert!(
        said[0].contains(&url) && !said[0].contains("oneiron project bind"),
        "the home directory is no workspace, so the line says nothing of a project: {said:?}"
    );

    let pid = server.0.id();
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
}

/// REVIEW-10567 round 1, `receipt()`: the MCP gateway gives the verb's result as
/// `structuredContent.output`, so the opted-in empty receipt never printed. A folder bound to a
/// project, the owner's carrier bar `quiet` and `recall.bar.empty_receipt` set for claude-code:
/// a prompt prints exactly the receipt line, naming the quiet rule the owner's row set. With the
/// receipt unset, the same prompt prints nothing. Red on the base: the first prompt prints no
/// line (the receipt was never read from `output.bar`).
#[test]
fn an_owner_who_asks_the_empty_receipt_hears_it_when_nothing_clears_the_bar() {
    // One vault per receipt setting: owner state is seeded on the stopped vault, and a running
    // `serve` holds its writer lease.
    for receipt in [true, false] {
        let home = Home::new();
        let vault = home.path("vault");
        let config = home.path("oneiron.toml");
        home.init(&vault, &config);
        let credential = home.credential(&config);
        let folder = home.path("work").join("heron-lantern");
        std::fs::create_dir_all(&folder).expect("test fixture");
        {
            let seeded = open_stopped(&vault);
            let (owner, proof) = owner_and_proof(&seeded);
            let project = mint_project(&seeded, owner, &proof, "hook-test-receipt-card");
            bind_folder(&seeded, &proof, &folder, project, "heron-lantern");
            owner_sets_bar(&seeded, &proof, "recall.bar.carrier", json!("quiet"));
            owner_sets_bar(&seeded, &proof, "recall.bar.empty_receipt", json!(receipt));
        }
        let config_arg = config.to_str().expect("UTF-8 path");
        let log_path = home.path("serve.log");
        let serve_log = std::fs::File::create(&log_path).expect("server log file");
        let server = Server(
            home.oneiron(&["serve", "--host", "127.0.0.1", "--config", config_arg])
                .stdout(serve_log.try_clone().expect("server log file"))
                .stderr(serve_log)
                .spawn()
                .expect("spawn oneiron serve"),
        );
        home.wait_for_runtime_file(server.0.id(), &log_path);
        let credential_arg = credential.to_str().expect("UTF-8 path");
        let prompt = json!({
            "hook_event_name": "UserPromptSubmit",
            "session_id": "0b5e55e0-4444-4555-8666-b77788889999",
            "cwd": folder,
            "prompt": "amber jackdaw timetable",
        });
        let said = lines(&home.hook(
            "prompt",
            &["--credential-file", credential_arg, "--timeout", "60"],
            &prompt,
        ));
        if receipt {
            assert_eq!(
                said.len(),
                1,
                "the opted-in empty receipt is one line: {said:?}"
            );
            assert_eq!(
                said[0],
                "From your Oneiron vault, for this prompt: nothing cleared the relevance bar \
                 (quiet: owner).",
                "{said:?}"
            );
        } else {
            assert!(
                said.is_empty(),
                "with no receipt asked, the prompt says nothing: {said:?}"
            );
        }
        let pid = server.0.id();
        sigterm(pid);
        home.wait_for_no_runtime_file(pid);
    }
}

/// REVIEW-10567 round 2 P1 3: the prompt's opted-in empty receipt names the effective query
/// when `--query` was given, with session-start's lead, not "for this prompt". Carrier `quiet`
/// and `recall.bar.empty_receipt` set for claude-code: `prompt --query "release checklist"` on
/// an event whose prompt is "summarize today's diff" prints exactly the query-named receipt
/// line; without the flag the same prompt still prints the "for this prompt" receipt.
#[test]
fn a_prompt_with_query_names_that_query_in_its_empty_receipt() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.path("oneiron.toml");
    home.init(&vault, &config);
    let credential = home.credential(&config);
    let folder = home.path("work").join("heron-lantern");
    std::fs::create_dir_all(&folder).expect("test fixture");
    {
        let seeded = open_stopped(&vault);
        let (owner, proof) = owner_and_proof(&seeded);
        let project = mint_project(&seeded, owner, &proof, "hook-test-receipt-query-card");
        bind_folder(&seeded, &proof, &folder, project, "heron-lantern");
        owner_sets_bar(&seeded, &proof, "recall.bar.carrier", json!("quiet"));
        owner_sets_bar(&seeded, &proof, "recall.bar.empty_receipt", json!(true));
    }
    let config_arg = config.to_str().expect("UTF-8 path");
    let log_path = home.path("serve.log");
    let serve_log = std::fs::File::create(&log_path).expect("server log file");
    let server = Server(
        home.oneiron(&["serve", "--host", "127.0.0.1", "--config", config_arg])
            .stdout(serve_log.try_clone().expect("server log file"))
            .stderr(serve_log)
            .spawn()
            .expect("spawn oneiron serve"),
    );
    home.wait_for_runtime_file(server.0.id(), &log_path);
    let credential_arg = credential.to_str().expect("UTF-8 path");
    let prompt = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "0b5e55e0-4444-4555-8666-b77788889999",
        "cwd": folder,
        "prompt": "summarize today's diff",
    });
    let said = lines(&home.hook(
        "prompt",
        &[
            "--credential-file",
            credential_arg,
            "--timeout",
            "60",
            "--query",
            "release checklist",
        ],
        &prompt,
    ));
    assert_eq!(
        said.len(),
        1,
        "a prompt with --query names that query in its empty receipt: {said:?}"
    );
    assert_eq!(
        said[0],
        "From your Oneiron vault, for \"release checklist\": nothing cleared the relevance bar \
         (quiet: owner).",
        "{said:?}"
    );
    let said = lines(&home.hook(
        "prompt",
        &["--credential-file", credential_arg, "--timeout", "60"],
        &prompt,
    ));
    assert_eq!(
        said.len(),
        1,
        "with no --query the prompt's own wording stays: {said:?}"
    );
    assert_eq!(
        said[0],
        "From your Oneiron vault, for this prompt: nothing cleared the relevance bar \
         (quiet: owner).",
        "{said:?}"
    );
    let pid = server.0.id();
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
}

/// REVIEW-10567 round 1, `tool_call()`: start and carrier pushes now ask `scope.kinds:
/// ["CLAIM"]`, so a TURN, MESSAGE or NOTE, which names no project, can no longer reach a
/// session from another project. A session in beta's folder is stopped and imported with a turn
/// holding a distinctive phrase; a prompt in alpha's folder whose words match only that turn,
/// with the owner's carrier bar `open`, prints no recalled line for it — while the CLAIM in
/// alpha holding the same words IS pushed. Red on the base: the prompt carries the beta turn's
/// line.
#[test]
fn a_push_gives_no_turn_from_another_projects_session() {
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
    let credential = home.credential(&config);

    let alpha = home.path("work").join("alpha");
    let beta = home.path("work").join("beta");
    std::fs::create_dir_all(&alpha).expect("test fixture");
    std::fs::create_dir_all(&beta).expect("test fixture");
    {
        let seeded = open_stopped(&vault);
        let (owner, proof) = owner_and_proof(&seeded);
        let alpha_project = mint_project(&seeded, owner, &proof, "hook-test-alpha-card");
        let beta_project = mint_project(&seeded, owner, &proof, "hook-test-beta-card");
        bind_folder(&seeded, &proof, &alpha, alpha_project, "alpha");
        bind_folder(&seeded, &proof, &beta, beta_project, "beta");
        owner_sets_bar(&seeded, &proof, "recall.bar.carrier", json!("open"));
        remember_in(
            &seeded,
            owner,
            &proof,
            alpha_project,
            "harbor.timetable",
            "the amber jackdaw ferry bell keeps pier nine order",
        );
    }

    // A session in beta's folder, holding the distinctive phrase, stops while the vault is
    // down: the session waits in the queue.
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
                "The amber jackdaw ferry bell rings twice at the slipway.",
            ),
            (
                second,
                Some(first),
                "Noted: the amber jackdaw bell rings twice at the slipway.",
            ),
        ],
    );
    let stop = json!({
        "hook_event_name": "Stop",
        "session_id": session,
        "transcript_path": log,
        "cwd": beta,
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

    // `serve` starts and imports the queued session.
    let log_path = home.path("serve.log");
    let serve_log = std::fs::File::create(&log_path).expect("server log file");
    let server = Server(
        home.oneiron(&["serve", "--host", "127.0.0.1", "--config", config_arg])
            .stdout(serve_log.try_clone().expect("server log file"))
            .stderr(serve_log)
            .spawn()
            .expect("spawn oneiron serve"),
    );
    home.wait_for_runtime_file(server.0.id(), &log_path);
    wait_for_empty(&queue, &log_path);

    // A prompt in alpha's folder, matching the beta turn's words: the turn stays out, the
    // alpha CLAIM rides in.
    let credential_arg = credential.to_str().expect("UTF-8 path");
    let prompt = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
        "cwd": alpha,
        "prompt": "amber jackdaw ferry bell",
    });
    let said = lines(&home.hook(
        "prompt",
        &["--credential-file", credential_arg, "--timeout", "60"],
        &prompt,
    ));
    assert_eq!(
        said.first().map(String::as_str),
        Some("From your Oneiron vault, for this prompt (may be dated):"),
        "the push rides under the prompt's header: {said:?}"
    );
    assert!(
        said.iter().any(|line| line.contains("pier nine order")),
        "the alpha CLAIM's line IS pushed: {said:?}"
    );
    assert!(
        said.iter().all(|line| !line.contains("slipway")),
        "no TURN from beta's session reaches alpha's: {said:?}"
    );

    let pid = server.0.id();
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
}

#[test]
fn a_queried_start_in_a_bound_project_names_its_session_and_the_records_it_pushes() {
    use std::os::unix::fs::PermissionsExt as _;

    let home = Home::new();
    let url = answering_vault();
    let folder = home.path("project");
    std::fs::create_dir(&folder).expect("project folder");
    let bridge = home.path("bridge");
    let argv = home.path("argv");
    let call = home.path("call");
    // Stand in at the MCP boundary to see the request and return a fixed, pinned hit.
    let script = r#"#!/bin/sh
printf '%s\n' "$@" > '@ARGV@'
read -r line
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"_meta":{"oneiron/workspace":{"project_bound":true}}}}'
read -r line
read -r line || exit 0
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"vault.recall"}]}}'
read -r line
printf '%s\n' "$line" > '@CALL@'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"structuredContent":{"items":[{"kind":"CLAIM","value_text":"heron lantern plans","predicate":"profile.hobby","short_id":"claim:42","source_revision_ref":"1234567890abcdef1234567890abcdef","provenance":{"source":"user_stated"},"line_provenance":{"approval":"auto","learned_at":1780000000,"source_conversations":["conv:ab","conv:cd"]}}]}}}'
"#;
    let script = script
        .replace("@ARGV@", argv.to_str().expect("UTF-8 path"))
        .replace("@CALL@", call.to_str().expect("UTF-8 path"));
    std::fs::write(&bridge, script).expect("write the bridge");
    std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o700))
        .expect("make the bridge executable");
    let credential = home.path("scripted.cred");
    let said = home.session_start_in(
        &folder,
        &[
            "--url",
            &url,
            "--oneiron",
            bridge.to_str().expect("UTF-8 path"),
            "--credential-file",
            credential.to_str().expect("UTF-8 path"),
            "--query",
            "heron lantern",
            "--timeout",
            "60",
        ],
    );

    let argv = std::fs::read_to_string(argv).expect("bridge arguments");
    let argv: Vec<_> = argv.lines().collect();
    assert!(
        argv.windows(2)
            .any(|args| args == ["--workspace", folder.to_str().expect("UTF-8 path")]),
        "the bridge names the bound folder: {argv:?}"
    );
    let call: Value = serde_json::from_slice(&std::fs::read(call).expect("recall request"))
        .expect("JSON-RPC call");
    assert_eq!(
        call.pointer("/params/arguments/arguments/spec/bar"),
        Some(&json!({
            "source": "start",
            "harness": "claude-code",
            "session": "0b5e55e0-2222-4333-8444-a55566667777",
        })),
    );
    assert_eq!(said.len(), 3, "{said:?}");
    assert!(
        said[1].contains("the whole record: vault.hydrate with the id"),
        "{said:?}"
    );
    assert_eq!(
        said[2],
        "- profile.hobby: heron lantern plans (claim:42@1234567890abcdef1234567890abcdef · stated · auto · from conv:ab +1 · learned 2026-05-28 20:26 UTC)"
    );
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

/// The stopped vault `path` names, opened as `serve` opens it, with this install's keystore,
/// so a test seeds owner state (projects, bindings, bars, claims) before `serve` starts. The
/// vault must be stopped: a running `serve` holds its writer lease. Like `serve`'s boot, the
/// handle holds the root's key, which proves the owner's acts on a self-host (row
/// CARRIER-OWNER-PROOF); without it an owner's setting waits for an owner key.
fn open_stopped(path: &Path) -> Vault {
    let vault = Vault::open_owned(path, VaultConfig::server()).expect("the stopped vault opens");
    KeystoreConfig::default().install_on(&vault, path);
    let issuer = vault
        .load_host_slip_issuer()
        .expect("the host issuer the shipped mints rooted");
    vault.hold_checkpoint_root_signer(std::sync::Arc::new(issuer));
    vault
}

/// The vault's owner and the owner's proof. The shipped mints rooted the vault under this
/// install's own host issuer seed, and their genesis bound the owner, so no hand-signed bind
/// is needed.
fn owner_and_proof(vault: &Vault) -> (EntityId, AuthenticatedOwner) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the owner actor");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner proof");
    (owner, proof)
}

/// A project the owner's tap bears from `card_id`, the way an owner's tap bears one: a card
/// minted through the public door over a witnessed source message, signed by the host for the
/// owner under the loaded issuer. Returns the PROJECT's id.
fn mint_project(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    card_id: &str,
) -> EntityId {
    let issuer = vault
        .load_host_slip_issuer()
        .expect("the host issuer the shipped mints rooted");
    let project_signer = vault
        .owner_project_signer(&issuer)
        .expect("the owner project signer");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is set")
        .as_secs();
    let source_message = EntityId::now().to_hex();
    let staged: WitnessTurn = serde_json::from_value(json!({
        "conversation_ref": EntityId::now().to_hex(),
        "occurred_at": now,
        "messages": [{
            "id": source_message,
            "author": "user",
            "message_type": "text",
            "content": "Does this sound like a project?",
            "is_visible": true,
            "order": 0,
        }],
    }))
    .expect("the card's source message");
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&staged)
        .expect("the owner stages the card's source message");
    let leader = EntityId::from_hex(
        &vault
            .project(vault.root_project().expect("the root PROJECT"))
            .expect("the root project reads")
            .expect("the root project is stored")
            .leader,
    )
    .expect("the root project's leader");
    let card = ProjectProposalCard::new(
        card_id,
        owner.to_hex(),
        source_message,
        ProjectGoalDraft {
            goal: "Seed a project the hook tests bind".to_owned(),
            why: "The carrier push reads the session folder's project".to_owned(),
            axes: vec!["coverage".to_owned()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: leader.to_hex(),
            board_human_refs: vec![owner.to_hex()],
            budget_share_bps: 1200,
            starting_skill_refs: vec![],
        },
    )
    .expect("the seeding card validates");
    let tap = ConsentActionRequest::new(
        card.card_id.clone(),
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: owner.to_hex(),
        },
        ConsentSurface::Dashboard,
        now,
    )
    .expect("the owner's tap validates");
    let receipt = vault
        .mint_project_from_card(&card, &tap, proof, &project_signer)
        .expect("the owner's card mints the project");
    EntityId::from_hex(&receipt.project_id).expect("the mint names its project")
}

/// The owner binds `folder`, which must exist, to `project`, labelled `label`: the PROJECT
/// its attached sessions read by default.
fn bind_folder(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    folder: &Path,
    project: EntityId,
    label: &str,
) {
    let digest = WorkspaceIdentity::of_session_folder(folder)
        .expect("the folder is a workspace")
        .own_digest()
        .to_owned();
    vault
        .bind_workspace_as_owner(
            proof,
            Some(ActSurface::ThisInstall),
            WorkspaceBindRequest {
                folder_digest: digest,
                project,
                label: Some(label.to_owned()),
            },
        )
        .expect("the owner binds the folder");
}

/// The owner sets `key` for harness `claude-code` at the vault: `value` (a `recall.bar.*`
/// rule, say `"quiet"`, or the empty receipt, `true`).
fn owner_sets_bar(vault: &Vault, proof: &AuthenticatedOwner, key: &str, value: Value) {
    let mut change = SetSetting::vault_value(key, value);
    change.item = Some("claude-code".to_owned());
    let outcome = vault
        .set_setting(SettingCaller::Owner(proof), change)
        .unwrap_or_else(|error| panic!("the owner sets {key}: {error}"));
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's change applies at once: {outcome:?}"
    );
}

/// The owner's claim about the owner, stamped with `project`: `predicate` is `value`.
fn remember_in(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    project: EntityId,
    predicate: &str,
    value: &str,
) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(EntityId::now().to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: substrate_facet_id(owner)
                    .expect("the owner's substrate facet")
                    .to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: project.to_hex(),
            }
            .into(),
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .expect("the owner's claim lands in the project");
}
