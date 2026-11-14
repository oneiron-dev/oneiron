#![cfg(all(oneiron_test_support, target_os = "linux"))]
//! `oneiron user-service` and the hook's step 4 (ARCH-0028
//! `#plugin-first-run`: "Otherwise, the hook starts a local server, with an
//! optional user service. The setup steps live in the skill or the MCP
//! doc."), through the shipped binary.
//!
//! The binary runs with a scratch `HOME`, `XDG_CONFIG_HOME` and
//! `XDG_RUNTIME_DIR`, and a stand-in `systemctl` first on `PATH` that
//! records each call and, on `--user start`, starts the unit's `ExecStart=`
//! the way the user manager would. The launchd agent is checked through
//! `oneiron_server::test_doors::user_service`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test hook_user_service`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use clap::Parser as _;
use serde_json::{Value, json};

const SECRET: &str = "user-service-issuer-key-not-a-bearer";
const MARKER: &str = "# Written by oneiron user-service install.";
const NOT_LOGGED_IN: &str = "Oneiron: started local; no hosted vault is signed in to here \
                             (`oneiron hosted login`); pin one with --url, ONEIRON_URL or hook \
                             config.";

/// The stand-in `systemctl`: it appends its arguments to `systemctl.log`
/// and, for `--user start`, runs the unit's `ExecStart=` in the background,
/// as the user manager would, and records its pid in `service.pid`.
const SYSTEMCTL: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$STANDIN_DIR/systemctl.log"
if [ "$1" = "--user" ] && [ "$2" = "start" ]; then
  exec_start=$(sed -n 's/^ExecStart=//p' "$XDG_CONFIG_HOME/systemd/user/oneiron.service")
  $exec_start </dev/null >>"$STANDIN_DIR/service-serve.log" 2>&1 &
  echo $! > "$STANDIN_DIR/service.pid"
fi
exit 0
"#;

/// A user's home with its own config and runtime folders and its own
/// `systemctl`, so nothing a test runs sees the host's vaults, runtime
/// files, units or user manager.
struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let home = Self {
            dir: tempfile::tempdir().expect("test fixture"),
        };
        for dir in ["home", "config", "runtime", "bin", "standin"] {
            std::fs::create_dir(home.dir.path().join(dir)).expect("test fixture");
        }
        let systemctl = home.path("bin").join("systemctl");
        std::fs::write(&systemctl, SYSTEMCTL).expect("test fixture");
        std::fs::set_permissions(&systemctl, std::fs::Permissions::from_mode(0o755))
            .expect("test fixture");
        home
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The per-user oneiron folder, where the default config sits.
    fn user_dir(&self) -> PathBuf {
        self.path("config").join("oneiron")
    }

    fn run_dir(&self) -> PathBuf {
        self.path("runtime").join("oneiron")
    }

    /// Where `install` writes the systemd user unit.
    fn unit(&self) -> PathBuf {
        self.path("config").join("systemd/user/oneiron.service")
    }

    fn oneiron(&self, args: &[&str]) -> Command {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut path_dirs = vec![self.path("bin")];
        path_dirs.extend(std::env::split_paths(&path));
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(args)
            .env(
                "PATH",
                std::env::join_paths(path_dirs).expect("test fixture"),
            )
            .env("STANDIN_DIR", self.path("standin"))
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

    /// Creates a vault at `vault` and the config every command reads when
    /// none is named, on any free port.
    fn init(&self, vault: &Path) -> PathBuf {
        let config = self.user_dir().join("oneiron.toml");
        std::fs::create_dir_all(self.user_dir()).expect("test fixture");
        let output = self
            .oneiron(&["init"])
            .arg(vault)
            .arg("--config")
            .arg(&config)
            .args(["--embedder", "none"])
            .output()
            .expect("run oneiron init");
        assert!(
            output.status.success(),
            "init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // A top-level key goes before the file's first table.
        let body = std::fs::read_to_string(&config).expect("test fixture");
        std::fs::write(&config, format!("port = 0\n{body}")).expect("test fixture");
        config
    }

    fn user_service(&self, args: &[&str]) -> Output {
        self.oneiron(&["user-service"])
            .args(args)
            .stdin(Stdio::null())
            .output()
            .expect("run oneiron user-service")
    }

    /// Each call the stand-in `systemctl` took, in order.
    fn systemctl_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.path("standin").join("systemctl.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The pid of the `serve` the stand-in started for `--user start`.
    fn service_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.path("standin").join("service.pid"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn session_start(&self) -> Vec<String> {
        let event = json!({
            "hook_event_name": "SessionStart",
            "session_id": "0b5e55e0-2222-4333-8444-a55566667777",
            "source": "startup",
            "cwd": "/tmp/heron-lantern",
            "transcript_path": "/dev/null",
        });
        let mut child = self
            .oneiron(&["hook", "--host", "claude-code", "session-start"])
            .args(["--timeout", "120"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn oneiron hook");
        child
            .stdin
            .take()
            .expect("hook stdin")
            .write_all(event.to_string().as_bytes())
            .expect("write the hook event");
        let output = child.wait_with_output().expect("run oneiron hook");
        assert_eq!(
            output.status.code(),
            Some(0),
            "a hook always exits 0; stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("UTF-8 stdout")
            .lines()
            .map(str::to_owned)
            .collect()
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

    fn wait_for_runtime_file(&self, pid: u32) -> Value {
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
                "serve never wrote its runtime file: {}{}",
                std::fs::read_to_string(self.path("serve.log")).unwrap_or_default(),
                std::fs::read_to_string(self.path("standin").join("service-serve.log"))
                    .unwrap_or_default()
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

/// A `serve` the stand-in started, by its pid file. Dropping it kills the
/// process, so a failed assertion never leaves one holding the vault.
struct ServicePid(PathBuf);

impl Drop for ServicePid {
    fn drop(&mut self) {
        if let Some(pid) = std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|pid| pid.trim().parse::<libc::pid_t>().ok())
        {
            // SAFETY: `kill` takes plain integers and touches no memory;
            // `pid` is the `serve` the stand-in started for this test.
            let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// A `serve` a session left running, by the pid its runtime file names.
/// Dropping it kills the process if it still runs.
struct ServerPid(u32);

impl Drop for ServerPid {
    fn drop(&mut self) {
        let Ok(pid) = libc::pid_t::try_from(self.0) else {
            return;
        };
        // SAFETY: `kill` takes plain integers and touches no memory; `pid`
        // is a `serve` this test's session started.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }
}

/// A server this test started. Dropping it kills the process.
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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn status_line(output: &Output) -> Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout");
    serde_json::from_str(stdout.lines().last().expect("a status line")).expect("status is JSON")
}

fn binary() -> PathBuf {
    std::fs::canonicalize(env!("CARGO_BIN_EXE_oneiron")).expect("the built binary")
}

#[test]
fn user_service_install_writes_the_user_unit_for_the_hook_config() {
    let home = Home::new();
    let config = home.init(&home.path("vault"));

    let output = home.user_service(&["install"]);

    assert!(output.status.success(), "install: {}", stderr(&output));
    let unit = std::fs::read_to_string(home.unit()).expect("the unit is written");
    assert_eq!(unit.lines().next(), Some(MARKER), "{unit}");
    let exec_start = format!(
        "ExecStart={} serve --config {} --host 127.0.0.1",
        binary().display(),
        config.display()
    );
    for line in [
        exec_start.as_str(),
        "Type=notify",
        "Environment=MALLOC_ARENA_MAX=2",
        "Restart=on-failure",
        "WantedBy=default.target",
    ] {
        assert!(
            unit.lines().any(|unit_line| unit_line == line),
            "the unit holds {line:?}: {unit}"
        );
    }
    assert_eq!(
        unit.lines()
            .filter(|line| line.starts_with("ExecStart="))
            .count(),
        1,
        "{unit}"
    );
    assert!(
        !unit.lines().any(|line| line.starts_with("PrivateTmp=")),
        "a user manager's private /tmp needs a user namespace: {unit}"
    );
    assert_eq!(
        home.systemctl_calls(),
        [
            "--user daemon-reload",
            "--user enable oneiron.service",
            "--user restart oneiron.service",
        ]
    );
    assert_eq!(
        status_line(&output),
        json!({
            "installed": true,
            "path": home.unit(),
            "supervisor": "systemd",
        })
    );
}

#[test]
fn user_service_install_refuses_a_unit_it_did_not_write() {
    let home = Home::new();
    home.init(&home.path("vault"));
    let hand_written = "[Service]\nExecStart=/usr/local/bin/oneiron serve\n";
    std::fs::create_dir_all(home.unit().parent().expect("unit folder")).expect("test fixture");
    std::fs::write(home.unit(), hand_written).expect("test fixture");

    let output = home.user_service(&["install"]);

    assert!(!output.status.success(), "install over a hand-written unit");
    assert!(
        stderr(&output).contains("was not written by `oneiron user-service install`"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        std::fs::read_to_string(home.unit()).expect("the unit stays"),
        hand_written
    );
    assert!(
        home.systemctl_calls().is_empty(),
        "{:?}",
        home.systemctl_calls()
    );
}

#[test]
fn user_service_remove_disables_and_deletes_the_unit() {
    let home = Home::new();
    home.init(&home.path("vault"));
    let installed = home.user_service(&["install"]);
    assert!(
        installed.status.success(),
        "install: {}",
        stderr(&installed)
    );

    let output = home.user_service(&["remove"]);

    assert!(output.status.success(), "remove: {}", stderr(&output));
    assert!(!home.unit().exists(), "the unit is deleted");
    assert_eq!(
        home.systemctl_calls(),
        [
            "--user daemon-reload",
            "--user enable oneiron.service",
            "--user restart oneiron.service",
            "--user disable --now oneiron.service",
            "--user daemon-reload",
        ]
    );
    assert_eq!(status_line(&output)["installed"], json!(false));
}

#[test]
fn user_service_install_refuses_while_another_server_runs_the_vault() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.init(&vault);
    let log = std::fs::File::create(home.path("serve.log")).expect("test fixture");
    let server = Server(
        home.oneiron(&["serve", "--host", "127.0.0.1"])
            .arg("--config")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("test fixture"))
            .stderr(log)
            .spawn()
            .expect("spawn oneiron serve"),
    );
    home.wait_for_runtime_file(server.0.id());

    let output = home.user_service(&["install"]);

    assert!(!output.status.success(), "install beside a running vault");
    assert!(
        stderr(&output).contains(&format!("is running now as pid {}", server.0.id())),
        "{}",
        stderr(&output)
    );
    assert!(!home.unit().exists(), "no unit is written");
    assert!(
        home.systemctl_calls().is_empty(),
        "{:?}",
        home.systemctl_calls()
    );
}

#[test]
fn session_start_step4_starts_the_installed_user_service() {
    let home = Home::new();
    let vault = home.path("vault");
    let config = home.init(&vault);
    // The unit `install` writes (its marker and its `ExecStart=`), written
    // here, so this test checks step 4 alone.
    std::fs::create_dir_all(home.unit().parent().expect("unit folder")).expect("test fixture");
    std::fs::write(
        home.unit(),
        format!(
            "{MARKER}\n[Service]\nExecStart={} serve --config {} --host 127.0.0.1\n",
            binary().display(),
            config.display()
        ),
    )
    .expect("test fixture");
    let _service = ServicePid(home.path("standin").join("service.pid"));

    let said = home.session_start();

    // Whatever `serve` the session left running stops with the test.
    let servers: Vec<ServerPid> = home
        .runtime_files()
        .iter()
        .filter_map(|file| file["pid"].as_u64())
        .filter_map(|pid| u32::try_from(pid).ok())
        .map(ServerPid)
        .collect();
    assert_eq!(
        home.systemctl_calls(),
        ["--user start --no-block oneiron.service"],
        "step 4 asks the user manager to start the service: {said:?}"
    );
    let pid = home
        .service_pid()
        .expect("the user service started a serve");
    let started = home.wait_for_runtime_file(pid);
    let url = started["url"].as_str().expect("url").to_owned();
    assert_eq!(
        Path::new(started["state_dir"].as_str().expect("state_dir")),
        vault,
        "the runtime file names the vault's folder"
    );
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(
        said[0].contains(&url)
            && said[0].ends_with(&format!(
                "Started by its user service ({}).",
                home.unit().display()
            )),
        "the line names the vault its user service started: {said:?}"
    );
    assert_eq!(said[1], NOT_LOGGED_IN, "{said:?}");
    sigterm(pid);
    home.wait_for_no_runtime_file(pid);
    // Stopped cleanly: nothing is left for the guards to kill.
    std::fs::remove_file(home.path("standin").join("service.pid")).expect("test fixture");
    std::mem::forget(servers);
}

#[test]
fn the_skill_names_the_user_service_step() {
    let skill = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../plugins/claude-code/skills/oneiron/SKILL.md"),
    )
    .expect("read the skill");
    let setup = skill
        .split_once("## Set up once")
        .and_then(|(_, rest)| rest.split("\n## ").next())
        .expect("the skill has a setup section");
    let mut in_block = false;
    let mut steps = Vec::new();
    for line in setup.lines().map(str::trim) {
        if line.starts_with("```") {
            in_block = !in_block;
        } else if in_block && line.starts_with("oneiron user-service ") {
            steps.push(line.to_owned());
        }
    }
    assert!(
        steps
            .iter()
            .any(|line| line == "oneiron user-service install"),
        "the setup gives the install step in a code block: {setup}"
    );
    for line in &steps {
        let argv: Vec<&str> = line.split_whitespace().collect();
        if let Err(error) = oneiron_server::cli::Cli::try_parse_from(argv) {
            panic!("the skill's {line:?} does not parse: {error}");
        }
    }
}
