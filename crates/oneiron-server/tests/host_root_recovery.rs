//! A self-host owner whose install lost the vault's host root gets it back
//! with the recovery kit they enrolled before the loss (L1-07; OF-570;
//! identity.md `#cloud-agent-recovery`, rows "Recovery in each mode" and
//! "Recovery reboot"). The root signs with this install's own issuer seed,
//! escrowed in the vault's key custody (FIX-LIST 3018, 10770). When the seed
//! is gone and the escrow gives none back, `oneiron host re-root` cannot
//! move the root, because it needs the current seed's signature.
//!
//! The checks: an enrolled kit moves the root to a new seed in-chain, so the
//! vault keeps its id and what was saved; the lost root's credentials stop
//! working, and a keystore found later holds a retired root. The command
//! refuses while this install holds the live root, refuses a kit that was
//! never enrolled and leaves the slot empty, and is not needed while the
//! escrow gives the seed back. After the move, `serve` shows the
//! fragile-genesis flag until a new kit is enrolled (L1-07-KIT-AFTER-MOVE).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! host_root_recovery`. Linux only: the keystore here is the file keystore,
//! one `<slot>.key` file per slot under `ONEIRON_KEYSTORE_DIR`.
#![cfg(all(unix, not(target_vendor = "apple"), oneiron_test_support))]
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use oneiron::memory::{RecallEffort, RecallScope, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron_remote::{OneironClient, unix_seconds_now};
use oneiron_server::config::{ServeArgs, resolve_serve_config};
use serde_json::Value;

/// The host secret before the loss. The secret is a presence check that
/// admits host commands, never the root's key.
const OLD: &str = "root-recovery-check-first-host-secret";
/// The host secret the owner sets after the loss: any value admits.
const NEW: &str = "root-recovery-check-later-host-secret";
const TEXT: &str = "The Varnholt orchard ladder is stored under the north eaves.";
/// The typed reason `serve` logs while the vault holds no recovery method.
const FRAGILE: &str = "GENESIS_FRAGILE";
/// What the refusal says when this install holds the live root.
const ROOT_HELD: &str = "holds the vault's live root";
/// What the refusal says for a kit whose key was never enrolled.
const NOT_ENROLLED: &str = "not a live owner key of this vault";

/// A running `oneiron serve`, killed on drop so a failed assertion never
/// leaves a server holding the vault.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One test's stopped self-host vault: its directory, config file, keystore
/// directory and the port it serves on.
struct Host {
    dir: tempfile::TempDir,
    vault: PathBuf,
    config: PathBuf,
    keys: PathBuf,
    port: u16,
}

impl Host {
    /// `oneiron init` with the first host secret. The first host command
    /// after it roots the vault.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        owner_only_dir(&keys);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let host = Self {
            vault: dir.path().join("vault"),
            config: dir.path().join("oneiron.toml"),
            keys,
            port,
            dir,
        };
        let vault = host.vault_arg().to_owned();
        json(host.oneiron(&["init", &vault, "--embedder", "none"], OLD));
        host
    }

    fn vault_arg(&self) -> &str {
        self.vault.to_str().unwrap()
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn oneiron(&self, args: &[&str], secret: &str) -> Command {
        self.oneiron_with_keys(args, secret, &self.keys)
    }

    /// The CLI with this host's config, `secret` as the host secret and
    /// `keys` as the keystore directory.
    fn oneiron_with_keys(&self, args: &[&str], secret: &str, keys: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        command
            .args(args)
            .arg("--config")
            .arg(&self.config)
            .env("ONEIRON_AUTH_SECRET", secret)
            .env("ONEIRON_KEYSTORE_DIR", keys)
            .env_remove("ONEIRON_KEYSTORE_BACKEND")
            .env_remove("ONEIRON_NEW_AUTH_SECRET")
            .env_remove("ONEIRON_VAULT_PATH")
            .env_remove("ONEIRON_URL")
            .stdin(Stdio::null());
        command
    }

    fn vault_id(&self, secret: &str) -> Value {
        json(self.oneiron(&["whoami", self.vault_arg()], secret))["vault_id"].clone()
    }

    /// Issues a world kit to three homes and confirms it with two of its
    /// pieces; the two piece files.
    fn issue_kit(&self, name: &str, secret: &str) -> [PathBuf; 2] {
        let out = self.dir.path().join(name);
        owner_only_dir(&out);
        let out_arg = out.to_str().unwrap();
        let issued = json(self.oneiron(
            &[
                "recovery-kit",
                "issue",
                "--home",
                "paper",
                "--home",
                "password-manager",
                "--home",
                "file-elsewhere",
                "--out",
                out_arg,
            ],
            secret,
        ));
        let files: Vec<PathBuf> = issued["pieces"]
            .as_array()
            .unwrap_or_else(|| panic!("the issued pieces: {issued:#}"))
            .iter()
            .map(|piece| PathBuf::from(piece["file"].as_str().unwrap()))
            .collect();
        assert!(files.len() >= 2, "{issued:#}");
        let pieces = [files[0].clone(), files[1].clone()];
        json(self.with_pieces(&["recovery-kit", "confirm"], &pieces, secret));
        pieces
    }

    /// `recovery-kit enroll-authority`: the kit's authority key becomes a
    /// live owner key of the vault, before any loss.
    fn enroll_kit(&self, pieces: &[PathBuf; 2], secret: &str) -> Value {
        json(self.with_pieces(&["recovery-kit", "enroll-authority"], pieces, secret))
    }

    fn recover_root(&self, pieces: &[PathBuf; 2], secret: &str) -> Output {
        run(self.with_pieces(&["host", "recover-root"], pieces, secret))
    }

    fn with_pieces(&self, verb: &[&str], pieces: &[PathBuf; 2], secret: &str) -> Command {
        let mut args = verb.to_vec();
        for piece in pieces {
            args.push("--piece");
            args.push(piece.to_str().unwrap());
        }
        self.oneiron(&args, secret)
    }

    /// The loss, in process on the stopped vault: this install's seed slot
    /// is emptied and the escrow can give no seed back.
    fn lose_the_host_root(&self) {
        let mut config = resolve_serve_config(&ServeArgs {
            config: Some(self.config.clone()),
            ..ServeArgs::default()
        })
        .expect("resolve the test config");
        config.keystore.dir = Some(self.keys.clone());
        let vault = oneiron::Vault::open_owned(&config.vault_path, config.vault_config())
            .expect("open the stopped vault");
        assert!(
            config.keystore.install_on(&vault, &config.vault_path),
            "the file keystore installs"
        );
        oneiron::test_doors::host_root_loss::lose_host_issuer_seed(&vault)
            .expect("lose this install's host issuer seed and its escrow");
    }

    /// Starts `oneiron serve` and waits until an unauthenticated call is
    /// refused. Its log (stdout, where tracing writes, and stderr) is
    /// `<name>.log` in the test directory.
    fn serve(&self, secret: &str, name: &str) -> Server {
        let port = self.port.to_string();
        let log = self.dir.path().join(format!("{name}.log"));
        let out = File::create(&log).expect("server log file");
        let err = out.try_clone().expect("server log file, again");
        let mut command = self.oneiron(&["serve", "--host", "127.0.0.1", "--port", &port], secret);
        command.stdout(out).stderr(err);
        let mut server = Server(command.spawn().expect("spawn oneiron serve"));
        let probe = reqwest::blocking::Client::new();
        let url = format!("{}/v1/core/facade/vault.receipts", self.origin());
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = server.0.try_wait().expect("poll oneiron serve") {
                panic!(
                    "oneiron serve exited during startup ({status}): {}",
                    std::fs::read_to_string(&log).unwrap_or_default()
                );
            }
            let answered = probe
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
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn log(&self, name: &str) -> String {
        std::fs::read_to_string(self.dir.path().join(format!("{name}.log"))).unwrap_or_default()
    }

    /// Pairs the owner through a bootstrap link minted with `secret`.
    fn pair_owner(&self, secret: &str) -> OneironClient {
        let link = json(self.oneiron(&["token", "bootstrap", "--url", &self.origin()], secret));
        let (url, credential, _comm) = OneironClient::pair(link.as_str().unwrap()).unwrap();
        OneironClient::connect(&url, &credential).unwrap()
    }
}

/// A rooted vault with agent A's credential and an enrolled kit; the owner's
/// text saved through a served session first when `witness` is set.
fn rooted_with_enrolled_kit(witness: bool) -> (Host, Value, [PathBuf; 2]) {
    let host = Host::new();
    let agent = json(host.oneiron(&["token", "agent", "--name", "claude-code"], OLD));
    if witness {
        let server = host.serve(OLD, "serve-before");
        witness_text(&host.pair_owner(OLD));
        drop_with_sigterm(server);
    }
    let pieces = host.issue_kit("kit-first", OLD);
    host.enroll_kit(&pieces, OLD);
    (host, agent, pieces)
}

fn witness_text(owner: &OneironClient) {
    owner
        .vault_witness(&WitnessTurn {
            conversation_ref: "66666666666666666666666666666666".into(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: TEXT.into(),
                metadata: None,
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: unix_seconds_now(),
            thread_audience: None,
            assertions: Default::default(),
        })
        .unwrap();
    assert_eq!(recall(owner), Ok(true));
}

fn run(mut command: Command) -> Output {
    command.output().expect("run oneiron")
}

fn printed(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn json(command: Command) -> Value {
    let output = run(command);
    assert!(output.status.success(), "{}", printed(&output));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    serde_json::from_str(stdout.trim()).unwrap_or_else(|_| Value::String(stdout.trim().into()))
}

/// The refusal's stderr; the command must have failed.
fn refused(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "expected a refusal: {}",
        printed(output)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn drop_with_sigterm(mut server: Server) {
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

fn recall(client: &OneironClient) -> Result<bool, String> {
    client
        .vault_recall(
            "Varnholt orchard ladder",
            RecallEffort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .map(|pack| pack.items.iter().any(|item| item.value_text.contains(TEXT)))
        .map_err(|error| error.to_string())
}

fn owner_only_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create the directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("set the directory's mode");
}

/// A copy of the keystore directory, as a backup of the old machine's
/// keystore that turns up after the loss.
fn copy_keys(from: &Path, to: &Path) {
    owner_only_dir(to);
    for entry in std::fs::read_dir(from).expect("read the keystore directory") {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), to.join(entry.file_name())).expect("copy a key file");
        }
    }
}

fn piece_texts(pieces: &[PathBuf; 2]) -> Vec<String> {
    pieces
        .iter()
        .map(|piece| std::fs::read_to_string(piece).unwrap().trim().to_owned())
        .collect()
}

#[test]
fn a_lost_host_root_recovers_with_the_enrolled_kit_and_keeps_the_vault_id() {
    let (host, agent, pieces) = rooted_with_enrolled_kit(true);
    let vault_id = host.vault_id(OLD);
    assert!(vault_id.is_string(), "rooted: {vault_id}");
    let found = host.dir.path().join("keys-found");
    copy_keys(&host.keys, &found);
    host.lose_the_host_root();

    // The kit is the proof; the new host secret only admits the command.
    let output = host.recover_root(&pieces, NEW);
    let text = printed(&output);
    assert!(output.status.success(), "{text}");
    for secret in [OLD, NEW] {
        assert!(!text.contains(secret), "{text}");
    }
    for piece in piece_texts(&pieces) {
        assert!(!text.contains(&piece), "a piece's code is printed: {text}");
    }
    let moved: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(moved["vault_id"], vault_id, "{moved:#}");
    assert!(
        moved["engine_writers_enrolled"].as_u64() > Some(0),
        "{moved:#}"
    );
    let agent_slip = agent["slip_id"].as_str().unwrap();
    assert!(
        moved["retired_credentials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|slip| slip["slip_id"].as_str() == Some(agent_slip)),
        "agent A's slip is listed: {moved:#}"
    );
    let next = moved["next"].to_string();
    assert!(next.contains("token agent"), "{moved:#}");
    assert!(next.contains("enroll-authority"), "{moved:#}");

    // The same vault under the new root: this install mints again.
    assert_eq!(host.vault_id(NEW), vault_id);
    let agent_b = json(host.oneiron(&["token", "agent", "--name", "claude-code"], NEW));
    // The old machine's keystore, found again, holds a retired root.
    refused(&run(host.oneiron_with_keys(
        &["token", "agent", "--name", "claude-code"],
        NEW,
        &found,
    )));

    let _server = host.serve(NEW, "serve-after");
    let owner = host.pair_owner(NEW);
    assert_eq!(recall(&owner), Ok(true), "what was saved is still found");
    let origin = host.origin();
    let new_agent =
        OneironClient::connect(&origin, agent_b["credential"].as_str().unwrap()).unwrap();
    assert!(recall(&new_agent).is_ok());
    let old_agent = OneironClient::connect(&origin, agent["credential"].as_str().unwrap()).unwrap();
    assert!(
        recall(&old_agent).is_err(),
        "agent A's slip stopped working"
    );
}

#[test]
fn recover_root_refuses_while_this_install_holds_the_live_root() {
    let (host, agent, pieces) = rooted_with_enrolled_kit(false);
    let vault_id = host.vault_id(OLD);

    let error = refused(&host.recover_root(&pieces, OLD));
    assert!(error.contains(ROOT_HELD), "{error}");

    // Nothing moved: the same vault, and agent A's slip still reads.
    assert_eq!(host.vault_id(OLD), vault_id);
    let _server = host.serve(OLD, "serve-after");
    let old_agent =
        OneironClient::connect(&host.origin(), agent["credential"].as_str().unwrap()).unwrap();
    assert!(recall(&old_agent).is_ok(), "agent A's slip still works");
}

#[test]
fn recover_root_refuses_a_kit_whose_key_was_never_enrolled() {
    let host = Host::new();
    json(host.oneiron(&["token", "agent", "--name", "claude-code"], OLD));
    let pieces = host.issue_kit("kit-unenrolled", OLD);
    host.lose_the_host_root();

    let error = refused(&host.recover_root(&pieces, NEW));
    assert!(error.contains(NOT_ENROLLED), "{error}");

    // The refusal put back what it found: this install's slot is empty.
    let error = refused(&run(
        host.oneiron(&["token", "agent", "--name", "claude-code"], NEW)
    ));
    assert!(error.contains("holds no host issuer"), "{error}");
}

#[test]
fn a_new_install_takes_back_the_escrowed_root_without_the_kit() {
    let (host, _agent, pieces) = rooted_with_enrolled_kit(false);
    let seeds: Vec<PathBuf> = std::fs::read_dir(&host.keys)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("host-issuer-seed") && name.ends_with(".key"))
        })
        .collect();
    assert_eq!(seeds.len(), 1, "one seed slot file: {seeds:?}");
    std::fs::remove_file(&seeds[0]).unwrap();

    // FIX-LIST 10770: the keystore install takes the escrowed seed back.
    json(host.oneiron(&["token", "agent", "--name", "claude-code"], NEW));
    let error = refused(&host.recover_root(&pieces, NEW));
    assert!(error.contains(ROOT_HELD), "{error}");
}

#[test]
fn a_recovered_root_flags_the_vault_until_a_new_kit_is_enrolled() {
    let (host, _agent, pieces) = rooted_with_enrolled_kit(false);
    drop_with_sigterm(host.serve(OLD, "serve-kit-enrolled"));
    let log = host.log("serve-kit-enrolled");
    assert!(!log.contains(FRAGILE), "{log}");

    host.lose_the_host_root();
    let output = host.recover_root(&pieces, NEW);
    assert!(output.status.success(), "{}", printed(&output));
    // The move retired the kit's key with every other key.
    drop_with_sigterm(host.serve(NEW, "serve-no-kit"));
    let log = host.log("serve-no-kit");
    assert!(log.contains(FRAGILE), "{log}");

    let fresh = host.issue_kit("kit-second", NEW);
    host.enroll_kit(&fresh, NEW);
    drop_with_sigterm(host.serve(NEW, "serve-new-kit"));
    let log = host.log("serve-new-kit");
    assert!(!log.contains(FRAGILE), "{log}");
}
