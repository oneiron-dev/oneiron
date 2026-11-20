//! [HOSTED-LOGIN-OAUTH-PLAIN-HTTP-ORIGIN] and [MCP-BRIDGE-OAUTH-BEARER-ANY-URL]
//! (REVIEW2-7877 P3-1 and P3-2): an OAuth sign-in's code, bearer and refresh
//! token prove no holder, so they go only to the vault the sign-in was made
//! at, over https or to this machine itself.
//!
//! - `oneiron hosted login --origin http://<another machine>` with no
//!   credential file refuses before it sends a request, and names
//!   `--credential-file` for a plain-http vault.
//! - `oneiron mcp --auth-mode oauth` refuses at spawn a plain-http `--url` to
//!   another machine, and a `--url` at another origin than the sign-in's
//!   token endpoint; and a refresh never takes the sign-in the file holds by
//!   then when that one was made at another origin.
//!
//! The vaults are stand-ins: loopback listeners that answer every request
//! HTTP 401 and keep what each one sent. The built binary is the client.
//!
//! Red on main: the login goes to the network ("could not reach"); the
//! bridge starts at a plain-http `--url` to another machine; it sends the
//! sign-in's bearer to a `--url` at another origin; and after a 401 it sends
//! the token of the sign-in the file then holds for another origin.
//!
//! `cargo test --locked -p oneiron-server --test hosted_login_token_transport`.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

/// A host no resolver answers (RFC 6761 §6.4): a request to it never lands.
const ANOTHER_MACHINE: &str = "http://vault.invalid";
/// How long the test waits for the binary to end.
const RUN_TIMEOUT: Duration = Duration::from_secs(90);
/// How long a stand-in reads one request.
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest request a stand-in keeps.
const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// A scratch HOME and config folder, and a `PATH` whose `xdg-open` records
/// the URL it is given.
struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        for sub in ["home", "config", "bin"] {
            std::fs::create_dir_all(dir.path().join(sub)).expect("scratch folder");
        }
        let opener = dir.path().join("bin/xdg-open");
        std::fs::write(
            &opener,
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$OPENED_URL_FILE\"\n",
        )
        .expect("write the stand-in opener");
        std::fs::set_permissions(&opener, std::fs::Permissions::from_mode(0o755))
            .expect("make the opener runnable");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron"));
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        command
            .args(args)
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("PATH", path)
            .env("OPENED_URL_FILE", self.path("opened.txt"))
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// Starts `oneiron mcp --auth-mode oauth` at `url` with the sign-in in
    /// `sign_in_file`, sends it one `initialize`, closes its stdin and
    /// answers what it printed.
    fn initialize_over_oauth(&self, url: &str, sign_in_file: &Path) -> Output {
        let mut child = self
            .command(&[
                "mcp",
                "--url",
                url,
                "--surface",
                "tool-first",
                "--auth-mode",
                "oauth",
                "--oauth-token-file",
                &sign_in_file.display().to_string(),
                "--request-timeout-secs",
                "20",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .expect("start oneiron mcp");
        let hello = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "hosted-login-token-transport", "version": "1"},
            },
        });
        let mut stdin = child.stdin.take().expect("stdin");
        // A bridge that refused at spawn has closed its end already.
        let _ = writeln!(stdin, "{hello}");
        drop(stdin);
        finish(child)
    }

    /// The hosted selection `oneiron hosted status` reads.
    fn status(&self) -> Value {
        let output = finish(
            self.command(&["hosted", "status"])
                .spawn()
                .expect("start oneiron hosted status"),
        );
        assert!(output.status.success(), "status: {}", stderr(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(stdout.lines().last().expect("a status line"))
            .expect("the status line is JSON")
    }
}

/// Waits for `child` to end, at most [`RUN_TIMEOUT`]; kills it past that.
fn finish(child: Child) -> Output {
    let pid = child.id();
    let (sender, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match ended.recv_timeout(RUN_TIMEOUT) {
        Ok(output) => output.expect("the binary ends"),
        Err(_) => {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            panic!("the binary ran past {RUN_TIMEOUT:?}");
        }
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_millis(),
    )
    .expect("ms fit u64")
}

/// Writes an OAuth sign-in made at `origin` to `file`, owner-only and in one
/// rename, as `hosted login` writes one: its access token `access`, good
/// for an hour, and its refresh token `{access}-refresh`.
fn write_sign_in(file: &Path, origin: &str, access: &str) {
    let body = json!({
        "token_endpoint": format!("{origin}/oauth/token"),
        "revocation_endpoint": format!("{origin}/oauth/revoke"),
        "client_id": "stand-in-client",
        "resource": format!("{origin}/mcp"),
        "access_token": access,
        "refresh_token": format!("{access}-refresh"),
        "expires_at_ms": now_ms() + 3_600_000,
        "scope": "read",
    });
    let staged = file.with_extension("staged");
    std::fs::write(&staged, serde_json::to_vec_pretty(&body).expect("JSON")).expect("write");
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600)).expect("owner-only");
    std::fs::rename(&staged, file).expect("move the sign-in in place");
}

/// A stand-in vault on a loopback port: it answers every request HTTP 401,
/// once `before_answer` has seen it, and keeps the text of each one.
struct StandIn {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    fn start() -> Self {
        Self::start_with(|_| {})
    }

    /// `before_answer` gets each request's number, from 1, before its 401
    /// goes back.
    fn start_with(before_answer: impl Fn(usize) + Send + 'static) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a loopback port");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let text = read_request(&mut stream);
                let number = {
                    let mut kept = kept.lock().expect("requests");
                    kept.push(text);
                    kept.len()
                };
                before_answer(number);
                let _ = stream.write_all(
                    b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
        Self { origin, requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }

    /// The requests that carried `token`, anywhere in their text.
    fn carrying(&self, token: &str) -> usize {
        self.requests()
            .iter()
            .filter(|text| text.contains(token))
            .count()
    }
}

/// One request's head and body, as text, read until its body ends or the
/// client stops sending.
fn read_request(stream: &mut TcpStream) -> String {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut held = Vec::new();
    let mut chunk = [0_u8; 4096];
    while held.len() < MAX_REQUEST_BYTES {
        if let Some(end) = held.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&held[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if held.len() >= end + 4 + length {
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => held.extend_from_slice(&chunk[..read]),
        }
    }
    String::from_utf8_lossy(&held).into_owned()
}

/// `hosted login` with no credential file at a plain-http origin on another
/// machine refuses before it sends a request: the code, the bearer and the
/// refresh token would cross the network in clear. It names
/// `--credential-file` for such a vault, opens no browser and records
/// nothing.
#[test]
fn an_oauth_login_at_a_plain_http_origin_on_another_machine_is_refused_before_any_request() {
    let scratch = Scratch::new();
    let output = finish(
        scratch
            .command(&[
                "hosted",
                "login",
                "--origin",
                &format!("{ANOTHER_MACHINE}:8080"),
                "--sign-in-timeout-secs",
                "10",
                "--timeout-secs",
                "10",
            ])
            .spawn()
            .expect("start oneiron hosted login"),
    );
    let said = stderr(&output);
    assert!(!output.status.success(), "the login is refused: {said}");
    assert!(
        said.contains("plain http to another machine") && said.contains("--credential-file"),
        "the refusal names the transport and the slip a plain-http vault takes: {said}"
    );
    assert!(
        !said.contains("could not reach"),
        "no request was sent before the refusal: {said}"
    );
    assert!(
        !scratch.path("opened.txt").exists(),
        "no browser was opened"
    );
    let status = scratch.status();
    assert_eq!(status["vaults"], json!([]), "nothing is recorded: {status}");
}

/// `oneiron mcp --auth-mode oauth` at a plain-http `--url` on another
/// machine refuses at spawn, though the sign-in was made there: its bearer
/// would cross the network in clear on every call.
#[test]
fn the_oauth_bridge_refuses_a_plain_http_url_on_another_machine_at_spawn() {
    let scratch = Scratch::new();
    let file = scratch.path("home/sign-in.json");
    write_sign_in(&file, ANOTHER_MACHINE, "v2.oauth-access.clear-text-route");
    let output = scratch.initialize_over_oauth(ANOTHER_MACHINE, &file);
    let said = stderr(&output);
    assert!(
        !output.status.success(),
        "the bridge refuses at spawn: {said}"
    );
    assert!(
        said.contains("plain http to another machine") && said.contains("--auth-mode slip"),
        "the refusal names the transport and the slip a plain-http vault takes: {said}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("\"id\":1"),
        "no call was answered: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// `oneiron mcp --auth-mode oauth` at a `--url` whose origin is not the one
/// the sign-in was made at (its token endpoint's) refuses at spawn, naming
/// both: neither origin is sent the bearer or the refresh token.
#[test]
fn the_oauth_bridge_refuses_a_url_at_another_origin_than_its_sign_in() {
    let scratch = Scratch::new();
    let made_at = StandIn::start();
    let elsewhere = StandIn::start();
    let file = scratch.path("home/sign-in.json");
    let access = "v2.oauth-access.made-at-one-vault";
    write_sign_in(&file, &made_at.origin, access);
    let output = scratch.initialize_over_oauth(&elsewhere.origin, &file);
    let said = stderr(&output);
    assert_eq!(
        elsewhere.carrying(access),
        0,
        "the --url at another origin is never sent the sign-in's bearer: {:?}",
        elsewhere.requests()
    );
    assert!(
        made_at.requests().is_empty(),
        "the sign-in's own vault is sent no refresh: {:?}",
        made_at.requests()
    );
    assert!(
        !output.status.success(),
        "the bridge refuses at spawn: {said}"
    );
    assert!(
        said.contains(&format!(
            "was made at {}, not at {}",
            made_at.origin, elsewhere.origin
        )),
        "the refusal names both origins: {said}"
    );
}

/// A bridge whose bearer the vault refuses (HTTP 401) reads the sign-in
/// file again under its refresh lock. When the file holds a sign-in made
/// at another origin by then, the bridge takes none of its tokens: the
/// `--url` is never sent that sign-in's bearer, and its own vault is never
/// sent its refresh token.
#[test]
fn an_oauth_refresh_never_takes_a_sign_in_the_file_now_holds_for_another_origin() {
    let scratch = Scratch::new();
    let other_vault = StandIn::start();
    let file = scratch.path("home/sign-in.json");
    let first = "v2.oauth-access.made-at-the-url";
    let swapped = "v2.oauth-access.made-at-another-vault";
    let (swap_file, swap_origin) = (file.clone(), other_vault.origin.clone());
    // The first request shows the bridge read the first sign-in; the file
    // then holds another vault's sign-in before the 401 goes back.
    let url_vault = StandIn::start_with(move |number| {
        if number == 1 {
            write_sign_in(&swap_file, &swap_origin, swapped);
        }
    });
    write_sign_in(&file, &url_vault.origin, first);
    let output = scratch.initialize_over_oauth(&url_vault.origin, &file);
    assert_eq!(
        url_vault.carrying(first),
        1,
        "the bridge sent its own sign-in's bearer once: {:?} / {}",
        url_vault.requests(),
        stderr(&output)
    );
    assert_eq!(
        url_vault.carrying(swapped),
        0,
        "the --url is never sent the bearer of a sign-in made at another origin: {:?}",
        url_vault.requests()
    );
    assert!(
        other_vault.requests().is_empty(),
        "the other vault is sent no refresh: {:?}",
        other_vault.requests()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let answer: Value = serde_json::from_str(
        stdout
            .lines()
            .find(|line| line.contains("\"id\":1"))
            .unwrap_or_else(|| panic!("initialize answered: {stdout} / {}", stderr(&output))),
    )
    .expect("the answer is JSON");
    assert!(
        answer.get("error").is_some(),
        "the call is refused, not answered: {answer}"
    );
}
