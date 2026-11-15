//! L1-14 PR 2 (ruling L1-14-HOSTED-LOGIN = B, Engine Sat 14 Nov 03:02):
//! `oneiron hosted login --origin <url>` with no credential signs this user
//! in at the hosted vault's own OAuth 2.1 server as a native app, and
//! records the vault in OAuth mode.
//!
//! The vault runs in process on a loopback port, with an https
//! `oauth_resource_indicator` so its OAuth routes answer, rooted, with its
//! embedded owner. The built binary is the client. A stand-in `xdg-open`
//! first on `PATH` records the URL it is asked to open. The test then acts
//! as the browser (it loads the consent page, polls its status and follows
//! the redirect back to the binary's loopback) and as the owner (he allows
//! the request in process, as his inbox's one-tap does).
//!
//! Red on main: `hosted login` with no credential file refuses ("slip mode
//! needs --credential-file"), opens no browser and records nothing; there is
//! no `--auth-mode oauth` for `oneiron mcp`.
//!
//! `cargo test --locked -p oneiron-server --all-features --features
//! oneiron/test-support --test hosted_native_sign_in`.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{OAuthAuthorizationAnswer, answer_oauth_authorization_as};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::Value;

/// The vault's public OAuth identity: its issuer.
const INDICATOR: &str = "https://vault.example";
/// The protected resource every token is minted for.
const RESOURCE: &str = "https://vault.example/mcp";
/// How long the test waits for the binary at each step.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the test holds the refresh lock before it lets a logout go on.
const LOCK_HOLD: Duration = Duration::from_secs(3);
/// The sign-in timeout of the login the loopback traffic is sent to.
const SHORT_SIGN_IN_TIMEOUT_SECS: &str = "10";
/// How long that login may take in all: its sign-in timeout and a margin.
const SHORT_SIGN_IN_BOUND: Duration = Duration::from_secs(30);
/// Loopback connections that send nothing, each held open: before the
/// fix, the loopback read each one for 5 s in turn, 60 s in all.
const IDLE_CONNECTIONS: usize = 12;

/// The served vault and its owner's proof.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    origin: String,
}

impl Served {
    async fn start() -> Self {
        let dir = tempfile::tempdir().expect("vault dir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("hosted-native-sign-in".to_owned()),
                    oauth_resource_indicator: Some(INDICATOR.to_owned()),
                    ..Default::default()
                },
            )
            .expect("a server"),
        );
        vault.bootstrap_host_slip_issuer().expect("host issuer");
        assert!(
            vault
                .authority_vault_id()
                .expect("authority fold")
                .is_some(),
            "FIXTURE: the vault is rooted"
        );
        let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let origin = format!("http://{}", listener.local_addr().expect("address"));
        let app = build_app(Arc::clone(&server));
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve the vault");
        });
        Self {
            _dir: dir,
            vault,
            owner,
            origin,
        }
    }

    /// The vault id MCP `initialize` answers, in hex.
    fn vault_id(&self) -> String {
        self.vault
            .authority_vault_id()
            .expect("authority fold")
            .expect("rooted")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

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

    /// Runs `oneiron hosted login --origin` with no credential and plays the
    /// browser and the owner, as the module docs say; the login is recorded.
    async fn sign_in(&self, served: &Served) -> SignedIn {
        self.sign_in_at(served, &served.origin).await
    }

    /// As [`Self::sign_in`], with `--origin` spelt as `origin`.
    async fn sign_in_at(&self, served: &Served, origin: &str) -> SignedIn {
        let (authorize, output) = self.login_at(served, origin, &[]).await;
        assert!(
            output.status.success(),
            "hosted login exits 0: {}",
            stderr(&output)
        );
        SignedIn {
            authorize,
            status: last_json_line(&output),
        }
    }

    /// Runs `oneiron hosted login --origin` with no credential and `extra`
    /// arguments, plays the browser and the owner up to the browser's return,
    /// and answers the authorize URL and the command's output.
    async fn login(&self, served: &Served, extra: &[&str]) -> (reqwest::Url, Output) {
        self.login_at(served, &served.origin, extra).await
    }

    /// As [`Self::login`], with `--origin` spelt as `origin`.
    async fn login_at(
        &self,
        served: &Served,
        origin: &str,
        extra: &[&str],
    ) -> (reqwest::Url, Output) {
        let _ = std::fs::remove_file(self.path("opened.txt"));
        let child = self
            .command(&[
                "hosted",
                "login",
                "--origin",
                origin,
                "--sign-in-timeout-secs",
                "120",
                "--timeout-secs",
                "60",
            ])
            .args(extra)
            .spawn()
            .expect("start hosted login");
        let login = tokio::task::spawn_blocking(move || child.wait_with_output());
        let authorize = self.opened_url().await;
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("browser");
        let page = browser
            .get(authorize.as_str())
            .send()
            .await
            .expect("load the consent page");
        assert_eq!(page.status(), 200, "the consent page loads");
        let page = page.text().await.expect("the page");
        let token = page_token(&page);
        let request_ref = EntityId::from_hex(token.split('.').next().expect("token prefix"))
            .expect("the page token names its request");
        let answered = answer_oauth_authorization_as(
            &served.vault,
            &served.owner,
            ActSurface::ThisInstall,
            OAuthAuthorizationAnswer {
                request_ref,
                allow: true,
                tier: None,
                world_ref: None,
            },
        )
        .expect("the owner allows the request");
        assert!(answered.allowed, "FIXTURE: the owner's answer allows it");
        let status: Value = browser
            .get(format!("{}/oauth/authorize/status", served.origin))
            .header("x-oneiron-oauth-page", &token)
            .send()
            .await
            .expect("poll the request")
            .json()
            .await
            .expect("the status answer");
        assert_eq!(status["status"], "allowed", "{status}");
        let back = status["redirect"]
            .as_str()
            .expect("the redirect")
            .to_owned();
        let landed = browser
            .get(&back)
            .send()
            .await
            .expect("the browser comes back to the loopback");
        assert_eq!(landed.status(), 200);
        assert!(
            landed.text().await.expect("the page").contains("Signed in"),
            "the loopback answers the browser"
        );
        let output = tokio::time::timeout(STEP_TIMEOUT, login)
            .await
            .expect("hosted login ends")
            .expect("join")
            .expect("hosted login output");
        (authorize, output)
    }

    /// The URL the stand-in opener was handed, once it is there.
    async fn opened_url(&self) -> reqwest::Url {
        let file = self.path("opened.txt");
        let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
        loop {
            if let Ok(text) = std::fs::read_to_string(&file)
                && let Some(line) = text.lines().next()
            {
                return reqwest::Url::parse(line).expect("the opened URL parses");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "hosted login opened no URL in a browser"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// What a sign-in left: the authorize URL the browser opened, and the
/// status line `hosted login` printed.
struct SignedIn {
    authorize: reqwest::Url,
    status: Value,
}

impl SignedIn {
    fn query(&self, name: &str) -> String {
        self.authorize
            .query_pairs()
            .find(|(key, _)| key == name)
            .map_or_else(
                || panic!("the authorize URL names {name}: {}", self.authorize),
                |(_, value)| value.into_owned(),
            )
    }

    /// The one recorded vault.
    fn vault(&self) -> &Value {
        let vaults = self.status["vaults"].as_array().expect("vaults");
        assert_eq!(vaults.len(), 1, "one recorded vault: {}", self.status);
        &vaults[0]
    }

    fn sign_in_file(&self) -> PathBuf {
        PathBuf::from(
            self.vault()["credential_file"]
                .as_str()
                .expect("credential_file"),
        )
    }
}

/// The page token the consent page carries for its script.
fn page_token(page: &str) -> String {
    let marker = "<meta name=oauth-page-token content=\"";
    let start = page.find(marker).expect("the page carries its token") + marker.len();
    let len = page[start..].find('"').expect("the token's end");
    page[start..start + len].to_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn last_json_line(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().last().expect("a status line");
    serde_json::from_str(line).expect("the status line is JSON")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read")).expect("JSON")
}

/// The vault's answer to a refresh with the refresh token of the sign-in
/// `held`: its HTTP status, and its body (null when it is not JSON).
async fn refresh_at_vault(served: &Served, held: &Value) -> (u16, Value) {
    let answer = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
        .post(format!("{}/oauth/token", served.origin))
        .form(&[
            ("grant_type", "refresh_token"),
            (
                "refresh_token",
                held["refresh_token"].as_str().expect("refresh"),
            ),
            ("client_id", held["client_id"].as_str().expect("client")),
            ("resource", RESOURCE),
        ])
        .send()
        .await
        .expect("call the token endpoint");
    let status = answer.status().as_u16();
    let body = answer.bytes().await.expect("the token answer");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// The refresh lock file beside the sign-in in `file`.
fn lock_file(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Sends `oneiron mcp --auth-mode oauth` one `initialize` and answers its
/// reply.
fn initialize_over_oauth(scratch: &Scratch, served: &Served, sign_in_file: &Path) -> Value {
    let mut child = scratch
        .command(&[
            "mcp",
            "--url",
            &served.origin,
            "--surface",
            "tool-first",
            "--auth-mode",
            "oauth",
            "--oauth-token-file",
            &sign_in_file.display().to_string(),
        ])
        .stdin(Stdio::piped())
        .spawn()
        .expect("start oneiron mcp");
    let hello = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "hosted-native-sign-in", "version": "1"},
        },
    });
    let mut stdin = child.stdin.take().expect("stdin");
    writeln!(stdin, "{hello}").expect("send initialize");
    drop(stdin);
    let output = child.wait_with_output().expect("oneiron mcp ends");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.contains("\"id\":1"))
        .unwrap_or_else(|| panic!("initialize answered: {stdout} / {}", stderr(&output)));
    serde_json::from_str(line).expect("the answer is JSON")
}

/// `hosted login` with no credential registers a public client, opens the
/// authorize URL (PKCE S256, `state`, the `read` scope, the vault's
/// resource, a loopback redirect), takes the code the browser brings back,
/// and records the vault in OAuth mode, selected, by the id the origin
/// answers for. The sign-in file is the owner's alone and holds the vault's
/// tokens for that resource.
#[test]
fn hosted_login_signs_in_at_the_vaults_own_oauth_server_and_records_it() {
    run_on_engine_stack("hosted-native-sign-in", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let signed_in = scratch.sign_in(&served).await;

        assert_eq!(
            signed_in.authorize.as_str().split('?').next(),
            Some(format!("{}/oauth/authorize", served.origin).as_str()),
            "the browser opens the vault's own authorize page"
        );
        assert_eq!(signed_in.query("response_type"), "code");
        assert_eq!(signed_in.query("code_challenge_method"), "S256");
        assert_eq!(
            signed_in.query("code_challenge").len(),
            43,
            "an S256 challenge"
        );
        assert_eq!(signed_in.query("scope"), "read");
        assert_eq!(signed_in.query("resource"), RESOURCE);
        assert!(signed_in.query("state").len() >= 16, "a fresh state");
        let redirect = signed_in.query("redirect_uri");
        assert!(
            redirect.starts_with("http://127.0.0.1:") && redirect.ends_with("/oauth/callback"),
            "a loopback redirect: {redirect}"
        );

        assert_eq!(
            signed_in.status["state"], "selected",
            "{}",
            signed_in.status
        );
        assert_eq!(signed_in.status["selected"], served.vault_id().as_str());
        let vault = signed_in.vault();
        assert_eq!(vault["auth_mode"], "oauth", "{vault}");
        assert_eq!(vault["origin"], served.origin.as_str());
        assert_eq!(vault["vault_id"], served.vault_id().as_str());

        let file = signed_in.sign_in_file();
        assert_eq!(
            file.parent(),
            Some(scratch.path("config").join("oneiron").as_path()),
            "the sign-in sits beside hosted.json"
        );
        let mode = std::fs::metadata(&file)
            .expect("the sign-in file")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "only its owner reads the sign-in: {mode:o}"
        );
        let held = read_json(&file);
        assert!(
            held["access_token"]
                .as_str()
                .is_some_and(|token| token.starts_with("v2.oauth-access.")),
            "an access token"
        );
        assert!(
            held["refresh_token"]
                .as_str()
                .is_some_and(|token| token.starts_with("v2.oauth-refresh.")),
            "a refresh token"
        );
        assert_eq!(held["client_id"], signed_in.query("client_id").as_str());
        assert_eq!(held["resource"], RESOURCE);
        assert_eq!(held["scope"], "read");
        let printed = signed_in.status.to_string();
        for token in [&held["access_token"], &held["refresh_token"]] {
            assert!(
                !printed.contains(token.as_str().expect("token")),
                "the status line names the file, never a token"
            );
        }
    });
}

/// `oneiron mcp --auth-mode oauth` reaches the vault over HTTP with the
/// sign-in's access token, refreshing an expired one first: the rotated
/// pair is written back. `hosted logout` then revokes the sign-in at the
/// vault and removes its file, so the last refresh token no longer
/// refreshes.
#[test]
fn the_oauth_bridge_refreshes_an_expired_token_and_logout_revokes_the_sign_in() {
    run_on_engine_stack("hosted-native-sign-in-refresh", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let signed_in = scratch.sign_in(&served).await;
        let file = signed_in.sign_in_file();

        let mut held = read_json(&file);
        let first_refresh = held["refresh_token"].as_str().expect("refresh").to_owned();
        let first_access = held["access_token"].as_str().expect("access").to_owned();
        held["expires_at_ms"] = Value::from(0_u64);
        std::fs::write(&file, serde_json::to_vec(&held).expect("JSON")).expect("expire it");

        // The vault answers on the runtime's workers; this thread may block.
        let answer = initialize_over_oauth(&scratch, &served, &file);
        assert_eq!(
            answer["result"]["vault_id"],
            served.vault_id().as_str(),
            "initialize answers over the OAuth sign-in: {answer}"
        );
        let renewed = read_json(&file);
        assert_ne!(
            renewed["access_token"].as_str(),
            Some(first_access.as_str()),
            "the expired access token was refreshed"
        );
        assert_ne!(
            renewed["refresh_token"].as_str(),
            Some(first_refresh.as_str()),
            "the refresh token rotated"
        );
        let mode = std::fs::metadata(&file)
            .expect("the sign-in file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the rewrite stays owner-only: {mode:o}");

        let last_refresh = renewed["refresh_token"]
            .as_str()
            .expect("refresh")
            .to_owned();
        let client_id = renewed["client_id"].as_str().expect("client").to_owned();
        let logout = scratch
            .command(&["hosted", "logout"])
            .output()
            .expect("hosted logout");
        assert!(
            logout.status.success(),
            "logout exits 0: {}",
            stderr(&logout)
        );
        assert_eq!(last_json_line(&logout)["state"], "not_logged_in");
        assert!(!file.exists(), "logout removes the sign-in file it wrote");

        let refused = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .post(format!("{}/oauth/token", served.origin))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", last_refresh.as_str()),
                ("client_id", client_id.as_str()),
                ("resource", RESOURCE),
            ])
            .send()
            .await
            .expect("try the revoked refresh token");
        assert_eq!(
            refused.status(),
            400,
            "the revoked sign-in no longer refreshes"
        );
    });
}

/// A second `hosted login` at the same origin that is not recorded (it
/// names a vault the origin does not answer for) leaves the recorded
/// sign-in as it was: the selection still names its file, the file holds
/// the same tokens, and `oneiron mcp` still reaches the vault with it. A
/// second login that is recorded takes its place, and the sign-in it
/// replaced is revoked at the vault.
#[test]
fn a_second_oauth_login_replaces_the_recorded_sign_in_only_once_admitted() {
    run_on_engine_stack("hosted-native-sign-in-relogin", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let first = scratch.sign_in(&served).await;
        let file = first.sign_in_file();
        let held = read_json(&file);

        let other_vault = "ab".repeat(32);
        assert_ne!(other_vault, served.vault_id(), "FIXTURE: another vault id");
        let (_, refused) = scratch.login(&served, &["--vault-id", &other_vault]).await;
        assert!(
            !refused.status.success(),
            "a login for another vault is not recorded"
        );
        assert!(
            stderr(&refused).contains(&format!("not {other_vault}")),
            "{}",
            stderr(&refused)
        );
        let status = scratch
            .command(&["hosted", "status"])
            .output()
            .expect("hosted status");
        let kept = SignedIn {
            authorize: first.authorize.clone(),
            status: last_json_line(&status),
        };
        assert_eq!(kept.vault()["vault_id"], served.vault_id().as_str());
        assert_eq!(
            kept.sign_in_file(),
            file,
            "the selection names the same file"
        );
        assert_eq!(
            read_json(&file),
            held,
            "the recorded sign-in keeps its tokens"
        );
        let mut staged = file.as_os_str().to_owned();
        staged.push(".staged");
        assert!(
            !Path::new(&staged).exists(),
            "the sign-in that was not recorded is removed"
        );
        let answer = initialize_over_oauth(&scratch, &served, &file);
        assert_eq!(
            answer["result"]["vault_id"],
            served.vault_id().as_str(),
            "the recorded sign-in still reaches the vault: {answer}"
        );

        let second = scratch.sign_in(&served).await;
        assert_eq!(second.sign_in_file(), file, "one sign-in file per origin");
        let replacing = read_json(&file);
        assert_ne!(
            replacing["refresh_token"], held["refresh_token"],
            "the recorded login's sign-in took the file"
        );
        let old_refresh = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .post(format!("{}/oauth/token", served.origin))
            .form(&[
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    held["refresh_token"].as_str().expect("refresh"),
                ),
                ("client_id", held["client_id"].as_str().expect("client")),
                ("resource", RESOURCE),
            ])
            .send()
            .await
            .expect("try the replaced refresh token");
        assert_eq!(old_refresh.status(), 400, "the replaced sign-in is revoked");
    });
}

/// REVIEW-7877 round 2, P1 hosted_command.rs:230. The same origin spelt
/// another way (`HTTP://` for `http://`) is the same origin: a login there
/// records the one spelling and keeps the one sign-in file, so the sign-in
/// it replaces is revoked, not left live in a second file logout never
/// visits.
#[test]
fn a_login_at_another_spelling_of_the_origin_replaces_the_same_sign_in() {
    run_on_engine_stack("hosted-native-sign-in-spelling", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let first = scratch.sign_in(&served).await;
        let file = first.sign_in_file();
        let held = read_json(&file);
        let respelt = served.origin.replacen("http://", "HTTP://", 1);
        assert_ne!(respelt, served.origin, "FIXTURE: another spelling");

        let second = scratch.sign_in_at(&served, &respelt).await;
        assert_eq!(
            second.vault()["origin"],
            served.origin.as_str(),
            "the origin is recorded in its one spelling"
        );
        assert_eq!(
            second.sign_in_file(),
            file,
            "one sign-in file per origin, however it is spelt"
        );
        let (status, _) = refresh_at_vault(&served, &held).await;
        assert_eq!(
            status, 400,
            "the sign-in the second login replaced is revoked"
        );
    });
}

/// REVIEW-7877 round 2, P1 hosted_command.rs:230. A vault's record whose
/// OAuth sign-in sits in another file (as an earlier spelling of the origin
/// left it) is replaced by the next login there, and that sign-in goes with
/// it: revoked at the vault and its file removed, since nothing names it
/// any more.
#[test]
fn a_login_that_replaces_a_record_signs_out_the_sign_in_it_named_elsewhere() {
    run_on_engine_stack("hosted-native-sign-in-displaced", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let first = scratch.sign_in(&served).await;
        let file = first.sign_in_file();
        let held = read_json(&file);
        let elsewhere = file.with_file_name("hosted-oauth-earlier.json");
        std::fs::rename(&file, &elsewhere).expect("move the sign-in to another file");
        let selection_file = scratch.path("config").join("oneiron").join("hosted.json");
        let mut selection = read_json(&selection_file);
        selection["vaults"][0]["credential_file"] = Value::from(elsewhere.display().to_string());
        std::fs::write(
            &selection_file,
            serde_json::to_vec(&selection).expect("JSON"),
        )
        .expect("name the other file in the record");

        let second = scratch.sign_in(&served).await;
        assert_eq!(
            second.sign_in_file(),
            file,
            "the new sign-in takes the origin's file"
        );
        assert!(
            !elsewhere.exists(),
            "the sign-in the replaced record named is removed"
        );
        let (status, _) = refresh_at_vault(&served, &held).await;
        assert_eq!(status, 400, "and revoked at the vault");
    });
}

/// REVIEW-7877 round 2, P1 hosted_sign_in.rs:155. `hosted logout` signs out
/// under the sign-in's refresh lock: while a refresh holds it, logout waits
/// and leaves the file; then it revokes the pair that refresh wrote. The
/// lock file stays, the same file, so a refresh still waiting on it shuts
/// out a later sign-in's refresh as before.
#[test]
fn logout_signs_out_under_the_refresh_lock_and_keeps_it() {
    run_on_engine_stack("hosted-native-sign-in-logout-lock", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let signed_in = scratch.sign_in(&served).await;
        let file = signed_in.sign_in_file();
        let lock_path = lock_file(&file);
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .expect("open the refresh lock");
        lock.lock()
            .expect("hold the refresh lock, as a refresh in flight does");
        let lock_inode = std::fs::metadata(&lock_path).expect("the lock file").ino();

        let mut logout = scratch
            .command(&["hosted", "logout"])
            .spawn()
            .expect("start hosted logout");
        tokio::time::sleep(LOCK_HOLD).await;
        assert!(
            logout.try_wait().expect("poll hosted logout").is_none(),
            "logout waits while a refresh holds the sign-in's lock"
        );
        assert!(file.exists(), "and leaves the sign-in file meanwhile");

        // The refresh in flight writes its next pair, then lets the lock go.
        let mut held = read_json(&file);
        let (status, next) = refresh_at_vault(&served, &held).await;
        assert_eq!(status, 200, "FIXTURE: the refresh in flight: {next}");
        held["access_token"] = next["access_token"].clone();
        held["refresh_token"] = next["refresh_token"].clone();
        std::fs::write(&file, serde_json::to_vec(&held).expect("JSON"))
            .expect("write the refreshed pair");
        drop(lock);

        let output = tokio::time::timeout(
            STEP_TIMEOUT,
            tokio::task::spawn_blocking(move || logout.wait_with_output()),
        )
        .await
        .expect("hosted logout ends once the lock is free")
        .expect("join")
        .expect("hosted logout output");
        assert!(
            output.status.success(),
            "logout exits 0: {}",
            stderr(&output)
        );
        assert_eq!(last_json_line(&output)["state"], "not_logged_in");
        assert!(!file.exists(), "logout removes the sign-in file");
        assert_eq!(
            std::fs::metadata(&lock_path)
                .expect("the refresh lock file stays")
                .ino(),
            lock_inode,
            "the same lock file"
        );
        let (status, _) = refresh_at_vault(&served, &held).await;
        assert_eq!(
            status, 400,
            "logout revoked the pair the refresh in flight wrote"
        );
    });
}

/// REVIEW-7877 round 2, P1 hosted_sign_in.rs:303. Connections to the
/// loopback that never bring the browser's return keep it busy, and the
/// sign-in still ends at its timeout: `hosted login` exits non-zero, says
/// the browser did not come back in time, and records nothing.
#[test]
fn loopback_traffic_does_not_hold_hosted_login_past_its_sign_in_timeout() {
    run_on_engine_stack("hosted-native-sign-in-timeout", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let child = scratch
            .command(&[
                "hosted",
                "login",
                "--origin",
                &served.origin,
                "--sign-in-timeout-secs",
                SHORT_SIGN_IN_TIMEOUT_SECS,
                "--timeout-secs",
                "60",
            ])
            .spawn()
            .expect("start hosted login");
        let login = tokio::task::spawn_blocking(move || child.wait_with_output());
        let authorize = scratch.opened_url().await;
        let redirect = authorize
            .query_pairs()
            .find(|(key, _)| key == "redirect_uri")
            .map(|(_, value)| value.into_owned())
            .expect("the authorize URL names its redirect");
        let port = reqwest::Url::parse(&redirect)
            .expect("the redirect parses")
            .port()
            .expect("the loopback's port");
        // Each sends nothing and stays open: the loopback waits on it.
        let idle: Vec<std::net::TcpStream> = (0..IDLE_CONNECTIONS)
            .filter_map(|_| std::net::TcpStream::connect(("127.0.0.1", port)).ok())
            .collect();
        assert!(!idle.is_empty(), "FIXTURE: the loopback takes connections");

        let output = tokio::time::timeout(SHORT_SIGN_IN_BOUND, login)
            .await
            .expect("hosted login ends at its sign-in timeout, whatever comes to the loopback")
            .expect("join")
            .expect("hosted login output");
        drop(idle);
        assert!(
            !output.status.success(),
            "a sign-in the browser never came back from fails"
        );
        assert!(
            stderr(&output).contains("did not come back from the sign-in in time"),
            "{}",
            stderr(&output)
        );
        let status = scratch
            .command(&["hosted", "status"])
            .output()
            .expect("hosted status");
        assert_eq!(
            last_json_line(&status)["state"],
            "not_logged_in",
            "nothing was recorded"
        );
    });
}

/// Blind review of #7877, F1. When an origin answers for another vault than
/// the one recorded there (recreated or repointed), the next OAuth login takes
/// the origin's sign-in file, and the record of the vault that named it goes:
/// no record sends the new vault's tokens under the old id, and no logout of
/// the old id revokes the new sign-in.
#[test]
fn an_oauth_login_drops_the_record_whose_sign_in_file_it_takes() {
    run_on_engine_stack("hosted-native-sign-in-repointed", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let first = scratch.sign_in(&served).await;
        let file = first.sign_in_file();
        let earlier_vault = "ab".repeat(32);
        assert_ne!(
            earlier_vault,
            served.vault_id(),
            "FIXTURE: another vault id"
        );
        let selection_file = scratch.path("config").join("oneiron").join("hosted.json");
        let mut selection = read_json(&selection_file);
        selection["vaults"][0]["vault_id"] = Value::from(earlier_vault.as_str());
        selection["selected"] = Value::from(earlier_vault.as_str());
        std::fs::write(
            &selection_file,
            serde_json::to_vec(&selection).expect("JSON"),
        )
        .expect("record the origin's file for the earlier vault");

        let second = scratch.sign_in(&served).await;
        assert_eq!(
            second.vault()["vault_id"],
            served.vault_id().as_str(),
            "only the vault the origin answers for stays recorded"
        );
        assert_eq!(second.sign_in_file(), file, "one sign-in file per origin");
        let logout = scratch
            .command(&["hosted", "logout", "--vault-id", &earlier_vault])
            .output()
            .expect("hosted logout");
        assert!(
            !logout.status.success(),
            "the earlier vault is no longer recorded: {}",
            stderr(&logout)
        );
        let answer = initialize_over_oauth(&scratch, &served, &file);
        assert_eq!(
            answer["result"]["vault_id"],
            served.vault_id().as_str(),
            "the new sign-in still reaches the vault: {answer}"
        );
    });
}
