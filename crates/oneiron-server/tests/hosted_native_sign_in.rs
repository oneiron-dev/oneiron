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
use std::os::unix::fs::PermissionsExt as _;
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
    /// browser and the owner, as the module docs say.
    async fn sign_in(&self, served: &Served) -> SignedIn {
        let child = self
            .command(&[
                "hosted",
                "login",
                "--origin",
                &served.origin,
                "--sign-in-timeout-secs",
                "120",
                "--timeout-secs",
                "60",
            ])
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
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("the authorize URL names {name}: {}", self.authorize))
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
