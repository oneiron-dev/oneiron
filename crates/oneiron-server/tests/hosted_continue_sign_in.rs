//! `oneiron continue --cloud` on an OAuth selection runs on a continue
//! sign-in of its own (row CONTINUE-PUSH-NON-SLIP-SELECTION, PR 2; lead
//! rulings CONTINUE-PUSH-GIT-TIER = C, Sat 21 Nov 05:4x, and
//! CONTINUE-STEP-UP-MCP-WRITE = A, 06:1x).
//!
//! Plain `oneiron hosted login` stays `read` at the vault's `/mcp`, so a
//! sign-in that only recalls never asks for write, and its token pushes
//! nothing. When `continue --cloud` finds no continue sign-in standing, it
//! starts the step-up itself, before its first call: the same native-app
//! sign-in, as the recall sign-in's client, asking `full` at `/mcp` and
//! `/git` in one request, and the owner's ask says "continue this session
//! in your hosted vault: land its log, push its code and start it there".
//! `hosted login --push` is the explicit form. The continue sign-in is kept
//! in its own file beside the recall one, and a logout signs it out too.
//!
//! The vault runs in process on a loopback port, rooted, with an https
//! `oauth_resource_indicator` so its OAuth routes answer. The built binary
//! is the client. A stand-in `xdg-open` first on `PATH` records the URL it
//! is asked to open; the test then acts as the browser (it loads the
//! consent page, polls its status and follows the redirect back to the
//! binary's loopback) and as the owner (he allows the request in process,
//! as his inbox's one-tap does).
//!
//! Red at the test-only commit (main a4da0172aab + #10026): `hosted login
//! --push` is no argument (clap exits 2, no URL opens), and `continue
//! --cloud` on an OAuth selection calls its check on the recall sign-in and
//! stops, opening no URL. The first case is a guard that holds there too
//! (#10026 already refuses an `/mcp` token at the git door). The push case
//! (its door is this PR's) runs green only.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! hosted_continue_sign_in`. Stock `git` must be on PATH.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, MachineRole, OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::GitPushRepo;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{OAuthAuthorizationAnswer, answer_oauth_authorization_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

/// The vault's public OAuth identity: its issuer.
const INDICATOR: &str = "https://vault.example";
/// The vault's MCP resource.
const MCP: &str = "https://vault.example/mcp";
/// The vault's git resource.
const GIT: &str = "https://vault.example/git";
/// The git resource's metadata document, as a 401 at the git door names it.
const GIT_METADATA: &str = "https://vault.example/.well-known/oauth-protected-resource/git";
/// What the continue step-up asks to do, as the owner's ask shows it.
const PURPOSE: &str =
    "continue this session in your hosted vault: land its log, push its code and start it there";
/// The served custody repo.
const REPO: &str = "demo";
/// How long the test waits for the binary at each step.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// The served vault, rooted and profiled as `oneiron init` leaves a serving
/// install, with [`REPO`] served and bound as a CODE anchor.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    owner_person: EntityId,
    origin: String,
    #[cfg_attr(not(oneiron_test_support), allow(dead_code))]
    push_repo: GitPushRepo,
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
                    auth_secret: Some("hosted-continue-sign-in".to_owned()),
                    oauth_resource_indicator: Some(INDICATOR.to_owned()),
                    ..Default::default()
                },
            )
            .expect("a server"),
        );
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner_person = vault.ensure_embedded_owner_actor().expect("owner");
        let owner = vault
            .authenticate_owner(
                owner_person,
                &owner_person.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof");
        vault
            .register_served_origin_as_owner(&owner, REPO, "main")
            .expect("register the served repo");
        let push_repo = oneiron::verbs::bind_repo_anchor_as(
            &vault,
            &owner,
            oneiron::verbs::RepoAnchorBindInput {
                repo: Some(REPO.to_owned()),
                local_folder: None,
                project: vault.root_project().expect("root project"),
                anchor: None,
                editable: None,
            },
        )
        .expect("bind the repo's CODE anchor")
        .anchor;
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
            owner_person,
            origin,
            push_repo,
        }
    }

    /// The `detail` of the owner's inbox ask for the sign-in request
    /// `request_ref`, as JSON.
    fn ask_detail(&self, request_ref: EntityId) -> Value {
        let rows = self
            .vault
            .memory(self.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows;
        let ask = rows
            .into_iter()
            .find(|row| {
                row.source.producer == OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER
                    && row.source.result.as_deref() == Some(request_ref.to_hex().as_str())
            })
            .expect("the owner's inbox asks about the sign-in");
        serde_json::from_str(ask.source.detail.as_deref().expect("the ask's detail"))
            .expect("the detail is JSON")
    }
}

/// A scratch HOME and config folder, and a `PATH` whose `xdg-open` records
/// the URL it is given.
struct Scratch {
    dir: tempfile::TempDir,
}

/// One run of the binary, waited for on the blocking pool.
type Run = JoinHandle<std::io::Result<Output>>;

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        for sub in ["home", "config", "bin", "work"] {
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

    /// The binary with `args`, in the scratch HOME, run in `work/`.
    fn spawn(&self, args: &[&str]) -> Run {
        let _ = std::fs::remove_file(self.path("opened.txt"));
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(args)
            .current_dir(self.path("work"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("PATH", path)
            .env("OPENED_URL_FILE", self.path("opened.txt"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the binary");
        tokio::task::spawn_blocking(move || child.wait_with_output())
    }

    /// The URL the stand-in opener was handed, once it is there; `None`
    /// when `run` ended before it opened one.
    async fn opened_url(&self, run: &Run) -> Option<reqwest::Url> {
        let file = self.path("opened.txt");
        let deadline = tokio::time::Instant::now() + STEP_TIMEOUT;
        loop {
            if let Ok(text) = std::fs::read_to_string(&file)
                && let Some(line) = text.lines().next()
            {
                return Some(reqwest::Url::parse(line).expect("the opened URL parses"));
            }
            if run.is_finished() {
                return None;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the binary opened no URL in a browser"
            );
            // testkit-lint: allow(sleep) polls a file the child process writes; no event marks it.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Runs `args`, which open a sign-in, and plays the browser and the
    /// owner for it, the owner allowing at the tier asked. Panics with the
    /// binary's output when it ends before it opens a URL.
    async fn signed_in_run(&self, served: &Served, args: &[&str]) -> (Allowed, Output) {
        let run = self.spawn(args);
        let Some(authorize) = self.opened_url(&run).await else {
            let output = finished(run).await;
            panic!(
                "`oneiron {}` opened no sign-in; it ended {}: {}",
                args.join(" "),
                output.status,
                stderr(&output)
            );
        };
        let allowed = allow(served, authorize).await;
        (allowed, finished(run).await)
    }

    /// `oneiron hosted login --origin` with no credential, allowed; the
    /// login is recorded.
    async fn login(&self, served: &Served) -> Allowed {
        let (allowed, output) = self
            .signed_in_run(served, &self.login_args(served, &[]))
            .await;
        assert!(
            output.status.success(),
            "hosted login exits 0: {}",
            stderr(&output)
        );
        allowed
    }

    /// `oneiron hosted login --origin <served> --push`, allowed.
    async fn login_push(&self, served: &Served) -> Allowed {
        let (allowed, output) = self
            .signed_in_run(served, &self.login_args(served, &["--push"]))
            .await;
        assert!(
            output.status.success(),
            "hosted login --push exits 0: {}",
            stderr(&output)
        );
        allowed
    }

    fn login_args<'a>(&self, served: &'a Served, extra: &[&'a str]) -> Vec<&'a str> {
        let mut args = vec![
            "hosted",
            "login",
            "--origin",
            served.origin.as_str(),
            "--sign-in-timeout-secs",
            "120",
            "--timeout-secs",
            "60",
        ];
        args.extend_from_slice(extra);
        args
    }

    /// The recall sign-in `hosted login` wrote, beside `hosted.json`.
    fn recall_file(&self) -> PathBuf {
        self.sign_in_file("hosted-oauth-")
    }

    /// The continue sign-in, beside the recall one.
    fn continue_file(&self) -> PathBuf {
        self.sign_in_file("hosted-oauth-continue-")
    }

    /// The one sign-in file in the per-user folder whose name is `prefix`
    /// and 16 hex.
    fn sign_in_file(&self, prefix: &str) -> PathBuf {
        let dir = self.path("config").join("oneiron");
        let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
            .expect("the per-user folder")
            .map(|entry| entry.expect("an entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix(prefix))
                    .and_then(|rest| rest.strip_suffix(".json"))
                    .is_some_and(|digest| {
                        digest.len() == 16 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
            .collect();
        assert_eq!(found.len(), 1, "one {prefix}<digest>.json in {dir:?}");
        found.remove(0)
    }

    /// A git repo with one commit in `work/`, where `continue` runs.
    fn work_repo(&self) {
        let work = self.path("work");
        for args in [
            &["init", "--initial-branch=main"][..],
            &["config", "user.email", "continue@test.invalid"],
            &["config", "user.name", "continue test"],
        ] {
            assert!(git(&work, args).status.success(), "git {args:?}");
        }
        std::fs::write(work.join("WORK.md"), "the session's work\n").expect("write work");
        assert!(git(&work, &["add", "WORK.md"]).status.success());
        assert!(git(&work, &["commit", "-q", "-m", "work"]).status.success());
    }
}

/// What the owner allowed: the authorize URL the browser opened, the
/// consent page it showed, the request, and the agent the client acts as.
struct Allowed {
    authorize: reqwest::Url,
    page: String,
    request_ref: EntityId,
    #[cfg_attr(not(oneiron_test_support), allow(dead_code))]
    agent: EntityId,
}

impl Allowed {
    /// Every value the authorize URL gives `name`, in order.
    fn query_all(&self, name: &str) -> Vec<String> {
        self.authorize
            .query_pairs()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .collect()
    }

    fn query(&self, name: &str) -> String {
        let mut values = self.query_all(name);
        assert_eq!(values.len(), 1, "one {name} in {}", self.authorize);
        values.remove(0)
    }
}

/// Plays the browser for `authorize` up to the owner's answer, the owner
/// allowing at the tier asked, and the browser's return to the loopback.
async fn allow(served: &Served, authorize: reqwest::Url) -> Allowed {
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
    let back = status["redirect"].as_str().expect("the redirect");
    let landed = browser
        .get(back)
        .send()
        .await
        .expect("the browser comes back to the loopback");
    assert_eq!(landed.status(), 200);
    Allowed {
        authorize,
        page,
        request_ref,
        agent: answered.agent.expect("the agent the client acts as"),
    }
}

/// `run`'s output, once it ends.
async fn finished(run: Run) -> Output {
    tokio::time::timeout(STEP_TIMEOUT, run)
        .await
        .expect("the binary ends")
        .expect("join")
        .expect("the binary's output")
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

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read")).expect("JSON")
}

/// Stock git in `dir`, never asking for a credential and reading no user or
/// system config.
fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("run git")
}

/// The vault's answer to a refresh with the refresh token of the sign-in
/// `held`: its HTTP status and its body.
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
            ("resource", held["resource"].as_str().expect("resource")),
        ])
        .send()
        .await
        .expect("call the token endpoint");
    let status = answer.status().as_u16();
    let body = answer.bytes().await.expect("the token answer");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// A read login cannot push: plain `hosted login` asks `read` at `/mcp`
/// alone, and its token answers 401 `invalid_token` at the git door, in
/// plain text. A guard: it holds at the test-only commit too.
#[test]
fn a_read_login_cannot_push() {
    run_on_engine_stack("hosted-continue-read-login", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let allowed = scratch.login(&served).await;
        assert_eq!(allowed.query("scope"), "read");
        assert_eq!(
            allowed.query_all("resource"),
            [MCP],
            "the recall sign-in names /mcp alone"
        );
        let held = read_json(&scratch.recall_file());
        assert_eq!(held["scope"], "read");
        assert_eq!(held["resource"], MCP);

        let refused = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .get(format!(
                "{}/git/{REPO}.git/info/refs?service=git-receive-pack",
                served.origin
            ))
            .bearer_auth(held["access_token"].as_str().expect("access"))
            .send()
            .await
            .expect("ask for the receive-pack advertisement");
        assert_eq!(
            refused.status(),
            401,
            "the read login's token pushes nothing"
        );
        let challenge = refused
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            challenge.contains("error=\"invalid_token\"")
                && challenge.contains(&format!("resource_metadata=\"{GIT_METADATA}\"")),
            "the challenge names the token invalid at the git resource: {challenge:?}"
        );
    });
}

/// `hosted login --push` makes the continue sign-in: the recall sign-in's
/// client asks `full` at `/mcp` and `/git` in one request; the consent page
/// and the owner's inbox ask say what it asks to do; the sign-in goes to its
/// own file beside the recall one, which stays `read` and unchanged.
#[test]
fn hosted_login_push_makes_the_continue_sign_in() {
    run_on_engine_stack("hosted-continue-login-push", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served).await;
        let recall_before = read_json(&scratch.recall_file());

        let allowed = scratch.login_push(&served).await;
        assert_eq!(allowed.query("scope"), "full");
        assert_eq!(
            allowed.query_all("resource"),
            [MCP, GIT],
            "one request names /mcp and /git"
        );
        assert_eq!(
            allowed.query("client_id"),
            recall_before["client_id"].as_str().expect("client"),
            "the step-up is the recall sign-in's client, so its agent"
        );
        assert!(
            allowed.page.contains(&format!(
                "with <strong>full</strong> access, to {}.",
                PURPOSE.replace('\'', "&#39;")
            )),
            "the consent page says what the sign-in asks to do: {}",
            allowed.page
        );
        let detail = served.ask_detail(allowed.request_ref);
        assert_eq!(detail["purpose"], PURPOSE, "{detail}");
        assert_eq!(detail["resources"], json!([MCP, GIT]), "{detail}");
        assert_eq!(detail["tier"], "full", "{detail}");

        let continue_file = scratch.continue_file();
        let mode = std::fs::metadata(&continue_file)
            .expect("the continue sign-in")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "only its owner reads it: {mode:o}");
        let held = read_json(&continue_file);
        assert_eq!(held["scope"], "full");
        assert_eq!(held["resource"], MCP);
        assert_eq!(held["client_id"], recall_before["client_id"]);
        assert_ne!(held["access_token"], recall_before["access_token"]);
        let recall_after = read_json(&scratch.recall_file());
        assert_eq!(
            recall_after, recall_before,
            "the recall sign-in stays read and unchanged"
        );
    });
}

/// `continue --cloud` on an OAuth selection with no continue sign-in starts
/// the step-up itself, before its first call, and goes on on the sign-in it
/// makes; a second run finds it standing and asks nothing. (Here the check
/// is refused, since the owner granted the agent no continue verb, so the
/// work does not move; the push is the next case's.)
#[test]
fn continue_cloud_starts_the_step_up_when_no_continue_sign_in_stands() {
    run_on_engine_stack("hosted-continue-step-up", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served).await;
        scratch.work_repo();
        let continue_args = ["continue", "--cloud", "--repo", REPO];

        let (allowed, output) = scratch.signed_in_run(&served, &continue_args).await;
        assert_eq!(allowed.query("scope"), "full");
        assert_eq!(allowed.query_all("resource"), [MCP, GIT]);
        assert!(
            stderr(&output).contains("No continue sign-in stands"),
            "it says why it asks: {}",
            stderr(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("The work did NOT move"),
            "the refused check ends the run: {}",
            stderr(&output)
        );
        assert_eq!(read_json(&scratch.continue_file())["scope"], "full");

        let again = scratch.spawn(&continue_args);
        assert!(
            scratch.opened_url(&again).await.is_none(),
            "a continue sign-in that stands is not asked for again"
        );
        let output = finished(again).await;
        assert!(!output.status.success(), "{}", stderr(&output));
        assert!(
            !stderr(&output).contains("No continue sign-in stands"),
            "{}",
            stderr(&output)
        );
    });
}

/// `hosted logout` signs out the continue sign-in with the recall one: both
/// files go, and the continue sign-in's refresh token no longer refreshes.
#[test]
fn logout_signs_out_the_continue_sign_in() {
    run_on_engine_stack("hosted-continue-logout", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served).await;
        scratch.login_push(&served).await;
        let (recall_file, continue_file) = (scratch.recall_file(), scratch.continue_file());
        let held = read_json(&continue_file);

        let output = finished(scratch.spawn(&["hosted", "logout"])).await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(!recall_file.exists(), "the recall sign-in is gone");
        assert!(!continue_file.exists(), "the continue sign-in is gone");
        let (status, body) = refresh_at_vault(&served, &held).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"], "invalid_grant", "{body}");
    });
}
