//! The hooks' hand-over on an OAuth selection lands session logs on a
//! hand-over sign-in of its own (row HOOK-HOSTED-HAND-OVER-OAUTH-READ-TIER;
//! lead ruling B, Sat 21 Nov 07:0x).
//!
//! Plain `oneiron hosted login` stays `read` at the vault's `/mcp`, and the
//! import is a Write row, so a hand-over on the recall sign-in never landed.
//! `oneiron hosted login --hand-over` makes the hand-over sign-in: the
//! recall sign-in's client asks `full` at `/mcp` alone, never `/git`, naming
//! the purpose `session_hand_over`, and the owner's ask says "land this
//! machine's coding sessions in your hosted vault as each ends". It is kept
//! in its own file beside the recall one, and only the hand-over reads it.
//! With none standing, a session's log waits on this machine; at the next
//! session end on a standing one, the logs waiting land after the session's
//! own. The import still needs the agent's Grant naming the verb.
//!
//! The ruling's change (PR 2): the first session end that finds no
//! hand-over sign-in files the request itself. It starts `hosted login
//! --hand-over --unattended` detached, which loads the consent page with no
//! browser (the owner's inbox ask) and polls his answer; once he allows it,
//! the sign-in is kept and the next session end lands the logs. While a
//! request waits, and after a deny, no session end asks again.
//!
//! The vault runs in process on a loopback port, rooted, with an https
//! `oauth_resource_indicator` so its OAuth routes answer. The built binary
//! is the client and the hooks (`hook --host claude-code`), and it runs its
//! own `oneiron mcp` bridge. A stand-in `xdg-open` first on `PATH` records
//! the URL it is asked to open; the test then acts as the browser and as
//! the owner, as `hosted_continue_sign_in.rs` does.
//!
//! Red at the test-only commit (#10039's head 82f399c4716 and this file):
//! `hosted login --hand-over` is no argument (clap exits 2, no URL opens);
//! a hand-over on a read login sends on the recall sign-in, which the
//! gateway refuses, and queues nothing; the vault records a request that
//! names the hand-over purpose beside `/git`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! hosted_hand_over_sign_in`.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, MachineRole, OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::ingest::history::{HistoryFile, HistorySource};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentGrantMintRequest, OAuthAuthorizationAnswer, answer_oauth_authorization_as,
    mint_agent_grant_as,
};
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
/// What the hand-over sign-in asks to do, as the owner's ask shows it.
const PURPOSE: &str = "land this machine's coding sessions in your hosted vault as each ends";
/// The purpose's name in the authorize request.
const PURPOSE_NAME: &str = "session_hand_over";
/// The verb the hand-over calls, which the agent's Grant must name.
const IMPORT_VERB: &str = "vault.imports.hook_transcript";
/// The first Claude Code session, whose log waits.
const FIRST_SESSION: &str = "1b5e55e0-3333-4444-8555-a66677778881";
/// The next session, whose end lands both.
const NEXT_SESSION: &str = "2b5e55e0-3333-4444-8555-a66677778882";
/// The served custody repo, so the git door answers on its credential.
const REPO: &str = "demo";
/// How long the test waits for the binary at each step.
const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// The served vault, rooted and profiled as `oneiron init` leaves a serving
/// install.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    owner_person: EntityId,
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
                    auth_secret: Some("hosted-hand-over-sign-in".to_owned()),
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

    /// The owner grants `agent` the import, as a paired agent's Grant names
    /// it.
    fn grant_import(&self, agent: EntityId) {
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            ["read", IMPORT_VERB]
                .map(str::to_owned)
                .into_iter()
                .collect(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .expect("the owner grants the agent the import");
        assert!(minted.grant.confers, "FIXTURE: the Grant confers");
    }

    /// The requests the owner's inbox asks about for a hand-over sign-in
    /// (the ask names its purpose).
    fn hand_over_asks(&self) -> Vec<EntityId> {
        self.vault
            .memory(self.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| row.source.producer == OAUTH_AUTHORIZATION_NOTIFICATION_PRODUCER)
            .filter(|row| {
                row.source
                    .detail
                    .as_deref()
                    .and_then(|detail| serde_json::from_str::<Value>(detail).ok())
                    .is_some_and(|detail| detail["purpose"] == PURPOSE)
            })
            .map(|row| {
                EntityId::from_hex(row.source.result.as_deref().expect("the ask's request"))
                    .expect("the request id")
            })
            .collect()
    }

    /// [`Served::hand_over_asks`], once there is one.
    async fn hand_over_asks_soon(&self) -> Vec<EntityId> {
        let asked = async {
            loop {
                let asks = self.hand_over_asks();
                if !asks.is_empty() {
                    return asks;
                }
                // testkit-lint: allow(sleep) polls for a request a detached child process files; no event marks it.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, asked)
            .await
            .expect("no hand-over sign-in request reached the owner's inbox")
    }

    /// The owner's answer to the request `request_ref`, in his inbox: the
    /// agent an allow admits.
    fn answer(&self, request_ref: EntityId, allow: bool) -> Option<EntityId> {
        answer_oauth_authorization_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            OAuthAuthorizationAnswer {
                request_ref,
                allow,
                tier: None,
                world_ref: None,
            },
        )
        .expect("the owner answers the request")
        .agent
    }

    /// How many Claude Code messages the vault has imported.
    fn landed(&self) -> usize {
        self.vault
            .history_import_ledger_len(HistorySource::ClaudeCode)
            .expect("read the import ledger")
    }
}

/// A scratch HOME, config, runtime and Claude Code folder, and a `PATH`
/// whose `xdg-open` records the URL it is given.
struct Scratch {
    dir: tempfile::TempDir,
}

/// One run of the binary, waited for on the blocking pool.
type Run = JoinHandle<std::io::Result<Output>>;

impl Scratch {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("scratch dir");
        for sub in [
            "home",
            "config",
            "runtime",
            "claude/projects",
            "bin",
            "work",
        ] {
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

    /// The binary with `args` and `stdin` on its stdin, in the scratch
    /// HOME, run in `work/`.
    fn spawn_with(&self, args: &[&str], stdin: Option<String>) -> Run {
        let _ = std::fs::remove_file(self.path("opened.txt"));
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_oneiron"))
            .args(args)
            .current_dir(self.path("work"))
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("CLAUDE_CONFIG_DIR", self.path("claude"))
            .env("PATH", path)
            .env("OPENED_URL_FILE", self.path("opened.txt"))
            .env_remove("ONEIRON_CONFIG")
            .env_remove("ONEIRON_URL")
            .env_remove("ONEIRON_SECRET")
            .env_remove("ONEIRON_BINDING_KEY")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the binary");
        if let Some(stdin) = stdin {
            child
                .stdin
                .take()
                .expect("the binary's stdin")
                .write_all(stdin.as_bytes())
                .expect("write the binary's stdin");
        }
        tokio::task::spawn_blocking(move || child.wait_with_output())
    }

    fn spawn(&self, args: &[&str]) -> Run {
        self.spawn_with(args, None)
    }

    /// The URL the stand-in opener was handed, once it is there; `None`
    /// when `run` ended before it opened one.
    async fn opened_url(&self, run: &Run) -> Option<reqwest::Url> {
        let file = self.path("opened.txt");
        let opened = async {
            loop {
                if let Ok(text) = std::fs::read_to_string(&file)
                    && let Some(line) = text.lines().next()
                {
                    return Some(reqwest::Url::parse(line).expect("the opened URL parses"));
                }
                if run.is_finished() {
                    return None;
                }
                // testkit-lint: allow(sleep) polls a file the child process writes; no event marks it.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, opened)
            .await
            .expect("the binary opened no URL in a browser")
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

    /// `oneiron hosted login --origin <served> <extra>` with no credential,
    /// allowed.
    async fn login(&self, served: &Served, extra: &[&str]) -> Allowed {
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
        let (allowed, output) = self.signed_in_run(served, &args).await;
        assert!(
            output.status.success(),
            "hosted login {extra:?} exits 0: {}",
            stderr(&output)
        );
        allowed
    }

    /// The recall sign-in `hosted login` wrote, beside `hosted.json`.
    fn recall_file(&self) -> PathBuf {
        self.sign_in_file("hosted-oauth-")
    }

    /// The hand-over sign-in, beside the recall one.
    fn hand_over_file(&self) -> PathBuf {
        self.sign_in_file("hosted-oauth-hand-over-")
    }

    /// The per-user oneiron folder.
    fn user_dir(&self) -> PathBuf {
        self.path("config").join("oneiron")
    }

    /// The one sign-in file in the per-user folder whose name is `prefix`
    /// and 16 hex.
    fn sign_in_file(&self, prefix: &str) -> PathBuf {
        let mut found: Vec<PathBuf> = self
            .named_in_user_dir(prefix, ".json")
            .into_iter()
            .filter(|path| path.is_file())
            .collect();
        assert_eq!(found.len(), 1, "one {prefix}<digest>.json in the user dir");
        found.remove(0)
    }

    /// The entries of the per-user folder named `prefix`, 16 hex and
    /// `suffix`.
    fn named_in_user_dir(&self, prefix: &str, suffix: &str) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(self.user_dir()) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.expect("an entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix(prefix))
                    .and_then(|rest| rest.strip_suffix(suffix))
                    .is_some_and(|digest| {
                        digest.len() == 16 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
            .collect()
    }

    /// The hooks' record of their hand-over sign-in request, when there is
    /// one.
    fn ask_record(&self) -> Option<Value> {
        self.named_in_user_dir("hosted-hand-over-ask-", ".json")
            .first()
            .map(|file| read_json(file))
    }

    /// Waits until `done` holds, which a detached child process brings
    /// about.
    async fn until(&self, what: &str, done: impl Fn(&Self) -> bool) {
        let reached = async {
            while !done(self) {
                // testkit-lint: allow(sleep) polls files a detached child process writes; no event marks them.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, reached)
            .await
            .unwrap_or_else(|_| panic!("{what}"));
    }

    /// The queued logs' files: each `.json` in the vault's hand-over queue
    /// folder, when there is one.
    fn queued(&self) -> Vec<PathBuf> {
        let folders = self.named_in_user_dir("hosted-hand-over-queue-", "");
        assert!(folders.len() <= 1, "one queue folder: {folders:?}");
        folders.first().map_or_else(Vec::new, |folder| {
            std::fs::read_dir(folder)
                .expect("the queue folder")
                .map(|entry| entry.expect("an entry").path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect()
        })
    }

    /// `session`'s Claude Code log, in Claude Code's own layout: its path.
    fn session_log(&self, session: &str) -> PathBuf {
        let folder = self.path("claude/projects/-tmp-heron-lantern");
        std::fs::create_dir_all(&folder).expect("the project folder");
        let log = folder.join(format!("{session}.jsonl"));
        std::fs::write(&log, turns(session)).expect("write the session log");
        log
    }

    /// `oneiron hook --host claude-code <event>` with `payload` on stdin,
    /// which exits 0: what it printed and said on stderr.
    async fn hook(&self, event: &[&str], payload: &Value) -> (String, String) {
        let mut args = vec!["hook", "--host", "claude-code"];
        args.extend_from_slice(event);
        let output = finished(self.spawn_with(&args, Some(payload.to_string()))).await;
        assert_eq!(
            output.status.code(),
            Some(0),
            "a hook always exits 0: {}",
            stderr(&output)
        );
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr(&output),
        )
    }

    /// Starts `session`, whose log is at `log`, with no recall; it binds
    /// the selected hosted vault.
    async fn session_start(&self, served: &Served, session: &str, log: &Path) {
        let (said, why) = self
            .hook(
                &["session-start", "--query", ""],
                &json!({
                    "hook_event_name": "SessionStart",
                    "session_id": session,
                    "transcript_path": log,
                    "cwd": "/tmp/heron-lantern",
                    "source": "startup",
                }),
            )
            .await;
        assert!(
            said.contains("uses your hosted vault") && said.contains(&served.origin),
            "FIXTURE: the session binds the selected hosted vault: {said} {why}"
        );
    }

    /// `session`'s end: its `SessionEnd` hand-over of the log at `log`.
    /// What it said on stderr.
    async fn session_end(&self, session: &str, log: &Path) -> String {
        let (said, why) = self
            .hook(
                &["hand-over", "--timeout", "60"],
                &json!({
                    "hook_event_name": "SessionEnd",
                    "session_id": session,
                    "transcript_path": log,
                    "cwd": "/tmp/heron-lantern",
                    "reason": "exit",
                }),
            )
            .await;
        assert!(said.is_empty(), "a hand-over prints nothing: {said}");
        why
    }
}

/// What the owner allowed: the authorize URL the browser opened, the
/// consent page it showed, the request, and the agent the client acts as.
struct Allowed {
    authorize: reqwest::Url,
    page: String,
    request_ref: EntityId,
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

/// A browser that follows no redirect.
fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("browser")
}

/// Plays the browser for `authorize` up to the owner's answer, the owner
/// allowing at the tier asked, and the browser's return to the loopback.
async fn allow(served: &Served, authorize: reqwest::Url) -> Allowed {
    let browser = browser();
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

/// Two whole Claude Code log lines of `session`, a user turn then an
/// assistant turn.
fn turns(session: &str) -> String {
    let user = json!({
        "parentUuid": null,
        "isSidechain": false,
        "userType": "external",
        "cwd": "/tmp/heron-lantern",
        "sessionId": session,
        "version": "2.1.0",
        "type": "user",
        "uuid": format!("{}-0000-4000-8000-000000000001", &session[..8]),
        "timestamp": "2026-11-21T01:00:00.000Z",
        "message": {
            "role": "user",
            "content": format!("For session {session}, keep the ferry timetable in pier nine order."),
        },
    });
    let assistant = json!({
        "parentUuid": format!("{}-0000-4000-8000-000000000001", &session[..8]),
        "isSidechain": false,
        "userType": "external",
        "cwd": "/tmp/heron-lantern",
        "sessionId": session,
        "version": "2.1.0",
        "type": "assistant",
        "uuid": format!("{}-0000-4000-8000-000000000002", &session[..8]),
        "timestamp": "2026-11-21T01:00:05.000Z",
        "message": {
            "id": format!("msg_{}", &session[..8]),
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": [{"type": "text", "text": "Noted: the timetable stays in pier nine order."}],
        },
    });
    format!("{user}\n{assistant}\n")
}

/// How many messages the Claude Code reader keeps from `session`'s log, as
/// the import reads it.
fn kept(session: &str) -> usize {
    HistorySource::ClaudeCode
        .decode(
            &turns(session),
            &HistoryFile {
                stem: session.to_owned(),
                parent: None,
            },
        )
        .expect("decode the session log")
        .iter()
        .map(|conversation| conversation.messages.len())
        .sum()
}

/// The vault's answer to a receive-pack advertisement asked with `bearer`:
/// its HTTP status.
async fn git_door_status(served: &Served, bearer: &str) -> u16 {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client")
        .get(format!(
            "{}/git/{REPO}.git/info/refs?service=git-receive-pack",
            served.origin
        ))
        .bearer_auth(bearer)
        .send()
        .await
        .expect("ask for the receive-pack advertisement")
        .status()
        .as_u16()
}

/// A session end on a read login lands nothing: the recall sign-in is
/// `read`, and the import writes. Its log waits on this machine, one file
/// in the vault's queue naming the session and the log, and the hook says
/// which command lets it land.
#[test]
fn a_read_login_lands_no_session_log_and_queues_it() {
    run_on_engine_stack("hosted-hand-over-read-login", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        assert_eq!(recall.query("scope"), "read", "FIXTURE: a read login");
        served.grant_import(recall.agent);
        let log = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &log).await;

        let said = scratch.session_end(FIRST_SESSION, &log).await;
        assert_eq!(served.landed(), 0, "nothing landed on the read login");
        let queued = scratch.queued();
        assert_eq!(queued.len(), 1, "the session's log waits: {said}");
        let entry = read_json(&queued[0]);
        assert_eq!(entry["session"], FIRST_SESSION, "{entry}");
        assert_eq!(entry["host"], "claude-code", "{entry}");
        assert_eq!(
            entry["log"],
            log.to_str().expect("UTF-8 path"),
            "it names the log, never a copy: {entry}"
        );
        let mode = std::fs::metadata(&queued[0])
            .expect("the queued log's file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "only its owner reads it: {mode:o}");
        assert!(
            said.contains("--hand-over"),
            "it says which command lets the log land: {said}"
        );

        // The same session's next end waits in the same file.
        scratch.session_end(FIRST_SESSION, &log).await;
        assert_eq!(scratch.queued(), queued, "one file per session");
        assert_eq!(served.landed(), 0);
    });
}

/// `hosted login --hand-over` makes the hand-over sign-in: the recall
/// sign-in's client asks `full` at `/mcp` alone, naming its purpose; the
/// consent page and the owner's inbox ask say what it asks to do; it goes
/// to its own file beside the recall one, which stays `read` and unchanged.
/// Its token, and the recall sign-in's, reach nothing at the git door.
#[test]
fn hosted_login_hand_over_makes_the_hand_over_sign_in() {
    run_on_engine_stack("hosted-hand-over-login", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served, &[]).await;
        let recall_before = read_json(&scratch.recall_file());

        let allowed = scratch.login(&served, &["--hand-over"]).await;
        assert_eq!(allowed.query("scope"), "full");
        assert_eq!(allowed.query_all("resource"), [MCP], "never /git");
        assert_eq!(allowed.query("purpose"), PURPOSE_NAME);
        assert_eq!(
            allowed.query("client_id"),
            recall_before["client_id"].as_str().expect("client"),
            "the hand-over sign-in is the recall sign-in's client, so its agent"
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
        assert_eq!(detail["resources"], json!([MCP]), "{detail}");
        assert_eq!(detail["tier"], "full", "{detail}");

        let hand_over_file = scratch.hand_over_file();
        let mode = std::fs::metadata(&hand_over_file)
            .expect("the hand-over sign-in")
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "only its owner reads it: {mode:o}");
        let held = read_json(&hand_over_file);
        assert_eq!(held["scope"], "full");
        assert_eq!(held["resource"], MCP);
        assert_eq!(held["client_id"], recall_before["client_id"]);
        assert_ne!(held["access_token"], recall_before["access_token"]);
        assert_eq!(
            read_json(&scratch.recall_file()),
            recall_before,
            "the recall sign-in stays read and unchanged"
        );
        for (whose, sign_in) in [("hand-over", &held), ("recall", &recall_before)] {
            assert_eq!(
                git_door_status(&served, sign_in["access_token"].as_str().expect("access")).await,
                401,
                "the {whose} sign-in's token pushes nothing"
            );
        }
    });
}

/// A request that names the hand-over purpose beside `/git` is refused
/// before anything is recorded: the hand-over never pushes. The vault sends
/// the browser back with `invalid_request`, and the owner is asked nothing.
#[test]
fn a_hand_over_request_naming_the_git_door_is_refused() {
    run_on_engine_stack("hosted-hand-over-no-git", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        let mut asked = recall.authorize.clone();
        asked
            .query_pairs_mut()
            .clear()
            .extend_pairs(
                recall
                    .authorize
                    .query_pairs()
                    .filter(|(key, _)| key != "scope"),
            )
            .append_pair("scope", "full")
            .append_pair("resource", GIT)
            .append_pair("purpose", PURPOSE_NAME);
        let asks_before = served
            .vault
            .memory(served.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .len();

        let answer = browser()
            .get(asked.as_str())
            .send()
            .await
            .expect("ask the vault");
        assert_eq!(answer.status(), 302, "sent back, not shown a page");
        let back = answer
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .expect("the redirect");
        let back = reqwest::Url::parse(back).expect("the redirect parses");
        assert!(
            back.query_pairs()
                .any(|(key, value)| key == "error" && value == "invalid_request"),
            "{back}"
        );
        let asks_after = served
            .vault
            .memory(served.owner_person, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .len();
        assert_eq!(asks_after, asks_before, "the owner is asked nothing");
    });
}

/// Once the hand-over sign-in stands (and the owner's Grant names the
/// import), the next session end lands its own log and then every log that
/// waited, and the queue empties. The hand-over sign-in acts as the agent
/// the owner already admitted.
#[test]
fn the_queued_logs_land_at_the_next_session_end_once_the_hand_over_sign_in_stands() {
    run_on_engine_stack("hosted-hand-over-queue-lands", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        served.grant_import(recall.agent);
        let first = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &first).await;
        scratch.session_end(FIRST_SESSION, &first).await;
        assert_eq!(scratch.queued().len(), 1, "FIXTURE: the first log waits");
        assert_eq!(served.landed(), 0);

        let stepped_up = scratch.login(&served, &["--hand-over"]).await;
        assert_eq!(
            stepped_up.agent, recall.agent,
            "the hand-over sign-in acts as the agent the owner already admitted"
        );
        let next = scratch.session_log(NEXT_SESSION);
        scratch.session_start(&served, NEXT_SESSION, &next).await;
        let said = scratch.session_end(NEXT_SESSION, &next).await;
        let both = kept(FIRST_SESSION) + kept(NEXT_SESSION);
        assert!(kept(FIRST_SESSION) > 0, "FIXTURE: the reader keeps the log");
        assert_eq!(
            served.landed(),
            both,
            "the next session's log and the one that waited both landed: {said}"
        );
        assert!(scratch.queued().is_empty(), "the queue is empty: {said}");

        // A later end lands only what is new.
        scratch.session_end(NEXT_SESSION, &next).await;
        assert_eq!(served.landed(), both);
    });
}

/// A new plain `hosted login` registers another client, and the hand-over
/// sign-in of the old one is signed out: its file goes and its refresh
/// token no longer refreshes. The next session end lands nothing and its
/// log waits, so no session lands as an agent the recall sign-in no longer
/// is.
#[test]
fn a_new_recall_login_stops_the_old_hand_over_sign_in() {
    run_on_engine_stack("hosted-hand-over-relogin", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        served.grant_import(recall.agent);
        scratch.login(&served, &["--hand-over"]).await;
        let first = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &first).await;
        scratch.session_end(FIRST_SESSION, &first).await;
        assert_eq!(served.landed(), kept(FIRST_SESSION), "FIXTURE: it lands");
        let hand_over_file = scratch.hand_over_file();
        let held = read_json(&hand_over_file);

        let again = scratch.login(&served, &[]).await;
        assert_ne!(again.agent, recall.agent, "FIXTURE: another client");
        assert!(
            !hand_over_file.exists(),
            "the old client's hand-over sign-in is gone"
        );
        let (status, body) = refresh_at_vault(&served, &held).await;
        assert_eq!(status, 400, "it is revoked at the vault: {body}");
        assert_eq!(body["error"], "invalid_grant", "{body}");
        let next = scratch.session_log(NEXT_SESSION);
        scratch.session_start(&served, NEXT_SESSION, &next).await;
        scratch.session_end(NEXT_SESSION, &next).await;
        assert_eq!(
            served.landed(),
            kept(FIRST_SESSION),
            "nothing lands on the old client's hand-over sign-in"
        );
        assert_eq!(scratch.queued().len(), 1, "the next log waits");
    });
}

/// A hand-over sign-in the vault no longer takes (revoked there) leaves the
/// log waiting, with a word on stderr; once a new hand-over sign-in stands,
/// the next session end lands it with its own.
#[test]
fn a_hand_over_the_vault_refuses_leaves_the_log_waiting() {
    run_on_engine_stack("hosted-hand-over-revoked", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        served.grant_import(recall.agent);
        scratch.login(&served, &["--hand-over"]).await;
        let held = read_json(&scratch.hand_over_file());
        let revoked = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client")
            .post(format!("{}/oauth/revoke", served.origin))
            .form(&[
                ("token", held["refresh_token"].as_str().expect("refresh")),
                ("token_type_hint", "refresh_token"),
                ("client_id", held["client_id"].as_str().expect("client")),
            ])
            .send()
            .await
            .expect("revoke at the vault");
        assert!(revoked.status().is_success(), "FIXTURE: revoked");
        let first = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &first).await;

        let said = scratch.session_end(FIRST_SESSION, &first).await;
        assert_eq!(served.landed(), 0, "nothing landed on the revoked sign-in");
        assert_eq!(scratch.queued().len(), 1, "the log waits: {said}");
        assert!(said.contains("did not land"), "{said}");

        scratch.login(&served, &["--hand-over"]).await;
        let next = scratch.session_log(NEXT_SESSION);
        scratch.session_start(&served, NEXT_SESSION, &next).await;
        scratch.session_end(NEXT_SESSION, &next).await;
        assert_eq!(served.landed(), kept(FIRST_SESSION) + kept(NEXT_SESSION));
        assert!(scratch.queued().is_empty(), "the queue is empty");
    });
}

/// `hosted logout` signs out the hand-over sign-in with the recall one and
/// empties the queue: the files go, and the hand-over sign-in's refresh
/// token no longer refreshes.
#[test]
fn logout_signs_out_the_hand_over_sign_in_and_empties_the_queue() {
    run_on_engine_stack("hosted-hand-over-logout", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served, &[]).await;
        let log = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &log).await;
        scratch.session_end(FIRST_SESSION, &log).await;
        assert_eq!(scratch.queued().len(), 1, "FIXTURE: the log waits");
        scratch.login(&served, &["--hand-over"]).await;
        let hand_over_file = scratch.hand_over_file();
        let held = read_json(&hand_over_file);

        let output = finished(scratch.spawn(&["hosted", "logout"])).await;
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(!hand_over_file.exists(), "the hand-over sign-in is gone");
        assert!(scratch.queued().is_empty(), "the queue is empty");
        let (status, body) = refresh_at_vault(&served, &held).await;
        assert_eq!(status, 400, "{body}");
        assert_eq!(body["error"], "invalid_grant", "{body}");
    });
}

/// The first session end on a read login files the hand-over sign-in
/// request itself: the owner's inbox asks for `full` at `/mcp` alone, worded
/// as ruled, and a second end while it waits asks nothing more. Once he
/// allows it, the sign-in is kept, the hooks' record of the ask goes, and
/// the next session end lands the log that waited and its own.
#[test]
fn the_first_session_end_files_the_hand_over_ask_itself() {
    run_on_engine_stack("hosted-hand-over-self-ask", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        let recall = scratch.login(&served, &[]).await;
        served.grant_import(recall.agent);
        let first = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &first).await;

        let said = scratch.session_end(FIRST_SESSION, &first).await;
        assert!(said.contains("inbox now asks"), "it says it asked: {said}");
        let asks = served.hand_over_asks_soon().await;
        assert_eq!(asks.len(), 1, "one request");
        let detail = served.ask_detail(asks[0]);
        assert_eq!(detail["tier"], "full", "{detail}");
        assert_eq!(detail["resources"], json!([MCP]), "never /git: {detail}");
        assert_eq!(
            scratch.ask_record().expect("the ask is recorded")["state"],
            "asked"
        );

        scratch.session_end(FIRST_SESSION, &first).await;
        assert_eq!(
            served.hand_over_asks().len(),
            1,
            "no second ask while one waits"
        );
        assert_eq!(served.landed(), 0);

        let agent = served.answer(asks[0], true);
        assert_eq!(agent, Some(recall.agent), "the recall sign-in's agent");
        scratch
            .until(
                "the allowed sign-in is kept and the ask forgotten",
                |scratch| {
                    !scratch
                        .named_in_user_dir("hosted-oauth-hand-over-", ".json")
                        .is_empty()
                        && scratch.ask_record().is_none()
                },
            )
            .await;
        assert_eq!(read_json(&scratch.hand_over_file())["scope"], "full");

        let next = scratch.session_log(NEXT_SESSION);
        scratch.session_start(&served, NEXT_SESSION, &next).await;
        scratch.session_end(NEXT_SESSION, &next).await;
        assert_eq!(
            served.landed(),
            kept(FIRST_SESSION) + kept(NEXT_SESSION),
            "the log that waited and the next one landed"
        );
        assert!(scratch.queued().is_empty(), "the queue is empty");
    });
}

/// A request the owner denies is never filed again by a session end: the
/// hooks record the deny, the log keeps waiting, and the explicit `hosted
/// login --hand-over` stays the way.
#[test]
fn a_denied_hand_over_ask_is_not_filed_again() {
    run_on_engine_stack("hosted-hand-over-self-ask-denied", || async {
        let served = Served::start().await;
        let scratch = Scratch::new();
        scratch.login(&served, &[]).await;
        let log = scratch.session_log(FIRST_SESSION);
        scratch.session_start(&served, FIRST_SESSION, &log).await;
        scratch.session_end(FIRST_SESSION, &log).await;
        let asks = served.hand_over_asks_soon().await;

        assert_eq!(
            served.answer(asks[0], false),
            None,
            "a deny admits no agent"
        );
        scratch
            .until("the deny is recorded", |scratch| {
                scratch
                    .ask_record()
                    .is_some_and(|record| record["state"] == "denied")
            })
            .await;
        let said = scratch.session_end(FIRST_SESSION, &log).await;
        assert_eq!(served.hand_over_asks().len(), 1, "no second ask: {said}");
        assert_eq!(scratch.ask_record().expect("the record")["state"], "denied");
        assert_eq!(scratch.queued().len(), 1, "the log keeps waiting");
        assert_eq!(served.landed(), 0);
    });
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
