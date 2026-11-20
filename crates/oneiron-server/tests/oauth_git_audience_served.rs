//! The vault's second OAuth audience, `{origin}/git` (lead ruling
//! CONTINUE-PUSH-NON-SLIP-SELECTION = B, Sat 21 Nov 04:3x: "only a token that
//! asked for git may push, through the same git_push permission check as
//! today; tokens for ChatGPT or Claude connectors still reach nothing else").
//!
//! One sign-in may name several RFC 8707 resources. A token whose sign-in
//! named `/git` goes through the git door (smart-HTTP and LFS) as the slip the
//! server holds for it, with a fresh holder proof on each request, so stock
//! git pushes with the token as one static header; the git door's gate and
//! the `git_push` admission then judge it as they judge every slip. A token
//! whose sign-in named `/mcp` alone reaches no git door, and one that named
//! `/git` alone reaches no MCP endpoint.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features --test
//! oauth_git_audience_served`. Stock `git` (with `http-backend`) must be on
//! PATH.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::GitPushRepo;
use oneiron::origin::smart_http;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    GitPushGrantMintInput, OAuthAuthorizationAnswer, RepoAnchorBindInput,
    answer_oauth_authorization_as, bind_repo_anchor_as, mint_git_push_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const INDICATOR: &str = "https://vault.example";
const MCP: &str = "https://vault.example/mcp";
const GIT: &str = "https://vault.example/git";
const GIT_METADATA: &str = "https://vault.example/.well-known/oauth-protected-resource/git";
const MCP_METADATA: &str = "https://vault.example/.well-known/oauth-protected-resource/mcp";
const CALLBACK: &str = "http://127.0.0.1:8787/oauth/callback";
/// The served repo's name.
const REPO: &str = "demo";
/// The ref each push lands on.
const PUSHED_REF: &str = "refs/heads/oauth-push";
const PROTOCOL_VERSION: &str = "2025-06-18";

struct Answer {
    status: u16,
    challenge: Option<String>,
    location: Option<String>,
    body: Value,
}

impl Answer {
    async fn read(reply: reqwest::Response) -> Self {
        let status = reply.status().as_u16();
        let header = |name: &str| {
            reply
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let (challenge, location) = (header("www-authenticate"), header("location"));
        let text = reply.text().await.expect("the answer's body");
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Self {
            status,
            challenge,
            location,
            body,
        }
    }

    /// Asserts a 401 whose challenge says `invalid_token` and names
    /// `metadata`, the resource the request reached.
    fn assert_token_refused(&self, metadata: &str, what: &str) {
        assert_eq!(self.status, 401, "{what}: {}", self.body);
        let challenge = self.challenge.as_deref().unwrap_or_default();
        assert!(
            challenge.contains("error=\"invalid_token\"")
                && challenge.contains(&format!("resource_metadata=\"{metadata}\"")),
            "{what}: the challenge names the token invalid at its resource: {challenge:?}"
        );
    }
}

/// The served app on a loopback port and the rooted vault behind it, with
/// the served repo [`REPO`] bound as a CODE anchor.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    origin: String,
    http: reqwest::Client,
    push_repo: GitPushRepo,
}

/// What one sign-in names and what the owner allows it.
#[derive(Clone, Copy)]
struct Asked {
    resources: &'static [&'static str],
    scope: &'static str,
    allowed: AgentTier,
}

/// A signed-in client: its tokens and the agent it acts as.
struct SignedIn {
    client_id: String,
    access: String,
    refresh: String,
    agent: EntityId,
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
                    auth_secret: Some("oauth-git-audience-served".to_owned()),
                    oauth_resource_indicator: Some(INDICATOR.to_owned()),
                    ..Default::default()
                },
            )
            .expect("a server"),
        );
        // Rooted and profiled as `oneiron init` leaves a serving install: the
        // owner's Grant act on this install needs its machine profile.
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner_id = vault.ensure_embedded_owner_actor().expect("owner");
        let owner = vault
            .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof");
        vault
            .register_served_origin_as_owner(&owner, REPO, "main")
            .expect("register the served repo");
        let push_repo = bind_repo_anchor_as(
            &vault,
            &owner,
            RepoAnchorBindInput {
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
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .expect("an HTTP client");
        Self {
            _dir: dir,
            vault,
            owner,
            origin,
            http,
            push_repo,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    async fn get(&self, path: &str, bearer: Option<&str>) -> Answer {
        let mut request = self.http.get(self.url(path));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        Answer::read(request.send().await.expect("GET")).await
    }

    async fn token(&self, form: &[(&str, &str)]) -> Answer {
        Answer::read(
            self.http
                .post(self.url("/oauth/token"))
                .form(form)
                .send()
                .await
                .expect("the token endpoint"),
        )
        .await
    }

    /// A public client with [`CALLBACK`].
    async fn register(&self) -> String {
        let registered = Answer::read(
            self.http
                .post(self.url("/oauth/register"))
                .json(&json!({
                    "redirect_uris": [CALLBACK],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                }))
                .send()
                .await
                .expect("register"),
        )
        .await;
        assert_eq!(registered.status, 201, "registers: {}", registered.body);
        registered.body["client_id"]
            .as_str()
            .expect("client_id")
            .to_owned()
    }

    /// The authorize request of `client_id` naming each of `resources`, as
    /// the browser loads it.
    async fn authorize(
        &self,
        client_id: &str,
        verifier: &str,
        scope: &str,
        resources: &[&str],
    ) -> Answer {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let mut query = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", CALLBACK),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "git-audience-state"),
            ("scope", scope),
        ];
        query.extend(resources.iter().map(|resource| ("resource", *resource)));
        Answer::read(
            self.http
                .get(self.url("/oauth/authorize"))
                .query(&query)
                .send()
                .await
                .expect("load the consent page"),
        )
        .await
    }

    /// Registers, asks as `asked` names, has the owner allow it over every
    /// world at `asked.allowed`, collects the code and trades it, naming the
    /// first resource asked.
    async fn sign_in(&self, asked: Asked) -> SignedIn {
        let client_id = self.register().await;
        let verifier = format!("git-audience-verifier-{}", "v".repeat(48));
        let page = self
            .authorize(&client_id, &verifier, asked.scope, asked.resources)
            .await;
        assert_eq!(
            page.status, 200,
            "the consent page loads for {:?}: {:?}",
            asked.resources, page.location
        );
        let token = page_token(page.body.as_str().expect("the page"));
        let request_ref = EntityId::from_hex(token.split('.').next().expect("token prefix"))
            .expect("the page token names its request");
        let answered = answer_oauth_authorization_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            OAuthAuthorizationAnswer {
                request_ref,
                allow: true,
                tier: Some(asked.allowed),
                world_ref: None,
            },
        )
        .expect("the owner allows the request");
        assert!(answered.allowed, "FIXTURE: the owner's answer allows it");
        let status = Answer::read(
            self.http
                .get(self.url("/oauth/authorize/status"))
                .header("x-oneiron-oauth-page", &token)
                .send()
                .await
                .expect("poll the request"),
        )
        .await;
        assert_eq!(status.body["status"], "allowed", "{}", status.body);
        let back = reqwest::Url::parse(status.body["redirect"].as_str().expect("the redirect"))
            .expect("the redirect parses");
        let code = back
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned())
            .expect("a code");
        let traded = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", client_id.as_str()),
                ("redirect_uri", CALLBACK),
                ("code_verifier", verifier.as_str()),
                ("resource", asked.resources[0]),
            ])
            .await;
        assert_eq!(traded.status, 200, "the code trades: {}", traded.body);
        SignedIn {
            client_id,
            access: traded.body["access_token"]
                .as_str()
                .expect("access")
                .to_owned(),
            refresh: traded.body["refresh_token"]
                .as_str()
                .expect("refresh")
                .to_owned(),
            agent: answered.agent.expect("the agent the client acts as"),
        }
    }

    /// The owner's `git_push` Grant to `agent` on [`REPO`], minted through
    /// `vault.repo.git_push.mint` as for any other holder.
    fn grant_push(&self, agent: EntityId) {
        mint_git_push_grant_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            GitPushGrantMintInput {
                member: agent,
                repos: BTreeSet::from([self.push_repo]),
                expires_at: None,
            },
        )
        .expect("the owner grants the agent git_push on the repo");
    }

    /// The commit the served repo's bare store holds on [`PUSHED_REF`].
    fn landed(&self) -> Option<String> {
        let bare = smart_http::origin_repo_dir(&self.vault, REPO).expect("the served repo dir");
        let output = git(&bare, &["rev-parse", "--verify", "--quiet", PUSHED_REF]);
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Stock `git push` of `work`'s HEAD to [`PUSHED_REF`] of [`REPO`], the
    /// access token as its one static `Authorization` header: the vault
    /// signs each request's holder proof itself.
    async fn push(&self, work: &Path, access: &str) -> std::process::Output {
        let url = self.url(&format!("/git/{REPO}.git"));
        let header = format!("http.extraHeader=Authorization: Bearer {access}");
        let work = work.to_owned();
        tokio::task::spawn_blocking(move || {
            git(
                &work,
                &["-c", &header, "push", &url, &format!("HEAD:{PUSHED_REF}")],
            )
        })
        .await
        .expect("the push thread")
    }
}

const GIT_AND_MCP_FULL: Asked = Asked {
    resources: &[MCP, GIT],
    scope: "full",
    allowed: AgentTier::FullAccess,
};

/// Stock git in `dir`, never asking for a credential and reading no user or
/// system configuration.
fn git(dir: &Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("stock git starts")
}

/// A work repo in `dir` with one commit of `text`; answers its id.
fn commit(dir: &Path, text: &str) -> String {
    if !dir.join(".git").exists() {
        assert!(
            git(dir, &["init", "--initial-branch=main"])
                .status
                .success()
        );
    }
    std::fs::write(dir.join("README.md"), text).expect("write the work");
    for args in [
        &["add", "--", "README.md"][..],
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            text,
        ],
    ] {
        let output = git(dir, args);
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let head = git(dir, &["rev-parse", "HEAD"]);
    String::from_utf8_lossy(&head.stdout).trim().to_owned()
}

/// The page token the consent page carries for its script.
fn page_token(page: &str) -> String {
    let marker = "<meta name=oauth-page-token content=\"";
    let start = page.find(marker).expect("the page carries its token") + marker.len();
    let len = page[start..].find('"').expect("the token's end");
    page[start..start + len].to_owned()
}

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "git-audience", "version": "1"},
        },
    })
}

/// A sign-in that named `/mcp` and `/git` pushes with stock git through the
/// git door, the access token its one static header, once the owner granted
/// its agent `git_push` on the repo; its refreshed token pushes again.
#[test]
fn a_sign_in_naming_git_pushes_through_the_git_door() {
    run_on_engine_stack("oauth-git-audience-push", || async {
        let served = Served::start().await;
        let signed = served.sign_in(GIT_AND_MCP_FULL).await;
        served.grant_push(signed.agent);
        let work = tempfile::tempdir().expect("work dir");
        let first = commit(work.path(), "first\n");
        let pushed = served.push(work.path(), &signed.access).await;
        assert!(
            pushed.status.success(),
            "the push lands: {}",
            String::from_utf8_lossy(&pushed.stderr)
        );
        assert_eq!(
            served.landed(),
            Some(first),
            "the served repo holds the push"
        );

        let refreshed = served
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", signed.refresh.as_str()),
                ("client_id", signed.client_id.as_str()),
                ("resource", GIT),
            ])
            .await;
        assert_eq!(
            refreshed.status, 200,
            "the family refreshes: {}",
            refreshed.body
        );
        let access = refreshed.body["access_token"].as_str().expect("access");
        let second = commit(work.path(), "second\n");
        let pushed = served.push(work.path(), access).await;
        assert!(
            pushed.status.success(),
            "the refreshed token pushes: {}",
            String::from_utf8_lossy(&pushed.stderr)
        );
        assert_eq!(served.landed(), Some(second));
    });
}

/// A sign-in that named `/mcp` alone, as every ChatGPT or Claude connector
/// signs in, reaches no git door, even at the full tier and with a
/// `git_push` Grant: each smart-HTTP and LFS request answers `invalid_token`
/// at the `/git` resource.
#[test]
fn a_sign_in_naming_mcp_alone_reaches_no_git_door() {
    run_on_engine_stack("oauth-git-audience-mcp-only", || async {
        let served = Served::start().await;
        let signed = served
            .sign_in(Asked {
                resources: &[MCP],
                ..GIT_AND_MCP_FULL
            })
            .await;
        served.grant_push(signed.agent);
        for service in ["git-receive-pack", "git-upload-pack"] {
            served
                .get(
                    &format!("/git/{REPO}.git/info/refs?service={service}"),
                    Some(&signed.access),
                )
                .await
                .assert_token_refused(GIT_METADATA, service);
        }
        let batch = Answer::read(
            served
                .http
                .post(served.url(&format!("/git/{REPO}.git/info/lfs/objects/batch")))
                .bearer_auth(&signed.access)
                .header("content-type", "application/vnd.git-lfs+json")
                .json(&json!({"operation": "upload", "objects": []}))
                .send()
                .await
                .expect("the LFS batch"),
        )
        .await;
        batch.assert_token_refused(GIT_METADATA, "the LFS batch");
        let work = tempfile::tempdir().expect("work dir");
        commit(work.path(), "refused\n");
        let pushed = served.push(work.path(), &signed.access).await;
        assert!(!pushed.status.success(), "stock git push is refused");
        assert_eq!(served.landed(), None, "nothing lands");
    });
}

/// A sign-in that named `/mcp` and `/git` still reaches `/mcp`; one that
/// named `/git` alone reaches no MCP endpoint.
#[test]
fn a_token_reaches_mcp_only_when_its_sign_in_named_it() {
    run_on_engine_stack("oauth-git-audience-mcp", || async {
        let served = Served::start().await;
        let both = served.sign_in(GIT_AND_MCP_FULL).await;
        let reached = Answer::read(
            served
                .http
                .post(served.url("/mcp"))
                .bearer_auth(&both.access)
                .json(&initialize_body())
                .send()
                .await
                .expect("POST /mcp"),
        )
        .await;
        assert_eq!(reached.status, 200, "{}", reached.body);
        assert!(
            reached.body["result"]["protocolVersion"].is_string(),
            "the handshake answers: {}",
            reached.body
        );

        let git_only = served
            .sign_in(Asked {
                resources: &[GIT],
                ..GIT_AND_MCP_FULL
            })
            .await;
        for path in ["/mcp", "/mcp/tool-first"] {
            Answer::read(
                served
                    .http
                    .post(served.url(path))
                    .bearer_auth(&git_only.access)
                    .json(&initialize_body())
                    .send()
                    .await
                    .expect("POST to MCP"),
            )
            .await
            .assert_token_refused(MCP_METADATA, path);
        }
    });
}

/// A sign-in that named `/git` but that the owner allowed at the read tier
/// reaches the git door as that tier: its token is taken, and the gate every
/// slip passes refuses its push for want of `core:write`, Grant or not.
#[test]
fn a_read_tier_git_sign_in_is_refused_at_the_push_gate() {
    run_on_engine_stack("oauth-git-audience-read-tier", || async {
        let served = Served::start().await;
        let signed = served
            .sign_in(Asked {
                allowed: AgentTier::ReadOnly,
                ..GIT_AND_MCP_FULL
            })
            .await;
        served.grant_push(signed.agent);
        let push = served
            .get(
                &format!("/git/{REPO}.git/info/refs?service=git-receive-pack"),
                Some(&signed.access),
            )
            .await;
        assert_eq!(push.status, 403, "{}", push.body);
        assert_eq!(push.body, Value::String("insufficient scope".to_owned()));
    });
}

/// `/git` has its own protected-resource document (RFC 9728 §3.1), naming the
/// same authorization server as `/mcp`'s, which is unchanged.
#[test]
fn the_git_resource_serves_its_metadata() {
    run_on_engine_stack("oauth-git-audience-metadata", || async {
        let served = Served::start().await;
        let git = served
            .get("/.well-known/oauth-protected-resource/git", None)
            .await;
        assert_eq!(git.status, 200, "{}", git.body);
        assert_eq!(git.body["resource"], GIT);
        assert_eq!(git.body["authorization_servers"], json!([INDICATOR]));
        assert_eq!(git.body["bearer_methods_supported"], json!(["header"]));
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ] {
            let mcp = served.get(path, None).await;
            assert_eq!(mcp.status, 200, "{path}: {}", mcp.body);
            assert_eq!(mcp.body["resource"], MCP, "{path}");
        }
    });
}

/// An authorize request may name each of the vault's resources once: one
/// named twice, or any other, sends the browser back with `invalid_target`.
#[test]
fn a_sign_in_naming_a_resource_twice_or_another_is_refused() {
    run_on_engine_stack("oauth-git-audience-targets", || async {
        let served = Served::start().await;
        let client_id = served.register().await;
        let verifier = format!("git-audience-verifier-{}", "w".repeat(48));
        for resources in [
            &[MCP, MCP][..],
            &[GIT, GIT],
            &[MCP, "https://vault.example/git/"],
            &[MCP, "https://vault.example/other"],
            &[],
        ] {
            let refused = served
                .authorize(&client_id, &verifier, "full", resources)
                .await;
            assert_eq!(refused.status, 302, "{resources:?}: {}", refused.body);
            let location = refused.location.unwrap_or_default();
            assert!(
                location.starts_with(CALLBACK) && location.contains("error=invalid_target"),
                "{resources:?}: {location}"
            );
        }
        let both = served
            .authorize(&client_id, &verifier, "full", &[GIT, MCP])
            .await;
        assert_eq!(both.status, 200, "either order is one request");
    });
}
