//! L1-02's acceptance slice (PLAN-L1-02; rulings L1-02-LIVE-ACCEPT = A and
//! L1-02-TEMPLATE-PUBLISH = A, Engine Sat 14 Nov 03:02): the two named cloud
//! agents, Grok Bot and Muse, sign in at the vault's own OAuth 2.1 server and
//! use `/mcp` (ARCH-0028 #default-route and #cloud-agents-connect;
//! RESEARCH-1396 #grok and #muse). A harness label grants nothing, so each
//! profile is only what its client sends: its DCR body, the redirect URI it
//! signs in through, and the headers it sends on later calls.
//!
//! - Grok Bot registers by DCR with the three redirect URIs Cursor staff
//!   document (RESEARCH-1396 source [G6], the forum post of 2026-09-16), one
//!   of them the dotless private scheme
//!   `cursor://anysphere.cursor-mcp/oauth/callback`. It signs in through the
//!   Cloud Agents https callback and sends a bearer only: no
//!   `MCP-Protocol-Version` after `initialize`.
//! - Muse registers by DCR with one https callback and sends the header.
//!
//! The vault runs in process on a loopback port, rooted on a
//! `MemoryKeystore`, with an https `oauth_resource_indicator` so its OAuth
//! routes answer. The test plays the client over HTTP, and the owner: he
//! allows each request in process, as his inbox's one-tap does, at the
//! propose tier and bound to world A.
//!
//! Red on main: the vault refuses Grok Bot's registration (400
//! `invalid_redirect_uri`: a private-use scheme is admitted only with a `.`
//! in it), so every Grok Bot case fails at its registration. The guard case
//! and the Muse case pass on main and on the head.
//!
//! `cargo test --locked -p oneiron-server --all-features --features
//! oneiron/test-support --test oauth_named_client_acceptance`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, AgentTier};
use oneiron::claim::default_project_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{OAuthAuthorizationAnswer, answer_oauth_authorization_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// The vault's public OAuth identity: its issuer.
const INDICATOR: &str = "https://vault.example";
/// The protected resource every token is minted for.
const RESOURCE: &str = "https://vault.example/mcp";
/// Where a 401 from `/mcp` sends a client to discover the sign-in.
const RESOURCE_METADATA: &str = "https://vault.example/.well-known/oauth-protected-resource/mcp";
/// Grok Bot's documented redirect URIs ([G6]): the legacy private scheme,
/// the Cloud Agents callback and the desktop loopback.
const CURSOR_CALLBACK: &str = "cursor://anysphere.cursor-mcp/oauth/callback";
const GROK_CLOUD_CALLBACK: &str = "https://www.cursor.com/agents/mcp/oauth/callback";
const GROK_DESKTOP_CALLBACK: &str = "http://localhost:8787/callback";
/// Muse's callback (a stand-in https URI: the service publishes none).
const MUSE_CALLBACK: &str = "https://muse.example/oauth/callback";
/// The MCP version a client that sends the header names.
const PROTOCOL_VERSION: &str = "2025-06-18";
/// World B's name, which no answer to a client bound to world A may carry.
const WORLD_B_NAME: &str = "Harbor ledger partition";
/// The owner's claim in world A, and his claim in world B.
const CLAIM_A_TEXT: &str = "lantern shelf amber";
const CLAIM_B_TEXT: &str = "tidewater ledger cobalt";
const OCCURRED_AT: u64 = 1_769_947_200;

/// One cloud agent as the vault sees it: what it registers and how it calls.
#[derive(Clone, Copy)]
struct Profile {
    name: &'static str,
    redirect_uris: &'static [&'static str],
    sign_in_redirect: &'static str,
    sends_protocol_header: bool,
}

const GROK_BOT: Profile = Profile {
    name: "grok-bot",
    redirect_uris: &[CURSOR_CALLBACK, GROK_CLOUD_CALLBACK, GROK_DESKTOP_CALLBACK],
    sign_in_redirect: GROK_CLOUD_CALLBACK,
    sends_protocol_header: false,
};

const MUSE: Profile = Profile {
    name: "muse",
    redirect_uris: &[MUSE_CALLBACK],
    sign_in_redirect: MUSE_CALLBACK,
    sends_protocol_header: true,
};

impl Profile {
    /// Its DCR body: a public client (RFC 7591) with the code and refresh
    /// grants.
    fn registration(self) -> Value {
        json!({
            "redirect_uris": self.redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })
    }
}

/// One HTTP answer: its status, its `WWW-Authenticate` and its JSON body.
struct Answer {
    status: u16,
    challenge: Option<String>,
    body: Value,
}

impl Answer {
    async fn read(reply: reqwest::Response) -> Self {
        let status = reply.status().as_u16();
        let challenge = reply
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let text = reply.text().await.expect("the answer's body");
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Self {
            status,
            challenge,
            body,
        }
    }

    /// A tool call's structured output.
    fn output(&self) -> &Value {
        assert!(
            self.body.get("error").is_none(),
            "the call answers: {}",
            self.body
        );
        &self.body["result"]["structuredContent"]["output"]
    }
}

/// The served vault, its owner's proof, and the two worlds he seeded.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    owner_id: EntityId,
    owner: AuthenticatedOwner,
    origin: String,
    http: reqwest::Client,
    world_a: EntityId,
    world_b: EntityId,
    claim_a: EntityId,
    claim_b: EntityId,
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
                    auth_secret: Some("oauth-named-client-acceptance".to_owned()),
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
        let world_a = vault
            .create_world(&owner, "Named client world", OCCURRED_AT)
            .expect("the owner creates world A");
        let world_b = vault
            .create_world(&owner, WORLD_B_NAME, OCCURRED_AT)
            .expect("the owner creates world B");
        let claim_a = owner_claim(&vault, owner_id, &owner, world_a, CLAIM_A_TEXT);
        let claim_b = owner_claim(&vault, owner_id, &owner, world_b, CLAIM_B_TEXT);
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
            owner_id,
            owner,
            origin,
            http,
            world_a,
            world_b,
            claim_a,
            claim_b,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    async fn get_json(&self, path: &str) -> Value {
        let answer = Answer::read(self.http.get(self.url(path)).send().await.expect("GET")).await;
        assert_eq!(answer.status, 200, "GET {path}: {}", answer.body);
        answer.body
    }

    async fn register(&self, body: &Value) -> Answer {
        Answer::read(
            self.http
                .post(self.url("/oauth/register"))
                .json(body)
                .send()
                .await
                .expect("register"),
        )
        .await
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

    /// POSTs one JSON-RPC body to an MCP path.
    async fn mcp(
        &self,
        path: &str,
        bearer: Option<&str>,
        protocol: Option<&str>,
        body: &Value,
    ) -> Answer {
        let mut request = self.http.post(self.url(path)).json(body);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(protocol) = protocol {
            request = request.header("mcp-protocol-version", protocol);
        }
        Answer::read(request.send().await.expect("POST to MCP")).await
    }

    /// The profile registers, asks at `/oauth/authorize` (PKCE S256, the
    /// `/mcp` resource, the propose scope), the owner allows it bound to world
    /// A, the status poll hands back the redirect, and the code is traded.
    async fn sign_in(&self, profile: Profile) -> SignedIn {
        let registered = self.register(&profile.registration()).await;
        assert_eq!(
            registered.status, 201,
            "{} registers: {}",
            profile.name, registered.body
        );
        let client_id = registered.body["client_id"]
            .as_str()
            .expect("client_id")
            .to_owned();
        let verifier = format!("{}-verifier-{}", profile.name, "v".repeat(48));
        let state = format!("{}-state-0001", profile.name);
        let (token, request_ref) = self
            .open_consent_page(&client_id, profile.sign_in_redirect, &verifier, &state)
            .await;
        let answered = answer_oauth_authorization_as(
            &self.vault,
            &self.owner,
            ActSurface::ThisInstall,
            OAuthAuthorizationAnswer {
                request_ref,
                allow: true,
                tier: Some(AgentTier::ProposeOnly),
                world_ref: Some(self.world_a),
            },
        )
        .expect("the owner allows the request");
        assert!(answered.allowed, "FIXTURE: the owner's answer allows it");
        assert_eq!(answered.world_ref, Some(self.world_a));
        let code = self
            .code_from_status(&token, profile.sign_in_redirect, &state)
            .await;
        let traded = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("client_id", client_id.as_str()),
                ("redirect_uri", profile.sign_in_redirect),
                ("code_verifier", verifier.as_str()),
                ("resource", RESOURCE),
            ])
            .await;
        assert_eq!(traded.status, 200, "the code trades: {}", traded.body);
        assert_eq!(traded.body["token_type"], "Bearer");
        assert_eq!(traded.body["scope"], "propose");
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
            protocol: profile.sends_protocol_header.then_some(PROTOCOL_VERSION),
        }
    }

    /// Loads the consent page the authorize request answers, and answers its
    /// page token and the request it names.
    async fn open_consent_page(
        &self,
        client_id: &str,
        redirect_uri: &str,
        verifier: &str,
        state: &str,
    ) -> (String, EntityId) {
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let page = self
            .http
            .get(self.url("/oauth/authorize"))
            .query(&[
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("state", state),
                ("scope", "propose"),
                ("resource", RESOURCE),
            ])
            .send()
            .await
            .expect("load the consent page");
        assert_eq!(page.status(), 200, "the consent page loads");
        let token = page_token(&page.text().await.expect("the page"));
        let request_ref = EntityId::from_hex(token.split('.').next().expect("token prefix"))
            .expect("the page token names its request");
        (token, request_ref)
    }

    /// Polls the allowed request and answers the code its redirect carries,
    /// after checking the redirect goes to the listed URI with the state and
    /// this vault's issuer.
    async fn code_from_status(&self, token: &str, redirect_uri: &str, state: &str) -> String {
        let status = Answer::read(
            self.http
                .get(self.url("/oauth/authorize/status"))
                .header("x-oneiron-oauth-page", token)
                .send()
                .await
                .expect("poll the request"),
        )
        .await;
        assert_eq!(status.body["status"], "allowed", "{}", status.body);
        let back = reqwest::Url::parse(status.body["redirect"].as_str().expect("the redirect"))
            .expect("the redirect parses");
        assert_eq!(
            back.as_str().split('?').next(),
            Some(redirect_uri),
            "the redirect goes to the URI the client signed in through"
        );
        let query = |name: &str| -> Option<String> {
            back.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
        };
        assert_eq!(query("state").as_deref(), Some(state));
        let issuer = self
            .get_json("/.well-known/oauth-authorization-server")
            .await["issuer"]
            .as_str()
            .expect("issuer")
            .to_owned();
        assert_eq!(query("iss"), Some(issuer), "RFC 9207 iss");
        query("code").expect("a code")
    }
}

/// The owner's claim in `world`, approved as he writes it.
fn owner_claim(
    vault: &Vault,
    owner_id: EntityId,
    owner: &AuthenticatedOwner,
    world: EntityId,
    text: &str,
) -> EntityId {
    let id = EntityId::now();
    vault
        .memory(owner_id, EdgeActorClass::Human)
        .with_owner_authorship(owner)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner_id.to_hex(),
            value: json!(text),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: claim_scope(vault, world),
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })
        .expect("the owner writes a claim in the world");
    id
}

fn claim_scope(vault: &Vault, world: EntityId) -> ClaimScope {
    ClaimScope {
        world_id: world.to_hex(),
        scope_facet_id: vault
            .default_facet()
            .expect("the owner's default facet")
            .to_hex(),
        scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
        scope_project_id: default_project_id().to_hex(),
    }
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
            "clientInfo": {"name": "named-client-acceptance", "version": "1"},
        },
    })
}

fn listed_tool_names(answer: &Answer) -> Vec<String> {
    answer.body["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("a tool list: {}", answer.body))
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

/// A signed-in client: its tokens, and the header its profile sends.
struct SignedIn {
    client_id: String,
    access: String,
    refresh: String,
    protocol: Option<&'static str>,
}

impl SignedIn {
    /// Calls one tool-first verb with `spec` as its input.
    async fn call(&self, served: &Served, tool: &str, spec: Value) -> Answer {
        let body = json!({
            "jsonrpc": "2.0",
            "id": tool,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {
                    "schema_version": "mcp_tool_args.v1",
                    "consent": {
                        "policy_ref": "policy:named-client-acceptance",
                        "purpose": "read_memory",
                        "require_human_approval": false,
                    },
                    "arguments": {"spec": spec},
                },
            },
        });
        served
            .mcp("/mcp/tool-first", Some(&self.access), self.protocol, &body)
            .await
    }

    async fn read_claim(&self, served: &Served, claim: EntityId) -> Answer {
        self.call(
            served,
            "vault.claims.read_filtered",
            json!({"claim_ref": claim.to_hex()}),
        )
        .await
    }

    /// `initialize`, both tool lists, and a read of the owner's claim in the
    /// granted world, each with this profile's headers.
    async fn assert_serves_world_a(&self, served: &Served) {
        let hello = served
            .mcp("/mcp", Some(&self.access), None, &initialize_body())
            .await;
        assert_eq!(hello.status, 200, "initialize: {}", hello.body);
        assert_eq!(
            hello.body["result"]["protocolVersion"], PROTOCOL_VERSION,
            "{}",
            hello.body
        );
        let list = json!({"jsonrpc": "2.0", "id": "list", "method": "tools/list"});
        let primary = served
            .mcp("/mcp", Some(&self.access), self.protocol, &list)
            .await;
        assert_eq!(primary.status, 200, "tools/list: {}", primary.body);
        assert!(
            listed_tool_names(&primary)
                .iter()
                .any(|name| name == "invoke_action"),
            "{}",
            primary.body
        );
        let verbs = served
            .mcp("/mcp/tool-first", Some(&self.access), self.protocol, &list)
            .await;
        assert!(
            listed_tool_names(&verbs)
                .iter()
                .any(|name| name == "vault.claims.read_filtered"),
            "{}",
            verbs.body
        );
        let read = self.read_claim(served, served.claim_a).await;
        assert_eq!(read.status, 200, "{}", read.body);
        let claim = &read.output()["value"];
        assert_eq!(claim["value"], CLAIM_A_TEXT, "{}", read.body);
        assert_eq!(claim["world_ref"], served.world_a.to_hex().as_str());
    }
}

/// An unauthenticated `/mcp` call points at the protected resource
/// metadata, which names this vault as the authorization server.
async fn assert_discovery(served: &Served) {
    let anonymous = served.mcp("/mcp", None, None, &initialize_body()).await;
    assert_eq!(anonymous.status, 401, "{}", anonymous.body);
    let challenge = anonymous.challenge.expect("a WWW-Authenticate challenge");
    assert!(
        challenge.contains(&format!("resource_metadata=\"{RESOURCE_METADATA}\"")),
        "{challenge}"
    );
    let resource = served
        .get_json("/.well-known/oauth-protected-resource/mcp")
        .await;
    assert_eq!(resource["resource"], RESOURCE);
    let server = served
        .get_json("/.well-known/oauth-authorization-server")
        .await;
    assert_eq!(resource["authorization_servers"][0], server["issuer"]);
    assert_eq!(server["code_challenge_methods_supported"], json!(["S256"]));
    assert!(
        server["registration_endpoint"]
            .as_str()
            .is_some_and(|endpoint| endpoint.ends_with("/oauth/register")),
        "{server}"
    );
}

/// Grok Bot's documented DCR body, with the dotless `cursor://` callback,
/// registers as a public client and keeps every URI it listed.
#[test]
fn grok_bot_registration_with_cursor_callback_is_admitted() {
    run_on_engine_stack("named-client-grok-register", || async {
        let served = Served::start().await;
        let registered = served.register(&GROK_BOT.registration()).await;
        assert_eq!(
            registered.status, 201,
            "Grok Bot's DCR body registers: {}",
            registered.body
        );
        assert_eq!(registered.body["token_endpoint_auth_method"], "none");
        assert_eq!(
            registered.body["redirect_uris"],
            json!(GROK_BOT.redirect_uris)
        );
        assert!(
            registered.body["client_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "{}",
            registered.body
        );
    });
}

/// The named callback is admitted as its exact string only: no other
/// dotless private scheme, path, query, fragment or spelling of it is.
#[test]
fn dotless_private_scheme_outside_the_named_list_stays_refused() {
    run_on_engine_stack("named-client-callback-guard", || async {
        let served = Served::start().await;
        for uri in [
            "cursorx://anysphere.cursor-mcp/oauth/callback",
            "cursor://anysphere.cursor-mcp/oauth/other",
            "cursor://anysphere.cursor-mcp/oauth/callback#frag",
            "cursor://anysphere.cursor-mcp/oauth/callback?next=1",
            "CURSOR://anysphere.cursor-mcp/oauth/callback",
        ] {
            let refused = served
                .register(&json!({
                    "redirect_uris": [uri],
                    "token_endpoint_auth_method": "none",
                }))
                .await;
            assert_eq!(refused.status, 400, "{uri}: {}", refused.body);
            assert_eq!(
                refused.body["error"], "invalid_redirect_uri",
                "{uri}: {}",
                refused.body
            );
        }
    });
}

/// Grok Bot's whole sign-in: discovery from the 401, DCR, consent, the code
/// trade, then `initialize`, the tool lists and a read in its world, all with
/// a bearer only and no `MCP-Protocol-Version` header.
#[test]
fn grok_bot_profile_signs_in_lists_tools_and_reads_in_scope() {
    run_on_engine_stack("named-client-grok-flow", || async {
        let served = Served::start().await;
        assert_discovery(&served).await;
        let signed_in = served.sign_in(GROK_BOT).await;
        assert_eq!(
            signed_in.protocol, None,
            "FIXTURE: Grok Bot sends no header"
        );
        signed_in.assert_serves_world_a(&served).await;
    });
}

/// Muse's sign-in on the same generic route, sending the header.
#[test]
fn muse_profile_signs_in_lists_tools_and_reads_in_scope() {
    run_on_engine_stack("named-client-muse-flow", || async {
        let served = Served::start().await;
        assert_discovery(&served).await;
        let signed_in = served.sign_in(MUSE).await;
        assert_eq!(signed_in.protocol, Some(PROTOCOL_VERSION));
        signed_in.assert_serves_world_a(&served).await;
    });
}

/// A client bound to world A reads world B's claim as nothing, by its id or
/// by a recall naming world B, and no answer carries world B's name or the
/// claim's text.
#[test]
fn named_client_read_outside_its_world_is_refused_without_the_world_name() {
    run_on_engine_stack("named-client-world-bound", || async {
        let served = Served::start().await;
        let signed_in = served.sign_in(GROK_BOT).await;
        let inside = signed_in.read_claim(&served, served.claim_a).await;
        assert_eq!(inside.output()["value"]["value"], CLAIM_A_TEXT);

        let by_id = signed_in.read_claim(&served, served.claim_b).await;
        assert!(
            by_id.output()["value"].is_null(),
            "world B's claim is not served: {}",
            by_id.body
        );
        let recall = signed_in
            .call(
                &served,
                "vault.recall",
                json!({
                    "query": "tidewater",
                    "effort": "light",
                    "scope": {"world_ref": served.world_b.to_hex()},
                }),
            )
            .await;
        if recall.body.get("error").is_none() {
            assert!(
                recall.output()["items"]
                    .as_array()
                    .is_none_or(Vec::is_empty),
                "a recall naming world B finds nothing: {}",
                recall.body
            );
        }
        for answer in [&by_id, &recall] {
            let text = answer.body.to_string();
            assert!(!text.contains(WORLD_B_NAME), "world B's name leaks: {text}");
            assert!(
                !text.contains(CLAIM_B_TEXT),
                "world B's claim leaks: {text}"
            );
        }
    });
}

/// At the propose tier a new claim lands as a proposal, not a claim, and a
/// rewrite in place, which would act at once, needs the full tier: the call
/// is refused and the owner's claim keeps its value.
#[test]
fn named_client_propose_lands_under_the_ceiling() {
    run_on_engine_stack("named-client-propose", || async {
        let served = Served::start().await;
        let signed_in = served.sign_in(GROK_BOT).await;
        let scope = serde_json::to_value(claim_scope(&served.vault, served.world_a))
            .expect("the claim scope as JSON");
        let spec = |id: Option<EntityId>, text: &str| {
            let mut spec = json!({
                "predicate": "profile.preference",
                "subject_ref": served.owner_id.to_hex(),
                "value": text,
                "confidence": 1.0,
                "source": "user_stated",
                "scope": scope.clone(),
            });
            if let Some(id) = id {
                spec["id"] = Value::String(id.to_hex());
            }
            spec
        };

        let proposed = signed_in
            .call(
                &served,
                "vault.claims.upsert",
                spec(None, "quiet desk lamp"),
            )
            .await;
        assert_eq!(
            proposed.output()["approval"],
            "proposed",
            "{}",
            proposed.body
        );

        let rewrite = signed_in
            .call(
                &served,
                "vault.claims.upsert",
                spec(Some(served.claim_a), "rewritten by the client"),
            )
            .await;
        assert_eq!(rewrite.body["error"]["code"], -32001, "{}", rewrite.body);
        assert!(
            rewrite.body.to_string().contains("mcp_auth_required"),
            "{}",
            rewrite.body
        );
        let kept = signed_in.read_claim(&served, served.claim_a).await;
        assert_eq!(kept.output()["value"]["value"], CLAIM_A_TEXT);
    });
}

/// A refresh rotates the pair and the new access token reads; revoking the
/// new refresh token ends the family: the access token answers 401
/// `invalid_token`, and neither refresh token refreshes again.
#[test]
fn named_client_refresh_rotates_and_revoke_ends_access() {
    run_on_engine_stack("named-client-refresh-revoke", || async {
        let served = Served::start().await;
        let first = served.sign_in(GROK_BOT).await;
        let renewed = served
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", first.refresh.as_str()),
                ("client_id", first.client_id.as_str()),
                ("resource", RESOURCE),
            ])
            .await;
        assert_eq!(renewed.status, 200, "the refresh answers: {}", renewed.body);
        let second = SignedIn {
            client_id: first.client_id.clone(),
            access: renewed.body["access_token"]
                .as_str()
                .expect("access")
                .to_owned(),
            refresh: renewed.body["refresh_token"]
                .as_str()
                .expect("refresh")
                .to_owned(),
            protocol: first.protocol,
        };
        assert_ne!(second.access, first.access, "a new access token");
        assert_ne!(second.refresh, first.refresh, "the refresh token rotated");
        let read = second.read_claim(&served, served.claim_a).await;
        assert_eq!(read.output()["value"]["value"], CLAIM_A_TEXT);

        let revoked = served
            .http
            .post(served.url("/oauth/revoke"))
            .form(&[
                ("token", second.refresh.as_str()),
                ("client_id", second.client_id.as_str()),
            ])
            .send()
            .await
            .expect("revoke");
        assert_eq!(revoked.status(), 200);
        let after = second.read_claim(&served, served.claim_a).await;
        assert_eq!(after.status, 401, "{}", after.body);
        assert!(
            after
                .challenge
                .as_deref()
                .is_some_and(|challenge| challenge.contains("invalid_token")),
            "{:?}",
            after.challenge
        );
        for spent in [&first.refresh, &second.refresh] {
            let refused = served
                .token(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", spent.as_str()),
                    ("client_id", second.client_id.as_str()),
                ])
                .await;
            assert_eq!(refused.status, 400, "{}", refused.body);
            assert_eq!(refused.body["error"], "invalid_grant");
        }
    });
}
