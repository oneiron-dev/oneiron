//! AGENT-CREDENTIAL-VERB-ALLOWLIST (lead 24 Nov 21:4x): a credential the
//! owner minted with a verb list calls every read verb, the verbs its list
//! names and the verbs a live Grant for its holder names, and nothing else,
//! over every transport that runs a verb: the HTTP facade, MCP `tools/call`
//! and the REST routes that run a verb's door themselves. A refused verb
//! stays refused on each of them; the owner's Grant naming it admits it, and
//! its revoke refuses it again. A credential with no list is unchanged.
//!
//! The test reads the list's own refusal sentence
//! ([`oneiron::authority::CREDENTIAL_VERB_NOT_LISTED`]): an admitted call may
//! still meet the verb's own checks after the list, which this test does not
//! judge.
//!
//! Run with: `cargo test --locked -p oneiron-server --all-features --test
//! credential_verb_allowlist`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::SigningKey;
use engine_stack::on_engine_stack;
use oneiron::authority::{
    ActSurface, CREDENTIAL_VERB_NOT_LISTED, CapabilitySlip, HostSlipIssuer, MachineRole,
    holder_proof,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// The one write verb the listed credential names.
const LISTED_WRITE: &str = "vault.notes.create";
/// A write verb its list leaves out, served by the facade, by MCP and by the
/// REST route `/v1/core/batch`.
const UNLISTED_WRITE: &str = "vault.batch";
/// A read verb (act class `read`): every list admits it.
const READ_VERB: &str = "vault.claims.list";
/// A Read-scope row whose act is no read (a model call): a list admits it
/// only by name.
const READ_SCOPE_MODEL_CALL: &str = "ai.anonymous_chat";

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(0x31);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6C; 32])
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    owner_proof: AuthenticatedOwner,
    agent: EntityId,
    /// The agent's credential with the verb list `[LISTED_WRITE]`.
    listed: CapabilitySlip,
    /// The same agent's credential with no list, as every slip minted
    /// before the list.
    unlisted: CapabilitySlip,
}

/// A rooted vault behind the server, one good-standing agent definition
/// with the owner's `read` and `write` Grant, and two credentials of that
/// agent: one with a verb list, one without.
fn setup() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let server = Arc::new(SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("credential-verb-allowlist".into()),
            ..Default::default()
        },
    )?);
    let issuer = vault.load_host_slip_issuer()?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let agent = EntityId::now();
    create_agent_definition_as(
        &vault,
        &owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "test.credential.verbs",
                "desc": "credential verb allowlist test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    grant(&vault, &owner_proof, agent, ["read", "write"])?;
    let listed = mint_agent_slip(
        &vault,
        &issuer,
        &root,
        agent,
        Some(BTreeSet::from([LISTED_WRITE.to_owned()])),
    )?;
    let unlisted = mint_agent_slip(&vault, &issuer, &root, agent, None)?;
    Ok(Fixture {
        _dir: dir,
        app: build_app(server),
        vault,
        owner_proof,
        agent,
        listed,
        unlisted,
    })
}

/// The owner's Grant to `agent` listing `verbs`: its id.
fn grant<const N: usize>(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    agent: EntityId,
    verbs: [&str; N],
) -> TestResult<EntityId> {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )?;
    Ok(minted.grant.grant_ref)
}

/// An agent credential the host mints `agent`, holding `read` and `write`,
/// with `verb_allowlist`.
fn mint_agent_slip(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    agent: EntityId,
    verb_allowlist: Option<BTreeSet<String>>,
) -> TestResult<CapabilitySlip> {
    let mut claims = root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    claims.verb_allowlist = verb_allowlist;
    Ok(vault.mint_capability_slip(issuer, claims)?)
}

impl Fixture {
    fn headers(&self, slip: &CapabilitySlip) -> TestResult<Vec<(&'static str, String)>> {
        let binding = holder_proof(slip, &holder_key(), self.vault.now_recorded_at())?;
        Ok(vec![
            ("authorization", format!("Bearer {}", slip.to_token()?)),
            ("x-oneiron-binding", binding.to_string()),
        ])
    }

    /// One POST of `body` to `path` under `slip`: the status and the reply.
    async fn post(
        &self,
        slip: &CapabilitySlip,
        path: &str,
        body: Value,
    ) -> TestResult<(u16, Value)> {
        let mut request = Request::post(path).header("content-type", "application/json");
        for (key, value) in self.headers(slip)? {
            request = request.header(key, value);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }

    /// `verb` on the HTTP facade.
    async fn facade(&self, slip: &CapabilitySlip, verb: &str) -> TestResult<(u16, Value)> {
        self.post(slip, &format!("/v1/core/facade/{verb}"), json!({}))
            .await
    }

    /// `verb` as one MCP `tools/call`.
    async fn mcp(&self, slip: &CapabilitySlip, verb: &str) -> TestResult<(u16, Value)> {
        let mut request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION);
        for (key, value) in self.headers(slip)? {
            request = request.header(key, value);
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": verb, "arguments": {} },
        });
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(body.to_string()))?)
            .await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }
}

/// Whether `reply` is the verb list's own refusal.
fn not_listed(reply: &Value) -> bool {
    reply.to_string().contains(CREDENTIAL_VERB_NOT_LISTED)
}

#[test]
fn a_listed_credential_calls_only_its_verbs_on_every_transport() -> TestResult {
    on_engine_stack(only_its_verbs)
}

async fn only_its_verbs() -> TestResult {
    let fixture = setup()?;
    let listed = &fixture.listed;

    // HTTP facade.
    let (status, reply) = fixture.facade(listed, UNLISTED_WRITE).await?;
    assert!(
        not_listed(&reply),
        "facade {UNLISTED_WRITE}: {status} {reply}"
    );
    assert_eq!(status, 403, "facade {UNLISTED_WRITE}: {reply}");
    let (status, reply) = fixture.facade(listed, READ_SCOPE_MODEL_CALL).await?;
    assert!(
        not_listed(&reply),
        "facade {READ_SCOPE_MODEL_CALL}: {status} {reply}"
    );
    let (status, reply) = fixture.facade(listed, LISTED_WRITE).await?;
    assert!(
        !not_listed(&reply),
        "facade {LISTED_WRITE}: {status} {reply}"
    );
    let (status, reply) = fixture.facade(listed, READ_VERB).await?;
    assert!(!not_listed(&reply), "facade {READ_VERB}: {status} {reply}");

    // MCP tools/call.
    let (status, reply) = fixture.mcp(listed, UNLISTED_WRITE).await?;
    assert!(not_listed(&reply), "mcp {UNLISTED_WRITE}: {status} {reply}");
    assert!(
        reply.get("result").is_none(),
        "mcp {UNLISTED_WRITE}: {reply}"
    );
    let (status, reply) = fixture.mcp(listed, LISTED_WRITE).await?;
    assert!(!not_listed(&reply), "mcp {LISTED_WRITE}: {status} {reply}");
    let (status, reply) = fixture.mcp(listed, READ_VERB).await?;
    assert!(!not_listed(&reply), "mcp {READ_VERB}: {status} {reply}");

    // The REST routes that run a verb's door themselves.
    let (status, reply) = fixture
        .post(listed, "/v1/core/batch", json!({"entities": []}))
        .await?;
    assert!(not_listed(&reply), "/v1/core/batch: {status} {reply}");
    assert_eq!(status, 403, "/v1/core/batch: {reply}");
    let (status, reply) = fixture
        .post(listed, "/v1/core/memory/verbs/remember", json!({}))
        .await?;
    assert!(not_listed(&reply), "memory remember: {status} {reply}");
    let (status, reply) = fixture
        .post(listed, "/v1/ai/anonymous-chat", json!({"messages": []}))
        .await?;
    assert!(not_listed(&reply), "anonymous chat: {status} {reply}");
    Ok(())
}

#[test]
fn the_owners_grant_widens_a_list_until_it_is_revoked() -> TestResult {
    on_engine_stack(grant_widens_until_revoked)
}

async fn grant_widens_until_revoked() -> TestResult {
    let fixture = setup()?;
    let listed = &fixture.listed;
    let (_, reply) = fixture.facade(listed, UNLISTED_WRITE).await?;
    assert!(not_listed(&reply), "before the Grant: {reply}");

    // The owner names the verb in a Grant for the agent: every transport
    // admits it past the list now.
    let widened = grant(
        &fixture.vault,
        &fixture.owner_proof,
        fixture.agent,
        ["read", UNLISTED_WRITE],
    )?;
    let (status, reply) = fixture.facade(listed, UNLISTED_WRITE).await?;
    assert!(
        !not_listed(&reply),
        "facade under the Grant: {status} {reply}"
    );
    let (status, reply) = fixture.mcp(listed, UNLISTED_WRITE).await?;
    assert!(!not_listed(&reply), "mcp under the Grant: {status} {reply}");
    let (status, reply) = fixture
        .post(listed, "/v1/core/batch", json!({"entities": []}))
        .await?;
    assert!(
        !not_listed(&reply),
        "/v1/core/batch under the Grant: {status} {reply}"
    );

    // Its revoke refuses the verb again, at the next call.
    revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref: widened,
            seen: None,
        },
    )?;
    let (status, reply) = fixture.facade(listed, UNLISTED_WRITE).await?;
    assert!(
        not_listed(&reply),
        "facade after the revoke: {status} {reply}"
    );
    let (status, reply) = fixture.mcp(listed, UNLISTED_WRITE).await?;
    assert!(not_listed(&reply), "mcp after the revoke: {status} {reply}");
    Ok(())
}

#[test]
fn a_credential_with_no_list_calls_as_before() -> TestResult {
    on_engine_stack(no_list_as_before)
}

async fn no_list_as_before() -> TestResult {
    let fixture = setup()?;
    let unlisted = &fixture.unlisted;
    for verb in [
        UNLISTED_WRITE,
        LISTED_WRITE,
        READ_VERB,
        READ_SCOPE_MODEL_CALL,
    ] {
        let (status, reply) = fixture.facade(unlisted, verb).await?;
        assert!(!not_listed(&reply), "facade {verb}: {status} {reply}");
        let (status, reply) = fixture.mcp(unlisted, verb).await?;
        assert!(!not_listed(&reply), "mcp {verb}: {status} {reply}");
    }
    let (status, reply) = fixture
        .post(unlisted, "/v1/core/batch", json!({"entities": []}))
        .await?;
    assert!(!not_listed(&reply), "/v1/core/batch: {status} {reply}");
    Ok(())
}
