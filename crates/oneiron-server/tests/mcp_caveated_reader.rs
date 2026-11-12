#![cfg(oneiron_test_support)]
//! MCP-CAVEATED-READER (RETRIEVAL-04): a reader's `core:read` slip, narrowed
//! by its holder to one world, reaches the MCP gateway as itself.
//! The gateway records it by the paired rule over its verified (narrowed)
//! claims, held to its registered mint, and it reads only within its
//! caveat. A widened actor echo is refused, a shape the adapter cannot hold
//! stays refused, and once its mint is revoked the caveated slip is refused.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mcp_caveated_reader`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OCCURRED_AT: u64 = 1_769_947_200;
const READABLE_TEXT: &str = "caveated quartz readable";
const HIDDEN_TEXT: &str = "caveated quartz hidden";
const HIDDEN_WORLD_NAME: &str = "Caveated private partition";
const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// A slip and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    readable: EntityId,
    hidden: EntityId,
    hidden_world: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, owner_proof) = embedded_owner(&vault)?;
        let hidden_world = vault.create_world(&owner_proof, HIDDEN_WORLD_NAME, OCCURRED_AT)?;
        let readable =
            write_owner_claim(&vault, owner, &owner_proof, base_world_id(), READABLE_TEXT)?;
        let hidden = write_owner_claim(&vault, owner, &owner_proof, hidden_world, HIDDEN_TEXT)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-caveated-reader".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            readable,
            hidden,
            hidden_world,
            _dir: dir,
        })
    }

    /// A distinct person's `core:read` slip, minted under the vault's logged
    /// issuer as pairing mints one: the mint itself, uncaveated. The
    /// gateway records it at its first use (the paired fallback).
    fn mint_reader(&self) -> TestResult<Holder> {
        let person = EntityId::now();
        self.vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a distinct reader",
        )?;
        let key = SigningKey::from_bytes(&[0x61; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x61; 32];
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        let slip = self.vault.mint_capability_slip(&self.issuer, claims)?;
        assert!(slip.caveats.is_empty(), "a mint carries no caveat");
        Ok(Holder { slip, key })
    }

    /// `holder`'s slip narrowed by its own holder to `worlds`, as
    /// `self.credential.attenuate` narrows it: a new token, the same key.
    fn narrowed(holder: &Holder, worlds: &[EntityId]) -> TestResult<Holder> {
        let mut slip = holder.slip.clone();
        let mut ceiling = Scope::top();
        ceiling.worlds = ScopeAxis::Some(worlds.iter().map(|world| ScopeId(*world)).collect());
        slip.attenuate(
            SlipCaveat {
                scope: Some(ceiling),
                ..Default::default()
            },
            &holder.key,
        )?;
        Ok(Holder {
            slip,
            key: holder.key.clone(),
        })
    }

    /// One JSON-RPC request to the tool-first MCP endpoint, under `holder`'s
    /// slip and a fresh holder proof: the HTTP status and the reply.
    async fn rpc(
        &self,
        holder: &Holder,
        id: u64,
        method: &str,
        params: Value,
    ) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = holder
            .key
            .sign(&holder.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", holder.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("mcp-protocol-version", MCP_PROTOCOL_VERSION)
            .body(Body::from(
                json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
                    .to_string(),
            ))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let reply = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, reply))
    }

    async fn initialize(&self, holder: &Holder, id: u64) -> TestResult<(u16, Value)> {
        self.rpc(
            holder,
            id,
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-caveated-reader", "version": "1" },
            }),
        )
        .await
    }

    /// `vault.get` of `entity` as a tool call, with `actor` echoed when given.
    async fn get(
        &self,
        holder: &Holder,
        id: u64,
        version: &Value,
        entity: EntityId,
        actor: Option<&Value>,
    ) -> TestResult<(u16, Value)> {
        let mut arguments = json!({
            "schema_version": version,
            "consent": {
                "policy_ref": "policy:agent-session",
                "purpose": "read the entity within the credential scope",
            },
            "arguments": { "spec": { "entity_ref": entity.to_hex() } },
        });
        if let Some(actor) = actor {
            arguments["actor"] = actor.clone();
        }
        self.rpc(
            holder,
            id,
            "tools/call",
            json!({ "name": "vault.get", "arguments": arguments }),
        )
        .await
    }
}

fn write_owner_claim(
    vault: &Vault,
    owner: EntityId,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    value: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(owner_proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: world.to_hex(),
                scope_facet_id: vault.default_facet()?.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(OCCURRED_AT),
            learned_at: Some(OCCURRED_AT),
            salience: None,
        })?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The JSON-RPC error kind of `reply`, if it is an error.
fn error_kind(reply: &Value) -> Option<&str> {
    reply["error"]["data"]["error_code"].as_str()
}

/// Runs `test` as the server's binary runs its app: on a multi-thread runtime
/// whose threads have the engine's stack, driven from a thread that has it
/// too. The generated dispatch's poll frame does not fit a test thread's
/// default stack (`ENGINE_THREAD_STACK_BYTES`).
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[test]
fn a_caveated_core_read_slip_reaches_mcp_and_reads_only_within_its_caveat() -> TestResult {
    on_engine_stack(caveated_slip_and_the_mcp_gateway)
}

async fn caveated_slip_and_the_mcp_gateway() -> TestResult {
    let fixture = Fixture::new()?;
    let base_world = base_world_id().to_hex();
    let hidden_world = fixture.hidden_world.to_hex();

    // The mint itself reaches the gateway, which records it (the control).
    let mint = fixture.mint_reader()?;
    let person = mint.slip.claims.holder_ref.clone();
    let (status, reply) = fixture.initialize(&mint, 1).await?;
    assert_eq!(status, 200, "the mint initializes: {reply}");
    assert_eq!(
        reply["result"]["actor"]["actor_ref"], person,
        "the mint initializes as its holder: {reply}"
    );

    // Its holder narrows it to the base world. The caveated slip is a new
    // token the gateway has never seen; it is admitted as itself.
    let reader = Fixture::narrowed(&mint, &[base_world_id()])?;
    assert_ne!(reader.slip.to_token()?, mint.slip.to_token()?);
    let (status, reply) = fixture.initialize(&reader, 2).await?;
    assert_eq!(status, 200, "the caveated slip initializes: {reply}");
    assert!(
        reply.get("error").is_none(),
        "the gateway admits the holder-caveated core:read slip: {reply}"
    );
    let actor = reply["result"]["actor"].clone();
    assert_eq!(actor["actor_ref"], person, "{reply}");
    assert_eq!(
        actor["scope"]["world_ref"], base_world,
        "the caveated slip is registered at its caveat's world: {reply}"
    );

    let (status, listed) = fixture.rpc(&reader, 3, "tools/list", json!({})).await?;
    assert_eq!(status, 200, "{listed}");
    let version = listed["result"]["tools"]
        .as_array()
        .ok_or("tools/list lists tools")?
        .iter()
        .find(|tool| tool["name"] == "vault.get")
        .map(|tool| tool["inputSchema"]["properties"]["schema_version"]["const"].clone())
        .ok_or("the tool-first endpoint lists vault.get")?;

    // Within its caveat: the base-world row reads; the hidden world's row is
    // absent, and nothing of it is named.
    let (status, answer) = fixture
        .get(&reader, 4, &version, fixture.readable, None)
        .await?;
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        answer["result"]["structuredContent"]["output"]["value"]["id_hex"],
        fixture.readable.to_hex(),
        "the caveated slip reads its base-world row over MCP: {answer}"
    );
    let (status, answer) = fixture
        .get(&reader, 5, &version, fixture.hidden, None)
        .await?;
    assert_eq!(status, 200, "{answer}");
    assert!(
        answer["result"]["structuredContent"]["output"]["value"].is_null(),
        "the hidden world's row is absent to the caveated slip: {answer}"
    );
    let text = answer.to_string();
    for secret in [HIDDEN_TEXT, HIDDEN_WORLD_NAME, hidden_world.as_str()] {
        assert!(!text.contains(secret), "the reply names {secret}: {text}");
    }

    // A widened actor echo is refused before any read: another world, and
    // every world.
    for (id, world) in [(6, json!(hidden_world)), (7, Value::Null)] {
        let mut widened = actor.clone();
        widened["scope"]["world_ref"] = world;
        let (_, answer) = fixture
            .get(&reader, id, &version, fixture.readable, Some(&widened))
            .await?;
        assert_eq!(
            error_kind(&answer),
            Some("mcp_actor_mismatch"),
            "a widened actor echo is refused: {answer}"
        );
        assert!(!answer.to_string().contains(READABLE_TEXT), "{answer}");
    }

    // A caveat the adapter cannot hold (two worlds) stays refused.
    let two_worlds = Fixture::narrowed(&mint, &[base_world_id(), fixture.hidden_world])?;
    let (_, reply) = fixture.initialize(&two_worlds, 8).await?;
    assert_eq!(
        error_kind(&reply),
        Some("mcp_credential_unknown"),
        "a two-world caveated slip is not registered: {reply}"
    );

    // The grant is live at each use: once the mint is revoked, its caveated
    // copy is refused at the door.
    fixture
        .vault
        .revoke_capability_slip(&fixture.issuer, mint.slip.claims.slip_id)?;
    let (status, reply) = fixture.initialize(&reader, 9).await?;
    assert_eq!(
        status, 401,
        "a caveated slip whose mint is revoked is refused: {reply}"
    );
    Ok(())
}
