#![cfg(oneiron_test_support)]
//! RECALL-SESSION-PROJECT PR 2 over MCP (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov:
//! Q1 = A, the session project is the default of a read that names none, never a wall; Q2 =
//! A): a `tools/call` whose `_meta["oneiron/workspace"]` names a folder bound to one project
//! reads only that project's claims through `vault.claims.list`, the recall A/B's leak; one
//! that names its projects (`project_refs`) reads those; a folder with no project bound reads
//! no claim and the receipt says `no_project_bound`; a call that names no folder reads as
//! before.
//!
//! Red on the base: the `workspace.project` key and the session default do not exist there, so
//! the fixture's binding is refused and the file's helpers do not build.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test mcp_session_project_reads`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WORKSPACE_PROJECT_KEY;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::room_facet_set::create_owner_project;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const MCP_PATH: &str = "/mcp/tool-first";
const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
/// The bound folder's workspace id.
const BOUND_ID: &str = "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// A folder nobody bound.
const UNBOUND_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A reader's slip and the key its holder proves it with.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// A served vault whose owner made `alpha` and `beta` under the root, with one claim in each,
/// and bound `BOUND_ID` to `alpha`; and a distinct person's `core:read` slip.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    reader: Holder,
    beta: EntityId,
    in_alpha: EntityId,
    in_beta: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let owner = vault.ensure_embedded_owner_actor()?;
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
        let proof =
            vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
        let root = vault.root_project()?;
        vault.sign_owner_project(&proof, &vault.owner_project_signer(&issuer)?, root)?;
        let facet = EntityId::now();
        vault.put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({ "name": "mcp session project facet" }))?,
        )?;
        let alpha = project_under(&vault, &issuer, &proof, owner, root, facet)?;
        let beta = project_under(&vault, &issuer, &proof, owner, root, facet)?;
        let in_alpha = write_claim(&vault, owner, &proof, facet, alpha, "profile.hobby")?;
        let in_beta = write_claim(&vault, owner, &proof, facet, beta, "profile.occupation")?;
        let mut binding = SetSetting::vault_value(
            WORKSPACE_PROJECT_KEY,
            json!({ "project": alpha.to_hex(), "label": "alpha" }),
        );
        binding.item = Some(BOUND_ID.to_owned());
        let outcome = vault.set_setting(SettingCaller::Owner(&proof), binding)?;
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "FIXTURE: the owner binds the folder: {outcome:?}"
        );
        let reader = mint_reader(&vault, &issuer)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-session-project-reads".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            reader,
            beta,
            in_alpha,
            in_beta,
            _dir: dir,
        })
    }

    /// One JSON-RPC request to the tool-first endpoint under the reader's slip and a fresh
    /// holder proof: the HTTP status and the reply.
    async fn rpc(&self, id: u64, method: &str, params: Value) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .reader
            .key
            .sign(&self.reader.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": oneiron_hex::encode(&signature),
        });
        let request = Request::post(MCP_PATH)
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!("Bearer {}", self.reader.slip.to_token()?),
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

    /// `tool` called with `input` under its one argument field, naming the folder `workspace`
    /// in `_meta` when given.
    async fn call(
        &self,
        id: u64,
        tools: &Value,
        tool: &str,
        input: Value,
        workspace: Option<&str>,
    ) -> TestResult<Value> {
        let schema = tools
            .as_array()
            .ok_or("tools/list lists tools")?
            .iter()
            .find(|listed| listed["name"] == tool)
            .map(|listed| listed["inputSchema"].clone())
            .ok_or_else(|| format!("the tool-first endpoint lists {tool}"))?;
        let field = schema["properties"]["arguments"]["properties"]
            .as_object()
            .and_then(|fields| fields.keys().next().cloned())
            .ok_or_else(|| format!("{tool} names its argument field"))?;
        let mut params = json!({
            "name": tool,
            "arguments": {
                "schema_version": schema["properties"]["schema_version"]["const"],
                "consent": {
                    "policy_ref": "policy:agent-session",
                    "purpose": "read the session's project",
                },
                "arguments": { field: input },
            },
        });
        if let Some(workspace) = workspace {
            params["_meta"] = json!({ "oneiron/workspace": { "ids": [workspace] } });
        }
        let (status, reply) = self.rpc(id, "tools/call", params).await?;
        assert_eq!(status, 200, "{reply}");
        assert!(reply.get("error").is_none(), "{tool} answers: {reply}");
        Ok(reply)
    }
}

fn project_under(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    proof: &AuthenticatedOwner,
    owner: EntityId,
    parent: EntityId,
    facet: EntityId,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(parent), vault.root_project()?, owner)?;
    record.slice.facet = Some(facet);
    record.depth_remaining = 1;
    create_owner_project(
        vault,
        issuer,
        proof,
        &vault.owner_project_signer(issuer)?,
        owner,
        id,
        &record,
    )?;
    Ok(id)
}

fn write_claim(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    facet: EntityId,
    project: EntityId,
    predicate: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(proof)
        .claim_upsert_scoped(&ScopedClaimInput {
            id: Some(id.to_hex()),
            predicate: predicate.to_owned(),
            subject_ref: owner.to_hex(),
            value: json!("session project"),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: facet.to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: project.to_hex(),
            }
            .into(),
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: Some(1),
            learned_at: Some(1),
            salience: None,
        })
        .map_err(|error| format!("FIXTURE: the owner's claim: {error:?}"))?;
    Ok(id)
}

/// A distinct person's `core:read` slip, minted under the vault's issuer as pairing mints one.
fn mint_reader(vault: &Vault, issuer: &HostSlipIssuer) -> TestResult<Holder> {
    let person = EntityId::now();
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a session reader",
    )?;
    let key = SigningKey::from_bytes(&[0x62; 32]);
    let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
    claims.parent_id = None;
    claims.slip_id = [0x62; 32];
    claims.holder_ref = person.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    Ok(Holder {
        slip: vault.mint_capability_slip(issuer, claims)?,
        key,
    })
}

/// Whether `reply` names `claim`.
fn names(reply: &Value, claim: EntityId) -> bool {
    reply.to_string().contains(&claim.to_hex())
}

#[test]
fn an_attached_sessions_reads_default_to_its_folders_project() -> TestResult {
    on_engine_stack(session_reads)
}

async fn session_reads() -> TestResult {
    let fixture = Fixture::new()?;
    let (status, reply) = fixture
        .rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-session-project-reads", "version": "1" },
            }),
        )
        .await?;
    assert_eq!(status, 200, "{reply}");
    let (status, listed) = fixture.rpc(2, "tools/list", json!({})).await?;
    assert_eq!(status, 200, "{listed}");
    let tools = listed["result"]["tools"].clone();
    let list = json!({ "limit": 100 });

    // No folder named: every project, as before.
    let reply = fixture
        .call(3, &tools, "vault.claims.list", list.clone(), None)
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && names(&reply, fixture.in_beta),
        "{reply}"
    );

    // The bound folder: alpha's claim alone, through the A/B's leak.
    let reply = fixture
        .call(4, &tools, "vault.claims.list", list.clone(), Some(BOUND_ID))
        .await?;
    assert!(
        names(&reply, fixture.in_alpha),
        "alpha's claim is read: {reply}"
    );
    assert!(
        !names(&reply, fixture.in_beta),
        "beta's claim is not read: {reply}"
    );
    assert!(reply.to_string().contains("session_project"), "{reply}");

    // A read that names its projects reads those, folder or not (Q1 = A).
    let reply = fixture
        .call(
            5,
            &tools,
            "vault.claims.list_filtered",
            json!({ "limit": 100, "project_refs": [fixture.beta.to_hex()] }),
            Some(BOUND_ID),
        )
        .await?;
    assert!(
        names(&reply, fixture.in_beta),
        "the named project is read: {reply}"
    );
    assert!(!names(&reply, fixture.in_alpha), "{reply}");

    // The filtered list that names no project reads the session's.
    let reply = fixture
        .call(
            6,
            &tools,
            "vault.claims.list_filtered",
            list.clone(),
            Some(BOUND_ID),
        )
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "{reply}"
    );

    // A folder with no project bound: no claim, and the receipt says why (Q2 = A).
    let reply = fixture
        .call(7, &tools, "vault.claims.list", list, Some(UNBOUND_ID))
        .await?;
    assert!(
        !names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "{reply}"
    );
    assert!(reply.to_string().contains("no_project_bound"), "{reply}");
    Ok(())
}
