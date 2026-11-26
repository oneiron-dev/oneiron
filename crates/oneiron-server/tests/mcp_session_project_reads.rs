#![cfg(oneiron_test_support)]
//! RECALL-SESSION-PROJECT PR 2 over MCP (Engine ANSWER RECALL-SESSION-PROJECT-INTENT, 26 Nov:
//! Q1 = A, the session project is the default of a read that names none, never a wall; Q2 =
//! A): a `tools/call` whose `_meta["oneiron/workspace"]` names a folder bound to one project
//! reads only that project's claims through `vault.claims.list`, the recall A/B's leak; one
//! that names its projects (`project_refs`) reads those; a folder with no project bound reads
//! no claim and the receipt says `no_project_bound`; a call that names no folder reads as
//! before. The folder comes from the client (Engine NOTE 22:5x), so a session that names
//! another bound folder reads nothing its credential could not read anyway. And a session's
//! `vault.claims.upsert` that names no project lands in its folder's project (PR 3, row
//! START-RECALL-WRITES-ROOT-PROJECT); an unbound folder's, and a call naming no folder, keep
//! the root's default project (Q2 = A).
//!
//! Red on the base: the `workspace.project` key, the bind method and the session default do
//! not exist there, so this file does not build.
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
use oneiron::authority::{
    ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::registry::ENTITY_TYPE_FACET;
use oneiron::session_project::WorkspaceBindRequest;
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
/// The digest of the folder bound to `alpha`.
const BOUND_DIGEST: &str =
    "blake3:a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f";
/// The digest of another folder, bound to `beta`.
const BETA_DIGEST: &str = "blake3:b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0";
/// A folder nobody bound.
const UNBOUND_DIGEST: &str =
    "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A person's slip, the key its holder proves it with, and the person.
struct Holder {
    slip: CapabilitySlip,
    key: SigningKey,
    person: EntityId,
}

/// A served vault whose owner made `alpha` and `beta` under the root, each on a facet of its
/// own, with one claim in each, and bound `BOUND_DIGEST` to `alpha` and `BETA_DIGEST` to
/// `beta`; a distinct person's `core:read` slip; another's narrowed to alpha's facet; and a
/// third person's `core:read` and `core:write` slip.
struct Fixture {
    app: Router,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    reader: Holder,
    alpha_reader: Holder,
    writer: Holder,
    alpha: EntityId,
    alpha_facet: EntityId,
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
        let alpha_facet = facet_named(&vault, "alpha facet")?;
        let beta_facet = facet_named(&vault, "beta facet")?;
        let alpha = project_under(&vault, &issuer, &proof, owner, root, alpha_facet)?;
        let beta = project_under(&vault, &issuer, &proof, owner, root, beta_facet)?;
        let in_alpha = write_claim(&vault, owner, &proof, alpha_facet, alpha, "profile.hobby")?;
        let in_beta = write_claim(
            &vault,
            owner,
            &proof,
            beta_facet,
            beta,
            "profile.occupation",
        )?;
        for (folder_digest, project, label) in
            [(BOUND_DIGEST, alpha, "alpha"), (BETA_DIGEST, beta, "beta")]
        {
            let binding = vault.bind_workspace_as_owner(
                &proof,
                Some(ActSurface::ThisInstall),
                WorkspaceBindRequest {
                    folder_digest: folder_digest.to_owned(),
                    project,
                    label: Some(label.to_owned()),
                },
            )?;
            assert_eq!(
                binding.project,
                Some(project),
                "FIXTURE: the owner binds {label}'s folder"
            );
        }
        let reader = mint_holder(&vault, &issuer, 0x62, &["core:read"], None)?;
        let alpha_reader = mint_holder(&vault, &issuer, 0x63, &["core:read"], Some(alpha_facet))?;
        let writer = mint_holder(&vault, &issuer, 0x64, &["core:read", "core:write"], None)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("mcp-session-project-reads".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(Arc::clone(&server)),
            server,
            vault,
            reader,
            alpha_reader,
            writer,
            alpha,
            alpha_facet,
            beta,
            in_alpha,
            in_beta,
            _dir: dir,
        })
    }

    /// One JSON-RPC request to the tool-first endpoint under `holder`'s slip and a fresh
    /// holder proof: the HTTP status and the reply.
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
            "signature": oneiron_hex::encode(&signature),
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

    /// `holder`'s session opened: `initialize`, then the tools `tools/list` lists.
    async fn tools(&self, holder: &Holder) -> TestResult<Value> {
        let (status, reply) = self
            .rpc(
                holder,
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
        let (status, listed) = self.rpc(holder, 2, "tools/list", json!({})).await?;
        assert_eq!(status, 200, "{listed}");
        Ok(listed["result"]["tools"].clone())
    }

    /// `tool` called by `holder` with `input` under its one argument field, naming the folder
    /// `workspace` (its digest) in `_meta` when given.
    async fn call(
        &self,
        holder: &Holder,
        id: u64,
        tools: &Value,
        tool: &str,
        input: Value,
        workspace: Option<&str>,
    ) -> TestResult<Value> {
        let params = tool_call_params(tools, tool, input, workspace)?;
        let (status, reply) = self.rpc(holder, id, "tools/call", params).await?;
        assert_eq!(status, 200, "{reply}");
        assert!(reply.get("error").is_none(), "{tool} answers: {reply}");
        Ok(reply)
    }
}

/// The schema-versioned arguments for a tool call, before it is sent.
fn tool_call_params(
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
        params["_meta"] = json!({ "oneiron/workspace": { "digests": [workspace] } });
    }
    Ok(params)
}

fn facet_named(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let facet = EntityId::now();
    vault.put_entity(
        &facet,
        ENTITY_TYPE_FACET,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&json!({ "name": name }))?,
    )?;
    Ok(facet)
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

/// A distinct person's slip for `verbs`, minted under the vault's issuer as pairing mints one,
/// with slip id and key from `seed`, and narrowed to `facet` when given.
fn mint_holder(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    seed: u8,
    verbs: &[&str],
    facet: Option<EntityId>,
) -> TestResult<Holder> {
    let person = EntityId::now();
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a session reader",
    )?;
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = vault.ensure_host_root_slip(issuer)?.claims;
    claims.parent_id = None;
    claims.slip_id = [seed; 32];
    claims.holder_ref = person.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.scope = Scope::top();
    claims.scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    if let Some(facet) = facet {
        claims.scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
    }
    Ok(Holder {
        slip: vault.mint_capability_slip(issuer, claims)?,
        key,
        person,
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
    let reader = &fixture.reader;
    let tools = fixture.tools(reader).await?;
    let list = json!({ "limit": 100 });

    // No folder named: every project, as before.
    let reply = fixture
        .call(reader, 3, &tools, "vault.claims.list", list.clone(), None)
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && names(&reply, fixture.in_beta),
        "{reply}"
    );

    // The bound folder: alpha's claim alone, through the A/B's leak.
    let reply = fixture
        .call(
            reader,
            4,
            &tools,
            "vault.claims.list",
            list.clone(),
            Some(BOUND_DIGEST),
        )
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
            reader,
            5,
            &tools,
            "vault.claims.list_filtered",
            json!({ "limit": 100, "project_refs": [fixture.beta.to_hex()] }),
            Some(BOUND_DIGEST),
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
            reader,
            6,
            &tools,
            "vault.claims.list_filtered",
            list.clone(),
            Some(BOUND_DIGEST),
        )
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "{reply}"
    );

    // A folder with no project bound: no claim, and the receipt says why (Q2 = A).
    let reply = fixture
        .call(
            reader,
            7,
            &tools,
            "vault.claims.list",
            list,
            Some(UNBOUND_DIGEST),
        )
        .await?;
    assert!(
        !names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "{reply}"
    );
    assert!(reply.to_string().contains("no_project_bound"), "{reply}");
    Ok(())
}

#[test]
fn a_session_naming_another_folder_reads_nothing_its_credential_could_not() -> TestResult {
    on_engine_stack(another_folder)
}

/// The folder a call names comes from the client, so a session may name a folder it does not
/// run in, here the one bound to `beta`. That only moves its default: a credential narrowed to
/// alpha's facet still reads no beta claim, by default or by naming beta.
async fn another_folder() -> TestResult {
    let fixture = Fixture::new()?;
    let reader = &fixture.alpha_reader;
    let tools = fixture.tools(reader).await?;
    let list = json!({ "limit": 100 });

    // No folder named: the credential's own ceiling, alpha's claim alone.
    let reply = fixture
        .call(reader, 3, &tools, "vault.claims.list", list.clone(), None)
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "the credential reads alpha's facet alone: {reply}"
    );

    // Its own folder: alpha's claim.
    let reply = fixture
        .call(
            reader,
            4,
            &tools,
            "vault.claims.list",
            list.clone(),
            Some(BOUND_DIGEST),
        )
        .await?;
    assert!(
        names(&reply, fixture.in_alpha) && !names(&reply, fixture.in_beta),
        "{reply}"
    );

    // Another folder, the one bound to beta: the default moves to beta, and the credential
    // reads no beta claim, so the read reads nothing.
    let reply = fixture
        .call(
            reader,
            5,
            &tools,
            "vault.claims.list",
            list.clone(),
            Some(BETA_DIGEST),
        )
        .await?;
    assert!(
        !names(&reply, fixture.in_beta),
        "naming beta's folder reads no claim past the credential: {reply}"
    );
    assert!(
        !names(&reply, fixture.in_alpha),
        "the default is beta's, so alpha's claim is not read either: {reply}"
    );

    // Naming beta outright reads no more.
    let reply = fixture
        .call(
            reader,
            6,
            &tools,
            "vault.claims.list_filtered",
            json!({ "limit": 100, "project_refs": [fixture.beta.to_hex()] }),
            Some(BETA_DIGEST),
        )
        .await?;
    assert!(
        !names(&reply, fixture.in_beta),
        "naming beta reads no claim past the credential: {reply}"
    );
    Ok(())
}

#[test]
fn an_attached_sessions_write_that_names_no_project_lands_in_its_folders_project() -> TestResult {
    on_engine_stack(session_write)
}

/// One `vault.claims.upsert` that names no project from the bound folder, one from a folder
/// nobody bound, and one naming no folder: where each claim is stored.
async fn session_write() -> TestResult {
    let fixture = Fixture::new()?;
    let writer = &fixture.writer;
    let tools = fixture.tools(writer).await?;
    let mut stored = Vec::new();
    for (id, folder) in [
        (3, Some(BOUND_DIGEST)),
        (4, Some(UNBOUND_DIGEST)),
        (5, None),
    ] {
        let claim = EntityId::now();
        let reply = fixture
            .call(
                writer,
                id,
                &tools,
                "vault.claims.upsert",
                json!({
                    "id": claim.to_hex(),
                    "predicate": "profile.note",
                    "subject_ref": writer.person.to_hex(),
                    "value": "a session write",
                    "confidence": 1.0,
                    "source": "user_stated",
                    "scope": { "scope_facet_id": fixture.alpha_facet.to_hex() },
                }),
                folder,
            )
            .await?;
        let body = fixture
            .vault
            .get_claim(&claim)?
            .ok_or_else(|| format!("the claim is stored: {reply}"))?;
        stored.push(body.scope_project);
    }
    assert_eq!(
        stored[0], fixture.alpha,
        "the bound folder's write lands in its project"
    );
    assert_eq!(
        stored[1],
        default_project_id(),
        "an unbound folder's write keeps the root's default project"
    );
    assert_eq!(
        stored[2],
        default_project_id(),
        "a call that names no folder writes as before"
    );
    Ok(())
}

#[cfg(feature = "code-sandbox-wasmtime")]
#[test]
fn an_approved_mcp_hook_ask_resumes_the_write_in_its_original_project() -> TestResult {
    on_engine_stack(approved_session_write)
}

#[cfg(feature = "code-sandbox-wasmtime")]
async fn approved_session_write() -> TestResult {
    use oneiron::skill_hub::HubFile;
    use oneiron::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord};
    use oneiron_server::test_doors::mcp_code_mode_verbs::install_verb_ask_resume;

    let fixture = Fixture::new()?;
    let vault = &fixture.vault;
    vault
        .install_hook_runtime(Arc::new(SessionWriteAsk::default()))
        .map_err(|error| format!("install the test hook runtime: {error}"))?;
    install_verb_ask_resume(&fixture.server);
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let disposition = vault.put_pack(
        &proof,
        vec![
            HubFile::new(
                "PACK.md",
                "---\nname: example.sessionwrite\ndescription: Ask before a session writes.\nversion: 1.0.0\nkind: capability\nhooks: [\"ask-before-write\"]\n---\nAsk before a session writes.\n",
            ),
            HubFile::new(
                "hooks/ask-before-write/HOOK.md",
                "---\nname: ask-before-write\nversion: 1.0.0\nverbs: [\"vault.claims.upsert\"]\nphase: pre\noutcomes: [\"ask\"]\n---\nAsk before a claim write.\n",
            ),
            HubFile::new(
                "hooks/ask-before-write/body.js",
                "return { kind: 'ask', question: 'May this claim be written?' };\n",
            ),
        ],
    )?;
    assert!(matches!(
        disposition,
        oneiron::skill_hub::pack_catalog::PackInstallDisposition::Installed(_)
    ));
    let binding = vault
        .pack_hook_bindings()?
        .into_iter()
        .find(|(_, row)| row.pack == "example.sessionwrite" && row.hook == "ask-before-write")
        .map(|(id, _)| id)
        .ok_or("the owner binds the asking hook")?;

    let writer = &fixture.writer;
    let tools = fixture.tools(writer).await?;
    let claim = EntityId::now();
    let mut params = tool_call_params(
        &tools,
        "vault.claims.upsert",
        json!({
            "id": claim.to_hex(),
            "predicate": "profile.note",
            "subject_ref": writer.person.to_hex(),
            "value": "a session write after approval",
            "confidence": 1.0,
            "source": "user_stated",
            "scope": { "scope_facet_id": fixture.alpha_facet.to_hex() },
        }),
        Some(BOUND_DIGEST),
    )?;
    params["_meta"]["oneiron/invocation"] = json!(EntityId::now().to_hex());
    let (_, held) = fixture.rpc(writer, 3, "tools/call", params).await?;
    let hook = held
        .pointer("/result/structuredContent/hook")
        .or_else(|| held.pointer("/error/data/hook"))
        .ok_or_else(|| format!("the pre-hook stops the claim: {held}"))?;
    let ask = match serde_json::from_value(hook.clone())? {
        oneiron::runtime_hooks::VerbHookStop::Pending { ask, .. } => EntityId::from_hex(&ask)?,
        other => return Err(format!("the hook must ask: {other:?}").into()),
    };
    assert!(vault.get_claim(&claim)?.is_none());

    let mut word = TaskAskWord::new(binding);
    word.option = Some(TaskAskOptionId::new("proceed").map_err(|_| "invalid proceed option")?);
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&TaskAskHandle { group_ref: ask }, &word)
        .map_err(|error| format!("the owner answers proceed: {error:?}"))?;
    let draining = Arc::clone(vault);
    tokio::task::spawn_blocking(move || draining.drain_verb_asks()).await??;
    let resumed = vault.get_claim(&claim)?.ok_or("the drain writes the claim")?;
    assert_eq!(resumed.scope_project, fixture.alpha);
    Ok(())
}

#[cfg(feature = "code-sandbox-wasmtime")]
#[derive(Default)]
struct SessionWriteAsk(std::sync::atomic::AtomicBool);

#[cfg(feature = "code-sandbox-wasmtime")]
impl oneiron::runtime_hooks::HookBodyRuntime for SessionWriteAsk {
    fn run_hook(
        &self,
        _body: &str,
        _input_json: &str,
        _context: &mut oneiron::runtime_hooks::HookRunContext,
        _read: &mut dyn FnMut(&str) -> Result<String, String>,
    ) -> oneiron::Result<oneiron::runtime_hooks::HookBodyRun> {
        let outcome = if self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
            json!({"kind": "nothing"})
        } else {
            json!({"kind": "ask", "question": "May this claim be written?"})
        };
        Ok(oneiron::runtime_hooks::HookBodyRun {
            outcome_json: outcome.to_string(),
            fuel_used: None,
            host_calls: 1,
        })
    }
}

#[test]
fn a_code_runs_room_claim_that_omits_its_project_lands_in_the_folders_project() -> TestResult {
    on_engine_stack(room_claim)
}

async fn room_claim() -> TestResult {
    use oneiron::code_run::SelfDispatchOutcome;
    use oneiron::off_record::OffRecordBackendClass;
    use oneiron_server::test_doors::mcp_code_mode_verbs::{call_off_record_claim, register_credential};

    let fixture = Fixture::new()?;
    let vault = &fixture.vault;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let writer = register_credential(&fixture.server, 0x65, &["read", "write"], None).await?;
    let session = vault
        .off_record_session_vault()
        .enter("off-record-session-project", OffRecordBackendClass::Local)?;
    let claim = EntityId::now();
    let outcome = call_off_record_claim(
        &fixture.server,
        &writer,
        &session,
        BOUND_DIGEST,
        json!({
            "id": claim.to_hex(),
            "predicate": "profile.note",
            "value": "a room claim from a bound folder",
            "confidence": 1.0,
            "source": "user_stated",
            "scope": { "scope_facet_id": fixture.alpha_facet.to_hex() },
        }),
    )
    .await?;
    assert!(
        matches!(outcome, SelfDispatchOutcome::AgentVerb(_)),
        "{outcome:?}"
    );
    assert!(
        vault.get_claim(&claim)?.is_none(),
        "the write stages off record"
    );
    session.save_artifact_as(&proof, &claim.to_hex())?;
    let saved = vault.get_claim(&claim)?.ok_or("the owner saves the staged claim")?;
    assert_eq!(saved.scope_project, fixture.alpha);
    session.close()?;
    Ok(())
}
