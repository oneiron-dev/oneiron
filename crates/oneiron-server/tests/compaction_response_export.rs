#![cfg(oneiron_test_support)]
//! A filed compaction step's response artifact holds the compactor's whole
//! answer about the records its call read (COMPACTION-STEP-CLAIM-READS-
//! WITHOUT-SOURCES). The HTTP export door served a version's bytes raw to a
//! credential with no record caveat (FIX 7645), so an agent that reads no
//! record of the conversation downloaded that answer, although its point
//! read of the artifact answers absent. Now the door judges a compaction
//! response version through the credential's own lane, as it judges reminder
//! wording (FIX 4997; Engine RULING STEPREAD-RESIDUAL-PATHS = A).
//!
//! Fixture: an owned vault with its embedded owner, one PERSON (owen), and
//! three agents with auto ceilings and `core:read` grants: the compactor
//! (scribe), cleo and bram. A project led by owen seats scribe and cleo, and
//! both read the home room's messages under a grant; bram is not seated and
//! holds no such grant. Owen speaks one trunk turn, and a step of scribe
//! files from it with an answer above the inline bound, so the answer lives
//! in a response artifact. Cleo and bram each hold an agent slip at full
//! record scope with the read verb, so neither carries a record caveat.
//!
//! Red at 5f7e178efbe: bram's export answers 200 with the answer. Guard (it
//! passes there too): cleo's export answers 200 with the answer.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks
//! --test compaction_response_export`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_PERSON};
use oneiron::test_doors::compaction_step_read::file_compaction_step;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The run a chat compaction files its steps under.
const CHAT_RUN: &str = "chat-compaction";
/// Words of the compactor's answer that only a reader of the room may see.
const ANSWER: &str = "Owen said the vendor contract renews on the ninth and he will not renew it.";

/// An agent's slip and the key that proves its holder.
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    /// The response artifact of scribe's step.
    artifact: EntityId,
    cleo: Credential,
    bram: Credential,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 64 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(directory.path(), config)?);
        let owner = vault.ensure_embedded_owner_actor()?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.agents.create")?;
        let owen = EntityId::now();
        let now = vault.now_recorded_at();
        vault.put_entity(
            &owen,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"owen",
        )?;
        let mut agents = Vec::new();
        for name in ["scribe", "cleo", "bram"] {
            let agent = EntityId::now();
            let definition: AgentDefinitionSpec = serde_json::from_value(json!({
                "agent_id": name,
                "display_name": name,
                "desc": name,
                "version": "1",
                "ceiling": "auto",
            }))?;
            oneiron::verbs::create_agent_definition_as(
                &vault,
                &proof,
                AgentDefinitionCreateRequest {
                    agent_def_ref: agent,
                    definition,
                },
            )?;
            agents.push(agent);
        }
        let (scribe, cleo, bram) = (agents[0], agents[1], agents[2]);
        let view =
            policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .ok_or("default policy manifest missing")?;
        let mut manifest = default.manifest.clone();
        let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
        for agent in [scribe, cleo, bram] {
            manifest.actor_ceilings.push(ActorCeiling {
                actor_class: "agent".into(),
                actor_ref: Some(agent.to_hex()),
                ceiling: PolicyCeiling::Auto,
            });
            rows.push(PolicyScopedGrantRow {
                actor_class: None,
                actor_ref: Some(agent.to_hex()),
                effector: "core:read".into(),
                scope: Scope::top(),
                selectors: None,
                budget: None,
                receipt_required: false,
            });
        }
        manifest.scoped_grants = Some(rows);
        put_policy_manifest_as_owner(
            &vault,
            &proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )?;
        let root_project = vault.root_project()?;
        let project_id = EntityId::now();
        let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, owen)?;
        project.roster.push(scribe.to_hex());
        project.roster.push(cleo.to_hex());
        vault.put_project(project_id, &project, vault.now_recorded_at())?;
        let room = EntityId::from_hex(&project.home_room)?;
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        for principal in [owen, scribe, cleo] {
            vault.create_access_grant(
                &EntityId::now(),
                &AccessGrant {
                    authority_scope: authority_scope.clone(),
                    principal_ref: principal,
                    scope: AccessGrantScope::ConversationMessages {
                        conversation_ref: room,
                    },
                    capability: AccessGrantCapability::MessagesRead,
                    status: AccessGrantStatus::Active,
                    created_at,
                    revoked_at: None,
                    expires_at: None,
                    companion_bounds: None,
                },
            )?;
        }
        let (turn, message) = (EntityId::now(), EntityId::now());
        vault
            .memory(owen, EdgeActorClass::Human)
            .rooms_speak(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: Some(message.to_hex()),
                    author: WitnessAuthor::User,
                    message_type: "text".into(),
                    content: "the vendor contract renews on the ninth; I will not renew it".into(),
                    parts: None,
                    metadata: Some(Value::Object(serde_json::Map::new())),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: vault.now_recorded_at(),
                assertions: Default::default(),
            })?;
        let message_ref = message.to_hex();
        assert!(
            vault
                .memory(cleo, EdgeActorClass::Agent)
                .get_entity(&message_ref)?
                .value
                .is_some(),
            "FIXTURE: cleo reads the room's message"
        );
        assert!(
            vault
                .memory(bram, EdgeActorClass::Agent)
                .get_entity(&message_ref)?
                .value
                .is_none(),
            "FIXTURE: bram does not read the room's message"
        );

        let before: BTreeSet<EntityId> = vault
            .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
            .into_iter()
            .collect();
        let long = format!("{ANSWER} {}", "And the rest of the window. ".repeat(700));
        file_compaction_step(
            &vault,
            CHAT_RUN,
            EntityId::now(),
            scribe,
            vec![turn, message],
            &long,
        )?;
        let artifacts: Vec<EntityId> = vault
            .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
            .into_iter()
            .filter(|artifact| !before.contains(artifact))
            .collect();
        let [artifact] = artifacts.as_slice() else {
            return Err(format!(
                "FIXTURE: one response artifact files beside the step: {artifacts:?}"
            )
            .into());
        };
        let artifact = *artifact;

        // HTTP trusts the logged issuer of each mint. Root this fixture
        // explicitly; the app needs no retained signing key.
        let issuer = HostSlipIssuer::from_secret(b"oneiron-test-compaction-response-export")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let credential = |agent: EntityId, seed: u8| -> TestResult<Credential> {
            let key = SigningKey::from_bytes(&[seed; 32]);
            let mut claims = root.claims.clone();
            claims.parent_id = None;
            claims.holder_ref = agent.to_hex();
            claims.binding_key = key.verifying_key().to_bytes();
            claims.actor_class = Some("agent".to_owned());
            claims.scope = Scope::top();
            claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
            claims.slip_id = [seed; 32];
            Ok(Credential {
                slip: vault.mint_capability_slip(&issuer, claims)?,
                key,
            })
        };
        let cleo_slip = credential(cleo, 0x71)?;
        let bram_slip = credential(bram, 0x72)?;
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            artifact,
            cleo: cleo_slip,
            bram: bram_slip,
            _directory: directory,
        })
    }

    /// The status and body of `credential`'s export of the response
    /// artifact's head version.
    async fn export(&self, credential: &Credential) -> TestResult<(u16, String)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = credential
            .key
            .sign(&credential.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::builder()
            .method("GET")
            .uri(format!(
                "/v1/core/artifacts/{}/export",
                self.artifact.to_hex()
            ))
            .header(
                "authorization",
                format!("Bearer {}", credential.slip.to_token()?),
            )
            .header("x-oneiron-binding", binding.to_string())
            .body(Body::empty())?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_compaction_response_exports_only_to_a_reader_of_its_sources() -> TestResult {
    on_engine_stack(compaction_response_export)
}

async fn compaction_response_export() -> TestResult {
    let fixture = Fixture::new()?;
    let (status, body) = fixture.export(&fixture.cleo).await?;
    assert_eq!(
        status, 200,
        "cleo, who reads the room, exports the response: {body}"
    );
    assert!(
        body.contains(ANSWER),
        "cleo's export holds the compactor's answer"
    );
    let (status, body) = fixture.export(&fixture.bram).await?;
    assert!(
        status != 200 && !body.contains(ANSWER),
        "LEAK: bram exports the compactor's answer without reading the room: status {status}"
    );
    Ok(())
}
