#![cfg(oneiron_test_support)]
//! A compaction flight files each paid call as a `dreamer.step` claim under
//! its writer, and the claim holds the compactor's whole answer about the
//! records the call read (COMPACTION-STEP-CLAIM-READS-WITHOUT-SOURCES; Engine
//! RULING CONNECTOR-STEP-CLAIM-READ = A). Such a step reads only while those
//! records read for the reader, as the summary does: an agent with an
//! ordinary claim read and no read of the conversation does not see it; the
//! owner and an agent that reads the conversation do. A chat compaction and
//! a code run's file through the same door, so both are checked. An answer
//! above the inline bound lives in a response artifact, which reads by the
//! same rule. On main every one of these steps read for the outsider.
//!
//! Fixture: an owned vault with its embedded owner, one PERSON (owen), and
//! three agents with auto ceilings and `core:read` grants: the compactor
//! (scribe), cleo and bram. A project led by owen seats scribe and cleo,
//! and both read the home room's messages under a grant; bram is not seated
//! and holds no such grant. Owen speaks one trunk turn: the call's source.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test compaction_step_source_read`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{ClaimListFilter, Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_PERSON};
use oneiron::test_doors::compaction_step_read::file_compaction_step;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The run a chat compaction files its steps under.
const CHAT_RUN: &str = "chat-compaction";
/// A code run's ref, as its compaction host stamps it.
const CODE_RUN: &str = "code-run-compaction-test";
/// Words of the compactor's answer that only a reader of the room may see.
const ANSWER: &str = "Owen said the vendor contract renews on the ninth and he will not renew it.";
/// The inline bound of a step's response, in bytes: above it the answer
/// lives in a response artifact.
const INLINE_RESPONSE_MAX_BYTES: usize = 16_384;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    scribe: EntityId,
    cleo: EntityId,
    bram: EntityId,
    /// Owen's trunk turn and its one MESSAGE: what the call read.
    sources: Vec<EntityId>,
    message: EntityId,
    _directory: tempfile::TempDir,
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
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
    let (turn, message) = speak_trunk(&vault, owen, room)?;
    Ok(Fixture {
        vault,
        owner,
        scribe,
        cleo,
        bram,
        sources: vec![turn, message],
        message,
        _directory: directory,
    })
}

/// `speaker`'s trunk turn in the home room `room`, one MESSAGE: its TURN and
/// MESSAGE ids.
fn speak_trunk(
    vault: &Vault,
    speaker: EntityId,
    room: EntityId,
) -> TestResult<(EntityId, EntityId)> {
    let (turn, message) = (EntityId::now(), EntityId::now());
    let input = WitnessTurn {
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
    };
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&input)?;
    Ok((turn, message))
}

impl Fixture {
    fn agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    fn owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// Files one step of `run_ref` under scribe, read from owen's turn.
    fn file_step(&self, run_ref: &str, answer: &str) -> TestResult<EntityId> {
        Ok(file_compaction_step(
            &self.vault,
            run_ref,
            EntityId::now(),
            self.scribe,
            self.sources.clone(),
            answer,
        )?)
    }

    /// The readers this test needs, as each stands before any step files:
    /// cleo reads owen's MESSAGE, bram does not.
    fn assert_message_readers(&self) -> TestResult {
        let message = self.message.to_hex();
        assert!(
            self.agent(self.cleo).get_entity(&message)?.value.is_some(),
            "cleo reads the room's message"
        );
        assert!(
            self.agent(self.bram).get_entity(&message)?.value.is_none(),
            "bram does not read the room's message"
        );
        Ok(())
    }
}

/// Whether `memory`'s `dreamer.step` list names `step`, and the claim's
/// value as that list shows it.
fn listed_step(memory: &Memory<'_>, step: EntityId) -> TestResult<Option<Value>> {
    let listed = memory
        .claim_list(&ClaimListFilter {
            predicate: Some("dreamer.step".to_owned()),
            limit: 100,
            ..Default::default()
        })?
        .value;
    Ok(listed
        .into_iter()
        .find(|view| EntityId::from_hex(&view.claim_ref).is_ok_and(|id| id == step))
        .map(|view| view.value))
}

/// Whether `memory` reads the row `id` by its point read.
fn reads(memory: &Memory<'_>, id: EntityId) -> TestResult<bool> {
    Ok(memory.get_entity(&id.to_hex())?.value.is_some())
}

#[test]
fn a_compaction_step_does_not_read_without_its_conversation() -> TestResult {
    let fixture = open_fixture()?;
    fixture.assert_message_readers()?;
    let step = fixture.file_step(CHAT_RUN, ANSWER)?;
    let bram = fixture.agent(fixture.bram);
    assert_eq!(
        listed_step(&bram, step)?,
        None,
        "bram's claim list does not show a step of a conversation he does not read"
    );
    assert!(
        !reads(&bram, step)?,
        "bram's point read of the step answers absent"
    );
    Ok(())
}

#[test]
fn the_owner_and_a_reader_of_the_conversation_read_a_compaction_step() -> TestResult {
    let fixture = open_fixture()?;
    fixture.assert_message_readers()?;
    let step = fixture.file_step(CHAT_RUN, ANSWER)?;
    let owner =
        listed_step(&fixture.owner(), step)?.ok_or("the owner's claim list shows the step")?;
    assert!(
        owner.to_string().contains(ANSWER),
        "the owner reads the compactor's answer: {owner}"
    );
    assert!(
        listed_step(&fixture.agent(fixture.cleo), step)?.is_some(),
        "cleo, who reads the room, sees the step"
    );
    assert!(
        reads(&fixture.agent(fixture.scribe), step)?,
        "scribe, who compacted the room and reads it, reads its own step"
    );
    Ok(())
}

#[test]
fn a_code_run_compaction_step_reads_only_beside_its_sources() -> TestResult {
    let fixture = open_fixture()?;
    fixture.assert_message_readers()?;
    let step = fixture.file_step(CODE_RUN, ANSWER)?;
    assert_eq!(
        listed_step(&fixture.agent(fixture.bram), step)?,
        None,
        "bram does not see a code run's step read from the room"
    );
    assert!(
        listed_step(&fixture.agent(fixture.cleo), step)?.is_some(),
        "cleo sees the code run's step"
    );
    assert!(
        listed_step(&fixture.owner(), step)?.is_some(),
        "the owner sees the code run's step"
    );
    Ok(())
}

#[test]
fn a_compaction_response_artifact_reads_only_beside_its_sources() -> TestResult {
    let fixture = open_fixture()?;
    fixture.assert_message_readers()?;
    let before: BTreeSet<EntityId> = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
        .into_iter()
        .collect();
    let long = format!("{ANSWER} {}", "And the rest of the window. ".repeat(700));
    assert!(
        long.len() > INLINE_RESPONSE_MAX_BYTES,
        "the answer is above the inline bound"
    );
    let step = fixture.file_step(CHAT_RUN, &long)?;
    let artifacts: Vec<EntityId> = fixture
        .vault
        .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
        .into_iter()
        .filter(|artifact| !before.contains(artifact))
        .collect();
    let [artifact] = artifacts.as_slice() else {
        return Err(format!("one response artifact files beside the step: {artifacts:?}").into());
    };
    let artifact = *artifact;
    let bram = fixture.agent(fixture.bram);
    assert!(
        !reads(&bram, artifact)?,
        "bram does not read the step's response artifact"
    );
    assert!(!reads(&bram, step)?, "bram does not read the step");
    assert!(
        reads(&fixture.agent(fixture.cleo), artifact)?,
        "cleo reads the step's response artifact"
    );
    assert!(
        reads(&fixture.owner(), artifact)?,
        "the owner reads the step's response artifact"
    );
    Ok(())
}
