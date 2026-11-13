//! A person's own DAG append is that person's word (Engine ruling
//! DAG-APPEND-SOURCE-LABEL = A).
//!
//! The DAG append door labels an append by its writer's actor class. A person
//! (Human) states it (`UserStated`), which needs no source-trust permit, so on
//! a default vault the owner appends trunk records and a thread reply with no
//! test policy. An agent's append stays `Generated` and still pends on
//! `gate.pending.source_trust` until an actor-bound permit names it. Canon:
//! ARCH-0040 #mcp-actor-ceilings, provenance is who writes; "Generated never
//! supersedes UserStated" (owner, 2026-09-22).
//!
//! Public paths only: `Memory::conversations_create`,
//! `Memory::conversations_records_append` (`vault.conversations.records.append`),
//! `Vault::reply_in_thread` (the REST thread reply's door) and the
//! agent-definition create verb. No source-trust permit is written anywhere:
//! no `put_dag_test_policy`. The agent's read of its conversation is one
//! actor-bound `core:read` row through `oneiron::test_support`, so its append
//! reaches the gate instead of the reference check.
//!
//! `cargo test --locked -p oneiron --all-features --test dag_append_source_label`.

use std::collections::BTreeSet;

use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TURN};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The gate's reason for a write whose source needs a permit it lacks.
const PENDING_SOURCE_TRUST: &str = "gate.pending.source_trust";

/// The shipped default policy pack, whose manifest the agent's read is added to.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// A default vault this process owns and its embedded owner. The vault
/// closes before its directory goes.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's agent door asks for.
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        vault,
        owner,
        _dir: dir,
    })
}

/// A plain conversation the owner creates, as COORDINATION-02 does.
fn create_conversation(fixture: &Fixture) -> TestResult<EntityId> {
    let receipt = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// One trunk record that advances HEAD from `parent`.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

/// A custom agent made through the agent-definition door, as the owner.
fn create_agent(fixture: &Fixture, agent_id: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
        "agent_id": agent_id,
        "display_name": agent_id,
        "desc": format!("{agent_id} appends to a conversation"),
        "version": "1",
    }))?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    oneiron::verbs::create_agent_definition_as(
        &fixture.vault,
        &host.embedded_owner("vault.agents.create")?,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// Lets `agent` read the vault's conversation records: one actor-bound
/// `core:read` row added to the shipped policy manifest, its other rows,
/// and its source-trust table, kept as they are.
fn permit_conversation_reads(fixture: &Fixture, agent: EntityId) -> TestResult {
    let vault = &fixture.vault;
    let mut shipped = None;
    for id in vault.entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)? {
        let Some(bytes) = vault.get(&id)? else {
            continue;
        };
        let manifest: serde_json::Value = rmp_serde::from_slice(&bytes)?;
        if manifest["pack_id"] == SHIPPED_POLICY_PACK {
            shipped = Some((id, manifest));
            break;
        }
    }
    let (id, mut manifest) = shipped.ok_or("the vault holds no shipped policy manifest")?;
    let mut read = Scope::top();
    read.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    manifest["scoped_grants"]
        .as_array_mut()
        .ok_or("the shipped policy manifest has no scoped grants")?
        .push(json!({
            "actor_ref": agent.to_hex(),
            "effector": "core:read",
            "scope": read,
            "receipt_required": false,
            "selectors": {"entity_types": [ENTITY_TYPE_CONVERSATION]},
        }));
    oneiron::test_support::put_policy_manifest_bytes(
        vault,
        id,
        &rmp_serde::to_vec_named(&manifest)?,
    )?;
    Ok(())
}

#[test]
fn the_owner_appends_a_trunk_record_and_a_thread_reply_on_a_default_vault_with_no_test_policy()
-> TestResult {
    let fixture = open()?;
    let conversation = create_conversation(&fixture)?;
    let host = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);

    // The trunk: two records, each the owner's own word, each advancing HEAD.
    let first = host
        .conversations_records_append(&trunk_record(conversation, None, "the plan"))
        .expect("the owner's trunk record is the owner's word, not generated text");
    assert_eq!(first.head.as_deref(), Some(first.id.as_str()));
    let second = host.conversations_records_append(&trunk_record(
        conversation,
        Some(&first.id),
        "the first step",
    ))?;
    assert_eq!(second.parent.as_deref(), Some(first.id.as_str()));
    let head = EntityId::from_hex(&second.id)?;

    // A thread reply under the first record: the owner's word too, and the
    // trunk HEAD stays where it was.
    let now = fixture.vault.now_recorded_at();
    let reply = fixture.vault.reply_in_thread(
        &host,
        EntityId::from_hex(&first.id)?,
        &AppendRecord {
            conversation,
            parent: None,
            reply_to: None,
            quote: None,
            address: AddressMode::Broadcast,
            recipients: Vec::new(),
            advance: false,
            kind: ENTITY_TYPE_TURN,
            containing_turn: None,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            body: rmp_serde::to_vec_named(&json!({"txt": "a side question", "speaker": "user"}))?,
            text: Vec::new(),
            session: None,
            actor: WriteActor::new(fixture.owner, EdgeActorClass::Human),
            thread_audience: None,
        },
    )?;
    assert_ne!(reply.id, head);
    assert_eq!(fixture.vault.head(&conversation)?, Some(head));
    Ok(())
}

/// The label follows the writer: an agent's append is generated text and
/// keeps needing its actor-bound permit.
#[test]
fn an_agents_append_on_a_default_vault_still_pends_on_source_trust() -> TestResult {
    let fixture = open()?;
    let conversation = create_conversation(&fixture)?;
    let agent = create_agent(&fixture, "dag-writer")?;
    permit_conversation_reads(&fixture, agent)?;

    let refusal = fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .conversations_records_append(&trunk_record(conversation, None, "an agent's note"))
        .expect_err("an agent's append is generated and pends without a permit");
    assert_eq!(refusal.code, MEMORY_CODE_FORBIDDEN);
    let denial = refusal
        .gate_denial
        .as_deref()
        .ok_or("the refusal carries its gate denial")?;
    assert_eq!(denial.outcome, "pending");
    assert!(
        denial
            .reason_codes
            .iter()
            .any(|code| code == PENDING_SOURCE_TRUST),
        "the agent's append pends on source trust: {:?}",
        denial.reason_codes
    );
    assert_eq!(fixture.vault.head(&conversation)?, None, "nothing landed");
    Ok(())
}
