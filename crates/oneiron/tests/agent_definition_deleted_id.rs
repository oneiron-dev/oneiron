//! An agent-authored create at a deleted agent's id is refused (R2d review finding 1).
//!
//! A deleted agent's id is not new: its durable pin survives the delete, and only the vault
//! owner brings the definition back. An author agent that creates a child, whose owner then
//! hard-deletes it, cannot create at the same id again through its own writer.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::deletion::DeleteReason;
use oneiron::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, RawEntityPut, TimeRange, Vault, VaultConfig};
use rmpv::Value as RmpValue;

const NOW: u64 = 1_700_000_000;

// Fixture ids are `[seed; 16]`, off the pinned bytes a fresh vault holds.
const AUTHOR: u8 = 0x70;
const CHILD: u8 = 0x79;

fn definition(
    name: &str,
    scope: AgentScope,
    ceiling: AgentCeiling,
    source: ClaimSource,
    generated: bool,
    human_authored: bool,
) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "deleted-id fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        scope,
        ceiling,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        source,
        1.0,
        generated,
        human_authored,
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}

/// A new candidate inside the author's own slice: Base, ceiling Proposed.
fn candidate() -> AgentDefinition {
    definition(
        "conformance.candidate",
        AgentScope::Base,
        AgentCeiling::Proposed,
        ClaimSource::Generated,
        true,
        false,
    )
}

/// Puts `def` at `id` on the Agent-class `Memory` of `writer`, as the run host door binds it.
fn put(
    vault: &Vault,
    writer: EntityId,
    id: EntityId,
    def: &AgentDefinition,
    at: u64,
) -> Result<(), String> {
    let bytes = encode_agent_definition(def).expect("valid definition");
    vault
        .memory(writer, EdgeActorClass::Agent)
        .raw_put_entity(RawEntityPut {
            id,
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            data: &bytes,
        })
        .map_err(|error| format!("{error:?}"))
}

/// Catches an author agent recreating a deleted agent's id as a fresh create: the owner
/// hard-deletes the child, and the author's second put at the same id lands again.
#[test]
fn an_author_cannot_create_again_at_a_deleted_agents_id() {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("personal vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner_person = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(
            owner_person,
            &owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let author = EntityId::from_bytes([AUTHOR; 16]).expect("author id");
    vault
        .create_agent_definition_as(
            &owner,
            &author,
            &definition(
                "conformance.author",
                AgentScope::Base,
                AgentCeiling::Proposed,
                ClaimSource::UserStated,
                false,
                true,
            ),
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("owner creates the Base, ceiling-Proposed author");
    vault
        .install_read_permits_for_test(&[oneiron::WriteActor::new(author, EdgeActorClass::Agent)])
        .expect("the author reads the rows it updates");

    let id = EntityId::from_bytes([CHILD; 16]).expect("child id");
    put(&vault, author, id, &candidate(), NOW + 1).expect("the author creates a child");
    let child = vault
        .get_agent_definition(&id)
        .expect("read the child")
        .expect("the child row");
    assert_eq!(
        child.approval_status,
        ClaimApprovalStatus::Approved,
        "a child inside its author's slice starts active"
    );

    vault
        .delete_entity_with_reason(&id, DeleteReason::UserHardDelete)
        .expect("the owner hard-deletes the child");
    assert_eq!(
        vault.get_agent_definition(&id).expect("read after delete"),
        None,
        "the hard delete removes the row"
    );

    let second = put(&vault, author, id, &candidate(), NOW + 2);
    assert!(
        second.as_ref().is_err_and(
            |error| error.contains("deleted agent") || error.contains("InvalidAgentDefBody")
        ),
        "the second create at the deleted id is refused: {second:?}"
    );
    assert_eq!(
        vault
            .get_agent_definition(&id)
            .expect("read after refused create"),
        None,
        "the refused create writes nothing"
    );
}
