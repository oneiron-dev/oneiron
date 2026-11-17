//! An agent-authored create at a deleted agent's id is refused (R2d review finding 1).
//!
//! A deleted agent's id is not new: its durable pin survives the delete, and only the vault
//! owner brings the definition back. An author agent that installs its local pack, whose owner
//! then hard-deletes the derived travelling child, cannot reinstall the same pack through its
//! own writer.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::deletion::DeleteReason;
use oneiron::share_travel::{AgentPackTravelProjection, BornWith};
use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;

const NOW: u64 = 1_700_000_000;

// The fixture author id is `[seed; 16]`, off the pinned bytes a fresh vault holds.
const AUTHOR: u8 = 0x70;

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

/// Catches an author agent recreating a deleted agent's id as a fresh create: the author
/// installs its local pack, the owner hard-deletes the derived child, and the author's
/// reinstall of the same pack is refused.
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
    let agent = vault
        .observed_write_actor(WriteActor::new(author, EdgeActorClass::Agent))
        .expect("agent writer");
    let files = AgentPackTravelProjection::from_definition(
        &definition(
            "local",
            AgentScope::Base,
            AgentCeiling::Proposed,
            ClaimSource::UserStated,
            false,
            true,
        ),
        None,
        Vec::new(),
        Vec::new(),
        BornWith::new(),
    )
    .expect("travelling local pack")
    .files()
    .expect("pack files");
    let receipt = match vault
        .put_local_pack_as_agent(&agent, files.clone())
        .expect("the author installs its local pack")
    {
        PackInstallDisposition::Installed(receipt) => receipt,
        other => panic!("the in-slice pack installs: {other:?}"),
    };
    let id =
        EntityId::from_hex(receipt.agent.as_deref().expect("the derived child")).expect("child id");
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

    let second = vault
        .put_local_pack_as_agent(&agent, files)
        .map(|_| ())
        .map_err(|error| format!("{error:?}"));
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
