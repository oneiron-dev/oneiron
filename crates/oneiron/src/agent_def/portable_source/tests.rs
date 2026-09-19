//! Actual birth capture and replay retain bytes without granting authority.
use super::*;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use rmpv::Value;
fn definition(agent_id: &str, forked_from: Option<EntityId>) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "Birth carrier fixture",
        "1.0.0",
        Some("Count carefully.\n".into()),
        vec![],
        vec![],
        vec![],
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        forked_from,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from("birth-source"))]),
        None,
        true,
        None,
    )
}

fn open() -> (tempfile::TempDir, crate::Vault) {
    let mut config = crate::VaultConfig::device();
    config.dimensions = 4;
    config.map_size = 16 * 1024 * 1024;
    crate::test_util::open_test_vault_with(config)
}
#[test]
fn captured_fork_source_replays_after_parent_edits_and_stays_untrusted() -> Result<()> {
    let (_dir, source) = open();
    let parent = EntityId::now();
    let child = EntityId::now();
    let parent_def = definition("birth.parent", None);
    let child_def = definition("birth.child", Some(parent));
    let at = crate::temporal::TimeRange { start: 10, end: 10 };
    source.put_agent_definition(&parent, &parent_def, at, 10)?;
    source.put_agent_definition(&child, &child_def, at, 10)?;
    let original =
        read_birth_source(&source.store, &source.store.env.read_txn()?, &child)?.unwrap();
    let mut edited = parent_def.clone();
    edited.version = "2".into();
    edited.instructions = Some("Different parent text".into());
    source.put_agent_definition(&parent, &edited, at, 10)?;
    assert_eq!(
        read_birth_source(&source.store, &source.store.env.read_txn()?, &child)?
            .unwrap()
            .tree,
        original.tree
    );
    let asset = birth_source_id(&child)?;
    let carrier = source
        .store
        .entities
        .get(&source.store.env.read_txn()?, asset.as_bytes())?
        .unwrap()[ENTITY_METADATA_HEADER_LEN..]
        .to_vec();
    let (_dir, target) = open();
    target
        .batch()
        .put_replicated(&asset, ENTITY_TYPE_ASSET, at, 10, &carrier)
        .put_replicated(
            &parent,
            ENTITY_TYPE_AGENT_DEF,
            at,
            10,
            &encode_agent_definition(&edited)?,
        )
        .put_replicated(
            &child,
            ENTITY_TYPE_AGENT_DEF,
            at,
            10,
            &encode_agent_definition(&child_def)?,
        )
        .commit()?;
    let recovered =
        read_birth_source(&target.store, &target.store.env.read_txn()?, &child)?.unwrap();
    assert_eq!(recovered.tree, original.tree);
    let hash = crate::agent_def::agent_fork_hash_in_txn(
        &target.store,
        &target.store.env.read_txn()?,
        &child,
    )?
    .unwrap();
    assert_eq!(Some(hash.to_hex()), original.tree.content_hash);
    assert!(
        target
            .put_entity(&asset, ENTITY_TYPE_ASSET, at, 10, b"changed")
            .is_err()
    );
    assert!(
        target
            .batch()
            .put_replicated(&EntityId::now(), ENTITY_TYPE_ASSET, at, 10, &carrier)
            .commit()
            .is_err()
    );
    target.batch().delete(&child).commit()?;
    let archive = target.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    let document = target.read_whole_vault_json(archive.bytes())?;
    assert!(
        !document
            .evidence_ledger
            .entities
            .iter()
            .any(|row| row.id == asset.to_hex())
    );
    Ok(())
}
#[test]
fn imported_definition_does_not_mint_a_local_birth_source() -> Result<()> {
    let (_dir, vault) = open();
    let id = EntityId::now();
    let mut def = definition("birth.imported", None);
    def.source = ClaimSource::Imported;
    def.enabled = false;
    def.approval_status = ClaimApprovalStatus::Proposed;
    def.ceiling = AgentCeiling::Proposed;
    let at = crate::temporal::TimeRange { start: 10, end: 10 };
    vault.put_agent_definition(&id, &def, at, 10)?;
    assert!(read_birth_source(&vault.store, &vault.store.env.read_txn()?, &id)?.is_none());
    assert!(vault.get_entity_type(&birth_source_id(&id)?)?.is_none());
    Ok(())
}
