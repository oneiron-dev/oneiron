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
    assert!(target.get_entity_type(&asset)?.is_none());
    assert!(
        target
            .batch()
            .put_replicated(&asset, ENTITY_TYPE_ASSET, at, 10, &carrier)
            .commit()
            .is_err()
    );
    assert!(
        target
            .put_entity(&asset, ENTITY_TYPE_ASSET, at, 10, b"unrelated")
            .is_err()
    );
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

fn captured_root() -> Result<(tempfile::TempDir, crate::Vault, EntityId, EntityId, Vec<u8>)> {
    let (dir, vault) = open();
    let child = EntityId::now();
    let at = crate::temporal::TimeRange { start: 10, end: 10 };
    vault.put_agent_definition(&child, &definition("birth.custody", None), at, 10)?;
    let asset = birth_source_id(&child)?;
    let bytes = vault.get_raw(&asset)?.unwrap();
    Ok((
        dir,
        vault,
        child,
        asset,
        bytes[ENTITY_METADATA_HEADER_LEN..].to_vec(),
    ))
}
fn tombstone(reason: crate::deletion::TombstoneReason) -> Vec<u8> {
    crate::deletion::TombstoneValueV2 {
        reason,
        deleted_at: 20,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode()
    .to_vec()
}
#[test]
fn agent_source_erasure_covers_pending_replay_and_retired_targets() -> Result<()> {
    use crate::deletion::{DeleteReason, TombstoneReason};
    for reason in [DeleteReason::UserDelete, DeleteReason::GdprDelete] {
        let (_dir, vault, child, asset, _) = captured_root()?;
        let outcome = vault.delete_entity_with_reason(&child, reason)?;
        assert!(vault.get_raw(&asset)?.is_none());
        if let Some(receipt) = outcome.receipt_id {
            let raw = vault.get_raw(&receipt)?.unwrap();
            let receipt = crate::deletion::decode_redaction_audit_receipt(
                &raw[ENTITY_METADATA_HEADER_LEN..],
            )?;
            assert!(receipt.scope.entity_ids.contains(&asset.to_hex()));
        }
    }
    let (_dir, _source, child, asset, body) = captured_root()?;
    let at = crate::temporal::TimeRange { start: 10, end: 10 };
    for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
        for carrier_first in [true, false] {
            let (_dir, vault) = open();
            if carrier_first {
                vault
                    .batch()
                    .put_replicated(&asset, ENTITY_TYPE_ASSET, at, 10, &body)
                    .commit()?;
            }
            vault.apply_replayed_tombstone(&child, &tombstone(reason))?;
            assert!(vault.get_raw(&asset)?.is_none());
            assert!(
                vault
                    .batch()
                    .put_replicated(&asset, ENTITY_TYPE_ASSET, at, 10, &body)
                    .commit()
                    .is_err()
            );
        }
    }
    let (_dir, vault) = open();
    vault.put_entity(&asset, ENTITY_TYPE_ASSET, at, 10, &body)?;
    vault.put_entity(
        &child,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        10,
        b"unrelated person",
    )?;
    assert!(vault.get_raw(&asset)?.is_none());
    assert_eq!(
        vault.get_entity_type(&child)?,
        Some(crate::registry::ENTITY_TYPE_PERSON)
    );
    Ok(())
}
#[cfg(feature = "sync")]
#[test]
fn agent_historical_source_erases_without_widening_from_a_forged_key() -> Result<()> {
    let (_dir, _source, child, asset, body) = captured_root()?;
    let (_dir, vault) = open();
    vault.apply_replayed_tombstone(
        &child,
        &tombstone(crate::deletion::TombstoneReason::GdprDelete),
    )?;
    let label = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let key = crate::sync::types::WindowKey::new(&label);
    let doc = crate::sync::schema::create_window_doc("birth-source-fixture", &key);
    let mut blob = vec![ENTITY_TYPE_ASSET];
    for stamp in [1_u64, 1, 1] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(&body);
    crate::sync::loro_support::map_insert_bytes(&doc.get_map("entities"), &asset.to_hex(), &blob)?;
    let mut malformed = blob.clone();
    malformed.truncate(malformed.len() - 10);
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        "malformed-source",
        &malformed,
    )?;
    let unrelated = EntityId::now();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &unrelated.to_hex(),
        &blob,
    )?;
    // A forged key may contain doomed bytes, but does not confer erasure of
    // other structures under that unrelated identity.
    let other = EntityId::now();
    let edge_key =
        crate::sync::bridge::format_edge_key(&unrelated, crate::edge::EdgeKind::Mentions, &other);
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("edges"),
        &edge_key,
        b"unrelated-edge",
    )?;
    doc.commit();
    let snapshot = crate::sync::loro_support::export_snapshot(&doc)?;
    vault.with_write_txn(|txn| {
        vault
            .store
            .sync_state
            .put(txn, &format!("d:w:{label}"), &snapshot)?;
        Ok(())
    })?;
    crate::sweep::run_hard_erase_sweep(&vault)?;
    let txn = vault.store.env.read_txn()?;
    let compacted = vault
        .store
        .sync_state
        .get(&txn, &format!("d:w:{label}"))?
        .unwrap();
    let doc = crate::sync::loro_support::doc_from_snapshot(&compacted)?;
    assert!(doc.get_map("entities").get(&asset.to_hex()).is_none());
    assert!(doc.get_map("entities").get("malformed-source").is_none());
    assert!(doc.get_map("entities").get(&unrelated.to_hex()).is_none());
    assert!(doc.get_map("edges").get(&edge_key).is_some());
    Ok(())
}

#[test]
fn retained_birth_hash_without_captured_bytes_is_an_explicit_archive_omission() -> Result<()> {
    let (_dir, vault, child, asset, _) = captured_root()?;
    let complete = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    assert!(
        !complete
            .manifest()
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == child.to_hex())
    );
    vault.batch().delete(&asset).commit()?;
    let incomplete = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    assert!(
        incomplete
            .manifest()
            .bundle_omissions
            .iter()
            .any(|omission| omission.entity_id == child.to_hex()
                && omission.reason
                    == crate::batch::export::BundleOmissionReason::AgentBirthSourceUnavailable)
    );
    Ok(())
}
