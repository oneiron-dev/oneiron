//! Public storage/export outcomes for explicitly untrusted receipt source data.
use super::codec::ReceiptArchive;
use crate::{
    EntityId, Vault, VaultConfig,
    batch::export::ExportReceiptSource,
    claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject},
    deletion::{DeleteReason, TombstoneReason, TombstoneValueV2},
    error::Result,
    receipt::{ReceiptKind, ReceiptRecord, attempt_pack_receipt},
    registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON},
    temporal::TimeRange,
};
use rmpv::Value;
use std::collections::BTreeMap;
fn at() -> TimeRange {
    TimeRange { start: 1, end: 1 }
}
fn open() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}
// This packet is deliberately foreign fixture data, NOT a native terminal act.
fn fixture(vault: &Vault) -> Result<(EntityId, EntityId, EntityId, Vec<u8>, String)> {
    let actor = EntityId::now();
    let holder = EntityId::now();
    let reference = format!("attempt:{}", EntityId::now().to_hex());
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        at(),
        1,
        b"archive fixture actor",
    )?;
    let mut body = ClaimBody::new(
        crate::actor_claims::PREDICATE_ACTOR_LESSON,
        ClaimSubject::Entity(actor),
        "retain the imported trace".into(),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Imported);
    body.scope = Some(Value::Map(vec![(
        crate::actor_claims::ACTOR_CLAIM_LINEAGE_KEY.into(),
        "imported".into(),
    )]));
    body.evidence = Some(Value::Map(vec![
        ("at".into(), 1.into()),
        ("lane".into(), "task".into()),
        (
            "receipts".into(),
            Value::Array(vec![reference.clone().into()]),
        ),
    ]));
    vault.with_write_txn(|txn| {
        vault.restore_actor_projection_in_txn(txn, &holder, &body, at(), 1)
    })?;
    let record = ReceiptRecord {
        receipt_id: reference.clone(),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: 1,
        actor: Some("foreign fixture".into()),
        on_behalf_of: None,
        outcome: "completed".into(),
        job_ref: None,
        trigger_ref: None,
        policy_trace: Vec::new(),
        fields: BTreeMap::from([("fixture".into(), "RECEIPT-SOURCE-CUSTODY-SENTINEL".into())]),
    };
    let source =
        ExportReceiptSource::from_record(reference.clone(), Some(&record))?.as_imported_archive();
    let raw = vault.get_raw(&holder)?.unwrap();
    let bytes = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let archive = ReceiptArchive::new(&holder, bytes, source.clone())?;
    let id = archive.id()?;
    vault.with_write_txn(|txn| {
        vault.restore_claim_receipt_sources_in_txn(txn, &holder, &[source])
    })?;
    assert_eq!(attempt_pack_receipt(vault, &reference)?, None);
    Ok((actor, holder, id, archive.bytes()?, reference))
}
fn tombstone() -> Vec<u8> {
    TombstoneValueV2 {
        reason: TombstoneReason::GdprDelete,
        deleted_at: 10,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode()
    .to_vec()
}
#[test]
fn source_replication_arrival_orders_and_holder_delete_are_physical_and_non_authoritative()
-> Result<()> {
    let (_origin_dir, origin) = open();
    let (actor, holder, id, bytes, reference) = fixture(&origin)?;
    let raw = origin.get_raw(&holder)?.unwrap();
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    for source_first in [false, true] {
        let (_dir, vault) = open();
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            at(),
            1,
            b"archive fixture actor",
        )?;
        if source_first {
            vault
                .batch()
                .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
                .commit()?;
        }
        vault
            .batch()
            .put_replicated(&holder, ENTITY_TYPE_CLAIM, at(), 1, body)
            .commit()?;
        if !source_first {
            vault
                .batch()
                .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
                .commit()?;
        }
        assert!(vault.get_raw(&id)?.is_some());
        assert_eq!(attempt_pack_receipt(&vault, &reference)?, None);
        let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
        let document = vault.read_whole_vault_json(export.bytes())?;
        let envelope = document
            .derivation_envelopes
            .iter()
            .find(|row| row.id == holder.to_hex())
            .unwrap();
        assert!(envelope.receipts[0].record()?.is_some());
        assert!(
            document
                .evidence_ledger
                .entities
                .iter()
                .all(|row| row.id != id.to_hex())
        );
        vault.batch().delete(&holder).commit()?;
        assert!(vault.get_raw(&id)?.is_none());
        assert!(vault.get_raw(&actor)?.is_some());
        assert!(
            vault
                .batch()
                .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
                .commit()
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn direct_carrier_delete_never_deletes_claim_and_absent_tombstones_block_late_payload() -> Result<()>
{
    let (_dir, vault) = open();
    let (_, holder, id, bytes, _) = fixture(&vault)?;
    let before = vault.get_claim(&holder)?;
    vault.batch().delete(&id).commit()?;
    assert!(vault.get_raw(&id)?.is_none());
    assert_eq!(vault.get_claim(&holder)?, before);
    assert!(
        vault
            .put_entity(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
            .is_err()
    );
    for erased in [holder, id] {
        let (_target_dir, target) = open();
        target.apply_replayed_tombstone(&erased, &tombstone())?;
        assert!(
            target
                .batch()
                .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
                .commit()
                .is_err()
        );
    }
    Ok(())
}
#[test]
fn hard_delete_receipt_names_source_payload_and_unrelated_holder_survives() -> Result<()> {
    let (_dir, vault) = open();
    let (_, holder, id, bytes, _) = fixture(&vault)?;
    let (_, other, other_id, _, _) = fixture(&vault)?;
    let outcome = vault.delete_entity_with_reason(&holder, DeleteReason::GdprDelete)?;
    assert!(vault.get_raw(&id)?.is_none());
    assert!(vault.get_raw(&other)?.is_some());
    assert!(vault.get_raw(&other_id)?.is_some());
    let raw = vault.get_raw(&outcome.receipt_id.unwrap())?.unwrap();
    let receipt = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    assert!(receipt.scope.entity_ids.contains(&id.to_hex()));
    assert!(
        vault
            .put_entity(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
            .is_err()
    );
    Ok(())
}
#[cfg(feature = "sync")]
#[test]
fn sweep_scrubs_historical_receipt_copies_without_forged_key_graph_authority() -> Result<()> {
    let (_source_dir, source) = open();
    let (_, holder, id, bytes, _) = fixture(&source)?;
    let (_dir, vault) = open();
    vault.apply_replayed_tombstone(&holder, &tombstone())?;
    let label = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let key = crate::sync::types::WindowKey::new(&label);
    let doc = crate::sync::schema::create_window_doc("receipt-fixture", &key);
    let mut blob = vec![ENTITY_TYPE_ASSET];
    for stamp in [1_u64, 1, 1] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend(&bytes);
    crate::sync::loro_support::map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
    let forged = EntityId::now();
    let survivor = EntityId::now();
    let mut truncated = blob;
    truncated.pop();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &forged.to_hex(),
        &truncated,
    )?;
    let edge =
        crate::sync::bridge::format_edge_key(&forged, crate::edge::EdgeKind::Mentions, &survivor);
    crate::sync::loro_support::map_insert_bytes(&doc.get_map("edges"), &edge, b"unrelated edge")?;
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
    let raw = vault
        .store
        .sync_state
        .get(&txn, &format!("d:w:{label}"))?
        .unwrap();
    let doc = crate::sync::loro_support::doc_from_snapshot(&raw)?;
    assert!(doc.is_shallow());
    assert!(doc.get_map("entities").get(&id.to_hex()).is_none());
    assert!(doc.get_map("entities").get(&forged.to_hex()).is_none());
    assert!(doc.get_map("edges").get(&edge).is_some());
    Ok(())
}

#[test]
fn conflicting_receipt_binding_refuses_at_raw_and_replay_admission_in_both_arrival_orders()
-> Result<()> {
    let (_origin_dir, origin) = open();
    let (actor, holder, id, bytes, reference) = fixture(&origin)?;
    let raw = origin.get_raw(&holder)?.unwrap();
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let original = super::codec::decode(&bytes)?.unwrap();
    let mut conflict = original.clone();
    let mut record = conflict.source.record()?.unwrap();
    record.outcome = "different foreign declaration".into();
    conflict.source =
        ExportReceiptSource::from_record(reference.clone(), Some(&record))?.as_imported_archive();
    let conflicting_bytes = conflict.bytes()?;
    let conflicting_id = conflict.id()?;
    for source_first in [false, true] {
        for replay in [false, true] {
            let (_dir, vault) = open();
            vault.put_entity(
                &actor,
                ENTITY_TYPE_PERSON,
                at(),
                1,
                b"archive fixture actor",
            )?;
            if !source_first {
                vault
                    .batch()
                    .put_replicated(&holder, ENTITY_TYPE_CLAIM, at(), 1, body)
                    .commit()?;
            }
            vault
                .batch()
                .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
                .commit()?;
            let attempted = if replay {
                vault
                    .batch()
                    .put_replicated(
                        &conflicting_id,
                        ENTITY_TYPE_ASSET,
                        at(),
                        1,
                        &conflicting_bytes,
                    )
                    .commit()
            } else {
                vault
                    .batch()
                    .put(
                        &conflicting_id,
                        ENTITY_TYPE_ASSET,
                        at(),
                        1,
                        &conflicting_bytes,
                    )
                    .commit()
            };
            assert!(matches!(
                attempted,
                Err(crate::error::Error::InvalidConfig(_))
            ));
            assert!(vault.get_raw(&conflicting_id)?.is_none());
            if source_first {
                vault
                    .batch()
                    .put_replicated(&holder, ENTITY_TYPE_CLAIM, at(), 1, body)
                    .commit()?;
            }
            let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
            let document = vault.read_whole_vault_json(export.bytes())?;
            let envelope = document
                .derivation_envelopes
                .iter()
                .find(|row| row.id == holder.to_hex())
                .unwrap();
            assert_eq!(envelope.receipts, vec![original.source.clone()]);
            assert_eq!(attempt_pack_receipt(&vault, &reference)?, None);
        }
    }
    Ok(())
}

#[test]
fn uncited_receipt_payload_cannot_hide_on_an_exact_holder_or_veto_its_arrival() -> Result<()> {
    let (_origin_dir, origin) = open();
    let (actor, holder, id, bytes, reference) = fixture(&origin)?;
    let raw = origin.get_raw(&holder)?.unwrap();
    let body = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    let mut uncited = super::codec::decode(&bytes)?.unwrap();
    let mut record = uncited.source.record()?.unwrap();
    record.receipt_id = format!("attempt:{}", EntityId::now().to_hex());
    uncited.source = ExportReceiptSource::from_record(record.receipt_id.clone(), Some(&record))?
        .as_imported_archive();
    let uncited_bytes = uncited.bytes()?;
    let uncited_id = uncited.id()?;
    for source_first in [false, true] {
        let (_dir, vault) = open();
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            at(),
            1,
            b"archive fixture actor",
        )?;
        if source_first {
            vault
                .batch()
                .put_replicated(&uncited_id, ENTITY_TYPE_ASSET, at(), 1, &uncited_bytes)
                .commit()?;
            assert!(vault.get_raw(&uncited_id)?.is_some());
        }
        vault
            .batch()
            .put_replicated(&holder, ENTITY_TYPE_CLAIM, at(), 1, body)
            .commit()?;
        assert!(vault.get_raw(&uncited_id)?.is_none());
        assert_eq!(vault.get_claim(&holder)?, origin.get_claim(&holder)?);
        assert!(matches!(
            vault
                .batch()
                .put_replicated(&uncited_id, ENTITY_TYPE_ASSET, at(), 1, &uncited_bytes)
                .commit(),
            Err(crate::error::Error::InvalidConfig(_))
        ));
        // A malicious pending packet never retires the actual holder or its
        // valid source slot. The correctly cited source remains admissible.
        vault
            .batch()
            .put_replicated(&id, ENTITY_TYPE_ASSET, at(), 1, &bytes)
            .commit()?;
        let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
        let document = vault.read_whole_vault_json(export.bytes())?;
        let envelope = document
            .derivation_envelopes
            .iter()
            .find(|row| row.id == holder.to_hex())
            .unwrap();
        assert_eq!(envelope.receipts.len(), 1);
        assert_eq!(envelope.receipts[0].receipt_id(), reference);
        assert_eq!(attempt_pack_receipt(&vault, &reference)?, None);
    }
    Ok(())
}
