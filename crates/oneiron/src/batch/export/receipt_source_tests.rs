//! Readable task trace sources are data, never local receipt authority.
use super::*;
use crate::actor_claims::{ActorClaimEvidence, ActorClaimRow, write_actor_claim};
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    ManifestEntry, ManifestKind,
};
use crate::context_pack::PackFormat;
use crate::error::Result;
use crate::receipt::{ReceiptRecord, attempt_pack_receipt, attempt_pack_receipt_id};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;
use crate::{EntityId, Vault, VaultConfig};

fn fixture(vault: &Vault) -> Result<(EntityId, ReceiptRecord)> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"archive actor",
    )?;
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "archive.trace".into(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("new attempt")
    };
    queue.append_manifest_entry(
        row.id,
        ManifestEntry::new(ManifestKind::Skill, "archive.fixture.skill", "1.0.0", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "archive.trace",
        ClaimAttempt {
            lease_owner: "host".into(),
            now: 12,
        },
    )?
    else {
        panic!("leased")
    };
    queue.complete(CompleteAttempt {
        id: row.id,
        lease_owner: "host".into(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;
    let receipt = attempt_pack_receipt(vault, &attempt_pack_receipt_id(&row.id))?.unwrap();
    let claim = write_actor_claim(
        vault,
        ActorClaimRow::Lesson {
            actor,
            text: "Use a scoped check before review".into(),
        },
        &ActorClaimEvidence::task(vec![receipt.receipt_id.clone()], 14)?,
    )?;
    Ok((claim, receipt))
}
#[test]
fn archived_task_receipt_retains_actual_manifest_but_cannot_stamp_a_receiving_vault() -> Result<()>
{
    let (_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let (claim, receipt) = fixture(&source)?;
    for format in [
        PackFormat::Json,
        PackFormat::Markdown,
        PackFormat::Toon,
        PackFormat::Yaml,
        PackFormat::Plaintext,
    ] {
        let export = source.export_whole_vault(format)?;
        assert!(!export.bytes().is_empty());
        assert!(String::from_utf8_lossy(export.bytes()).contains(&receipt.receipt_id));
    }
    let export = source.export_whole_vault(PackFormat::Json)?;
    let document = target.read_whole_vault_json(export.bytes())?;
    let envelope = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    assert_eq!(envelope.receipts.len(), 1);
    assert_eq!(envelope.receipts[0].record()?, Some(receipt.clone()));
    assert_eq!(attempt_pack_receipt(&target, &receipt.receipt_id)?, None);
    // An unrelated citation or duplicate cannot be attached to a native row.
    let mut altered = document.clone();
    let envelope = altered
        .derivation_envelopes
        .iter_mut()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    envelope.receipts.push(envelope.receipts[0].clone());
    assert!(
        target
            .read_whole_vault_json(&serde_json::to_vec(&altered).unwrap())
            .is_err()
    );
    let mut altered = document;
    let envelope = altered
        .derivation_envelopes
        .iter_mut()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    envelope.receipts[0] = ExportReceiptSource::Unavailable {
        receipt_id: format!("attempt:{}", EntityId::now().to_hex()),
        reason: ReceiptSourceOmission::NotStored,
    };
    assert!(
        target
            .read_whole_vault_json(&serde_json::to_vec(&altered).unwrap())
            .is_err()
    );
    Ok(())
}
#[test]
fn missing_or_credential_bearing_receipt_sources_are_explicit_never_fabricated() -> Result<()> {
    let (_dir, source) = open_test_vault_with(VaultConfig::default());
    let (claim, mut receipt) = fixture(&source)?;
    let mut key = b"attempt_receipt:v1:".to_vec();
    key.extend_from_slice(receipt.receipt_id.as_bytes());
    // Simulate an already-persisted secret. The export must independently null it.
    let secret = format!("ghp_{}", "c".repeat(36));
    receipt.fields.insert("api_key".into(), secret.clone());
    let raw = rmp_serde::to_vec_named(&receipt).unwrap();
    source.with_write_txn(|txn| {
        source.store.vault_meta.put(txn, &key, &raw)?;
        Ok(())
    })?;
    for format in [
        PackFormat::Json,
        PackFormat::Markdown,
        PackFormat::Toon,
        PackFormat::Yaml,
        PackFormat::Plaintext,
    ] {
        let export = source.export_whole_vault(format)?;
        assert!(!String::from_utf8_lossy(export.bytes()).contains(&secret));
    }
    let export = source.export_whole_vault(PackFormat::Json)?;
    let document = source.read_whole_vault_json(export.bytes())?;
    let envelope = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    assert_eq!(
        envelope.receipts,
        vec![ExportReceiptSource::Unavailable {
            receipt_id: receipt.receipt_id.clone(),
            reason: ReceiptSourceOmission::CredentialRedaction
        }]
    );
    source.with_write_txn(|txn| {
        source.store.vault_meta.delete(txn, &key)?;
        Ok(())
    })?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    let document = source.read_whole_vault_json(export.bytes())?;
    let envelope = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    assert_eq!(
        envelope.receipts,
        vec![ExportReceiptSource::Unavailable {
            receipt_id: receipt.receipt_id,
            reason: ReceiptSourceOmission::NotStored
        }]
    );
    Ok(())
}

#[test]
fn real_cited_receipt_source_survives_import_reopen_and_reexport_without_native_authority()
-> Result<()> {
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (target_dir, target) = open_test_vault_with(VaultConfig::default());
    let (claim, receipt) = fixture(&source)?;
    let archive = source.export_whole_vault(PackFormat::Json)?;
    let imported = target.import_whole_vault_json(archive.bytes())?;
    assert_eq!(imported.archived_receipt_sources, 1);
    assert_eq!(
        target
            .import_whole_vault_json(archive.bytes())?
            .archived_receipt_sources,
        0
    );
    assert_eq!(attempt_pack_receipt(&target, &receipt.receipt_id)?, None);
    drop(target);
    let target = Vault::open(target_dir.path(), VaultConfig::default())?;
    let reexport = target.export_whole_vault(PackFormat::Json)?;
    let document = target.read_whole_vault_json(reexport.bytes())?;
    let row = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == claim.to_hex())
        .unwrap();
    assert_eq!(row.receipts[0].record()?, Some(receipt.clone()));
    assert!(matches!(
        row.receipts[0],
        ExportReceiptSource::Preserved {
            origin: ReceiptSourceOrigin::ImportedArchive,
            ..
        }
    ));
    let (_third_dir, third) = open_test_vault_with(VaultConfig::default());
    third.import_whole_vault_json(reexport.bytes())?;
    assert_eq!(attempt_pack_receipt(&third, &receipt.receipt_id)?, None);
    // Receipt contents cannot change while their holder/body/reference remains identical.
    let mut forged = source.read_whole_vault_json(archive.bytes())?;
    let mut different = receipt.clone();
    different.outcome = "foreign altered outcome".into();
    forged
        .derivation_envelopes
        .iter_mut()
        .find(|row| row.id == claim.to_hex())
        .unwrap()
        .receipts[0] =
        ExportReceiptSource::from_record(receipt.receipt_id.clone(), Some(&different))?;
    assert!(
        target
            .import_whole_vault_json(&serde_json::to_vec(&forged).unwrap())
            .is_err()
    );
    let after = target.export_whole_vault(PackFormat::Json)?;
    let after = target.read_whole_vault_json(after.bytes())?;
    assert_eq!(
        after
            .derivation_envelopes
            .iter()
            .find(|row| row.id == claim.to_hex())
            .unwrap()
            .receipts[0]
            .record()?,
        Some(receipt)
    );
    Ok(())
}

#[test]
fn receipt_id_collision_cannot_replace_either_bound_archive_or_native_terminal_data() -> Result<()>
{
    let (_source_dir, source) = open_test_vault_with(VaultConfig::default());
    let (_target_dir, target) = open_test_vault_with(VaultConfig::default());
    let (imported_claim, _) = fixture(&source)?;
    let (native_claim, native_receipt) = fixture(&target)?;
    let export = source.export_whole_vault(PackFormat::Json)?;
    let mut document = source.read_whole_vault_json(export.bytes())?;
    // This is deliberately hostile foreign data, not a claimed local terminal
    // act. It alleges the same receipt ID as a real local terminal event.
    let claim = document
        .claims
        .iter_mut()
        .find(|row| row.id == imported_claim.to_hex())
        .unwrap();
    let mut body = crate::claim::decode_claim_body(&claim.body.to_bytes()?, true)?;
    let Some(rmpv::Value::Map(evidence)) = &mut body.evidence else {
        panic!("task evidence");
    };
    *evidence
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("receipts"))
        .unwrap() = (
        "receipts".into(),
        rmpv::Value::Array(vec![native_receipt.receipt_id.clone().into()]),
    );
    claim.body = crate::serialize::ExportBody::from_bytes(
        &crate::claim::encode_claim_body(&body)?,
        crate::registry::ENTITY_TYPE_CLAIM,
    );
    let crate::serialize::ExportBody::MessagePack(crate::serialize::ExportValue::Map(entries)) =
        &claim.body
    else {
        panic!("claim tree");
    };
    let evidence = entries
        .iter()
        .find(|(key, _)| matches!(key,crate::serialize::ExportValue::String(key) if key=="evid"))
        .unwrap()
        .1
        .clone();
    let envelope = document
        .derivation_envelopes
        .iter_mut()
        .find(|row| row.id == imported_claim.to_hex())
        .unwrap();
    envelope.evidence = evidence;
    let mut foreign = native_receipt.clone();
    foreign
        .fields
        .insert("foreign_fixture".into(), "different untrusted data".into());
    envelope.receipts = vec![ExportReceiptSource::from_record(
        foreign.receipt_id.clone(),
        Some(&foreign),
    )?];
    target.import_whole_vault_json(&serde_json::to_vec(&document).unwrap())?;
    assert_eq!(
        attempt_pack_receipt(&target, &native_receipt.receipt_id)?,
        Some(native_receipt.clone())
    );
    let export = target.export_whole_vault(PackFormat::Json)?;
    let document = target.read_whole_vault_json(export.bytes())?;
    let imported = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == imported_claim.to_hex())
        .unwrap();
    assert_eq!(imported.receipts[0].record()?, Some(foreign));
    assert!(matches!(
        imported.receipts[0],
        ExportReceiptSource::Preserved {
            origin: ReceiptSourceOrigin::ImportedArchive,
            ..
        }
    ));
    let native = document
        .derivation_envelopes
        .iter()
        .find(|row| row.id == native_claim.to_hex())
        .unwrap();
    assert_eq!(native.receipts[0].record()?, Some(native_receipt));
    assert!(matches!(
        native.receipts[0],
        ExportReceiptSource::Preserved {
            origin: ReceiptSourceOrigin::CapturedLocalTerminal,
            ..
        }
    ));
    Ok(())
}
