//! The same source custody laws for claim and skill refinement receipts.
use super::*;
use crate::{
    llm::decision::{
        AnswerContract, DecisionAnswer, DecisionBand, DecisionClass, DecisionQuestion,
        DecisionReceipt, DecisionRung, ProviderPin, TypedDecision,
    },
    skill_hub::{SharedSkillDelta, SharedSkillLane},
};
fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn ruling(candidate: EntityId, id: EntityId, claim: bool) -> RefinementReceipt {
    let question = DecisionQuestion {
        id: candidate,
        version: 1,
        text: "answer this".into(),
        class: DecisionClass::UsefulUpstream,
        contract: AnswerContract::Noul,
        accept_type: false,
    };
    let decision = TypedDecision {
        answer: DecisionAnswer::Noul(false),
        probability: Some(0.1),
        evidence: vec![],
        in_band: false,
        receipt: DecisionReceipt {
            question: candidate,
            question_version: 1,
            principal: EntityId::now(),
            providers: vec![ProviderPin {
                rung: DecisionRung::SystemOne,
                model: "seat".into(),
                version: "1".into(),
            }],
            band: DecisionBand::default(),
        },
        human_ask: None,
    };
    if claim {
        RefinementReceipt::Claim(ClaimRefinementMergeReceipt {
            receipt_id: id.to_hex(),
            candidate: candidate.to_hex(),
            base: EntityId::now().to_hex(),
            resident: EntityId::now().to_hex(),
            session_tag: "session:fixture".into(),
            question,
            decision,
            consent_digest: "consent".into(),
            binding: "basis".into(),
            held_out_digest: "reserve".into(),
            useful_upstream: false,
            before: None,
            after: None,
            accepted: false,
            at: 2,
        })
    } else {
        RefinementReceipt::Skill(SharedSkillMergeReceipt {
            receipt_id: id.to_hex(),
            delta: SharedSkillDelta {
                candidate: candidate.to_hex(),
                base: EntityId::now().to_hex(),
                base_binding: "basis".into(),
                content_hash: "hash".into(),
                lane: SharedSkillLane::FederationMergeBack,
                submitted_by: "member:fixture".into(),
                submitted_fork: EntityId::now().to_hex(),
            },
            consent_digest: "consent".into(),
            binding: "basis".into(),
            useful_upstream: false,
            resident: EntityId::now().to_hex(),
            question,
            decision,
            before: None,
            after: None,
            held_out_digest: "reserve".into(),
            accepted: false,
            at: 2,
        })
    }
}
fn synthetic_id(index: u32, domain: u8) -> EntityId {
    let mut bytes = [domain; 16];
    bytes[12..].copy_from_slice(&index.to_be_bytes());
    EntityId::from_bytes(bytes).expect("non-reserved test id")
}
#[test]
fn inert_source_cannot_set_local_latest_and_never_survives_candidate_delete() -> Result<()> {
    for claim in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let candidate = EntityId::now();
        let receipt = ruling(candidate, EntityId::now(), claim);
        let (id, bytes) = encode(&candidate, &receipt)?;
        let wrong = EntityId::now();
        assert!(
            vault
                .batch()
                .put(&wrong, ENTITY_TYPE_ASSET, at(1), 1, &bytes)
                .commit()
                .is_err()
        );
        vault
            .batch()
            .put(&id, ENTITY_TYPE_ASSET, at(1), 1, &bytes)
            .commit()?;
        let txn = vault.store.env.read_txn()?;
        assert!(
            vault
                .latest_refinement_receipt_in_txn(&txn, candidate)?
                .is_none(),
            "foreign source bytes must remain inert"
        );
        assert!(refinement_custody_exists_in_txn(
            &vault.store,
            &txn,
            &candidate
        )?);
        drop(txn);
        assert!(
            vault
                .batch()
                .put(&id, ENTITY_TYPE_ASSET, at(2), 2, b"different bytes")
                .commit()
                .is_err()
        );
        assert!(vault.delete_entity(&candidate)?);
        assert!(vault.get_raw(&id)?.is_none());
        let txn = vault.store.env.read_txn()?;
        assert!(!refinement_custody_exists_in_txn(
            &vault.store,
            &txn,
            &candidate
        )?);
        drop(txn);
        assert!(
            vault
                .batch()
                .put(&id, ENTITY_TYPE_ASSET, at(3), 3, &bytes)
                .commit()
                .is_err()
        );
        drop(vault);
        let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
        assert!(reopened.get_raw(&id)?.is_none());
    }
    Ok(())
}
#[test]
fn candidate_prefix_erases_over_100k_own_without_scanning_100k_unrelated() -> Result<()> {
    // Both receipt types use exactly this writer/index/eraser. Exercise both.
    for claim in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let unrelated = EntityId::now();
        let target = EntityId::now();
        let large = EntityId::now();
        let unrelated_receipt = ruling(unrelated, EntityId::now(), claim);
        let target_receipt = ruling(target, EntityId::now(), claim);
        let large_receipt = ruling(large, EntityId::now(), claim);
        let (large_id, _) = encode(&large, &large_receipt)?;
        let (other_id, _) = encode(&unrelated, &unrelated_receipt)?;
        let (target_id, _) = encode(&target, &target_receipt)?;
        vault.with_write_txn(|txn| {
            vault.put_refinement_receipt_in_txn(txn, unrelated, unrelated_receipt, at(1), 1)?;
            vault.put_refinement_receipt_in_txn(txn, target, target_receipt, at(1), 1)?;
            vault.put_refinement_receipt_in_txn(txn, large, large_receipt, at(1), 1)
        })?;
        vault.with_write_txn(|txn| {
            for i in 0..100_001 {
                let fake = synthetic_id(i, 0x52);
                vault
                    .store
                    .vault_meta
                    .put(txn, &owned_key(OWNED, &unrelated, &fake), &[])?;
                vault
                    .store
                    .vault_meta
                    .put(txn, &key(BINDING, &fake), unrelated.as_bytes())?;
            }
            Ok(())
        })?;
        assert!(
            vault.delete_entity(&target)?,
            "unrelated history cannot block deletion"
        );
        assert!(vault.get_raw(&target_id)?.is_none());
        assert!(vault.get_raw(&other_id)?.is_some());
        let extra_receipts = (0..256)
            .map(|i| ruling(large, synthetic_id(i, 0x54), claim))
            .collect::<Vec<_>>();
        let extra_ids = extra_receipts
            .iter()
            .map(|receipt| encode(&large, receipt).map(|(id, _)| id))
            .collect::<Result<Vec<_>>>()?;
        vault.with_write_txn(|txn| {
            for receipt in extra_receipts {
                vault.put_refinement_receipt_in_txn(txn, large, receipt, at(1), 1)?;
            }
            for i in 0..100_001 {
                let fake = synthetic_id(i, 0x53);
                vault
                    .store
                    .vault_meta
                    .put(txn, &owned_key(OWNED, &large, &fake), &[])?;
                vault
                    .store
                    .vault_meta
                    .put(txn, &key(BINDING, &fake), large.as_bytes())?;
            }
            Ok(())
        })?;
        // The target's own large history is erased with 128 IDs in memory at
        // a time; the other candidate's receipts and indexes stay untouched.
        assert!(vault.delete_entity(&large)?);
        assert!(vault.get_raw(&large_id)?.is_none());
        for id in extra_ids {
            assert!(vault.get_raw(&id)?.is_none());
        }
        let txn = vault.store.env.read_txn()?;
        assert!(!refinement_custody_exists_in_txn(
            &vault.store,
            &txn,
            &large
        )?);
        assert!(refinement_custody_exists_in_txn(
            &vault.store,
            &txn,
            &unrelated
        )?);
        drop(txn);
        assert!(vault.get_raw(&other_id)?.is_some());
    }
    Ok(())
}

#[test]
fn soft_tombstone_before_refinement_carrier_refuses_late_payload() -> Result<()> {
    for claim in [false, true] {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
        let candidate = EntityId::now();
        let receipt = ruling(candidate, EntityId::now(), claim);
        let (source_id, bytes) = encode(&candidate, &receipt)?;
        let tombstone = crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::UserDelete,
            deleted_at: 2,
            request_id: *EntityId::now().as_bytes(),
        }
        .encode();
        vault.apply_replayed_tombstone(&candidate, &tombstone)?;
        assert!(
            vault
                .batch()
                .put(&source_id, ENTITY_TYPE_ASSET, at(3), 3, &bytes)
                .commit()
                .is_err()
        );
        assert!(vault.get_raw(&source_id)?.is_none());
    }
    Ok(())
}

#[test]
fn over_100k_real_unrelated_carriers_cannot_strand_one_receipt_delete() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let unrelated = EntityId::now();
    let target = EntityId::now();
    let target_receipt = ruling(target, EntityId::now(), false);
    let (target_id, _) = encode(&target, &target_receipt)?;
    vault.with_write_txn(|txn| {
        vault.put_refinement_receipt_in_txn(txn, target, target_receipt, at(1), 1)
    })?;
    let mut first_unrelated = None;
    vault.with_write_txn(|txn| {
        for start in (0..100_001).step_by(128) {
            let mut batch = vault.batch_in();
            for i in start..(start + 128).min(100_001) {
                let receipt = ruling(unrelated, synthetic_id(i, 0x65), false);
                let (id, bytes) = encode(&unrelated, &receipt)?;
                if first_unrelated.is_none() {
                    first_unrelated = Some(id);
                }
                batch = batch.put(&id, ENTITY_TYPE_ASSET, at(1), 1, &bytes);
            }
            batch.apply(txn)?;
        }
        Ok(())
    })?;
    let unrelated_id = first_unrelated.expect("writer appended history");
    assert!(vault.get_raw(&unrelated_id)?.is_some());
    assert!(vault.delete_entity(&target)?);
    assert!(vault.get_raw(&target_id)?.is_none());
    assert!(vault.get_raw(&unrelated_id)?.is_some());
    let txn = vault.store.env.read_txn()?;
    assert!(refinement_custody_exists_in_txn(
        &vault.store,
        &txn,
        &unrelated
    )?);
    drop(txn);
    drop(vault);
    let reopened = Vault::open(dir.path(), crate::VaultConfig::default())?;
    assert!(reopened.get_raw(&target_id)?.is_none());
    assert!(reopened.get_raw(&unrelated_id)?.is_some());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn historical_refinement_carrier_scrubs_by_holder_without_trusting_forged_key() -> Result<()> {
    use crate::sync::loro_support::export_snapshot;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let holder = EntityId::now();
    let receipt = ruling(holder, EntityId::now(), false);
    let (carrier, bytes) = encode(&holder, &receipt)?;
    vault.with_write_txn(|txn| {
        vault.put_refinement_receipt_in_txn(txn, holder, receipt, at(1), 1)
    })?;
    assert!(
        vault
            .delete_entity_with_reason(&holder, crate::deletion::DeleteReason::GdprDelete)?
            .existed
    );
    assert!(vault.get_raw(&carrier)?.is_none());
    let label = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let window = crate::sync::types::WindowKey::new(&label);
    let doc = crate::sync::schema::create_window_doc("refinement-fixture", &window);
    let mut blob = vec![ENTITY_TYPE_ASSET];
    for stamp in [1_u64, 1, 1] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(&bytes);
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &carrier.to_hex(),
        &blob,
    )?;
    let mut malformed = blob.clone();
    malformed.pop();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        "forged-source-key",
        &malformed,
    )?;
    doc.commit();
    vault.with_write_txn(|txn| {
        vault
            .store
            .sync_state
            .put(txn, &format!("d:w:{label}"), &export_snapshot(&doc)?)?;
        Ok(())
    })?;
    crate::sweep::run_hard_erase_sweep(&vault)?;
    let txn = vault.store.env.read_txn()?;
    let compacted = vault
        .store
        .sync_state
        .get(&txn, &format!("d:w:{label}"))?
        .unwrap();
    let compacted = crate::sync::loro_support::doc_from_snapshot(&compacted)?;
    assert!(
        compacted
            .get_map("entities")
            .get(&carrier.to_hex())
            .is_none()
    );
    assert!(
        compacted
            .get_map("entities")
            .get("forged-source-key")
            .is_none()
    );
    Ok(())
}
