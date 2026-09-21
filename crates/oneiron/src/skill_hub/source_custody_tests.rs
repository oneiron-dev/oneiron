//! Source payload lifetime and egress laws, not reader-only concealment.
use super::source_carrier::{encode_source_carrier, source_carrier_id};
use super::{HubFile, HubPackage, SkillPackageFormat};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::deletion::{DeleteReason, TombstoneReason, TombstoneValueV2};
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_SKILL};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash, encode_skill_record};
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};

fn at(value: u64) -> TimeRange {
    TimeRange {
        start: value,
        end: value,
    }
}
fn open() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::default())
}
fn package(version: &str) -> Result<HubPackage> {
    let files = vec![
        HubFile::new("SKILL.md", format!(
            "---\nname: custody-report\ndescription: Count lines\nversion: {version}\n---\n\nCount lines.\n"
        ).into_bytes()),
        HubFile::new("scripts/count.py", format!("# SOURCE-CUSTODY-SENTINEL-{version}\nprint(3)\n").into_bytes()),
    ];
    let hash = canonical_skill_tree_hash(
        files
            .iter()
            .map(|f| (f.path.as_str(), f.content.as_slice())),
    )?;
    let record = SkillRecord::new(
        "custody-report",
        "Count lines",
        version,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![("source".into(), "fixture".into())]),
    )
    .with_content_hash(hash);
    super::package_from_source(&record, files, SkillPackageFormat::Native)
}
fn persist(vault: &Vault, holder: &EntityId, package: &HubPackage) -> Result<EntityId> {
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, holder, &package.record, at(1), 1)?;
        vault.persist_hub_package_in_txn(txn, holder, package)
    })?;
    source_carrier_id(holder, &package.content_hash()?)
}
fn source(vault: &Vault, holder: &EntityId) -> Result<Option<HubPackage>> {
    let txn = vault.store.env.read_txn()?;
    vault.export_hub_package_in_txn(&txn, holder)
}
fn tombstone(reason: TombstoneReason) -> Vec<u8> {
    TombstoneValueV2 {
        reason,
        deleted_at: 10,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode()
    .to_vec()
}

#[test]
fn every_holder_delete_physically_removes_only_its_custody() -> Result<()> {
    for mode in [
        None,
        Some(DeleteReason::UserDelete),
        Some(DeleteReason::GdprDelete),
    ] {
        let (_dir, vault) = open();
        let a = EntityId::now();
        let b = EntityId::now();
        let package = package("1")?;
        let a_source = persist(&vault, &a, &package)?;
        let b_source = persist(&vault, &b, &package)?;
        assert_ne!(a_source, b_source);
        match mode {
            None => vault.batch().delete(&a).commit()?,
            Some(reason) => {
                vault.delete_entity_with_reason(&a, reason)?;
            }
        }
        assert!(vault.get_raw(&a_source)?.is_none());
        assert!(source(&vault, &a)?.is_none());
        assert!(vault.get_raw(&b_source)?.is_some());
        assert_eq!(source(&vault, &b)?.unwrap().files, package.files);
        assert_eq!(
            vault
                .put_entity(
                    &a_source,
                    ENTITY_TYPE_ASSET,
                    at(20),
                    20,
                    &encode_source_carrier(&a, &package)?
                )
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    Ok(())
}

#[test]
fn deleting_carrier_also_erases_the_duplicate_sidecar_without_deleting_holder() -> Result<()> {
    let (_dir, vault) = open();
    let holder = EntityId::now();
    let carrier = persist(&vault, &holder, &package("1")?)?;
    vault.batch().delete(&carrier).commit()?;
    assert!(vault.get_raw(&carrier)?.is_none());
    assert!(vault.get_skill_record(&holder)?.is_some());
    // A dead carrier cannot be bypassed by reading the source sidecar.
    assert!(source(&vault, &holder)?.is_none());
    let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    assert!(!String::from_utf8_lossy(export.bytes()).contains("SOURCE-CUSTODY-SENTINEL"));
    Ok(())
}

#[test]
fn absent_holder_and_carrier_tombstones_refuse_late_source_on_raw_and_replay_doors() -> Result<()> {
    for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
        for erase_carrier in [false, true] {
            let (_dir, vault) = open();
            let holder = EntityId::now();
            let package = package("1")?;
            let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
            let bytes = encode_source_carrier(&holder, &package)?;
            vault.apply_replayed_tombstone(
                if erase_carrier { &carrier } else { &holder },
                &tombstone(reason),
            )?;
            assert_eq!(
                vault
                    .put_entity(&carrier, ENTITY_TYPE_ASSET, at(2), 2, &bytes)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSkillBody
            );
            assert_eq!(
                vault
                    .batch()
                    .put_replicated(&carrier, ENTITY_TYPE_ASSET, at(2), 2, &bytes)
                    .commit()
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidSkillBody
            );
            assert!(vault.get_raw(&carrier)?.is_none());
        }
    }
    Ok(())
}

#[test]
fn pending_source_is_purged_by_holder_tombstone_without_a_skill_header() -> Result<()> {
    for reason in [TombstoneReason::UserDelete, TombstoneReason::GdprDelete] {
        let (_dir, vault) = open();
        let holder = EntityId::now();
        let package = package("1")?;
        let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
        vault
            .batch()
            .put_replicated(
                &carrier,
                ENTITY_TYPE_ASSET,
                at(1),
                1,
                &encode_source_carrier(&holder, &package)?,
            )
            .commit()?;
        vault.apply_replayed_tombstone(&holder, &tombstone(reason))?;
        assert!(vault.get_raw(&carrier)?.is_none());
        assert!(vault.get_raw(&holder)?.is_none());
    }
    Ok(())
}

#[test]
fn clean_source_replay_order_survives_separate_commits_and_exports_no_standalone_asset()
-> Result<()> {
    for first in [true, false] {
        let (_dir, vault) = open();
        let holder = EntityId::now();
        let package = package("1")?;
        let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
        for carrier_turn in [first, !first] {
            if carrier_turn {
                vault
                    .batch()
                    .put_replicated(
                        &carrier,
                        ENTITY_TYPE_ASSET,
                        at(1),
                        1,
                        &encode_source_carrier(&holder, &package)?,
                    )
                    .commit()?;
            } else {
                vault
                    .batch()
                    .put_replicated(
                        &holder,
                        ENTITY_TYPE_SKILL,
                        at(1),
                        1,
                        &encode_skill_record(&package.record)?,
                    )
                    .commit()?;
            }
        }
        assert_eq!(source(&vault, &holder)?.unwrap().files, package.files);
        let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
        let document = vault.read_whole_vault_json(export.bytes())?;
        assert!(
            !document
                .entities()
                .any(|entity| entity.id == carrier.to_hex())
        );
        assert!(
            document
                .skills
                .iter()
                .any(|skill| skill.entity.id == holder.to_hex() && skill.source_tree.is_some())
        );
    }
    Ok(())
}

#[test]
fn updates_purge_old_source_without_losing_new_source_in_either_arrival_order() -> Result<()> {
    for new_carrier_first in [true, false] {
        let (_dir, vault) = open();
        let holder = EntityId::now();
        let old = package("1")?;
        let new = package("2")?;
        let old_carrier = persist(&vault, &holder, &old)?;
        let new_carrier = source_carrier_id(&holder, &new.content_hash()?)?;
        for carrier_turn in [new_carrier_first, !new_carrier_first] {
            if carrier_turn {
                vault
                    .batch()
                    .put_replicated(
                        &new_carrier,
                        ENTITY_TYPE_ASSET,
                        at(2),
                        2,
                        &encode_source_carrier(&holder, &new)?,
                    )
                    .commit()?;
            } else {
                vault
                    .batch()
                    .put_replicated(
                        &holder,
                        ENTITY_TYPE_SKILL,
                        at(2),
                        2,
                        &encode_skill_record(&new.record)?,
                    )
                    .commit()?;
            }
        }
        assert!(vault.get_raw(&old_carrier)?.is_none());
        assert_eq!(source(&vault, &holder)?.unwrap().files, new.files);
        assert_eq!(
            vault
                .batch()
                .put_replicated(
                    &old_carrier,
                    ENTITY_TYPE_ASSET,
                    at(3),
                    3,
                    &encode_source_carrier(&holder, &old)?
                )
                .commit()
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    Ok(())
}

#[test]
fn refused_batch_does_not_retire_or_erase_source() -> Result<()> {
    let (_dir, vault) = open();
    let holder = EntityId::now();
    let package = package("1")?;
    let carrier = persist(&vault, &holder, &package)?;
    assert!(
        vault
            .batch()
            .delete(&holder)
            .put(&EntityId::now(), ENTITY_TYPE_SKILL, at(2), 2, b"invalid")
            .commit()
            .is_err()
    );
    assert!(vault.get_raw(&carrier)?.is_some());
    assert_eq!(source(&vault, &holder)?.unwrap().files, package.files);
    Ok(())
}

#[test]
fn tainted_excluded_and_not_yet_present_holders_cannot_export_through_source_assets() -> Result<()>
{
    for mode in [0, 1, 2] {
        let (_dir, vault) = open();
        let holder = EntityId::now();
        let package = package("1")?;
        let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
        let mut session = None;
        if mode != 2 {
            persist(&vault, &holder, &package)?;
        } else {
            vault.put_entity(
                &carrier,
                ENTITY_TYPE_ASSET,
                at(1),
                1,
                &encode_source_carrier(&holder, &package)?,
            )?;
        }
        if mode == 0 {
            vault.mark_artifact_tainted(
                &holder,
                &[crate::secret_lease::SecretTaintRef {
                    secret_ref: "source-test".to_owned(),
                    generation: 0,
                }],
            )?;
        } else if mode == 1 {
            let room = vault.off_record_session_vault().enter(
                "source-test",
                crate::off_record::OffRecordBackendClass::Local,
            )?;
            let overlay = room.overlay();
            let segment = overlay.install_txn_segment()?;
            overlay.put(
                crate::session_overlay::OverlayKeyspace::Entities,
                holder.as_bytes(),
                b"overlay",
            )?;
            segment.commit()?;
            session = Some(room);
        }
        let export = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
        assert!(!String::from_utf8_lossy(export.bytes()).contains("SOURCE-CUSTODY-SENTINEL"));
        let document = vault.read_whole_vault_json(export.bytes())?;
        assert!(!document.entities().any(|row| row.id == carrier.to_hex()));
        if let Some(room) = session {
            room.close()?;
        }
    }
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_sweep_erases_a_source_present_only_in_crdt_history_by_its_holder() -> Result<()> {
    use crate::sync::loro_support::export_snapshot;
    let (_dir, vault) = open();
    let holder = EntityId::now();
    let package = package("1")?;
    let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
    vault.apply_replayed_tombstone(&holder, &tombstone(TombstoneReason::GdprDelete))?;
    let label = crate::deletion::window_label_from_timestamp(1_771_027_200);
    let key = crate::sync::types::WindowKey::new(&label);
    let doc = crate::sync::schema::create_window_doc("source-fixture", &key);
    let mut blob = vec![ENTITY_TYPE_ASSET];
    for stamp in [1_u64, 1, 1] {
        blob.extend_from_slice(&stamp.to_be_bytes());
    }
    blob.extend_from_slice(&encode_source_carrier(&holder, &package)?);
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        &carrier.to_hex(),
        &blob,
    )?;
    // Invalid carrier key and package bytes must not retain an erased
    // holder's payload merely because full package validation would fail.
    let mut malformed = blob.clone();
    malformed.pop();
    crate::sync::loro_support::map_insert_bytes(
        &doc.get_map("entities"),
        "invalid-source-key",
        &malformed,
    )?;
    doc.commit();
    let snapshot = export_snapshot(&doc)?;
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
    assert!(doc.is_shallow());
    assert!(doc.get_map("entities").get(&carrier.to_hex()).is_none());
    assert!(doc.get_map("entities").get("invalid-source-key").is_none());
    Ok(())
}

#[test]
fn a_pending_source_cannot_reserve_an_unrelated_entity_id_or_kind() -> Result<()> {
    let (_dir, vault) = open();
    let holder = EntityId::now();
    let package = package("1")?;
    let carrier = source_carrier_id(&holder, &package.content_hash()?)?;
    vault.put_entity(
        &carrier,
        ENTITY_TYPE_ASSET,
        at(1),
        1,
        &encode_source_carrier(&holder, &package)?,
    )?;
    vault.put_entity(
        &holder,
        crate::registry::ENTITY_TYPE_PERSON,
        at(2),
        2,
        b"person",
    )?;
    assert!(vault.get_raw(&carrier)?.is_none());
    assert!(vault.get_raw(&holder)?.is_some());
    Ok(())
}

#[test]
fn hard_erase_receipt_and_sweep_cover_every_admitted_source_revision() -> Result<()> {
    let (_dir, vault) = open();
    let holder = EntityId::now();
    let old = package("1")?;
    let current = package("2")?;
    let old_carrier = persist(&vault, &holder, &old)?;
    let current_carrier = persist(&vault, &holder, &current)?;
    let outcome = vault.delete_entity_with_reason(&holder, DeleteReason::GdprDelete)?;
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .entities
        .get(&txn, outcome.receipt_id.unwrap().as_bytes())?
        .unwrap();
    let receipt = crate::deletion::decode_redaction_audit_receipt(
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    let raw = vault
        .store
        .sync_queue
        .get(&txn, &outcome.sweep_key.unwrap())?
        .unwrap();
    let sweep = crate::deletion::decode_hard_erase_sweep_job(&raw)?;
    for id in [holder, old_carrier, current_carrier] {
        assert!(receipt.scope.entity_ids.contains(&id.to_hex()));
        assert!(sweep.scope.entity_ids.contains(&id.to_hex()));
    }
    Ok(())
}

#[test]
fn holderless_transport_packages_are_not_admitted_as_source_assets() -> Result<()> {
    let (_dir, vault) = open();
    let package = package("1")?;
    let holderless = super::encode_hub_package(&package)?;
    assert_eq!(
        vault
            .put_entity(&EntityId::now(), ENTITY_TYPE_ASSET, at(1), 1, &holderless)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}
