//! Replicated source custody: ordinary ASSET carriers replay in any order,
//! export recovers the exact package, drift fails closed.
use super::package_codec::encode_hub_package;
use super::source_carrier::source_carrier_id;
use super::{HubFile, SkillPackageFormat, decode_hub_package};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use crate::temporal::TimeRange;
use crate::{Vault, VaultConfig};

fn at(value: u64) -> TimeRange {
    TimeRange {
        start: value,
        end: value,
    }
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("replication fixture directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("replication fixture vault");
    (dir, vault)
}

fn files() -> Vec<HubFile> {
    vec![
        HubFile::new(
            "SKILL.md",
            b"---\nname: replicate-report\ndescription: Count lines\nversion: 1\n---\n\nCount lines.\n"
                .to_vec(),
        ),
        HubFile::new("scripts/count.py", b"print(3)\n".to_vec()),
    ]
}

fn persisted() -> (tempfile::TempDir, Vault, EntityId, SkillRecord, Vec<u8>) {
    let (dir, vault) = open();
    let hash = canonical_skill_tree_hash(
        files()
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )
    .expect("fixture hash");
    let record = SkillRecord::new(
        "replicate-report",
        "Count lines",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("replication-fixture"),
        )]),
    )
    .with_content_hash(hash);
    let package =
        super::package_from_source(&record, files(), SkillPackageFormat::Native).expect("package");
    let id = EntityId::now();
    vault
        .with_write_txn(|txn| {
            vault.put_skill_record_in_txn(txn, &id, &record, at(1), 1)?;
            vault.persist_hub_package_in_txn(txn, &id, &package)
        })
        .expect("persist with carrier");
    let canonical =
        super::source_carrier::canonical_source_package(&package).expect("canonical custody");
    let encoded = encode_hub_package(&canonical).expect("carrier bytes");
    assert_eq!(
        decode_hub_package(&encoded).expect("carrier decodes"),
        canonical
    );
    (dir, vault, id, record, encoded)
}

fn replayed_skill_body(record: &SkillRecord) -> Vec<u8> {
    crate::skill::encode_skill_record(record).expect("skill body")
}

#[test]
fn replicated_asset_and_skill_replay_recovers_exact_source_in_both_orders() -> Result<()> {
    let (_dir, _vault, id, record, carrier_bytes) = persisted();
    let carrier = source_carrier_id(&record.content_hash.expect("hash")).expect("carrier id");
    let skill_bytes = replayed_skill_body(&record);
    for carrier_first in [true, false] {
        let (_target_dir, target) = open();
        let batch = target.batch();
        let batch = if carrier_first {
            batch
                .put_replicated(&carrier, ENTITY_TYPE_ASSET, at(5), 5, &carrier_bytes)
                .put_replicated(
                    &id,
                    crate::registry::ENTITY_TYPE_SKILL,
                    at(5),
                    5,
                    &skill_bytes,
                )
        } else {
            batch
                .put_replicated(
                    &id,
                    crate::registry::ENTITY_TYPE_SKILL,
                    at(5),
                    5,
                    &skill_bytes,
                )
                .put_replicated(&carrier, ENTITY_TYPE_ASSET, at(5), 5, &carrier_bytes)
        };
        batch.commit()?;
        let txn = target.store.env.read_txn()?;
        let package = target
            .export_hub_package_in_txn(&txn, &id)?
            .expect("carrier-backed source");
        assert_eq!(package.content_hash()?, record.content_hash.expect("hash"));
        assert_eq!(package.export_files()?, files());
        assert_eq!(
            target
                .hub_package_from_carrier_in_txn(&txn, &record)?
                .expect("direct carrier recovery"),
            package
        );
    }
    Ok(())
}

#[test]
fn replicated_source_drift_and_carrier_overwrite_fail_closed() -> Result<()> {
    let (_dir, _vault, id, record, carrier_bytes) = persisted();
    let carrier = source_carrier_id(&record.content_hash.expect("hash")).expect("carrier id");
    // Same hash, forged description: the carrier must not present as this skill.
    let mut forged = record.clone();
    forged.desc = "Forged instructions".into();
    let (_target_dir, target) = open();
    target
        .batch()
        .put_replicated(&carrier, ENTITY_TYPE_ASSET, at(5), 5, &carrier_bytes)
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_SKILL,
            at(5),
            5,
            &replayed_skill_body(&forged),
        )
        .commit()?;
    let txn = target.store.env.read_txn()?;
    assert_eq!(
        target
            .export_hub_package_in_txn(&txn, &id)
            .expect_err("drifted source fails closed")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    drop(txn);
    // The carrier itself is immutable on every door once written.
    assert_eq!(
        target
            .put_entity(&carrier, ENTITY_TYPE_ASSET, at(6), 6, b"replacement")
            .expect_err("carrier cannot be overwritten")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        target
            .batch()
            .put_replicated(&carrier, ENTITY_TYPE_ASSET, at(6), 6, b"replacement")
            .commit()
            .expect_err("replay cannot overwrite a carrier")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let txn = target.store.env.read_txn()?;
    assert_eq!(
        target
            .export_hub_package_in_txn(&txn, &id)
            .expect_err("carrier still refuses the drifted skill")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

#[test]
fn carrier_is_credential_nulled_on_export_and_clean_source_roundtrips() -> Result<()> {
    let (_dir, vault, id, record, bytes) = persisted();
    let body = crate::serialize::ExportBody::from_bytes(&bytes, ENTITY_TYPE_ASSET);
    body.validate(ENTITY_TYPE_ASSET)?;
    assert_eq!(body.to_bytes()?, bytes);
    let exported = vault.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    let (_target_dir, target) = open();
    target.import_whole_vault_json(exported.bytes())?;
    let txn = target.store.env.read_txn()?;
    assert_eq!(
        target
            .export_hub_package_in_txn(&txn, &id)?
            .unwrap()
            .export_files()?,
        files()
    );
    drop(txn);
    let mut package = decode_hub_package(&bytes)?;
    package.files.push(HubFile::new(
        "private.env",
        b"api_key=not-pattern-recognizable\n".to_vec(),
    ));
    package.record.content_hash = Some(package.content_hash()?);
    // Residual storage fixture bypasses ingress: the serializer must still null it.
    package.format = SkillPackageFormat::Folder;
    let unsafe_bytes = encode_hub_package(&package)?;
    let redacted = crate::serialize::ExportBody::from_bytes(&unsafe_bytes, ENTITY_TYPE_ASSET);
    let serialized = serde_json::to_string(&redacted).unwrap();
    assert!(!serialized.contains("not-pattern-recognizable"));
    assert!(redacted.to_bytes().is_err());
    assert_eq!(
        record.content_hash,
        target.get_skill_record(&id)?.unwrap().content_hash
    );
    Ok(())
}
