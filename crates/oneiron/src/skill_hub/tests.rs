use super::*;
use crate::skill::SkillGovernanceTier;
use crate::skill_optimize::{SkillTierVerdict, skill_governance_tier};

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn fixture_hash() -> SkillContentHash {
    canonical_skill_tree_hash([("SKILL.md", b"# fixture\n".as_slice())]).expect("fixture hash")
}

fn candidate(skill_id: &str) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "fixture description",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("fixture"))]),
    )
    .with_content_hash(fixture_hash())
}

fn package(record: SkillRecord, capabilities: SkillCapabilitySurface) -> HubPackage {
    HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", b"# fixture\n".to_vec())],
        capabilities,
    )
}

fn package_with_content(
    mut record: SkillRecord,
    content: &[u8],
    capabilities: SkillCapabilitySurface,
) -> HubPackage {
    record.content_hash =
        Some(canonical_skill_tree_hash([("SKILL.md", content)]).expect("package content hash"));
    HubPackage::new(
        record,
        vec![HubFile::new("SKILL.md", content.to_vec())],
        capabilities,
    )
}

fn hub_ref(pin: HubPin) -> HubRef {
    HubRef::new(EntityId::now(), "skills/example", pin).expect("hub ref")
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let temp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(temp.path(), crate::VaultConfig::default()).expect("open vault");
    (temp, vault)
}

fn materialize_shared_hash_skills(vault: &Vault) -> Result<(EntityId, EntityId)> {
    let local_entity = EntityId::now();
    let mut local = candidate("fixture.local-shared-hash");
    local.source = ClaimSource::UserStated;
    vault.put_skill_record(&local_entity, &local, t(1), 2)?;

    let imported_entity = EntityId::now();
    let imported = package(
        candidate("fixture.imported-shared-hash"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(
        &hub_ref(HubPin::None),
        &imported,
        imported_entity,
        t(3),
        4,
    )?;
    Ok((local_entity, imported_entity))
}

/// Active verdict rows for `content_hash`, minus the engine's OWN static
/// receipt.
///
/// ONE-1892 wired a producer into the import/sync doors, so every hub
/// import now mints an `oneiron.static.v1` row for the bytes it lands.
/// These assertions are about the third-party providers the test ingests,
/// and counting the engine's own row alongside them would measure the
/// producer instead of the contract under test (the producer has its own
/// coverage in `skill_scan::tests`).
fn third_party_verdicts(vault: &Vault, content_hash: SkillContentHash) -> Result<Vec<ClaimBody>> {
    Ok(vault
        .skill_scan_verdicts_for_content_hash(content_hash)?
        .into_iter()
        .filter(|body| {
            map_text(&body.value, "provider") != Some(crate::skill_scan::SCAN_PROVIDER_STATIC_V1)
        })
        .collect())
}

fn scan_verdict_body(subject: EntityId, provider: &str, scanned_at: u64) -> ClaimBody {
    let mut body = ClaimBody::new(
        PREDICATE_SKILL_SCAN_VERDICT,
        ClaimSubject::Entity(subject),
        Value::Map(vec![
            (
                Value::from("contentHash"),
                Value::from(fixture_hash().to_hex()),
            ),
            (Value::from("provider"), Value::from(provider)),
            (Value::from("scannedAt"), Value::from(scanned_at)),
            (Value::from("verdict"), Value::from("clean")),
            (Value::from("riskLevel"), Value::from("low")),
            (Value::from("completeness"), Value::from("complete")),
            (Value::from("governance"), Value::from("recommended")),
        ]),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body
}

#[test]
fn hub_package_rejects_file_count_above_limit() {
    let files = (0..=MAX_HUB_PACKAGE_FILES)
        .map(|index| HubFile::new(format!("file-{index}"), Vec::new()))
        .collect();
    let package = HubPackage::new(
        candidate("fixture.file-count-limit"),
        files,
        SkillCapabilitySurface::default(),
    );

    assert_eq!(package.files.len(), MAX_HUB_PACKAGE_FILES + 1);
    assert_eq!(
        package
            .content_hash()
            .expect_err("file count must be capped")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        package
            .export_files()
            .expect_err("export file count must be capped")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
}

#[test]
fn hub_package_rejects_total_bytes_above_limit() {
    let bytes_per_file = MAX_HUB_PACKAGE_TOTAL_BYTES / 3 + 1;
    assert!(bytes_per_file < MAX_HUB_FILE_BYTES);
    let files = (0..3)
        .map(|index| HubFile::new(format!("file-{index}"), vec![0; bytes_per_file]))
        .collect();
    let package = HubPackage::new(
        candidate("fixture.total-bytes-limit"),
        files,
        SkillCapabilitySurface::default(),
    );

    assert!(
        package
            .files
            .iter()
            .map(|file| file.content.len())
            .sum::<usize>()
            > MAX_HUB_PACKAGE_TOTAL_BYTES
    );
    assert_eq!(
        package
            .content_hash()
            .expect_err("total bytes must be capped")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        package
            .export_files()
            .expect_err("export bytes must be capped")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
}

#[test]
fn hub_package_accepts_normal_small_package() -> Result<()> {
    let package = package(
        candidate("fixture.normal-package"),
        SkillCapabilitySurface::default(),
    );

    assert_eq!(package.content_hash()?, fixture_hash());
    assert_eq!(package.export_files()?, package.files);
    Ok(())
}

#[test]
fn checked_adapter_ingest_refuses_declared_hash_mismatch_before_writes() -> Result<()> {
    let (_temp, vault) = open_vault();
    let hub_id = EntityId::now();
    let target = EntityId::now();
    let package = package(
        candidate("fixture.checked-adapter"),
        SkillCapabilitySurface::default(),
    );
    let alternate_hash =
        canonical_skill_tree_hash([("SKILL.md", b"# alternate adapter bytes\n".as_slice())])?;
    let mut adapter = LocalDirSkillHubAdapter::new(hub_id);
    adapter.insert_package(
        "skills/checked-adapter",
        HubPin::ContentHash(alternate_hash.to_hex()),
        package.clone(),
    );
    let mismatched_entry = HubIndexEntry {
        name: "checked-adapter".to_owned(),
        description: "fixture".to_owned(),
        version: "1.0.0".to_owned(),
        content_hash: alternate_hash,
        ref_string: "skills/checked-adapter".to_owned(),
    };

    vault
        .ingest_skill_from_adapter_checked(&adapter, &mismatched_entry, target, t(1), 2)
        .expect_err("declared hash mismatch must refuse before import");
    assert_eq!(vault.get_skill_record(&target)?, None);
    assert!(vault.claims_for_subject(&target)?.is_empty());

    adapter.insert_package(
        "skills/checked-adapter",
        HubPin::ContentHash(fixture_hash().to_hex()),
        package,
    );
    let matching_entry = HubIndexEntry {
        content_hash: fixture_hash(),
        ..mismatched_entry
    };
    assert_eq!(
        vault.ingest_skill_from_adapter_checked(&adapter, &matching_entry, target, t(3), 4,)?,
        target
    );
    let stored = vault
        .get_skill_record(&target)?
        .expect("matching package materialized");
    assert_eq!(stored.content_hash, Some(fixture_hash()));
    assert_eq!(stored.lifecycle_status, SkillLifecycle::Candidate);
    Ok(())
}

#[test]
fn audit_ingest_preserves_independent_provider_rows_and_lifecycle() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let imported = package(
        candidate("fixture.audit-batch"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &imported, entity, t(1), 2)?;
    let before = vault
        .get_skill_record(&entity)?
        .expect("imported candidate");
    let receipts = [
        SkillScanReceipt::new(
            "alpha",
            3,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Complete,
            SkillGovernance::Recommended,
        )?,
        SkillScanReceipt::new(
            "beta",
            3,
            ScanVerdict::Malicious,
            ScanRiskLevel::Critical,
            ScanCompleteness::Complete,
            SkillGovernance::Prohibited,
        )?,
        SkillScanReceipt::new(
            "gamma",
            3,
            ScanVerdict::Clean,
            ScanRiskLevel::Low,
            ScanCompleteness::Partial,
            SkillGovernance::Recommended,
        )?,
    ];

    assert_eq!(
        vault.ingest_skill_audit_verdicts(&entity, fixture_hash(), &receipts, t(3), 4)?,
        3
    );
    // ONE-1741: audit verdicts anchor to the content bytes, discovered by
    // content hash rather than the submitting holder's subject edges.
    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(rows.len(), 3);
    let providers = rows
        .iter()
        .filter_map(|body| map_text(&body.value, "provider"))
        .collect::<BTreeSet<_>>();
    assert_eq!(providers, BTreeSet::from(["alpha", "beta", "gamma"]));
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("skill remains materialized")
            .lifecycle_status,
        before.lifecycle_status
    );
    Ok(())
}

#[test]
fn audit_ingest_rejects_bad_middle_receipt_atomically() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let imported = package(
        candidate("fixture.audit-atomic"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &imported, entity, t(1), 2)?;
    let first = SkillScanReceipt::new(
        "first",
        3,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    let mut bad = first.clone();
    bad.provider.clear();
    let last = SkillScanReceipt::new(
        "last",
        3,
        ScanVerdict::Suspicious,
        ScanRiskLevel::High,
        ScanCompleteness::Partial,
        SkillGovernance::Discouraged,
    )?;

    let error = vault
        .ingest_skill_audit_verdicts(&entity, fixture_hash(), &[first, bad, last], t(3), 4)
        .expect_err("a malformed middle receipt must reject the whole batch");
    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
    assert!(
        vault
            .active_claims_for_predicate(&entity, PREDICATE_SKILL_SCAN_VERDICT)?
            .is_empty()
    );
    Ok(())
}

#[test]
fn content_hash_index_returns_every_entity_for_shared_bytes() -> Result<()> {
    let (_temp, vault) = open_vault();
    let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
    let rtxn = vault.store.env.read_txn()?;
    let indexed = vault
        .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
        .into_iter()
        .map(|(entity, _)| entity)
        .collect::<BTreeSet<_>>();

    assert_eq!(indexed, BTreeSet::from([local_entity, imported_entity]));
    Ok(())
}

#[test]
fn deleting_skill_cleans_index_and_stale_rows_do_not_block_import_dedup() -> Result<()> {
    let (_temp, vault) = open_vault();
    let imported = package(
        candidate("fixture.delete-index"),
        SkillCapabilitySurface::default(),
    );
    let entity = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(1), 2)?;
    let key = content_hash_index_key(fixture_hash(), &entity);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_some());
    drop(rtxn);

    // Deleting the holder drops its content-hash index row, so import dedup
    // stops resolving the departed entity. (Scan verdicts are unaffected:
    // they anchor to the content bytes, not to this holder — see the
    // anchor-invariant tests.)
    assert!(vault.delete_entity(&entity)?);
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_none());
    assert!(
        vault
            .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
            .is_empty()
    );
    drop(rtxn);

    // A lagging index row whose entity no longer exists must be skipped by
    // the rebuildable-index reader, never resurrecting a departed holder.
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.vault_meta.put(&mut wtxn, &key, &[])?;
    wtxn.commit()?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
            .is_empty()
    );
    drop(rtxn);

    // Re-importing the same bytes mints a fresh entity (the stale row does
    // not block it), and a second import dedups to that entity.
    let reimported = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;
    assert_ne!(reimported, entity);
    assert_eq!(
        vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(5), 6,)?,
        reimported
    );
    Ok(())
}

#[test]
fn soft_erasing_skill_cleans_content_hash_index_before_body_truncation() -> Result<()> {
    let (_temp, vault) = open_vault();
    let imported = package(
        candidate("fixture.soft-delete-index"),
        SkillCapabilitySurface::default(),
    );
    let entity = vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(1), 2)?;
    let key = content_hash_index_key(fixture_hash(), &entity);

    vault.delete_entity_with_reason(&entity, crate::DeleteReason::UserDelete)?;

    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.store.vault_meta.get(&rtxn, &key)?.is_none());
    drop(rtxn);
    assert!(third_party_verdicts(&vault, fixture_hash())?.is_empty());
    Ok(())
}

#[test]
fn open_backfills_pre_index_structured_skills() -> Result<()> {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().to_path_buf();
    let vault = Vault::open(&path, crate::VaultConfig::default())?;
    let entity = EntityId::now();
    let imported = package(
        candidate("fixture.pre-index"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &imported, entity, t(1), 2)?;

    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, &content_hash_index_key(fixture_hash(), &entity))?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?;
    wtxn.commit()?;
    drop(vault);

    let vault = Vault::open(&path, crate::VaultConfig::default())?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .structured_skills_for_content_hash_in_txn(&rtxn, fixture_hash())?
            .into_iter()
            .map(|(entity, _)| entity)
            .collect::<Vec<_>>(),
        vec![entity]
    );
    drop(rtxn);
    assert_eq!(
        vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4,)?,
        entity
    );
    let receipt = SkillScanReceipt::new(
        "backfilled",
        5,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(5), 6)?;
    assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
    Ok(())
}

#[test]
fn open_backfill_is_not_capped_by_on_demand_reader_limit() -> Result<()> {
    let temp = tempfile::tempdir().expect("temp dir");
    let path = temp.path().to_path_buf();
    let vault = Vault::open(&path, crate::VaultConfig::default())?;
    let template_entity = EntityId::now();
    let imported = package(
        candidate("fixture.uncapped-backfill"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(
        &hub_ref(HubPin::None),
        &imported,
        template_entity,
        t(1),
        2,
    )?;

    let mut wtxn = vault.store.env.write_txn()?;
    let template_raw = vault
        .store
        .entities
        .get(&wtxn, template_entity.as_bytes())?
        .expect("template skill")
        .to_vec();
    vault.store.vault_meta.delete(
        &mut wtxn,
        &content_hash_index_key(fixture_hash(), &template_entity),
    )?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?;

    let mut last_entity = template_entity;
    for index in 0..MAX_HUB_SKILL_SCAN_ENTRIES {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&0x0170_0000_0000_0000_u64.to_be_bytes());
        bytes[8..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        let entity = EntityId::from_bytes(bytes)?;
        vault
            .store
            .entities
            .put(&mut wtxn, entity.as_bytes(), &template_raw)?;
        vault.store.type_index.put(
            &mut wtxn,
            &crate::store::Store::encode_type_key(ENTITY_TYPE_SKILL, &entity),
            &[],
        )?;
        last_entity = entity;
    }
    wtxn.commit()?;
    drop(vault);

    let vault = Vault::open(&path, crate::VaultConfig::default())?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, CONTENT_HASH_INDEX_SCHEMA_VERSION_KEY)?
            .as_deref(),
        Some(&[CONTENT_HASH_INDEX_SCHEMA_VERSION][..])
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &content_hash_index_key(fixture_hash(), &last_entity))?
            .is_some()
    );
    Ok(())
}

#[test]
fn reserved_scan_door_preserves_content_global_supersession() -> Result<()> {
    let (_temp, vault) = open_vault();
    let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
    let receipt = SkillScanReceipt::new(
        "reserved-door",
        5,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    let prior =
        vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &receipt, t(5), 6)?;
    vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &receipt, t(7), 8)?;

    assert_eq!(
        vault.get_claim(&prior)?.expect("prior receipt").lifecycle,
        ClaimLifecycleStatus::Superseded
    );
    assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
    Ok(())
}

#[test]
fn scan_verdict_supersession_is_content_global_across_entities() -> Result<()> {
    let (_temp, vault) = open_vault();
    let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
    let alpha = SkillScanReceipt::new(
        "alpha",
        5,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    let anchor = skill_content_anchor_entity_id(fixture_hash())?;
    // Same (content_hash, provider) ingested via two different holders
    // dedups to ONE active verdict on the shared content anchor.
    vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &alpha, t(5), 6)?;
    vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &alpha, t(7), 8)?;

    // Verdicts never attach to the submitting holders themselves.
    assert!(
        vault
            .active_claims_for_predicate(&imported_entity, PREDICATE_SKILL_SCAN_VERDICT)?
            .is_empty()
    );
    assert!(
        vault
            .active_claims_for_predicate(&local_entity, PREDICATE_SKILL_SCAN_VERDICT)?
            .is_empty()
    );

    // Exactly one active alpha row plus one superseded, both on the anchor.
    assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);
    let mut anchor_superseded = 0;
    for claim_id in vault.claims_for_subject(&anchor)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
            && body.lifecycle == ClaimLifecycleStatus::Superseded
        {
            anchor_superseded += 1;
        }
    }
    assert_eq!(anchor_superseded, 1);
    let hash_rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(hash_rows.len(), 1);
    assert_eq!(map_text(&hash_rows[0].value, "provider"), Some("alpha"));

    let beta = SkillScanReceipt::new(
        "beta",
        9,
        ScanVerdict::Suspicious,
        ScanRiskLevel::High,
        ScanCompleteness::Partial,
        SkillGovernance::Discouraged,
    )?;
    vault.ingest_skill_scan_verdict(&local_entity, fixture_hash(), &beta, t(9), 10)?;
    let hash_rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(hash_rows.len(), 2);
    let providers = hash_rows
        .iter()
        .filter_map(|body| map_text(&body.value, "provider"))
        .collect::<BTreeSet<_>>();
    assert_eq!(providers, BTreeSet::from(["alpha", "beta"]));
    Ok(())
}

#[test]
fn adapter_package_store_resolves_full_structured_pin() -> Result<()> {
    let hub_id = EntityId::now();
    let first = package(
        candidate("fixture.pin-first"),
        SkillCapabilitySurface::default(),
    );
    let second = package_with_content(
        candidate("fixture.pin-second"),
        b"# second pinned package\n",
        SkillCapabilitySurface::default(),
    );
    let mut adapter = GitSkillHubAdapter::new(hub_id);
    adapter.insert_package(
        "skills/shared-ref",
        HubPin::Tag("first".to_owned()),
        first.clone(),
    );
    adapter.insert_package(
        "skills/shared-ref",
        HubPin::Commit("0123456789abcdef".to_owned()),
        second.clone(),
    );

    let first_ref = HubRef::new(hub_id, "skills/shared-ref", HubPin::Tag("first".to_owned()))?;
    let second_ref = HubRef::new(
        hub_id,
        "skills/shared-ref",
        HubPin::Commit("0123456789abcdef".to_owned()),
    )?;
    assert_eq!(adapter.fetch_package(&first_ref)?, first);
    assert_eq!(adapter.fetch_package(&second_ref)?, second);

    let missing_ref = HubRef::new(
        hub_id,
        "skills/shared-ref",
        HubPin::Semver("^1.0".to_owned()),
    )?;
    adapter
        .fetch_package(&missing_ref)
        .expect_err("an uninserted pin must not resolve another package");
    Ok(())
}

#[test]
fn hub_import_skips_legacy_opaque_skill_during_dedup_scan() -> Result<()> {
    let (_temp, vault) = open_vault();
    let legacy_entity = EntityId::now();
    let structured = encode_skill_record(&candidate("fixture.legacy-opaque"))?;
    vault.put_entity(&legacy_entity, ENTITY_TYPE_SKILL, t(1), 2, &structured)?;

    let legacy_body = b"legacy opaque skill body";
    assert!(crate::skill::is_legacy_opaque_skill_body(legacy_body));
    let rtxn = vault.store.env.read_txn()?;
    let mut raw = vault
        .store
        .entities
        .get(&rtxn, legacy_entity.as_bytes())?
        .expect("legacy fixture entity")
        .to_vec();
    drop(rtxn);
    raw.truncate(ENTITY_METADATA_HEADER_LEN);
    raw.extend_from_slice(legacy_body);
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .entities
        .put(&mut wtxn, legacy_entity.as_bytes(), &raw)?;
    wtxn.commit()?;

    let imported = package(
        candidate("fixture.import-after-legacy"),
        SkillCapabilitySurface::default(),
    );
    let imported_entity =
        vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;

    assert_ne!(imported_entity, legacy_entity);
    assert_eq!(
        vault
            .get_skill_record(&imported_entity)?
            .expect("imported skill")
            .skill_id,
        "fixture.import-after-legacy"
    );
    Ok(())
}

#[test]
fn hub_import_content_hash_pin_must_match_computed_tree_hash() -> Result<()> {
    let (_temp, vault) = open_vault();
    let imported = package(
        candidate("fixture.content-hash-pinned-import"),
        SkillCapabilitySurface::default(),
    );
    let computed_hash = imported.content_hash()?;
    let different_hash =
        canonical_skill_tree_hash([("SKILL.md", b"# different pinned content\n".as_slice())])?;
    assert_ne!(computed_hash, different_hash);

    let mismatched_ref = hub_ref(HubPin::ContentHash(different_hash.to_hex()));
    assert_eq!(
        vault
            .import_skill_from_hub(&mismatched_ref, &imported, t(1), 2)
            .expect_err("content-hash pin must match the computed package tree")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    let matching_ref = hub_ref(HubPin::ContentHash(computed_hash.to_hex()));
    let imported_entity = vault.import_skill_from_hub(&matching_ref, &imported, t(3), 4)?;
    assert_eq!(
        vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(5), 6)?,
        imported_entity
    );
    Ok(())
}

#[test]
fn hub_import_dedup_ignores_local_skill_with_matching_content_hash() -> Result<()> {
    let (_temp, vault) = open_vault();
    let local_entity = EntityId::now();
    let mut local = candidate("fixture.local-hash-owner");
    local.source = ClaimSource::UserStated;
    vault.put_skill_record(&local_entity, &local, t(1), 2)?;

    let imported = package(
        candidate("fixture.imported-hash-owner"),
        SkillCapabilitySurface::default(),
    );
    assert_eq!(local.content_hash, Some(imported.content_hash()?));
    let imported_entity =
        vault.import_skill_from_hub(&hub_ref(HubPin::None), &imported, t(3), 4)?;

    assert_ne!(imported_entity, local_entity);
    assert_eq!(
        vault
            .get_skill_record(&local_entity)?
            .expect("local skill remains materialized")
            .source,
        ClaimSource::UserStated
    );
    assert_eq!(vault.skill_hub_provenance_count(&local_entity)?, 0);
    assert_eq!(
        vault
            .get_skill_record(&imported_entity)?
            .expect("hub import creates a distinct skill")
            .source,
        ClaimSource::Imported
    );
    assert_eq!(vault.skill_hub_provenance_count(&imported_entity)?, 1);
    Ok(())
}

#[test]
fn import_refuses_hash_collision_across_skill_ids() -> Result<()> {
    let (_temp, vault) = open_vault();
    let first_ref = HubRef::new(EntityId::now(), "skills/foo", HubPin::None)?;
    let second_ref = HubRef::new(EntityId::now(), "skills/bar", HubPin::None)?;
    let first = package(candidate("foo"), SkillCapabilitySurface::default());
    let second = package(candidate("bar"), SkillCapabilitySurface::default());

    let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
    let error = vault
        .import_skill_from_hub(&second_ref, &second, t(3), 4)
        .expect_err("matching content must not dedup across skill ids");

    assert!(matches!(
        error,
        Error::InvalidSkillBody("hub import content hash collides with a different skill id")
    ));
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("original imported skill")
            .skill_id,
        "foo"
    );
    Ok(())
}

#[test]
fn import_dedups_matching_skill_id_across_hubs() -> Result<()> {
    let (_temp, vault) = open_vault();
    let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
    let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
    let imported = package(candidate("foo"), SkillCapabilitySurface::default());

    let entity = vault.import_skill_from_hub(&first_ref, &imported, t(1), 2)?;
    assert_eq!(
        vault.import_skill_from_hub(&second_ref, &imported, t(3), 4)?,
        entity
    );
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);
    Ok(())
}

#[test]
fn import_refuses_conflicting_capabilities_on_dedup() -> Result<()> {
    let (_temp, vault) = open_vault();
    let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
    let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
    let first = package(
        candidate("foo"),
        SkillCapabilitySurface::default().with_bin("foo"),
    );
    let second = package(
        candidate("foo"),
        SkillCapabilitySurface::default().with_bin("bar"),
    );

    let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
    let error = vault
        .import_skill_from_hub(&second_ref, &second, t(3), 4)
        .expect_err("matching content must not dedup conflicting capabilities");

    assert!(matches!(
        error,
        Error::InvalidSkillBody("matching content hash carries conflicting capabilities")
    ));
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
    Ok(())
}

#[test]
fn import_dedups_equal_capabilities() -> Result<()> {
    let (_temp, vault) = open_vault();
    let first_ref = HubRef::new(EntityId::now(), "skills/foo-a", HubPin::None)?;
    let second_ref = HubRef::new(EntityId::now(), "skills/foo-b", HubPin::None)?;
    let first = package(
        candidate("foo"),
        SkillCapabilitySurface::default().with_bin("foo"),
    );
    let second = package(
        candidate("foo"),
        SkillCapabilitySurface::default().with_bin("foo"),
    );

    let entity = vault.import_skill_from_hub(&first_ref, &first, t(1), 2)?;
    assert_eq!(
        vault.import_skill_from_hub(&second_ref, &second, t(3), 4)?,
        entity
    );
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);
    Ok(())
}

#[test]
fn hub_reimport_moves_provenance_alias_to_new_content_entity() -> Result<()> {
    let (_temp, vault) = open_vault();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.mutable-hub-alias"),
        SkillCapabilitySurface::default(),
    );
    let first_entity =
        vault.import_skill_from_hub_with_id(&reference, &initial, EntityId::now(), t(1), 2)?;

    let moved = package_with_content(
        candidate("fixture.mutable-hub-alias"),
        b"# moved upstream ref\n",
        SkillCapabilitySurface::default(),
    );
    let moved_hash = moved.content_hash()?;
    let second_entity =
        vault.import_skill_from_hub_with_id(&reference, &moved, EntityId::now(), t(3), 4)?;
    assert_ne!(first_entity, second_entity);

    let mut first_alias_superseded = 0;
    for claim_id in vault.claims_for_subject(&first_entity)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_SKILL_HUB_PROVENANCE {
            continue;
        }
        let stored_ref =
            HubRef::from_value(map_value(&body.value, "hubRef").expect("provenance hub ref"))?;
        if same_hub_alias(&stored_ref, &reference)
            && body.lifecycle == ClaimLifecycleStatus::Superseded
        {
            first_alias_superseded += 1;
        }
    }
    assert_eq!(first_alias_superseded, 1);

    let first_active =
        vault.active_claims_for_predicate(&first_entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
    let second_active =
        vault.active_claims_for_predicate(&second_entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
    assert_eq!(first_active.len(), 0);
    assert_eq!(second_active.len(), 1);
    assert_eq!(first_active.len() + second_active.len(), 1);
    assert_eq!(
        map_text(&second_active[0].1.value, "contentHash"),
        Some(moved_hash.to_hex().as_str())
    );
    assert_eq!(
        HubRef::from_value(
            map_value(&second_active[0].1.value, "hubRef").expect("provenance hub ref")
        )?,
        reference
    );
    Ok(())
}

#[test]
fn hub_ref_round_trips_all_five_pin_types() {
    let pins = [
        HubPin::Semver("^1.0".to_owned()),
        HubPin::Tag("stable".to_owned()),
        HubPin::Commit("0123456789abcdef".to_owned()),
        HubPin::ContentHash(fixture_hash().to_hex()),
        HubPin::None,
    ];
    let mut round_tripped = Vec::new();
    for pin in pins {
        let original = hub_ref(pin);
        let encoded = original.to_value().expect("encode hub ref");
        round_tripped.push(HubRef::from_value(&encoded).expect("decode hub ref"));
        assert_eq!(round_tripped.last(), Some(&original));
    }
    assert_eq!(round_tripped.len(), 5);

    let invalid = HubRef {
        hub_id: EntityId::now(),
        ref_string: String::new(),
        pin: HubPin::None,
    };
    assert!(invalid.to_value().is_err());
}

#[test]
fn skill_hub_record_round_trips_exact_body() {
    let record = SkillHubRecord::new(
        SkillHubKind::HttpIndex,
        "configured-endpoint",
        SkillHubTrustTier::Community,
        HubSyncPolicy::MirrorOfHub,
    )
    .expect("hub record");
    let bytes = encode_skill_hub_record(&record).expect("encode");
    assert_eq!(decode_skill_hub_record(&bytes).expect("decode"), record);
}

#[test]
fn hub_sync_applies_narrowing_and_proposes_widening() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let initial_surface = SkillCapabilitySurface::default().with_bin("existing-bin");
    let initial = package(candidate("fixture.sync"), initial_surface);
    let reference = hub_ref(HubPin::None);
    assert_eq!(
        vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?,
        entity
    );
    let mut invalid_record = candidate("fixture.sync");
    invalid_record.version.clear();
    let invalid = package(invalid_record, SkillCapabilitySurface::default());
    vault
        .import_skill_from_hub(&hub_ref(HubPin::None), &invalid, t(2), 3)
        .expect_err("invalid dedup package must be rejected");
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 1);
    let mut active = vault.get_skill_record(&entity)?.expect("candidate");
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&entity, &active, t(3), 4)?;

    let mut narrower_record = candidate("fixture.sync");
    narrower_record.version = "1.1.0".to_owned();
    narrower_record.confidence = 0.75;
    let narrower = package(narrower_record, SkillCapabilitySurface::default());
    let narrowed = vault.sync_skill_from_hub(
        &entity,
        &reference,
        &narrower,
        HubSyncPolicy::MirrorOfHub,
        t(5),
        6,
    )?;
    assert_eq!(narrowed, HubSyncDisposition::Applied);
    let narrowed_record = vault.get_skill_record(&entity)?.expect("narrowed record");
    assert_eq!(narrowed_record.confidence, 0.75);

    let mut frozen_record = candidate("fixture.sync");
    frozen_record.version = "1.1.1".to_owned();
    let frozen = package(frozen_record, SkillCapabilitySurface::default());
    let frozen_ref = hub_ref(HubPin::ContentHash(fixture_hash().to_hex()));
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &frozen_ref,
            &frozen,
            HubSyncPolicy::ContentHashFrozen,
            t(7),
            8,
        )?,
        HubSyncDisposition::RefusedByPolicy
    );
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("still narrowed")
            .version,
        "1.1.0"
    );

    let mut wider_record = candidate("fixture.sync");
    wider_record.version = "1.2.0".to_owned();
    let wider = package(
        wider_record,
        SkillCapabilitySurface::default().with_bin("new-bin"),
    );
    let widened = vault.sync_skill_from_hub(
        &entity,
        &reference,
        &wider,
        HubSyncPolicy::MirrorOfHub,
        t(9),
        10,
    )?;
    assert_eq!(
        widened.approval_status(),
        Some(ClaimApprovalStatus::Proposed)
    );
    assert_eq!(
        vault.get_skill_record(&entity)?.expect("stored").version,
        "1.1.0"
    );
    Ok(())
}

/// ONE-1448 regression: the owner's tier mark is the third STATE axis, so hub
/// sync restores it from the local record exactly like approval and lifecycle.
/// Without that line an upstream revision that merely OMITS `governanceTier`
/// (the wire elides an absent mark) erases an Identity mark, and the erased
/// record — imported, hub-vouched — resolves to `LegacyStandard`, which is
/// optimizable: the automated edit loop would be handed the very skill the
/// mark existed to protect.
#[test]
fn hub_sync_preserves_owner_marked_governance_tier() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.governance-tier-sync"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let mut active = vault.get_skill_record(&entity)?.expect("imported record");
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&entity, &active, t(3), 4)?;

    // The owner's act, through the ordinary update door: marking the tier is a
    // state flip, so it lands on imported content with no version bump.
    let mut marked = vault.get_skill_record(&entity)?.expect("active record");
    marked.governance_tier = Some(SkillGovernanceTier::Identity);
    vault.update_skill_record(&entity, &marked, t(5), 6)?;
    assert_eq!(
        skill_governance_tier(&vault, &entity)?,
        SkillTierVerdict::Marked(SkillGovernanceTier::Identity)
    );

    // Upstream ships a revision that says nothing about the tier at all.
    let mut silent_record = candidate("fixture.governance-tier-sync");
    silent_record.version = "1.1.0".to_owned();
    assert_eq!(silent_record.governance_tier, None);
    let silent = package(silent_record, SkillCapabilitySurface::default());
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &silent,
            HubSyncPolicy::MirrorOfHub,
            t(7),
            8,
        )?,
        HubSyncDisposition::Applied
    );
    let after_silence = vault.get_skill_record(&entity)?.expect("synced record");
    // The content half of the sync still landed ...
    assert_eq!(after_silence.version, "1.1.0");
    // ... and the owner's axis survived it.
    assert_eq!(
        after_silence.governance_tier,
        Some(SkillGovernanceTier::Identity)
    );

    // And a revision that actively LOWERS the tier is no more persuasive.
    let mut lowered_record = candidate("fixture.governance-tier-sync");
    lowered_record.version = "1.2.0".to_owned();
    lowered_record.governance_tier = Some(SkillGovernanceTier::Standard);
    let lowered = package(lowered_record, SkillCapabilitySurface::default());
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &lowered,
            HubSyncPolicy::MirrorOfHub,
            t(9),
            10,
        )?,
        HubSyncDisposition::Applied
    );
    let after_lowering = vault.get_skill_record(&entity)?.expect("synced record");
    assert_eq!(after_lowering.version, "1.2.0");
    assert_eq!(
        after_lowering.governance_tier,
        Some(SkillGovernanceTier::Identity)
    );

    // The mark holds where it is spent: the skill stays out of the edit loop.
    let verdict = skill_governance_tier(&vault, &entity)?;
    assert_eq!(
        verdict,
        SkillTierVerdict::Marked(SkillGovernanceTier::Identity)
    );
    assert!(!verdict.optimizable());
    Ok(())
}

#[test]
fn sync_enforces_content_hash_pin_under_any_policy() -> Result<()> {
    let (_temp, vault) = open_vault();
    let initial = package(
        candidate("fixture.content-hash-pin-sync"),
        SkillCapabilitySurface::default(),
    );
    let initial_hash = initial.content_hash()?;
    let reference = hub_ref(HubPin::ContentHash(initial_hash.to_hex()));
    let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

    let mut update_record = candidate("fixture.content-hash-pin-sync");
    update_record.version = "1.1.0".to_owned();
    let update = package_with_content(
        update_record,
        b"# drifted content-hash-pinned tree\n",
        SkillCapabilitySurface::default(),
    );
    let updated_hash = update.content_hash()?;
    assert_ne!(updated_hash, initial_hash);

    let error = vault
        .sync_skill_from_hub(
            &entity,
            &reference,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )
        .expect_err("content-hash pin must bind every sync policy");
    assert!(matches!(
        error,
        Error::InvalidSkillBody("content-hash-pinned ref drifted")
    ));
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("original pinned skill")
            .content_hash,
        Some(initial_hash)
    );

    let provenance = vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
    assert_eq!(provenance.len(), 1);
    assert_eq!(
        map_text(&provenance[0].1.value, "contentHash"),
        Some(initial_hash.to_hex().as_str())
    );
    assert_eq!(
        HubRef::from_value(
            map_value(&provenance[0].1.value, "hubRef").expect("pinned provenance hub ref")
        )?,
        reference
    );
    Ok(())
}

#[test]
fn sync_none_pin_still_moves_hash() -> Result<()> {
    let (_temp, vault) = open_vault();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.none-pin-sync"),
        SkillCapabilitySurface::default(),
    );
    let initial_hash = initial.content_hash()?;
    let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

    let mut update_record = candidate("fixture.none-pin-sync");
    update_record.version = "1.1.0".to_owned();
    let update = package_with_content(
        update_record,
        b"# movable none-pin tree\n",
        SkillCapabilitySurface::default(),
    );
    let updated_hash = update.content_hash()?;
    assert_ne!(updated_hash, initial_hash);
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )?,
        HubSyncDisposition::Applied
    );
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("updated none-pin skill")
            .content_hash,
        Some(updated_hash)
    );
    Ok(())
}

#[test]
fn content_hash_frozen_requires_pin() -> Result<()> {
    let (_temp, vault) = open_vault();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.frozen-policy-pin-required"),
        SkillCapabilitySurface::default(),
    );
    let entity = vault.import_skill_from_hub(&reference, &initial, t(1), 2)?;

    let mut update_record = candidate("fixture.frozen-policy-pin-required");
    update_record.version = "1.1.0".to_owned();
    let update = package(update_record, SkillCapabilitySurface::default());
    let error = vault
        .sync_skill_from_hub(
            &entity,
            &reference,
            &update,
            HubSyncPolicy::ContentHashFrozen,
            t(3),
            4,
        )
        .expect_err("content-hash-frozen policy requires a content_hash pin");
    assert!(matches!(
        error,
        Error::InvalidSkillBody("content-hash-frozen policy requires a content_hash pin")
    ));
    Ok(())
}

#[test]
fn hub_sync_requires_existing_provenance_alias_but_allows_untracked_skills() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.sync-authority"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let mut update_record = candidate("fixture.sync-authority");
    update_record.version = "1.1.0".to_owned();
    let update = package(update_record, SkillCapabilitySurface::default());
    let unrelated_ref = HubRef::new(EntityId::now(), reference.ref_string.clone(), HubPin::None)?;
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &unrelated_ref,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )?,
        HubSyncDisposition::RefusedByPolicy
    );
    assert_eq!(
        vault
            .get_skill_record(&entity)?
            .expect("original skill")
            .version,
        "1.0.0"
    );
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?,
        HubSyncDisposition::Applied
    );

    let direct_entity = EntityId::now();
    let direct = package_with_content(
        candidate("fixture.sync-without-provenance"),
        b"# direct import\n",
        SkillCapabilitySurface::default(),
    );
    vault.put_skill_record(&direct_entity, &direct.record, t(7), 8)?;
    assert_eq!(vault.skill_hub_provenance_count(&direct_entity)?, 0);
    let mut direct_update_record = direct.record;
    direct_update_record.version = "1.1.0".to_owned();
    let direct_update = package_with_content(
        direct_update_record,
        b"# direct import\n",
        SkillCapabilitySurface::default(),
    );
    assert_eq!(
        vault.sync_skill_from_hub(
            &direct_entity,
            &hub_ref(HubPin::None),
            &direct_update,
            HubSyncPolicy::MirrorOfHub,
            t(9),
            10,
        )?,
        HubSyncDisposition::Applied
    );
    assert_eq!(
        vault
            .get_skill_record(&direct_entity)?
            .expect("direct imported skill")
            .version,
        "1.1.0"
    );
    Ok(())
}

#[test]
fn hub_sync_requires_exact_provenance_pin() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let hub_id = EntityId::now();
    let stable_ref = HubRef::new(
        hub_id,
        "skills/pinned-authority",
        HubPin::Tag("stable".to_owned()),
    )?;
    let beta_ref = HubRef::new(
        hub_id,
        "skills/pinned-authority",
        HubPin::Tag("beta".to_owned()),
    )?;
    let initial = package(
        candidate("fixture.pinned-sync-authority"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&stable_ref, &initial, entity, t(1), 2)?;

    let mut update_record = candidate("fixture.pinned-sync-authority");
    update_record.version = "1.1.0".to_owned();
    let update = package(update_record, SkillCapabilitySurface::default());
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &beta_ref,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )?,
        HubSyncDisposition::RefusedByPolicy
    );
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &stable_ref,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?,
        HubSyncDisposition::Applied
    );
    Ok(())
}

#[test]
fn hub_sync_refuses_content_hash_owned_by_different_entity() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.hash-collision-source"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let owner = EntityId::now();
    let owner_package = package_with_content(
        candidate("fixture.hash-collision-owner"),
        b"# already owned\n",
        SkillCapabilitySurface::default(),
    );
    let owner_hash = owner_package.content_hash()?;
    vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &owner_package, owner, t(3), 4)?;

    let mut colliding_record = candidate("fixture.hash-collision-source");
    colliding_record.version = "2.0.0".to_owned();
    let colliding = package_with_content(
        colliding_record,
        b"# already owned\n",
        SkillCapabilitySurface::default(),
    );
    assert_eq!(colliding.content_hash()?, owner_hash);
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &colliding,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?,
        HubSyncDisposition::RefusedByPolicy
    );

    let unchanged = vault.get_skill_record(&entity)?.expect("source skill");
    let existing_owner = vault.get_skill_record(&owner)?.expect("hash owner");
    assert_ne!(entity, owner);
    assert_eq!(unchanged.content_hash, Some(fixture_hash()));
    assert_eq!(unchanged.version, "1.0.0");
    assert_eq!(existing_owner.content_hash, Some(owner_hash));
    Ok(())
}

#[test]
fn hub_sync_refreshes_provenance_after_content_hash_change() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.provenance-refresh"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let mut update_record = candidate("fixture.provenance-refresh");
    update_record.version = "1.1.0".to_owned();
    let update = package_with_content(
        update_record,
        b"# changed upstream tree\n",
        SkillCapabilitySurface::default(),
    );
    let updated_hash = update.content_hash()?;
    assert_ne!(updated_hash, fixture_hash());
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(3),
            4,
        )?,
        HubSyncDisposition::Applied
    );

    let rows = vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        map_text(&rows[0].1.value, "contentHash"),
        Some(updated_hash.to_hex().as_str())
    );
    assert_eq!(
        HubRef::from_value(map_value(&rows[0].1.value, "hubRef").expect("provenance hub ref"))?,
        reference
    );
    Ok(())
}

#[test]
fn hub_sync_content_change_supersedes_other_hub_provenance_aliases() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let syncing_ref = hub_ref(HubPin::None);
    let other_ref = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.multi-hub-provenance-refresh"),
        SkillCapabilitySurface::default(),
    );
    assert_eq!(
        vault.import_skill_from_hub_with_id(&syncing_ref, &initial, entity, t(1), 2)?,
        entity
    );
    assert_eq!(
        vault.import_skill_from_hub_with_id(&other_ref, &initial, EntityId::now(), t(3), 4,)?,
        entity
    );
    assert_eq!(vault.skill_hub_provenance_count(&entity)?, 2);

    let mut update_record = candidate("fixture.multi-hub-provenance-refresh");
    update_record.version = "1.1.0".to_owned();
    let update = package_with_content(
        update_record,
        b"# changed through the syncing hub\n",
        SkillCapabilitySurface::default(),
    );
    let updated_hash = update.content_hash()?;
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &syncing_ref,
            &update,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?,
        HubSyncDisposition::Applied
    );

    let active = vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_PROVENANCE)?;
    assert_eq!(active.len(), 1);
    assert_eq!(
        map_text(&active[0].1.value, "contentHash"),
        Some(updated_hash.to_hex().as_str())
    );
    assert_eq!(
        HubRef::from_value(
            map_value(&active[0].1.value, "hubRef").expect("active provenance hub ref")
        )?,
        syncing_ref
    );

    let mut other_alias_superseded = 0;
    for claim_id in vault.claims_for_subject(&entity)? {
        let Some(body) = vault.get_claim(&claim_id)? else {
            continue;
        };
        if body.predicate != PREDICATE_SKILL_HUB_PROVENANCE {
            continue;
        }
        let stored_ref =
            HubRef::from_value(map_value(&body.value, "hubRef").expect("provenance hub ref"))?;
        if same_hub_alias(&stored_ref, &other_ref)
            && body.lifecycle == ClaimLifecycleStatus::Superseded
        {
            other_alias_superseded += 1;
        }
    }
    assert_eq!(other_alias_superseded, 1);
    Ok(())
}

#[test]
fn hub_sync_deduplicates_identical_widening_proposals() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.proposal-dedup"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let mut wider_record = candidate("fixture.proposal-dedup");
    wider_record.version = "2.0.0".to_owned();
    let wider = package(
        wider_record,
        SkillCapabilitySurface::default().with_bin("new-bin"),
    );
    let first = vault.sync_skill_from_hub(
        &entity,
        &reference,
        &wider,
        HubSyncPolicy::MirrorOfHub,
        t(3),
        4,
    )?;
    let first_id = match first {
        HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
        other => panic!("expected proposal, got {other:?}"),
    };
    assert_eq!(
        vault.sync_skill_from_hub(
            &entity,
            &reference,
            &wider,
            HubSyncPolicy::MirrorOfHub,
            t(5),
            6,
        )?,
        HubSyncDisposition::Proposed {
            proposal_id: first_id,
            approval: ClaimApprovalStatus::Proposed,
        }
    );

    let proposals =
        vault.active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL)?;
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].0, first_id);
    Ok(())
}

#[test]
fn sync_widening_proposal_refreshes_on_changed_capabilities() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let initial = package(
        candidate("fixture.proposal-capability-refresh"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&reference, &initial, entity, t(1), 2)?;

    let wider_record = candidate("fixture.proposal-capability-refresh");
    let first_wider = package(
        wider_record.clone(),
        SkillCapabilitySurface::default().with_bin("bin-a"),
    );
    let second_wider = package(
        wider_record,
        SkillCapabilitySurface::default()
            .with_bin("bin-a")
            .with_bin("bin-b"),
    );
    let first_id = match vault.sync_skill_from_hub(
        &entity,
        &reference,
        &first_wider,
        HubSyncPolicy::MirrorOfHub,
        t(3),
        4,
    )? {
        HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
        other => panic!("expected proposal, got {other:?}"),
    };
    let second_id = match vault.sync_skill_from_hub(
        &entity,
        &reference,
        &second_wider,
        HubSyncPolicy::MirrorOfHub,
        t(5),
        6,
    )? {
        HubSyncDisposition::Proposed { proposal_id, .. } => proposal_id,
        other => panic!("expected refreshed proposal, got {other:?}"),
    };

    assert_ne!(second_id, first_id);
    assert_eq!(
        vault
            .active_claims_for_predicate(&entity, PREDICATE_SKILL_HUB_UPDATE_PROPOSAL)?
            .len(),
        2
    );
    Ok(())
}

#[test]
fn scan_verdict_supersedes_same_hash_and_provider() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    let reference = hub_ref(HubPin::None);
    let imported = package(candidate("fixture.scan"), SkillCapabilitySurface::default());
    vault.import_skill_from_hub_with_id(&reference, &imported, entity, t(1), 2)?;
    let receipt = SkillScanReceipt::new(
        "provider-a",
        3,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    let anchor = skill_content_anchor_entity_id(fixture_hash())?;
    vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(3), 4)?;
    vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(2), 2)?;
    // Same (content_hash, provider) supersedes on the anchor: one active row.
    // Equal `scannedAt` is the TIE case newest-wins leaves to the later
    // call (ONE-1892) — both ingests carry `scanned_at = 3`.
    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(rows.len(), 1);
    let mut superseded = 0;
    for id in vault.claims_for_subject(&anchor)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate == PREDICATE_SKILL_SCAN_VERDICT
            && body.lifecycle == ClaimLifecycleStatus::Superseded
        {
            superseded += 1;
        }
    }
    assert_eq!(superseded, 1);
    Ok(())
}

// ═══ ONE-1892 — newest-wins ingest + anchor type guard ══════════════════

fn scan_receipt_at(provider: &str, scanned_at: u64) -> Result<SkillScanReceipt> {
    SkillScanReceipt::new(
        provider,
        scanned_at,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )
}

#[test]
fn older_scan_ingested_after_a_newer_one_never_takes_the_active_slot() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    vault.put_skill_record(&entity, &candidate("fixture.newest-wins"), t(1), 2)?;

    let newer = vault.ingest_skill_scan_verdict(
        &entity,
        fixture_hash(),
        &scan_receipt_at("provider-a", 500)?,
        t(500),
        501,
    )?;
    let older = vault.ingest_skill_scan_verdict(
        &entity,
        fixture_hash(),
        &scan_receipt_at("provider-a", 100)?,
        t(600),
        601,
    )?;

    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(rows.len(), 1, "one active row per (hash, provider)");
    assert_eq!(
        map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
        Some(500),
        "the LATEST-SCANNED verdict holds the active slot, not the last ingested"
    );
    assert_eq!(
        vault.get_claim(&newer)?.expect("newer row").lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        vault.get_claim(&older)?.expect("older row").lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the late-arriving older scan is kept as history, never dropped"
    );
    Ok(())
}

#[test]
fn a_far_future_scan_cannot_pin_the_active_slot() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    vault.put_skill_record(&entity, &candidate("fixture.future-clamp"), t(1), 2)?;

    vault.ingest_skill_scan_verdict(
        &entity,
        fixture_hash(),
        &scan_receipt_at("provider-a", u64::MAX)?,
        t(500),
        501,
    )?;
    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(
        map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
        Some(501),
        "a scan time beyond now+skew is clamped to ingest time"
    );
    assert_eq!(
        map_value(&rows[0].value, "scannedAtDeclared").and_then(Value::as_u64),
        Some(u64::MAX),
        "the clamp is receipted on the row, not silent"
    );

    // A later, ordinary scan now wins on merit instead of losing to a
    // timestamp no clock will ever reach.
    let normal = vault.ingest_skill_scan_verdict(
        &entity,
        fixture_hash(),
        &scan_receipt_at("provider-a", 600)?,
        t(600),
        601,
    )?;
    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        map_value(&rows[0].value, "scannedAt").and_then(Value::as_u64),
        Some(600)
    );
    assert_eq!(
        vault.get_claim(&normal)?.expect("normal row").lifecycle,
        ClaimLifecycleStatus::Active
    );
    Ok(())
}

#[test]
fn a_non_anchor_entity_squatting_the_anchor_id_is_refused() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    vault.put_skill_record(&entity, &candidate("fixture.anchor-squat"), t(1), 2)?;

    // Pre-seed a foreign entity at the derived anchor id.
    let anchor_id = skill_content_anchor_entity_id(fixture_hash())?;
    vault.put_entity(
        &anchor_id,
        crate::registry::ENTITY_TYPE_PERSON,
        t(1),
        2,
        b"squatter",
    )?;

    let error = vault
        .ingest_skill_scan_verdict(
            &entity,
            fixture_hash(),
            &scan_receipt_at("provider-a", 5)?,
            t(5),
            6,
        )
        .expect_err("a squatted anchor id must not be silently adopted");
    assert!(
        matches!(
            error,
            Error::SkillContentAnchorTypeMismatch {
                existing: crate::registry::ENTITY_TYPE_PERSON
            }
        ),
        "expected a typed anchor mismatch, got {error:?}"
    );
    assert!(
        vault
            .skill_scan_verdicts_for_content_hash(fixture_hash())?
            .is_empty(),
        "the refused ingest wrote nothing"
    );
    Ok(())
}

// ═══ ONE-1741 — content-anchor invariants ═══════════════════════════════

#[test]
fn content_anchor_id_is_deterministic_and_non_reserved() -> Result<()> {
    let same_a = skill_content_anchor_entity_id(fixture_hash())?;
    let same_b = skill_content_anchor_entity_id(fixture_hash())?;
    assert_eq!(same_a, same_b, "same content hash derives the same anchor");

    let other_hash = canonical_skill_tree_hash([("SKILL.md", b"# different bytes\n".as_slice())])?;
    assert_ne!(
        skill_content_anchor_entity_id(other_hash)?,
        same_a,
        "distinct content hashes derive distinct anchors"
    );
    // The derived id round-trips the reserved-sentinel gate.
    assert_eq!(EntityId::from_bytes(*same_a.as_bytes())?, same_a);
    Ok(())
}

#[test]
fn ingest_creates_content_anchor_entity_carrying_the_hash() -> Result<()> {
    let (_temp, vault) = open_vault();
    let entity = EntityId::now();
    // Born through the local put door, NOT the hub import door: the import
    // door now ingests its own scan (ONE-1892), which would mint the anchor
    // before this test could observe it missing. The contract under test is
    // that INGEST mints it, so the fixture reaches ingest with no anchor.
    vault.put_skill_record(&entity, &candidate("fixture.anchor-create"), t(1), 2)?;
    let anchor = skill_content_anchor_entity_id(fixture_hash())?;
    assert_eq!(
        vault.get(&anchor)?,
        None,
        "anchor is minted lazily at ingest"
    );

    let receipt = SkillScanReceipt::new(
        "anchor-provider",
        3,
        ScanVerdict::Clean,
        ScanRiskLevel::Low,
        ScanCompleteness::Complete,
        SkillGovernance::Recommended,
    )?;
    vault.ingest_skill_scan_verdict(&entity, fixture_hash(), &receipt, t(3), 4)?;

    let raw = vault
        .get(&anchor)?
        .expect("ingest minted the anchor entity");
    assert_eq!(
        raw.as_slice(),
        fixture_hash().as_bytes(),
        "anchor body carries the 32-byte content hash"
    );
    let header = vault
        .read_entity_header(&anchor)?
        .expect("anchor header present");
    assert_eq!(header.entity_type, ENTITY_TYPE_SKILL_CONTENT_ANCHOR);
    Ok(())
}

#[test]
fn verdict_anchored_to_content_hash_survives_every_holder_departure() -> Result<()> {
    let (_temp, vault) = open_vault();
    let (local_entity, imported_entity) = materialize_shared_hash_skills(&vault)?;
    let receipt = SkillScanReceipt::new(
        "immortal",
        5,
        ScanVerdict::Malicious,
        ScanRiskLevel::Critical,
        ScanCompleteness::Complete,
        SkillGovernance::Prohibited,
    )?;
    // Ingested via one holder while two hold the shared bytes.
    vault.ingest_skill_scan_verdict(&imported_entity, fixture_hash(), &receipt, t(5), 6)?;
    let discoverable =
        |vault: &Vault| -> Result<usize> { Ok(third_party_verdicts(vault, fixture_hash())?.len()) };
    assert_eq!(discoverable(&vault)?, 1);

    // Hard-delete one holder → still discoverable on the anchor.
    assert!(vault.delete_entity(&imported_entity)?);
    assert_eq!(discoverable(&vault)?, 1);

    // Soft-erase the last remaining holder → still discoverable.
    vault.delete_entity_with_reason(&local_entity, crate::DeleteReason::UserDelete)?;
    assert_eq!(
        discoverable(&vault)?,
        1,
        "verdict is anchored to the immortal bytes, not any holder"
    );

    // Re-import the same bytes and hard-delete via a batch → survives.
    let reholder = EntityId::now();
    let reimported = package(
        candidate("fixture.local-shared-hash"),
        SkillCapabilitySurface::default(),
    );
    vault.import_skill_from_hub_with_id(&hub_ref(HubPin::None), &reimported, reholder, t(9), 10)?;
    vault.batch().delete(&reholder).commit()?;
    assert_eq!(
        discoverable(&vault)?,
        1,
        "verdict outlives batch deletion of a fresh holder too"
    );

    // The surviving row still carries its original provider and hash.
    let rows = third_party_verdicts(&vault, fixture_hash())?;
    assert_eq!(map_text(&rows[0].value, "provider"), Some("immortal"));
    assert_eq!(
        map_text(&rows[0].value, "contentHash"),
        Some(fixture_hash().to_hex().as_str())
    );
    Ok(())
}

// AUD-1741: the anchor's immortality must be ENFORCED, not just assumed —
// deleting the anchor would strand every verdict for its bytes. It must be
// refused on every delete door (targeted AND batch/bulk share one guard).
#[test]
fn content_anchor_is_delete_protected_on_every_door() -> Result<()> {
    let (_temp, vault) = open_vault();
    let (_local, imported) = materialize_shared_hash_skills(&vault)?;
    let receipt = SkillScanReceipt::new(
        "anchor-protect",
        5,
        ScanVerdict::Malicious,
        ScanRiskLevel::Critical,
        ScanCompleteness::Complete,
        SkillGovernance::Prohibited,
    )?;
    vault.ingest_skill_scan_verdict(&imported, fixture_hash(), &receipt, t(5), 6)?;
    let anchor_id = skill_content_anchor_entity_id(fixture_hash())?;
    assert_eq!(third_party_verdicts(&vault, fixture_hash())?.len(), 1);

    // Targeted delete door refuses the anchor; the verdict survives.
    assert!(
        matches!(
            vault.delete_entity(&anchor_id),
            Err(Error::MaintenanceKindNotWritable(_))
        ),
        "targeted delete of the content anchor must be refused"
    );
    assert_eq!(
        third_party_verdicts(&vault, fixture_hash())?.len(),
        1,
        "verdict survives a targeted anchor-delete attempt"
    );

    // Batch/bulk delete door refuses it too (same guard, single source).
    assert!(
        matches!(
            vault.batch().delete(&anchor_id).commit(),
            Err(Error::MaintenanceKindNotWritable(_))
        ),
        "batch delete of the content anchor must be refused"
    );
    assert_eq!(
        third_party_verdicts(&vault, fixture_hash())?.len(),
        1,
        "verdict survives a batch anchor-delete attempt"
    );
    Ok(())
}

#[test]
fn anchor_subjected_verdict_stays_unforgeable_via_public_door() -> Result<()> {
    let (_temp, vault) = open_vault();
    // A well-formed anchor subject cannot smuggle a reserved skill.* claim
    // through the public door — the forgery guard is predicate-keyed and
    // independent of the (now anchor) subject.
    let anchor = skill_content_anchor_entity_id(fixture_hash())?;
    let body = scan_verdict_body(anchor, "forged", 1);
    assert!(matches!(
        vault.put_claim(&EntityId::now(), &body, t(1), 2),
        Err(Error::ReservedPredicate { .. })
    ));
    Ok(())
}
