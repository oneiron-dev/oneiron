use super::super::{LlmCapability, LlmCatalogCost, ModelLocality, score_scraper::*};
use super::*;
fn row(provider: &str) -> ModelRegistryRow {
    ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::OpenaiCompat,
        catalog: LlmCatalogEntry {
            model: ModelId::new(format!("{provider}/model@r1")).unwrap(),
            display_name: provider.into(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 8192,
            max_output_tokens: Some(1024),
            cost: Some(LlmCatalogCost {
                input_per_million: "1.25".into(),
                output_per_million: "3.50".into(),
                cache_read_per_million: None,
                cache_write_per_million: None,
            }),
            capabilities: vec![LlmCapability::Streaming],
            metadata: BTreeMap::new(),
        },
        scores: BTreeMap::new(),
        fetched_at: BTreeMap::new(),
    }
}
#[test]
fn prices_survive_restart_and_catalog_always_exposes_both_prices() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault");
    let a = row("one");
    let b = row("two");
    {
        let vault = Vault::open(&path, crate::VaultConfig::device())?;
        vault.put_model_registry_row(&a)?;
        vault.put_model_registry_row(&b)?;
    }
    let vault = Vault::open(&path, crate::VaultConfig::device())?;
    assert_eq!(vault.model_registry_rows()?, vec![a, b]);
    let catalog = vault.model_catalog_entries(ModelWireFormat::OpenaiCompat)?;
    assert_eq!(catalog.len(), 2);
    for entry in catalog {
        let cost = entry.cost.unwrap();
        assert_eq!(cost.input_per_million, "1.25");
        assert_eq!(cost.output_per_million, "3.50");
    }
    Ok(())
}
fn pack_fixture() -> Result<crate::skill_hub::pack_catalog::PackSource> {
    use crate::skill_hub::HubFile;
    crate::skill_hub::pack_catalog::PackSource::from_files(vec![
        HubFile::new(
            "PACK.md",
            include_bytes!("../../../tests/fixtures/model-pack/PACK.md").to_vec(),
        ),
        HubFile::new(
            "knowledge/catalog.json",
            include_bytes!("../../../tests/fixtures/model-pack/knowledge/catalog.json").to_vec(),
        ),
    ])
}

struct FixtureQualification;
impl crate::skill_hub::pack_catalog::PackQualifier for FixtureQualification {
    fn qualify(
        &self,
        _: &crate::skill_hub::pack_catalog::PackSource,
    ) -> Result<crate::skill_hub::pack_catalog::PackQualification> {
        Ok(crate::skill_hub::pack_catalog::PackQualification {
            suite: "catalog-data-fixture".into(),
            report_hash: "12".repeat(32),
            passed: true,
            advisory_accepted: true,
            advisory: "Data-only fixture; no execution rights".into(),
            runtime: None,
        })
    }
}

#[test]
fn installed_hub_catalog_parity_and_capability_admission() -> Result<()> {
    use crate::{
        skill_hub::{HubPin, HubRef, pack_catalog::PackInstallDisposition},
        temporal::TimeRange,
    };
    let source = pack_fixture()?;
    assert_eq!(
        source.content_hash().to_hex(),
        crate::skill_hub::MODEL_PACK_HASH
    );
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let at = TimeRange { start: 1, end: 1 };
    // A staged source without an owner-approved installation is not a catalog.
    assert!(CatalogSeed::from_installed_pack(&vault).is_err());
    let source_id = vault.stage_pack_source(&source, at, 1)?;
    assert!(CatalogSeed::from_installed_pack(&vault).is_err());
    let owner_id = crate::EntityId::now();
    vault.put_entity(
        &owner_id,
        crate::registry::ENTITY_TYPE_PERSON,
        at,
        1,
        b"owner",
    )?;
    let owner = vault.authenticate_owner(
        owner_id,
        "principal:catalog-owner",
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let hub_id = crate::skill_hub::default_skill_hub_id()?;
    let publisher = vault.admit_skill_publisher(&owner, "publisher:model-catalog", hub_id)?;
    let reference = HubRef::new(
        hub_id,
        crate::skill_hub::MODEL_PACK_SUBTREE,
        HubPin::ContentHash(source.content_hash().to_hex()),
    )?;
    let ask =
        vault.prepare_pack_install(source_id, &reference, &publisher, &FixtureQualification)?;
    assert_eq!(
        vault.install_pack(&ask)?,
        PackInstallDisposition::PendingConsent
    );
    vault.approve_pack_install(&ask, &owner)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("owner-approved data pack must install");
    };
    assert!(receipt.requested_grants.is_empty());
    assert!(receipt.wake_subscriptions.is_empty());
    assert!(vault.model_manifest()?.is_none());
    let loaded = CatalogSeed::from_installed_pack(&vault)?;
    assert_eq!(
        vault
            .model_catalog_entries(ModelWireFormat::OpenaiCompat)?
            .len(),
        54
    );
    let pack_bytes = &source
        .files()
        .iter()
        .find(|f| f.path == "knowledge/catalog.json")
        .unwrap()
        .content;
    assert_eq!(loaded, CatalogSeed::from_json(pack_bytes)?);
    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.rows.len(), 54);
    assert_eq!(
        vault.model_registry_row(&loaded.rows[0].catalog.model)?,
        Some(loaded.rows[0].clone())
    );
    let vendors: std::collections::BTreeSet<_> = loaded
        .rows
        .iter()
        .map(|r| r.catalog.model.provider())
        .collect();
    assert!(vendors.len() >= 40);
    for row in &loaded.rows {
        row.validate()?;
        assert!(row.catalog.cost.is_some());
        assert!(row.catalog.context_window_tokens > 0);
        assert!(!row.catalog.capabilities.is_empty());
        assert!(row.catalog.metadata.contains_key("description"));
        assert!(row.catalog.model.as_str().contains('@'));
        assert!(
            row.description()?
                .ranked()
                .all(|(_, contribution)| !contribution.source.is_empty())
        );
    }
    let restricted = loaded
        .rows
        .iter()
        .find(|row| !row.catalog.supports(&LlmCapability::ImageInput))
        .expect("seed has a restricted model");
    assert!(
        restricted
            .catalog
            .require(LlmCapability::ImageInput)
            .is_err()
    );
    let mut local = loaded.rows[0].clone();
    local.catalog.cost.as_mut().unwrap().input_per_million = "0".into();
    vault.put_model_registry_row(&local)?;
    vault.seed_installed_model_catalog()?;
    vault.seed_installed_model_catalog()?;
    assert_eq!(vault.model_registry_row(&local.catalog.model)?, Some(local));
    assert_eq!(vault.model_registry_rows()?.len(), loaded.rows.len());
    assert!(vault.model_manifest()?.is_none()); // Catalog data never binds a role.
    Ok(())
}

#[test]
fn model_description_keeps_source_rank_and_rejects_fabricated_or_empty_evidence() -> Result<()> {
    let mut model = row("model");
    let description = ModelDescription {
        owner_line: Some(DescriptionContribution {
            text: "Owner preference".into(),
            source: "owner:1".into(),
        }),
        vault_measurements: Some(DescriptionContribution {
            text: "Measured on real tasks".into(),
            source: "vault:task-1".into(),
        }),
        public_benchmarks: Some(DescriptionContribution {
            text: "Public score".into(),
            source: "https://bench.example/1".into(),
        }),
        vendor_copy: Some(DescriptionContribution {
            text: "Vendor claim".into(),
            source: "https://vendor.example/model".into(),
        }),
    };
    model.catalog.metadata.insert(
        "description".into(),
        serde_json::to_value(&description).unwrap(),
    );
    model.validate()?;
    assert_eq!(
        model
            .description()?
            .ranked()
            .map(|(class, _)| class)
            .collect::<Vec<_>>(),
        vec![
            DescriptionClass::OwnerLine,
            DescriptionClass::VaultMeasurements,
            DescriptionClass::PublicBenchmarks,
            DescriptionClass::VendorCopy,
        ]
    );
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    vault.put_model_registry_row(&model)?;
    assert_eq!(
        vault
            .model_registry_row(&model.catalog.model)?
            .unwrap()
            .description()?,
        description
    );
    let mut bad = model.clone();
    bad.catalog.metadata.get_mut("description").unwrap()["owner_line"]["source"] =
        serde_json::json!("");
    assert!(bad.validate().is_err());
    let mut poisoned = CatalogSeed {
        version: 1,
        rows: vec![row("absent")],
    };
    assert!(CatalogSeed::from_json(&serde_json::to_vec(&poisoned).unwrap()).is_err());
    poisoned.rows[0]
        .catalog
        .metadata
        .insert("description".into(), serde_json::json!({}));
    assert!(CatalogSeed::from_json(&serde_json::to_vec(&poisoned).unwrap()).is_ok());
    Ok(())
}
#[test]
fn configured_scraper_diffs_only_changes_and_only_nominates() -> Result<()> {
    struct Fetch(std::collections::VecDeque<serde_json::Value>);
    impl ScoreFetch for Fetch {
        fn fetch(&mut self, _: &ScoreSourceConfig) -> Result<serde_json::Value> {
            Ok(self.0.pop_front().unwrap())
        }
    }
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let registered = row("one");
    vault.put_model_registry_row(&registered)?;
    let model = registered.catalog.model.clone();
    let config = ScoreScraperConfig {
        version: 1,
        fetch_interval_secs: 60,
        sources: vec![ScoreSourceConfig {
            id: "artificialanalysis.ai".into(),
            url: "https://artificialanalysis.ai/fixture".into(),
            rows_pointer: "/data".into(),
            model_pointer: "/model".into(),
            score_pointer: "/score".into(),
            benchmark: "held-out-candidate-index".into(),
            model_bindings: BTreeMap::from([("external-name".into(), model.clone())]),
        }],
    };
    for field in ["id", "benchmark"] {
        let mut invalid = config.clone();
        if field == "id" {
            invalid.sources[0].id = "a".repeat(129);
        } else {
            invalid.sources[0].benchmark = "a".repeat(129);
        }
        assert!(invalid.validate().is_err());
    }
    let snapshot = |score| serde_json::json!({"data":[{"model":"external-name","score":score}]});
    let mut scraper = ScoreScraper::new(
        config,
        Fetch(vec![snapshot(50), snapshot(50), snapshot(70)].into()),
    )?;
    assert_eq!(scraper.refresh(&vault, 100)?.len(), 1);
    assert!(scraper.refresh(&vault, 101)?.is_empty());
    assert!(scraper.refresh(&vault, 160)?.is_empty());
    assert_eq!(scraper.refresh(&vault, 220)?.len(), 1);
    assert_eq!(vault.model_score_diffs(&model)?.len(), 2);
    assert_eq!(
        scraper.nominate(&vault, "artificialanalysis.ai", "held-out-candidate-index")?,
        Some(model.clone())
    );
    // The updater cannot change catalog bindings, capabilities, or prices.
    assert_eq!(
        vault.model_registry_row(&model)?.unwrap().catalog,
        registered.catalog
    );
    assert!(vault.model_manifest()?.is_none());
    Ok(())
}

#[test]
fn unchanged_observation_advances_watermark_without_diff_and_blocks_stale_change() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let row = row("one");
    vault.put_model_registry_row(&row)?;
    let model = row.catalog.model;
    let snapshot = |at, score| ScoreSnapshot {
        source: "bench".into(),
        fetched_at: at,
        observations: vec![ScoreObservation {
            model: model.clone(),
            benchmark: "quality".into(),
            score,
        }],
    };
    assert_eq!(vault.apply_model_scores(&snapshot(100, 50.0))?.len(), 1);
    assert!(vault.apply_model_scores(&snapshot(160, 50.0))?.is_empty());
    assert!(vault.apply_model_scores(&snapshot(120, 60.0)).is_err());
    assert!(vault.apply_model_scores(&snapshot(160, 50.0))?.is_empty());
    assert!(vault.apply_model_scores(&snapshot(160, 60.0)).is_err());
    let current = vault.model_registry_row(&model)?.expect("row");
    assert_eq!(current.scores["bench"]["quality"], 50.0);
    assert_eq!(current.fetched_at["bench"], 160);
    assert_eq!(vault.model_score_diffs(&model)?.len(), 1);
    Ok(())
}

#[test]
fn newer_multi_benchmark_snapshot_uses_prior_watermark_and_replay_is_atomic() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let row = row("one");
    vault.put_model_registry_row(&row)?;
    let model = row.catalog.model;
    let snapshot = |at, a, b| ScoreSnapshot {
        source: "bench".into(),
        fetched_at: at,
        observations: vec![
            ScoreObservation {
                model: model.clone(),
                benchmark: "a".into(),
                score: a,
            },
            ScoreObservation {
                model: model.clone(),
                benchmark: "b".into(),
                score: b,
            },
        ],
    };
    assert_eq!(vault.apply_model_scores(&snapshot(10, 1.0, 2.0))?.len(), 2);
    assert_eq!(vault.apply_model_scores(&snapshot(20, 3.0, 4.0))?.len(), 2);
    assert!(
        vault
            .apply_model_scores(&snapshot(20, 3.0, 4.0))?
            .is_empty()
    );
    assert!(vault.apply_model_scores(&snapshot(20, 3.0, 5.0)).is_err());
    let stored = vault.model_registry_row(&model)?.unwrap();
    assert_eq!(stored.scores["bench"]["a"], 3.0);
    assert_eq!(stored.scores["bench"]["b"], 4.0);
    assert_eq!(vault.model_score_diffs(&model)?.len(), 4);
    Ok(())
}

#[test]
fn seed_rejects_score_watermarks_without_inserting_any_rows() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let mut poisoned = row("poisoned");
    poisoned.fetched_at.insert("bench".into(), u64::MAX);
    poisoned
        .catalog
        .metadata
        .insert("description".into(), serde_json::json!({}));
    let mut valid = row("valid");
    valid
        .catalog
        .metadata
        .insert("description".into(), serde_json::json!({}));
    let seed = CatalogSeed {
        version: 1,
        rows: vec![valid, poisoned],
    };
    assert!(matches!(
        CatalogSeed::from_json(&serde_json::to_vec(&seed).unwrap()),
        Err(Error::InvalidConfig(_))
    ));
    assert!(matches!(
        vault.seed_model_catalog(&seed),
        Err(Error::InvalidConfig(_))
    ));
    assert!(vault.model_registry_rows()?.is_empty());
    Ok(())
}

#[test]
fn multi_source_refresh_is_atomic_on_parse_and_storage_refusals() -> Result<()> {
    struct Fetch(std::collections::VecDeque<serde_json::Value>);
    impl ScoreFetch for Fetch {
        fn fetch(&mut self, _: &ScoreSourceConfig) -> Result<serde_json::Value> {
            Ok(self.0.pop_front().expect("scheduled fetch"))
        }
    }
    for storage_failure in [false, true] {
        let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
        let registered = row("one");
        vault.put_model_registry_row(&registered)?;
        let model = registered.catalog.model.clone();
        if storage_failure {
            vault.apply_model_scores(&ScoreSnapshot {
                source: "second".into(),
                fetched_at: 200,
                observations: vec![ScoreObservation {
                    model: model.clone(),
                    benchmark: "quality".into(),
                    score: 30.0,
                }],
            })?;
        }
        let before = vault.model_registry_row(&model)?.unwrap();
        let before_diffs = vault.model_score_diffs(&model)?;
        let config = ScoreScraperConfig {
            version: 1,
            fetch_interval_secs: 60,
            sources: ["first", "second"]
                .into_iter()
                .map(|id| ScoreSourceConfig {
                    id: id.into(),
                    url: "https://example.invalid/scores".into(),
                    rows_pointer: "/data".into(),
                    model_pointer: "/model".into(),
                    score_pointer: "/score".into(),
                    benchmark: "quality".into(),
                    model_bindings: BTreeMap::from([("external".into(), model.clone())]),
                })
                .collect(),
        };
        let good = serde_json::json!({"data":[{"model":"external","score":50.0}]});
        let bad = if storage_failure {
            good.clone()
        } else {
            serde_json::json!({"data":{}})
        };
        let mut scraper = ScoreScraper::new(
            config,
            Fetch(vec![good.clone(), bad, good.clone(), good].into()),
        )?;
        assert!(matches!(
            scraper.refresh(&vault, 100),
            Err(Error::InvalidConfig(_))
        ));
        assert_eq!(vault.model_registry_row(&model)?.unwrap(), before);
        assert_eq!(vault.model_score_diffs(&model)?, before_diffs);
        let retry_at = if storage_failure { 201 } else { 100 };
        assert_eq!(scraper.refresh(&vault, retry_at)?.len(), 2);
        assert!(scraper.refresh(&vault, retry_at)?.is_empty());
        let after = vault.model_registry_row(&model)?.unwrap();
        assert_eq!(after.scores["first"]["quality"], 50.0);
        assert_eq!(after.scores["second"]["quality"], 50.0);
    }
    Ok(())
}

#[test]
fn scheduled_scraper_fetches_changed_snapshots_without_changing_answerer_bindings() -> Result<()> {
    use std::{collections::VecDeque, sync::Arc, time::Duration};
    struct Fetch(VecDeque<serde_json::Value>);
    impl ScoreFetch for Fetch {
        fn fetch(&mut self, _: &ScoreSourceConfig) -> Result<serde_json::Value> {
            Ok(self
                .0
                .pop_front()
                .expect("one fixture per scheduled attempt"))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(
        dir.path().join("vault"),
        crate::VaultConfig::device(),
    )?);
    let registered = row("one");
    let model = registered.catalog.model.clone();
    vault.put_model_registry_row(&registered)?;
    let config = ScoreScraperConfig {
        version: 1,
        fetch_interval_secs: 1,
        sources: vec![ScoreSourceConfig {
            id: "external-bench".into(),
            url: "https://example.invalid/scores".into(),
            rows_pointer: "/data".into(),
            model_pointer: "/model".into(),
            score_pointer: "/score".into(),
            benchmark: "quality".into(),
            model_bindings: BTreeMap::from([("external".into(), model.clone())]),
        }],
    };
    let snapshot = |score| serde_json::json!({"data": [{"model":"external", "score":score}]});
    let scraper = ScoreScraper::new(config, Fetch(vec![snapshot(50), snapshot(70)].into()))?;
    let worker = scraper.start(Arc::clone(&vault));
    let first = worker
        .results()
        .recv_timeout(Duration::from_secs(5))
        .unwrap()?;
    assert_eq!(first.len(), 1);
    let second = worker
        .results()
        .recv_timeout(Duration::from_secs(5))
        .unwrap()?;
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].previous, Some(50.0));
    drop(worker);
    assert_eq!(vault.model_score_diffs(&model)?.len(), 2);
    assert_eq!(
        vault.model_registry_row(&model)?.unwrap().catalog,
        registered.catalog
    );
    assert!(vault.model_manifest()?.is_none());
    Ok(())
}
