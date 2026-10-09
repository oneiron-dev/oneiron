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

// Model the pinned Git transport's successful fetch of the fixture tree.
struct CatalogAdapter {
    hub: crate::EntityId,
    endpoint: String,
    source: crate::skill_hub::pack_catalog::PackSource,
}
impl crate::skill_hub::SkillHubAdapter for CatalogAdapter {
    fn hub_id(&self) -> crate::EntityId {
        self.hub
    }
    fn kind(&self) -> crate::skill_hub::SkillHubKind {
        crate::skill_hub::SkillHubKind::Git
    }
    fn endpoint(&self) -> Option<&str> {
        Some(&self.endpoint)
    }
    fn fetch_package(&self, _: &crate::skill_hub::HubRef) -> Result<crate::skill_hub::HubPackage> {
        Err(crate::Error::EntityNotFound)
    }
}
impl crate::skill_hub::pack_catalog::PackSourceAdapter for CatalogAdapter {
    fn fetch_pack_source(
        &self,
        _: &crate::skill_hub::HubRef,
    ) -> Result<crate::skill_hub::pack_catalog::PackSource> {
        Ok(self.source.clone())
    }
}

struct DataOnlyFit;
impl crate::skill_hub::pack_catalog::PackFitPolicy for DataOnlyFit {
    fn evaluate(
        &self,
        _: &crate::skill_hub::pack_catalog::PackSource,
        permissions: &crate::skill_hub::pack_catalog::PackPermissions,
    ) -> Result<crate::skill_hub::pack_catalog::PackFitVerdict> {
        assert!(permissions.grants.is_empty());
        assert!(permissions.wakes.is_empty());
        assert!(permissions.bundled_skills.is_empty());
        Ok(crate::skill_hub::pack_catalog::PackFitVerdict {
            fits: true,
            rules_hit: false,
            code_auto_install: false,
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
    // Install admission resolves the seeded policy manifest.
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::device())?;
    let at = TimeRange { start: 1, end: 1 };
    // A staged source without an installation is not a catalog.
    assert!(CatalogSeed::from_installed_pack(&vault).is_err());
    vault.stage_pack_source(&source, at, 1)?;
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
    let adapter = CatalogAdapter {
        hub: hub_id,
        endpoint: vault.skill_hub_record(&hub_id)?.endpoint,
        source: source.clone(),
    };
    let (source_id, pinned) =
        vault.fetch_pack_from_adapter(&adapter, &reference, &publisher, at, 1)?;
    let ask = vault.prepare_pack_install(source_id, &pinned, &publisher, &DataOnlyFit)?;
    let PackInstallDisposition::Installed(receipt) = vault.install_pack(&ask)? else {
        panic!("post-fit data pack must install");
    };
    assert!(receipt.permissions.grants.is_empty());
    assert!(receipt.permissions.wakes.is_empty());
    assert!(receipt.skills.is_empty());
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
