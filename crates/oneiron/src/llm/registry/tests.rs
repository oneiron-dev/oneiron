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
#[test]
fn seeded_vendors_validate_and_flags_gate_admission() -> Result<()> {
    let seed = CatalogSeed::bundled()?;
    assert!(seed.rows.len() >= 40);
    let vendors: std::collections::BTreeSet<_> = seed
        .rows
        .iter()
        .map(|r| r.catalog.model.provider())
        .collect();
    assert!(vendors.len() >= 40);
    for row in &seed.rows {
        row.validate()?;
        assert!(row.catalog.cost.is_some());
        assert!(row.catalog.context_window_tokens > 0);
    }
    let entry = row("restricted").catalog;
    assert!(entry.require(LlmCapability::ToolCalling).is_err());
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    vault.seed_model_catalog(&seed)?;
    vault.seed_model_catalog(&seed)?;
    assert_eq!(vault.model_registry_rows()?.len(), seed.rows.len());
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
    let current = vault.model_registry_row(&model)?.expect("row");
    assert_eq!(current.scores["bench"]["quality"], 50.0);
    assert_eq!(current.fetched_at["bench"], 160);
    assert_eq!(vault.model_score_diffs(&model)?.len(), 1);
    Ok(())
}
