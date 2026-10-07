//! Item 10: the budget sweep and the results rows.

#[cfg(test)]
mod tests {
    use super::super::sweep::{BudgetLabel, PriceConfig, SweepOptions, parse_budgets, wilson};
    use oneiron::policy_model::SecretScanMode;
    use super::super::tests_contract_v2::tests::V2Fixture;
    use super::super::*;
    use std::path::Path;

    #[test]
    fn budget_list_parses_sorted_distinct_with_full_last() {
        let budgets = parse_budgets("65536,4096,8192,full,16384,32768,4096").unwrap();
        assert_eq!(
            budgets,
            [4096, 8192, 16384, 32768, 65536]
                .map(BudgetLabel::Tokens)
                .into_iter()
                .chain([BudgetLabel::Full])
                .collect::<Vec<_>>()
        );
        assert!(parse_budgets("0").is_err());
        assert!(parse_budgets("lots").is_err());
        assert!(parse_budgets("").is_err());
    }

    #[test]
    fn wilson_interval_brackets_the_rate() {
        let (lo, hi) = wilson(8, 10);
        assert!(lo < 0.8 && 0.8 < hi && lo > 0.4 && hi < 0.97);
        assert_eq!(wilson(0, 0), (0.0, 1.0));
    }

    fn prices() -> PriceConfig {
        PriceConfig::load(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/prices.example.json"),
        )
        .unwrap()
    }

    #[test]
    fn sweep_runs_every_arm_at_every_budget_and_writes_rows() {
        let fixture = V2Fixture::write(&["q-a", "q-b"]);
        let mut raw: serde_json::Value =
            serde_json::from_str(super::super::tests_community_eval004::CONTRACT_MANIFEST_JSON)
                .unwrap();
        raw["runId"] = serde_json::json!(super::super::tests_contract_v2::tests::V2_RUN_ID);
        raw["dataset"]["path"] = serde_json::json!(fixture.run_jsonl);
        raw["caseIds"] = serde_json::json!(["q-a", "q-b"]);
        raw["outputs"]["packsJsonl"] = serde_json::json!(fixture.packs_jsonl);
        raw["outputs"]["resultsRoot"] = serde_json::json!(fixture.path().join("results"));
        // A tiny budget legitimately returns an empty pack.
        raw["dataset"]["expectedMinResults"] = serde_json::json!(0);
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let results_path = fixture.path().join("rows.jsonl");
        // 25 tokens hold only the newest item, m-2; the evidence is m-1.
        let sweep = SweepOptions {
            budgets: parse_budgets("25,full").unwrap(),
            prices: Some(prices()),
            results_path: Some(results_path.clone()),
            secrets: None,
        };
        let report = super::super::runner::run_manifest_with(&manifest, None, &sweep).unwrap();
        assert_eq!(report.cases.len(), 4, "2 questions x 2 budgets");
        assert_eq!(report.dataset.forks, 2, "budgets share the question's fork");
        let pack_budgets: Vec<u64> = std::fs::read_to_string(&fixture.packs_jsonl)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["budget"]["limit"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert!(
            pack_budgets.contains(&25) && pack_budgets.contains(&(1 << 30)),
            "each pack row states the sweep point it was built under: {pack_budgets:?}"
        );

        let row = |approach: &str, label: &str, metric: &str| {
            report
                .results
                .iter()
                .find(|row| {
                    row.approach == approach
                        && row.budget_label == label
                        && row.group == "all"
                        && row.metric == metric
                })
                .unwrap_or_else(|| panic!("row {approach} {label} {metric}"))
                .clone()
        };
        let window_small = row("full-context", "25", "evidence_recall");
        let window_full = row("full-context", "full", "evidence_recall");
        assert_eq!(window_small.accuracy, Some(0.0), "the window lost m-1");
        assert_eq!(window_full.accuracy, Some(1.0));
        assert!(window_small.rot && window_full.rot);
        assert_eq!(window_small.budget, Some(25));
        assert_eq!(window_full.budget, None, "full carries no number");
        assert!(window_full.prompt_tokens_mean > window_small.prompt_tokens_mean);
        assert!(
            window_full.usd_per_1k_questions.unwrap() > window_small.usd_per_1k_questions.unwrap()
        );
        let oneiron = row("oneiron-deterministic", "full", "evidence_all_found");
        assert_eq!(oneiron.n, 2);
        assert!(
            oneiron.ci95_low.is_some(),
            "0/1 metric carries a Wilson interval"
        );
        assert!(oneiron.latency_ms_p50.is_some() && oneiron.latency_ms_p95.is_some());
        assert_eq!(oneiron.price_table.as_ref().unwrap().as_of, "2026-10-06");
        assert!(
            report
                .results
                .iter()
                .any(|row| row.approach == "vanilla-rag")
        );
        assert!(
            report
                .results
                .iter()
                .any(|row| row.group == "ability:information_extraction")
        );

        let card = report.card.as_ref().unwrap();
        assert_eq!(card.pins.budget_sweep, ["25", "full"]);
        assert_eq!(
            card.references[0].title,
            "Context Rot: How Increasing Input Tokens Impacts LLM Performance"
        );
        let written = std::fs::read_to_string(&results_path).unwrap();
        assert_eq!(written.lines().count(), report.results.len());
        let first: serde_json::Value =
            serde_json::from_str(written.lines().next().unwrap()).unwrap();
        assert_eq!(first["schema"], "oneiron-bench.results-row.v1");
        assert!(
            card.result_dir
                .as_ref()
                .unwrap()
                .join("results.jsonl")
                .exists()
        );
    }

    #[test]
    fn a_record_budget_run_still_writes_rows_at_the_record_budget() {
        let fixture = V2Fixture::write(&["q-a"]);
        let report = run_manifest(&fixture.manifest(&["q-a"]), None).unwrap();
        assert!(report.results.iter().all(|row| row.budget == Some(131_072)));
        assert!(
            report
                .results
                .iter()
                .any(|row| row.approach == "full-context")
        );
        assert_eq!(report.card.unwrap().pins.budget_sweep, ["record"]);
    }

    /// A GitHub-token-shaped value, assembled at run time so no literal in
    /// the source matches a provider pattern.
    fn token_shaped() -> String {
        ["gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"].concat()
    }

    /// The v2 fixture with m-2 replaced by a turn that carries a
    /// credential-shaped token, and its corpus sha256 updated.
    fn fixture_with_token() -> V2Fixture {
        use super::super::tests_contract_v2::tests::{corpus_jsonl, v2_corpus_items};
        let fixture = V2Fixture::write(&["q-a"]);
        let mut items = v2_corpus_items();
        let text = format!("my deploy token is {} for now", token_shaped());
        items[1]["text"] = serde_json::json!(text);
        items[1]["source_sha256"] =
            serde_json::json!(super::super::load::sha256_hex(text.as_bytes()));
        let corpus = corpus_jsonl(&items);
        std::fs::write(&fixture.corpus_path, &corpus).unwrap();
        let run = std::fs::read_to_string(&fixture.run_jsonl).unwrap();
        let old = super::super::load::sha256_hex(corpus_jsonl(&v2_corpus_items()).as_bytes());
        std::fs::write(
            &fixture.run_jsonl,
            run.replace(&old, &super::super::load::sha256_hex(corpus.as_bytes())),
        )
        .unwrap();
        fixture
    }

    fn sweep_with(secrets: Option<SecretScanMode>) -> SweepOptions {
        SweepOptions {
            budgets: parse_budgets("full").unwrap(),
            secrets,
            ..SweepOptions::default()
        }
    }

    #[test]
    fn secret_scan_off_ingests_a_token_shaped_turn_that_the_default_refuses() {
        let flags = |value: &str| {
            super::super::arms::parse_sweep_flags(&["--secret-scan".to_owned(), value.to_owned()])
        };
        assert_eq!(flags("off").unwrap().secrets, Some(SecretScanMode::Off));
        assert_eq!(flags("on").unwrap().secrets, Some(SecretScanMode::On));
        assert!(flags("maybe").is_err());
        assert_eq!(SweepOptions::default().secrets, None);

        let fixture = fixture_with_token();
        let manifest = fixture.manifest(&["q-a"]);
        let error = super::super::runner::run_manifest_with(&manifest, None, &sweep_with(None))
            .expect_err("the scan is on by default")
            .to_string();
        assert!(error.contains("refused 1 of 2 corpus items"), "{error}");
        let error = super::super::runner::run_manifest_with(
            &manifest,
            None,
            &sweep_with(Some(SecretScanMode::On)),
        )
        .expect_err("--secret-scan on keeps the scan")
        .to_string();
        assert!(error.contains("refused 1 of 2 corpus items"), "{error}");

        let report = super::super::runner::run_manifest_with(
            &manifest,
            None,
            &sweep_with(Some(SecretScanMode::Off)),
        )
        .expect("--secret-scan off ingests every item");
        let exactness = report.exactness.as_ref().unwrap();
        assert_eq!(exactness.items_checked, 2, "both items read back byte-exact");
        assert!(exactness.mismatches.is_empty());
    }

    #[test]
    fn every_row_and_the_card_state_the_secrets_setting_the_forks_read_back() {
        let (base, ()) = super::super::fork::BaseVault::build(
            "corpus-a".into(),
            super::super::util::beam_vault_config(),
            Some(SecretScanMode::Off),
            |_| Ok(()),
        )
        .unwrap();
        let fork = base.fork("q-a").unwrap();
        assert_eq!(fork.secrets, SecretScanMode::Off, "the copy carries the switch");
        assert_eq!(fork.vault.secret_scan_mode().unwrap(), SecretScanMode::Off);

        let fixture = fixture_with_token();
        let manifest = fixture.manifest(&["q-a"]);
        let results_path = fixture.path().join("rows.jsonl");
        let report = super::super::runner::run_manifest_with(
            &manifest,
            None,
            &SweepOptions {
                results_path: Some(results_path.clone()),
                ..sweep_with(Some(SecretScanMode::Off))
            },
        )
        .unwrap();
        assert!(!report.results.is_empty());
        assert!(
            report
                .results
                .iter()
                .all(|row| row.secrets == Some(SecretScanMode::Off))
        );
        assert_eq!(report.card.as_ref().unwrap().pins.secrets, ["off"]);
        let written = std::fs::read_to_string(&results_path).unwrap();
        for line in written.lines() {
            let row: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["secrets"], "off", "{line}");
        }

        let clean = V2Fixture::write(&["q-a"]);
        let report = super::super::runner::run_manifest_with(
            &clean.manifest(&["q-a"]),
            None,
            &sweep_with(None),
        )
        .unwrap();
        assert!(
            report
                .results
                .iter()
                .all(|row| row.secrets == Some(SecretScanMode::On)),
            "a vault nobody switched reads on"
        );
        assert_eq!(report.card.unwrap().pins.secrets, ["on"]);
    }
}
