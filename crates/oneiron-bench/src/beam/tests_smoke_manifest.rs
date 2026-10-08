//! Smoke and manifest tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::{
        budget_score, empty_pack_stats_report, find_arm,
    };
    use super::super::*;
    use oneiron::Vault;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::collections::HashSet;

    #[test]
    fn manifest_schema_version_rejects_legacy_v1_before_required_competitors() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["schemaVersion"] = serde_json::json!(1);
        manifest_json
            .as_object_mut()
            .expect("manifest object")
            .remove("competitors");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("legacy v1 manifests must be rejected by schema version first");

        assert!(matches!(
            &err,
            BeamError::UnsupportedSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: 1
            }
        ));
        assert!(!err.to_string().contains("missing field `competitors`"));
    }

    #[test]
    fn manifest_validation_rejects_uncarded_competitor_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]
            .as_object_mut()
            .expect("competitor object")
            .remove("card");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("uncarded competitors must be rejected");

        assert!(
            err.to_string()
                .contains("uncarded BEAM competitor row `deterministic-context-pack`")
        );
    }

    #[test]
    fn oracle_and_in_family_competitors_stay_out_of_the_main_report() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["axes"]["regime"] = serde_json::json!("oracle");
        manifest_json["competitors"][1]["card"]["axes"]["judge"]["inFamily"] =
            serde_json::json!(true);
        let manifest = parse_manifest_json(&manifest_json.to_string()).expect("manifest parses");
        let report = run_fixture_manifest(&manifest, &fixture).expect("fixture runs");
        for case in &report.cases {
            assert!(
                case.competitors.iter().all(|row| {
                    !matches!(row.arm, ArmKind::Deterministic | ArmKind::VanillaRag)
                })
            );
            assert_eq!(case.appendix[0].competitor_id, "deterministic-context-pack");
            assert_eq!(case.appendix[1].competitor_id, "vanilla-rag");
        }
    }

    #[test]
    fn deterministic_arm_exercises_serialized_128k_budget_path() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        load_dataset(&vault, &manifest, Some(&fixture)).expect("fixture loads");

        let pack =
            run_deterministic_context_pack(&vault, &fixture.cases[0]).expect("deterministic run");
        let serialized_text =
            std::str::from_utf8(&pack.serialized).expect("serialized context pack is UTF-8");

        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(pack.raw.results.len() >= fixture.cases[0].expected_min_results);
        assert!(!pack.serialized.is_empty());
        assert!(serialized_text.contains("results:"));
        assert!(serialized_text.contains(
            "txt: BEAM deterministic context pack 128K smoke target for evaluation scaffolding."
        ));
        assert!(serialized_text.contains("lvl: benchmark-smoke"));
        assert!(serialized_text.contains("at: beam-smoke-t1"));
        let report = context_pack_report(&pack, &fixture.cases[0]);
        assert_eq!(report.result_count, pack.raw.results.len());
        assert_eq!(report.budgeted_text_by_entity_id.len(), report.result_count);
        let mut wrong_frontier = pack.raw.clone();
        for entity in wrong_frontier
            .results
            .iter_mut()
            .chain(&mut wrong_frontier.neighbors)
        {
            let mut revision = entity.source_revision_ref.expect("captured revision");
            revision[0] ^= 1;
            entity.source_revision_ref = Some(revision);
        }
        assert!(
            context_entity_reports_for_ids(&wrong_frontier.results, &pack.serialized_ids.results,)
                .is_empty()
        );
        assert!(
            budgeted_text_by_entity_id(&wrong_frontier, &pack.serialized_ids.text_by_id,)
                .is_empty()
        );
        assert!(
            pack.serialized_ids
                .results
                .iter()
                .any(|id| id.starts_with("sm"))
        );
    }

    #[test]
    fn serialized_context_pack_ids_ignore_nested_yaml_id_fields() {
        let serialized = r#"
results:
  memory:
    - id: result:01
      txt: Budgeted result text
      title: kept
      nested:
        - id: dropped-result:02
neighbors:
  memory:
    - id: neighbor:03
      txt: "Budgeted neighbor text"
      nested:
        - id: dropped-neighbor:04
"#;

        let ids = serialized_context_pack_ids(serialized);

        assert_eq!(ids.results, HashSet::from(["result:01".to_owned()]));
        assert_eq!(ids.neighbors, HashSet::from(["neighbor:03".to_owned()]));
        assert_eq!(
            ids.text_by_id.get("result:01").map(String::as_str),
            Some("Budgeted result text")
        );
        assert_eq!(
            ids.text_by_id.get("neighbor:03").map(String::as_str),
            Some("Budgeted neighbor text")
        );
    }

    #[test]
    fn budget_discipline_uses_accounting_not_serialized_byte_count() {
        let case = FixtureCase {
            ppr_vad_query: None,
            case_id: "budget-accounting-regression".to_owned(),
            query: "budget accounting".to_owned(),
            limit: 1,
            token_budget: 8,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let mut context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 24,
            serialized_tokens: 6,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 2,
                output_tokens: 6,
                target_tokens: case.token_budget as u64,
                elapsed_us: 10,
                cost_usd: 0.0,
            },
            result_count: 1,
            neighbor_count: 0,
            results: Vec::new(),
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: None,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        };

        let scores = completed_ability_scores(&case, &context_pack);
        let budget = budget_score(&scores);
        assert_eq!(
            budget.passed,
            Some(true),
            "bytes can exceed token budget units when no serializer accounting loss occurred"
        );
        assert_eq!(budget.score, Some(1.0));

        context_pack.serialized_bytes = 4;
        context_pack.stats.items_dropped = 1;
        context_pack.stats.items_dropped_reasons = vec!["token_budget".to_owned()];

        let scores = completed_ability_scores(&case, &context_pack);
        let budget = budget_score(&scores);
        assert_eq!(
            budget.passed,
            Some(false),
            "small byte output must not pass when serialization accounting dropped content"
        );
        assert_eq!(budget.score, Some(0.0));
    }

    #[test]
    fn deterministic_arm_runs_beam_128k_fixture_end_to_end() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let deterministic = find_arm(&report, ArmKind::Deterministic);

        let ArmOutcome::Completed { context_pack } = &deterministic.outcome else {
            panic!("deterministic arm should complete");
        };
        assert_eq!(context_pack.token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(context_pack.result_count >= 1);
        assert!(
            context_pack
                .results
                .iter()
                .any(|entity| { entity.id == "10101010101010101010101010101010" })
        );
    }

    #[test]
    fn vanilla_rag_arm_runs_beam_128k_fixture_end_to_end() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let vanilla = find_arm(&report, ArmKind::VanillaRag);

        let ArmOutcome::Completed { context_pack } = &vanilla.outcome else {
            panic!("vanilla-rag arm should complete");
        };

        assert_eq!(context_pack.token_budget, BEAM_128K_TOKEN_BUDGET);
        assert!(context_pack.result_count >= 1);
        assert!(
            context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "vector")
        );
        assert!(
            context_pack
                .stats
                .signals_used
                .iter()
                .any(|signal| signal == "text")
        );
        assert!(
            context_pack
                .results
                .iter()
                .any(|entity| { entity.id == "10101010101010101010101010101010" })
        );
    }
}
