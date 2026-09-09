//! Smoke and manifest tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::{
        budget_score, completed_context_pack, empty_pack_stats_report, find_arm,
    };
    use super::super::*;
    use oneiron::Vault;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::collections::HashSet;

    #[test]
    fn parse_fixture_and_manifest_accepts_beam_128k_smoke_schema() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");

        assert_eq!(fixture.schema_version, SCHEMA_VERSION);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
        assert_eq!(fixture.fixture_id, "beam-128k-smoke");
        assert_eq!(fixture.cases[0].token_budget, BEAM_128K_TOKEN_BUDGET);
        ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect("manifest selects the 128K smoke case");
        assert_eq!(
            manifest.arms,
            vec![
                ArmKind::Deterministic,
                ArmKind::VanillaRag,
                ArmKind::BackboneSolo,
                ArmKind::Agentic,
                ArmKind::Chat
            ]
        );
    }

    #[test]
    fn fixture_validation_requires_fields_object() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["fields"] = serde_json::json!(["body"]);
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("fixture fields must be object");

        assert!(
            err.to_string()
                .contains("record fields must be a JSON object")
        );
    }

    #[test]
    fn fixture_validation_rejects_missing_fields() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]
            .as_object_mut()
            .expect("record object")
            .remove("fields");
        let err =
            parse_fixture_json(&fixture_json.to_string()).expect_err("record fields are required");

        assert!(err.to_string().contains("missing field `fields`"));
    }

    #[test]
    fn fixture_validation_rejects_text_field_missing_from_fields() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["records"][0]["text"][0]["field"] = serde_json::json!("missing");
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("text field must reference stored field");

        assert!(
            err.to_string()
                .contains("text fields must reference keys present in record.fields")
        );
    }

    #[test]
    fn manifest_validation_rejects_duplicate_arms() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["arms"] = serde_json::json!(["deterministic", "deterministic"]);
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("duplicate arms must be rejected");

        assert!(err.to_string().contains("manifest arms must be unique"));
    }

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
    fn manifest_validation_requires_competitor_rows_to_match_arms() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["arm"] = serde_json::json!("chat");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("competitor rows must match arms");

        assert!(
            err.to_string()
                .contains("competitor row arms must match manifest arms in order")
        );
    }

    #[test]
    fn manifest_validation_rejects_public_parity_for_fixture_dataset() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["publicParityStatus"] =
            serde_json::json!("public_parity");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("fixture-backed manifests must not claim public parity");

        assert!(
            err.to_string()
                .contains("fixture-backed BEAM manifests cannot claim public parity")
        );
    }

    #[test]
    fn run_fixture_manifest_validates_manifest_before_loading_dataset() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest.schema_version = 1;
        manifest.dataset = DatasetSource::Miracl {
            dataset: "should-not-load".to_owned(),
        };

        let err = run_fixture_manifest(&manifest, &fixture)
            .expect_err("manifest validation must run before dataset loading");

        assert!(matches!(
            err,
            BeamError::UnsupportedSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: 1
            }
        ));
    }

    #[test]
    fn run_fixture_manifest_validates_case_ids_before_loading_dataset() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        fixture.records[0].id = "not-a-hex-entity-id".to_owned();
        manifest.case_ids = vec!["missing_case".to_owned()];

        let err = run_fixture_manifest(&manifest, &fixture)
            .expect_err("case-id validation must run before dataset loading");

        assert!(matches!(
            err,
            BeamError::MissingCase {
                fixture_id,
                case_id
            } if fixture_id == "beam-128k-smoke" && case_id == "missing_case"
        ));
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
    fn deterministic_arm_reports_budgeted_pack_when_token_budget_drops_rows() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        for (offset, id) in [
            "30303030303030303030303030303030",
            "40404040404040404040404040404040",
            "50505050505050505050505050505050",
        ]
        .into_iter()
        .enumerate()
        {
            let mut record = fixture.records[0].clone();
            record.id = id.to_owned();
            record.occurred.start = 3 + offset as u64;
            record.occurred.end = 3 + offset as u64;
            record.learned_at = 3 + offset as u64;
            fixture.records.push(record);
        }
        fixture.cases[0].token_budget = 1;
        fixture.cases[0].expected_min_results = 0;
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        let loaded = load_dataset(&vault, &manifest, Some(&fixture)).expect("fixture loads");
        let raw_pack = configured_context_pack_builder(&vault, &fixture.cases[0])
            .run()
            .expect("raw context pack");

        let arm = DeterministicContextPackArm
            .run(&vault, &loaded, &fixture.cases[0])
            .expect("deterministic arm reports");
        let ArmOutcome::Completed { context_pack } = arm.outcome else {
            panic!("deterministic arm should complete");
        };

        assert_eq!(context_pack.serialized_format, "yaml");
        assert!(raw_pack.results.len() > context_pack.result_count);
        assert!(context_pack.stats.items_dropped > 0);
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
        assert!(budget.detail.contains("token_budget"));
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

    #[test]
    fn vanilla_rag_and_deterministic_share_real_token_budget() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let deterministic = completed_context_pack(&report, ArmKind::Deterministic);
        let vanilla = completed_context_pack(&report, ArmKind::VanillaRag);

        assert_eq!(deterministic.token_budget, vanilla.token_budget);
        assert_eq!(
            deterministic.query_cost.target_tokens,
            vanilla.query_cost.target_tokens
        );
        assert_eq!(deterministic.tokenizer_id, vanilla.tokenizer_id);
        assert_eq!(deterministic.stats.tokenizer_id, vanilla.stats.tokenizer_id);
        assert!(deterministic.serialized_tokens <= deterministic.token_budget as u64);
        assert!(vanilla.serialized_tokens <= vanilla.token_budget as u64);
        assert_eq!(
            vanilla.query_cost.token_source,
            TokenAccountingSource::TokenizerCount
        );
    }

    #[test]
    fn built_in_128k_guard_checks_manifest_selected_cases() {
        let mut fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        fixture.cases.push(FixtureCase {
            ppr_vad_query: None,
            case_id: "beam_small_budget_smoke".to_owned(),
            query: "BEAM deterministic context pack".to_owned(),
            limit: 5,
            token_budget: 4096,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        });
        manifest.case_ids = vec!["beam_small_budget_smoke".to_owned()];

        let err = ensure_manifest_selects_128k_case(&manifest, &fixture)
            .expect_err("manifest must select a 128K case");
        assert!(
            err.to_string()
                .contains("built-in BEAM smoke manifest must select a 128K token-budget case")
        );
    }

}
