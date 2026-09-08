//! JSONL contract tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::empty_pack_stats_report;
    use super::super::*;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::path::PathBuf;

    #[test]
    fn jsonl_contract_manifest_emits_packs_with_bucket_labels() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        std::fs::write(&run_jsonl_path, CONTRACT_RUN_JSONL).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let report = run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(report.dataset.source_kind, "jsonl");
        assert_eq!(report.dataset.pending_vectors, 0);
        assert_eq!(rows.len(), 2);
        assert_eq!(deterministic["contract_version"], EVAL_CONTRACT_VERSION);
        assert_eq!(deterministic["record_type"], "context_pack");
        assert_eq!(deterministic["arm"]["id"], "oneiron");
        assert_eq!(deterministic["arm"]["kind"], ONEIRON_CONTEXT_PACK_ARM_KIND);
        assert_eq!(
            deterministic["gold"]["labels"]["ability"],
            "information_extraction"
        );
        assert_eq!(
            deterministic["gold"]["labels"]["wedge_bucket"],
            "needle_short"
        );
        assert!(
            deterministic["pack"]["contexts"]
                .as_array()
                .expect("contexts array")
                .iter()
                .any(|context| context["id"] == "turn-1"
                    && context["text"]
                        .as_str()
                        .expect("context text")
                        .contains("contract launch code is tulip"))
        );
        assert_eq!(vanilla["arm"]["id"], VANILLA_RAG_CONTRACT_ARM_ID);
        assert_eq!(vanilla["arm"]["kind"], VANILLA_RAG_CONTRACT_ARM_KIND);
        assert_eq!(
            vanilla["pack"]["config"]["kind"],
            VANILLA_RAG_CONTRACT_ARM_KIND
        );
        assert_eq!(vanilla["pack"]["config"]["topK"], 5);
        assert_eq!(
            vanilla["pack"]["config"]["fusion"],
            serde_json::json!(VANILLA_RAG_FUSION)
        );
        assert_eq!(
            deterministic["pack"]["corpusDigest"], vanilla["pack"]["corpusDigest"],
            "purity gate: comparator rows must share the exact same ingested corpus"
        );
        assert!(
            vanilla["pack"]["contexts"]
                .as_array()
                .expect("contexts array")
                .iter()
                .any(|context| context["id"] == "turn-1")
        );
    }

    #[test]
    fn jsonl_arm_id_selects_oneiron_row_when_question_has_two_arms() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut ours: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        ours["arm"]["id"] = serde_json::json!("oneiron");
        ours["arm"]["kind"] = serde_json::json!(ONEIRON_CONTEXT_PACK_ARM_KIND);
        let mut l0 = ours.clone();
        l0["arm"]["id"] = serde_json::json!("longmemeval_l0");
        l0["arm"]["kind"] = serde_json::json!("baseline_jsonl");
        l0["gold"]["labels"]["wedge_bucket"] = serde_json::json!("wrong_arm_bucket");
        std::fs::write(&run_jsonl_path, format!("{l0}\n{ours}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["armId"] = serde_json::json!("oneiron");
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(rows.len(), 2);
        assert_eq!(deterministic["arm"]["id"], "oneiron");
        assert_eq!(deterministic["arm"]["kind"], ONEIRON_CONTEXT_PACK_ARM_KIND);
        assert_eq!(
            deterministic["gold"]["labels"]["wedge_bucket"],
            "needle_short"
        );
        assert_eq!(vanilla["arm"]["id"], VANILLA_RAG_CONTRACT_ARM_ID);
        assert_eq!(vanilla["gold"]["labels"]["wedge_bucket"], "needle_short");
    }

    #[test]
    fn purity_gate_keeps_gold_unreachable_from_arm_assembly() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let secret = "PURE_RECALL_GOLD_ONLY";
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["question_id"] = serde_json::json!("purity_gate_gold_unreachable");
        row["question"] = serde_json::json!("What does the purity probe note say?");
        row["corpus"] = serde_json::json!([
            {
                "id": "visible-turn",
                "text": "The purity probe note says the visible answer is amber.",
                "metadata": {"case": "purity"},
                "embedding": {
                    "encoding": "f32-le-base64",
                    "dimensions": 4,
                    "data": "AACAPwAAAAAAAAAAAAAAAA=="
                }
            }
        ]);
        row["gold"]["answers"] = serde_json::json!([secret]);
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");

        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["caseIds"] = serde_json::json!(["purity_gate_gold_unreachable"]);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        run_manifest(&manifest, None).expect("purity run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();
        let deterministic = rows
            .iter()
            .find(|row| row["arm"]["kind"] == ONEIRON_CONTEXT_PACK_ARM_KIND)
            .expect("deterministic context-pack row");
        let vanilla = rows
            .iter()
            .find(|row| row["arm"]["kind"] == VANILLA_RAG_CONTRACT_ARM_KIND)
            .expect("vanilla-rag row");

        assert_eq!(rows.len(), 2);
        assert_eq!(
            deterministic["pack"]["corpusDigest"],
            vanilla["pack"]["corpusDigest"]
        );
        for row in rows {
            assert_eq!(row["gold"]["answers"][0], secret);
            let contexts = row["pack"]["contexts"].as_array().expect("contexts array");
            assert!(contexts.iter().any(|context| {
                context["text"]
                    .as_str()
                    .expect("context text")
                    .contains("visible answer is amber")
            }));
            assert!(contexts.iter().all(|context| {
                !context["text"]
                    .as_str()
                    .expect("context text")
                    .contains(secret)
            }));
        }
    }

    #[test]
    fn duplicate_jsonl_question_without_arm_id_fails_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut first: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        first["arm"]["id"] = serde_json::json!("oneiron");
        let mut second = first.clone();
        second["arm"]["id"] = serde_json::json!("oneiron-shadow");
        std::fs::write(&run_jsonl_path, format!("{first}\n{second}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]
            .as_object_mut()
            .expect("dataset object")
            .remove("armId");
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("duplicate question must fail");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 2,
                    reason,
                    ..
                } if reason.contains("multiple selected run records")
                    && reason.contains("set dataset.armId")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn non_context_pack_jsonl_arm_kind_fails_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["arm"]["id"] = serde_json::json!("longmemeval_l0");
        row["arm"]["kind"] = serde_json::json!("baseline_jsonl");
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["armId"] = serde_json::json!("longmemeval_l0");
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-context-pack arm must fail");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("arm.kind `baseline_jsonl`")
                    && reason.contains(ONEIRON_CONTEXT_PACK_ARM_KIND)
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_expected_min_results_must_not_exceed_limit() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["limit"] = serde_json::json!(1);
        manifest_json["dataset"]["expectedMinResults"] = serde_json::json!(2);

        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("expectedMinResults > limit is invalid");

        assert!(matches!(
            err,
            BeamError::InvalidManifest { reason, .. }
                if reason.contains("expectedMinResults must be <= limit")
        ));
    }

    #[test]
    fn jsonl_ready_embedding_dimensions_must_match_engine_config() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["corpus"][0]["embedding"] = serde_json::json!({
            "encoding": "f32-le-base64",
            "dimensions": 3,
            "data": "AAAAAAAAAAAAAAAA"
        });
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-4D vector must fail typed");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("vector dimensions must be 4")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_budget_currency_must_be_tokens() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["budget"]["currency"] = serde_json::json!("usd");
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("non-token budget must fail typed");

        assert!(
            matches!(
                &err,
                BeamError::InvalidRunJsonl {
                    line: 1,
                    reason,
                    ..
                } if reason.contains("budget.currency `usd`")
                    && reason.contains("expected `tokens`")
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn jsonl_cases_are_loaded_into_isolated_vaults() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut first: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        first["question_id"] = serde_json::json!("case_a");
        first["question"] = serde_json::json!("shared keyword answer");
        first["corpus"] = serde_json::json!([
            {
                "id": "a-turn",
                "text": "shared keyword alpha answer only in case A",
                "metadata": {"case": "a"}
            }
        ]);
        let mut second = first.clone();
        second["question_id"] = serde_json::json!("case_b");
        second["corpus"] = serde_json::json!([
            {
                "id": "b-turn",
                "text": "shared keyword beta answer only in case B",
                "metadata": {"case": "b"}
            }
        ]);
        std::fs::write(&run_jsonl_path, format!("{first}\n{second}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["dataset"]["limit"] = serde_json::json!(5);
        manifest_json["caseIds"] = serde_json::json!(["case_a", "case_b"]);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let report = run_manifest(&manifest, None).expect("contract run succeeds");
        let packs_jsonl = std::fs::read_to_string(&packs_jsonl_path).expect("packs.jsonl exists");
        let rows: Vec<serde_json::Value> = packs_jsonl
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row JSON"))
            .collect();

        assert_eq!(report.dataset.records_loaded, 2);
        assert_eq!(rows.len(), 4);
        for row in rows {
            let expected_prefix = if row["question_id"] == "case_a" {
                "a-"
            } else {
                assert_eq!(row["question_id"], "case_b");
                "b-"
            };
            let contexts = row["pack"]["contexts"].as_array().expect("contexts array");
            assert!(!contexts.is_empty());
            assert!(contexts.iter().all(|context| {
                context["id"]
                    .as_str()
                    .expect("context id")
                    .starts_with(expected_prefix)
            }));
        }
    }

    #[test]
    fn jsonl_outputs_must_not_overwrite_input_run_jsonl() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        std::fs::write(&run_jsonl_path, CONTRACT_RUN_JSONL).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(&run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(run_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("same output/input path must fail");

        assert!(matches!(
            err,
            BeamError::InvalidManifest { reason, .. }
                if reason.contains("must not resolve to the input run.jsonl path")
        ));
    }

    pub(crate) fn fixture_file_manifest(dir: &Path, input: &str, output: &str) -> PathBuf {
        let mut manifest: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("fixture manifest");
        manifest["dataset"]["path"] = serde_json::json!(input);
        manifest["outputs"] = serde_json::json!({"packsJsonl": output});
        manifest["arms"] = serde_json::json!(["deterministic"]);
        let competitor = manifest["competitors"][0].clone();
        manifest["competitors"] = serde_json::json!([competitor]);
        let path = dir.join("run.json");
        std::fs::write(&path, manifest.to_string()).expect("manifest file");
        path
    }

    #[test]
    fn fixture_outputs_must_not_overwrite_relative_input() {
        for output in [
            "data/fixture.json",
            "data/./fixture.json",
            "data/../data/fixture.json",
        ] {
            let dir = tempfile::tempdir().expect("private test directory");
            std::fs::create_dir(dir.path().join("data")).expect("data directory");
            let input = dir.path().join("data/fixture.json");
            std::fs::write(&input, BUILTIN_FIXTURE_JSON).expect("fixture file");
            let manifest = fixture_file_manifest(dir.path(), "data/fixture.json", output);
            assert!(matches!(run_manifest_path(&manifest),
                    Err(BeamError::InvalidManifest { reason, .. })
                        if reason.contains("must not resolve to the input fixture path")));
            assert_eq!(
                std::fs::read(&input).expect("preserved input"),
                BUILTIN_FIXTURE_JSON.as_bytes()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn fixture_outputs_must_not_overwrite_symlink_alias_input() {
        for alias_is_input in [false, true] {
            let dir = tempfile::tempdir().expect("private test directory");
            let input = dir.path().join("fixture.json");
            std::fs::write(&input, BUILTIN_FIXTURE_JSON).expect("fixture file");
            std::os::unix::fs::symlink("fixture.json", dir.path().join("alias.json"))
                .expect("private fixture alias");
            let (source, output) = if alias_is_input {
                ("alias.json", "fixture.json")
            } else {
                ("fixture.json", "alias.json")
            };
            let manifest = fixture_file_manifest(dir.path(), source, output);
            assert!(matches!(run_manifest_path(&manifest),
                    Err(BeamError::InvalidManifest { reason, .. })
                        if reason.contains("must not resolve to the input fixture path")));
            assert_eq!(
                std::fs::read(&input).expect("preserved input"),
                BUILTIN_FIXTURE_JSON.as_bytes()
            );
        }
    }

    #[test]
    fn fixture_file_run_preserves_input_with_distinct_output() {
        let dir = tempfile::tempdir().expect("private test directory");
        let input = dir.path().join("fixture.json");
        std::fs::write(&input, BUILTIN_FIXTURE_JSON).expect("fixture file");
        let manifest = fixture_file_manifest(dir.path(), "./fixture.json", "packs.jsonl");
        for _ in 0..2 {
            let report = run_manifest_path(&manifest).expect("normal fixture run");
            assert_eq!(report.fixture_id, "beam-128k-smoke");
            assert!(dir.path().join("packs.jsonl").is_file());
            assert_eq!(
                std::fs::read(&input).expect("preserved input"),
                BUILTIN_FIXTURE_JSON.as_bytes()
            );
        }
    }

    #[test]
    fn contract_pack_rows_use_budgeted_serialized_text() {
        let manifest = parse_manifest_json(CONTRACT_MANIFEST_JSON).expect("manifest parses");
        let record: RunContractRecord =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        let entity_id = "10101010101010101010101010101010";
        let case = FixtureCase {
            ppr_vad_query: None,
            case_id: record.question_id.clone(),
            query: record.question.clone(),
            limit: 1,
            token_budget: 128,
            expected_min_results: 1,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let loaded = LoadedDataset {
            ppr_vad_fixture: None,
            report: DatasetLoadReport {
                dataset_id: "dataset".to_owned(),
                source_kind: JSONL_CONTRACT_SOURCE_KIND.to_owned(),
                records_loaded: 1,
                text_fields_indexed: 1,
                pending_vectors: 0,
            },
            fixture_id: "dataset".to_owned(),
            fixture_description: "dataset".to_owned(),
            cases: vec![case.clone()],
            contract_records: BTreeMap::from([(case.case_id.clone(), record)]),
            source_id_by_entity_id: BTreeMap::from([(entity_id.to_owned(), "turn-1".to_owned())]),
            query_vector_by_case_id: BTreeMap::new(),
        };
        let mut budgeted_text_by_entity_id = BTreeMap::new();
        budgeted_text_by_entity_id.insert(entity_id.to_owned(), "budgeted emitted txt".to_owned());
        let context_pack = ContextPackReport {
            token_budget: case.token_budget,
            limit: case.limit,
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 64,
            serialized_tokens: 7,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 1,
                output_tokens: 7,
                target_tokens: case.token_budget as u64,
                elapsed_us: 1,
                cost_usd: 0.0,
            },
            result_count: 1,
            neighbor_count: 0,
            results: vec![ContextEntityReport {
                id: entity_id.to_owned(),
                short_id: "sm1".to_owned(),
                entity_type: BENCH_CONTRACT_ENTITY_TYPE,
                score: 1.0,
            }],
            neighbors: Vec::new(),
            stats: empty_pack_stats_report(),
            empty: None,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id,
        };
        let arm_report = ArmReport {
            arm: ArmKind::Deterministic,
            outcome: ArmOutcome::Completed {
                context_pack: Box::new(context_pack),
            },
        };

        let row = contract_context_pack_record(
            &manifest,
            &loaded,
            &case,
            &manifest.competitors[0],
            &arm_report,
        )
        .expect("row generation succeeds")
        .expect("row emitted");

        assert_eq!(row.pack.contexts[0].id, "turn-1");
        assert_eq!(row.pack.contexts[0].text, "budgeted emitted txt");
    }

    #[test]
    fn pending_jsonl_embeddings_fail_deterministic_arm_typed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let run_jsonl_path = tempdir.path().join("run.jsonl");
        let packs_jsonl_path = tempdir.path().join("packs.jsonl");
        let mut row: serde_json::Value =
            serde_json::from_str(CONTRACT_RUN_JSONL.trim()).expect("contract row JSON");
        row["corpus"][0]["embedding"] = serde_json::json!({"status": "pending"});
        std::fs::write(&run_jsonl_path, format!("{row}\n")).expect("write run.jsonl");
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["dataset"]["path"] = serde_json::json!(run_jsonl_path);
        manifest_json["outputs"]["packsJsonl"] = serde_json::json!(packs_jsonl_path);
        let manifest =
            parse_manifest_json(&manifest_json.to_string()).expect("contract manifest parses");

        let err = run_manifest(&manifest, None).expect_err("pending embeddings fail typed");

        assert!(matches!(
            err,
            BeamError::PendingEmbeddings {
                case_id,
                pending_vectors: 1,
            } if case_id == "beam_128k_contract_context_pack_smoke"
        ));
    }

    #[test]
    fn non_wired_dataset_sources_still_return_dataset_not_ready() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let mut manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest.dataset = DatasetSource::Miracl {
            dataset: "miracl-dev-smoke".to_owned(),
        };

        let err = run_fixture_manifest(&manifest, &fixture).expect_err("MIRACL remains unwired");

        assert!(
            matches!(err, BeamError::DatasetNotReady(state) if state.component == "dataset loader")
        );
    }
}
