//! JSONL contract tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
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
    fn jsonl_runner_keeps_loader_index_time_once_in_offline_cost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        std::fs::write(&path, CONTRACT_RUN_JSONL).unwrap();
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["dataset"]["path"] = serde_json::json!(path);
        raw.as_object_mut().unwrap().remove("outputs");
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(vault_dir.path(), beam_vault_config()).unwrap();
        let loaded = load_dataset(&vault, &manifest, None).unwrap();
        assert!(loaded.offline_index_build_us > 0);
        assert_eq!(
            loaded.offline.elapsed_us,
            loaded.offline_ingest_us + loaded.offline_index_build_us
        );
        let (cases, _) = run_loaded_cases(&vault, &manifest, &loaded).unwrap();
        let expected = loaded
            .offline
            .elapsed_us
            .div_ceil(manifest.case_ids.len() as u64);
        assert_eq!(cases[0].offline_amortized_cost.elapsed_us, expected);
        let isolated = run_manifest(&manifest, None).unwrap();
        assert!(isolated.cases[0].offline_amortized_cost.elapsed_us > 0);
        let isolated_elapsed = isolated.cases[0].offline_amortized_cost.elapsed_us;
        assert!(
            isolated.cases[0]
                .competitors
                .iter()
                .chain(&isolated.cases[0].appendix)
                .chain(&isolated.cases[0].dropped)
                .all(|row| row.costs.offline.elapsed_us == isolated_elapsed)
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
                "metadata": {"case": "purity", "dataset_timestamp": 1780000000_u64},
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
                "metadata": {"case": "a", "dataset_timestamp": 1780000000_u64}
            }
        ]);
        let mut second = first.clone();
        second["question_id"] = serde_json::json!("case_b");
        second["corpus"] = serde_json::json!([
            {
                "id": "b-turn",
                "text": "shared keyword beta answer only in case B",
                "metadata": {"case": "b", "dataset_timestamp": 1780000000_u64}
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
            assert!(matches!(
                run_manifest_path(&manifest),
                Err(BeamError::InvalidManifest { .. })
            ));
            assert_eq!(
                std::fs::read(&input).expect("preserved input"),
                BUILTIN_FIXTURE_JSON.as_bytes(),
            );
        }
    }
}
