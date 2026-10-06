//! Contract v2 tests: schema round-trip, shared corpus files, sha256 refusals.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::CONTRACT_MANIFEST_JSON;
    use super::super::*;
    use std::path::{Path, PathBuf};

    pub(crate) const V2_RUN_ID: &str = "contract-v2-fixture";
    pub(crate) const V2_DATASET_ID: &str = "beam-v2-fixture";
    pub(crate) const V2_CORPUS_ID: &str = "chat-7";
    pub(crate) const V2_QUESTION_TIME: u64 = 1_780_000_500;

    pub(crate) fn sha256_hex_of(bytes: &[u8]) -> String {
        super::super::load::sha256_hex(bytes)
    }

    /// Two corpus items with the 4-d contract vectors the vanilla arm needs.
    pub(crate) fn v2_corpus_items() -> Vec<serde_json::Value> {
        let rows = [
            (
                "m-1",
                "The contract launch code is tulip. This record is the BEAM contract smoke target.",
                1_780_000_000_u64,
                "AACAPwAAAAAAAAAAAAAAAA==",
            ),
            (
                "m-2",
                "A distractor note says the archive code is violet, unrelated to the contract launch code.",
                1_780_000_060,
                "AAAAAAAAgD8AAAAAAAAAAA==",
            ),
        ];
        rows.iter()
            .map(|(id, text, ts, vector)| {
                serde_json::json!({
                    "id": id,
                    "text": text,
                    "source_sha256": sha256_hex_of(text.as_bytes()),
                    "metadata": {"role": "user", "dataset_timestamp": ts},
                    "embedding": {"encoding": "f32-le-base64", "dimensions": 4, "data": vector},
                })
            })
            .collect()
    }

    pub(crate) fn corpus_jsonl(items: &[serde_json::Value]) -> String {
        items.iter().map(|item| format!("{item}\n")).collect()
    }

    /// A v2 record that reads the shared corpus file `corpus/<id>.jsonl`.
    pub(crate) fn v2_record(question_id: &str, corpus_sha256: &str) -> serde_json::Value {
        serde_json::json!({
            "contract_version": "oneiron-eval.contract.v2",
            "record_type": "run",
            "run_id": V2_RUN_ID,
            "question_id": question_id,
            "dataset": {"id": V2_DATASET_ID, "revision": "fixture-v2"},
            "arm": {"id": "oneiron", "kind": "context_pack_http"},
            "budget": {"currency": "tokens", "limit": 131072},
            "question": "What is the contract launch code?",
            "query_embedding": {"encoding": "f32-le-base64", "dimensions": 4, "data": "AACAPwAAAAAAAAAAAAAAAA=="},
            "question_time": V2_QUESTION_TIME,
            "corpus_ref": {"corpus_id": V2_CORPUS_ID, "path": format!("corpus/{V2_CORPUS_ID}.jsonl"), "sha256": corpus_sha256},
            "split": super::super::split::expected_split(V2_DATASET_ID, V2_CORPUS_ID).as_str(),
            "cleaning": {"manifest_id": "fixture-cleaning-v1", "sha256": "a".repeat(64), "action": "kept"},
            "gold": {
                "answers": ["tulip"],
                "labels": {"ability": "information_extraction", "wedge_bucket": "needle_short"},
                "evidence_ids": ["m-1"],
                "pool": [{"text": "tulip", "role": "gold"}, {"text": "violet", "role": "distractor"}],
                "answer_keys": {"original": ["tulip"], "audit_corrected": ["tulip"]},
            },
        })
    }

    pub(crate) struct V2Fixture {
        pub(crate) dir: tempfile::TempDir,
        pub(crate) run_jsonl: PathBuf,
        pub(crate) packs_jsonl: PathBuf,
        pub(crate) corpus_path: PathBuf,
    }

    impl V2Fixture {
        /// Writes the corpus file and one v2 record per question id.
        pub(crate) fn write(question_ids: &[&str]) -> Self {
            Self::write_with(question_ids, |_| {})
        }

        pub(crate) fn write_with(
            question_ids: &[&str],
            edit: impl Fn(&mut serde_json::Value),
        ) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let corpus_dir = dir.path().join("corpus");
            std::fs::create_dir_all(&corpus_dir).expect("corpus dir");
            let corpus = corpus_jsonl(&v2_corpus_items());
            let corpus_path = corpus_dir.join(format!("{V2_CORPUS_ID}.jsonl"));
            std::fs::write(&corpus_path, &corpus).expect("corpus file");
            let sha = sha256_hex_of(corpus.as_bytes());
            let mut lines = String::new();
            for question_id in question_ids {
                let mut record = v2_record(question_id, &sha);
                edit(&mut record);
                lines.push_str(&format!("{record}\n"));
            }
            let run_jsonl = dir.path().join("run.jsonl");
            std::fs::write(&run_jsonl, lines).expect("run.jsonl");
            let packs_jsonl = dir.path().join("packs.jsonl");
            Self {
                dir,
                run_jsonl,
                packs_jsonl,
                corpus_path,
            }
        }

        pub(crate) fn manifest(&self, case_ids: &[&str]) -> RunManifest {
            let mut raw: serde_json::Value =
                serde_json::from_str(CONTRACT_MANIFEST_JSON).expect("manifest JSON");
            raw["runId"] = serde_json::json!(V2_RUN_ID);
            raw["dataset"]["path"] = serde_json::json!(self.run_jsonl);
            raw["caseIds"] = serde_json::json!(case_ids);
            raw["outputs"]["packsJsonl"] = serde_json::json!(self.packs_jsonl);
            parse_manifest_json(&raw.to_string()).expect("v2 manifest parses")
        }

        pub(crate) fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn pack_rows(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .expect("packs.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).expect("pack row"))
            .collect()
    }

    #[test]
    fn v2_record_round_trips_every_new_field_into_packs() {
        let fixture = V2Fixture::write(&["q-a"]);
        let manifest = fixture.manifest(&["q-a"]);
        run_manifest(&manifest, None).expect("v2 run succeeds");
        let rows = pack_rows(&fixture.packs_jsonl);
        assert_eq!(rows.len(), 2, "deterministic and vanilla-rag rows");
        let record = v2_record(
            "q-a",
            &sha256_hex_of(std::fs::read(&fixture.corpus_path).unwrap().as_slice()),
        );
        for row in &rows {
            assert_eq!(row["contract_version"], "oneiron-eval.contract.v2");
            assert_eq!(row["question_time"], V2_QUESTION_TIME);
            assert_eq!(row["corpus_ref"], record["corpus_ref"]);
            assert_eq!(row["split"], record["split"]);
            assert_eq!(row["cleaning"], record["cleaning"]);
            assert_eq!(
                row["gold"], record["gold"],
                "gold passes through byte-for-byte"
            );
            assert!(
                row["pack"]["contexts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|context| context["id"] == "m-1"),
                "source ids survive the shared-corpus entity ids"
            );
        }
        assert_eq!(
            rows[0]["pack"]["corpusDigest"],
            rows[1]["pack"]["corpusDigest"]
        );
    }

    #[test]
    fn v2_question_time_reaches_the_reader_case() {
        let fixture = V2Fixture::write(&["q-a"]);
        let manifest = fixture.manifest(&["q-a"]);
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(vault_dir.path(), beam_vault_config()).unwrap();
        let loaded = load_dataset(&vault, &manifest, None).unwrap();
        assert_eq!(loaded.cases[0].question_time, Some(V2_QUESTION_TIME));
        let record = &loaded.contract_records["q-a"];
        assert_eq!(record.corpus_items().len(), 2);
        assert!(record.corpus.is_empty(), "v2 corpus comes from the file");
    }

    #[test]
    fn v1_records_stay_valid_and_may_carry_v2_fields() {
        let fixture = V2Fixture::write_with(&["q-a"], |record| {
            record["contract_version"] = serde_json::json!("oneiron-eval.contract.v1");
            let object = record.as_object_mut().unwrap();
            object.remove("split");
            object.remove("cleaning");
            object.remove("question_time");
            object["gold"].as_object_mut().unwrap().remove("pool");
        });
        let manifest = fixture.manifest(&["q-a"]);
        run_manifest(&manifest, None).expect("v1 record with optional v2 fields runs");
        let rows = pack_rows(&fixture.packs_jsonl);
        assert_eq!(rows[0]["contract_version"], "oneiron-eval.contract.v1");
        assert!(rows[0].get("question_time").is_none());
    }

    #[test]
    fn v2_record_missing_a_required_field_is_refused() {
        for field in [
            "/question_time",
            "/split",
            "/cleaning",
            "/gold/evidence_ids",
            "/gold/pool",
            "/gold",
            "/corpus_ref",
        ] {
            let fixture = V2Fixture::write_with(&["q-a"], |record| {
                let (parent, leaf) = field.rsplit_once('/').unwrap();
                record
                    .pointer_mut(if parent.is_empty() { "" } else { parent })
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(leaf);
            });
            let error = read_run_jsonl_records(&fixture.run_jsonl)
                .expect_err("missing v2 field must refuse")
                .to_string();
            let leaf = field.rsplit('/').next().unwrap();
            assert!(
                error.contains(leaf) || error.contains("corpus must not be empty"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn corpus_ref_sha256_mismatch_fails_the_run() {
        let fixture = V2Fixture::write(&["q-a"]);
        // One flipped byte in the shared corpus file after the adapter hashed it.
        let mut bytes = std::fs::read(&fixture.corpus_path).unwrap();
        let at = bytes.iter().position(|b| *b == b't').unwrap();
        bytes[at] = b'T';
        std::fs::write(&fixture.corpus_path, bytes).unwrap();
        let manifest = fixture.manifest(&["q-a"]);
        let error = run_manifest(&manifest, None)
            .expect_err("sha256 mismatch must fail the run")
            .to_string();
        assert!(error.contains("sha256 mismatch"), "{error}");
        assert!(!fixture.packs_jsonl.exists(), "no packs are written");
    }

    #[test]
    fn corpus_item_source_sha256_mismatch_fails_the_load() {
        let fixture = V2Fixture::write(&["q-a"]);
        let mut items = v2_corpus_items();
        items[1]["source_sha256"] = serde_json::json!(sha256_hex_of(b"other bytes"));
        let corpus = corpus_jsonl(&items);
        std::fs::write(&fixture.corpus_path, &corpus).unwrap();
        let run = std::fs::read_to_string(&fixture.run_jsonl).unwrap();
        let old_sha = sha256_hex_of(corpus_jsonl(&v2_corpus_items()).as_bytes());
        std::fs::write(
            &fixture.run_jsonl,
            run.replace(&old_sha, &sha256_hex_of(corpus.as_bytes())),
        )
        .unwrap();
        let error = super::super::load::read_and_resolve_run_jsonl(&fixture.run_jsonl)
            .expect_err("item hash mismatch must refuse")
            .to_string();
        assert!(
            error.contains("m-2") && error.contains("source_sha256"),
            "{error}"
        );
        let _ = fixture.path();
    }

    #[test]
    fn two_records_naming_one_corpus_id_with_different_bytes_are_refused() {
        let fixture = V2Fixture::write_with(&["q-a", "q-b"], |record| {
            if record["question_id"] == "q-b" {
                record["corpus_ref"]["sha256"] = serde_json::json!("b".repeat(64));
            }
        });
        let error = read_run_jsonl_records(&fixture.run_jsonl)
            .expect_err("conflicting corpus refs must refuse")
            .to_string();
        assert!(error.contains("different path or sha256"), "{error}");
    }

    #[test]
    fn fork_per_question_reuses_one_base_vault_per_corpus() {
        let fixture = V2Fixture::write(&["q-a", "q-b", "q-c"]);
        let manifest = fixture.manifest(&["q-c", "q-a", "q-b"]);
        let report = run_manifest(&manifest, None).expect("shared-corpus run succeeds");
        assert_eq!(report.dataset.base_vaults, 1, "one corpus, one ingest");
        assert_eq!(report.dataset.forks, 3, "one fork per question");
        assert_eq!(
            report.dataset.records_loaded, 2,
            "the two corpus items are written once, not once per question"
        );
        let order: Vec<_> = report
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect();
        assert_eq!(order, ["q-c", "q-a", "q-b"], "report keeps manifest order");
        let keys: std::collections::BTreeSet<_> = report
            .cases
            .iter()
            .map(|case| case.fork_key.clone().expect("forked case carries its key"))
            .collect();
        assert_eq!(keys.len(), 3, "every question has its own fork key");
        let rows = pack_rows(&fixture.packs_jsonl);
        assert_eq!(rows.len(), 6);
        assert!(rows.iter().all(|row| {
            row["pack"]["contexts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|context| context["id"] == "m-1")
        }));
    }

    #[test]
    fn inline_corpora_keep_one_base_vault_per_question() {
        let tempdir = tempfile::tempdir().unwrap();
        let run_jsonl = tempdir.path().join("run.jsonl");
        let first: serde_json::Value =
            serde_json::from_str(super::super::tests_community_eval004::CONTRACT_RUN_JSONL.trim())
                .unwrap();
        let mut second = first.clone();
        second["question_id"] = serde_json::json!("second-question");
        std::fs::write(&run_jsonl, format!("{first}\n{second}\n")).unwrap();
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["dataset"]["path"] = serde_json::json!(run_jsonl);
        raw["caseIds"] = serde_json::json!([first["question_id"], "second-question"]);
        raw.as_object_mut().unwrap().remove("outputs");
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let report = run_manifest(&manifest, None).unwrap();
        assert_eq!(report.dataset.base_vaults, 2);
        assert_eq!(report.dataset.forks, 2);
        assert_eq!(report.dataset.records_loaded, 4);
    }

    #[test]
    fn exact_run_reports_items_checked_and_resolved_evidence() {
        let fixture = V2Fixture::write(&["q-a", "q-b"]);
        let report = run_manifest(&fixture.manifest(&["q-a", "q-b"]), None).unwrap();
        let exactness = report.exactness.expect("jsonl runs carry exactness");
        assert_eq!(
            exactness.items_checked, 2,
            "a shared corpus is checked once"
        );
        assert!(exactness.mismatches.is_empty());
        assert_eq!(
            exactness.evidence_ids_checked, 2,
            "one evidence id per question"
        );
        assert!(exactness.evidence_ids_unresolved.is_empty());
    }

    #[test]
    fn unresolved_gold_evidence_id_fails_the_run() {
        let fixture = V2Fixture::write_with(&["q-a"], |record| {
            record["gold"]["evidence_ids"] = serde_json::json!(["m-1", "m-404"]);
        });
        let error = run_manifest(&fixture.manifest(&["q-a"]), None)
            .expect_err("an unresolved evidence id must fail the run")
            .to_string();
        assert!(error.contains("exactness check failed"), "{error}");
        assert!(error.contains("m-404"), "{error}");
        assert!(
            !fixture.packs_jsonl.exists(),
            "the run stops before any pack"
        );
    }

    #[test]
    fn read_back_bytes_that_differ_from_the_source_fail() {
        let dir = tempfile::tempdir().unwrap();
        let run_jsonl = dir.path().join("run.jsonl");
        std::fs::write(
            &run_jsonl,
            super::super::tests_community_eval004::CONTRACT_RUN_JSONL,
        )
        .unwrap();
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["dataset"]["path"] = serde_json::json!(run_jsonl);
        raw.as_object_mut().unwrap().remove("outputs");
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let vault_dir = tempfile::tempdir().unwrap();
        let vault = oneiron::Vault::open(vault_dir.path(), beam_vault_config()).unwrap();
        let mut loaded = load_dataset(&vault, &manifest, None).unwrap();
        let clean = super::super::exactness::verify_loaded_corpus(&vault, &loaded).unwrap();
        assert!(clean.is_exact());
        assert_eq!(clean.items_checked, 2);

        // The source says one thing; the vault holds another.
        let record = loaded.contract_records.values_mut().next().unwrap();
        record.corpus[0].text.push_str(" (edited after ingest)");
        // And an item the vault never received.
        record.corpus[1].id = "never-ingested".to_owned();
        let report = super::super::exactness::verify_loaded_corpus(&vault, &loaded).unwrap();
        assert_eq!(report.mismatches.len(), 2);
        assert!(report.mismatches[0].actual_sha256.is_some());
        assert_eq!(report.mismatches[1].actual_sha256, None);
        let error = report
            .into_result()
            .expect_err("mismatch fails")
            .to_string();
        assert!(error.contains("2 of 2 corpus items differ"), "{error}");
    }

    #[test]
    fn verify_corpus_subcommand_checks_without_running_arms() {
        let fixture = V2Fixture::write(&["q-a", "q-b"]);
        let manifest_path = fixture.path().join("verify.run.json");
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["runId"] = serde_json::json!(V2_RUN_ID);
        raw["dataset"]["path"] = serde_json::json!("run.jsonl");
        raw["caseIds"] = serde_json::json!(["q-a", "q-b"]);
        raw["outputs"]["packsJsonl"] = serde_json::json!("packs.jsonl");
        std::fs::write(&manifest_path, raw.to_string()).unwrap();
        let report = super::super::exactness::run(&manifest_path).expect("exact corpus");
        assert_eq!(report.items_checked, 2);
        assert_eq!(report.evidence_ids_checked, 2);
        assert!(!fixture.packs_jsonl.exists(), "verify-corpus runs no arm");

        let broken = V2Fixture::write_with(&["q-a"], |record| {
            record["gold"]["evidence_ids"] = serde_json::json!(["m-9"]);
        });
        let broken_manifest = broken.path().join("verify.run.json");
        raw["caseIds"] = serde_json::json!(["q-a"]);
        std::fs::write(&broken_manifest, raw.to_string()).unwrap();
        let error = super::super::exactness::run(&broken_manifest)
            .expect_err("unresolved evidence fails verify-corpus")
            .to_string();
        assert!(error.contains("1 of 1 evidence ids unresolved"), "{error}");
    }

    #[test]
    fn split_that_disagrees_with_the_frozen_rule_is_refused() {
        let declared = super::super::split::expected_split(V2_DATASET_ID, V2_CORPUS_ID);
        let flipped = match declared {
            ContractSplit::Dev => "heldout",
            ContractSplit::Heldout => "dev",
        };
        let fixture = V2Fixture::write_with(&["q-a"], |record| {
            record["split"] = serde_json::json!(flipped);
        });
        let error = run_manifest(&fixture.manifest(&["q-a"]), None)
            .expect_err("a wrong split must refuse the run")
            .to_string();
        assert!(error.contains("disagrees with the frozen rule"), "{error}");
        assert!(
            error.contains(V2_CORPUS_ID),
            "the unit is the corpus: {error}"
        );
        // A v1 record that states a split is held to the same rule.
        let v1 = V2Fixture::write_with(&["q-a"], |record| {
            record["contract_version"] = serde_json::json!("oneiron-eval.contract.v1");
            record["split"] = serde_json::json!(flipped);
        });
        assert!(read_run_jsonl_records(&v1.run_jsonl).is_err());
    }

    #[test]
    fn split_unit_is_the_corpus_for_shared_and_the_question_for_inline() {
        let fixture = V2Fixture::write(&["q-a", "q-b"]);
        let entries = read_run_jsonl_records(&fixture.run_jsonl).unwrap();
        for entry in &entries {
            assert_eq!(super::super::split::split_unit(&entry.record), V2_CORPUS_ID);
        }
        let inline: RunContractRecord =
            serde_json::from_str(super::super::tests_community_eval004::CONTRACT_RUN_JSONL.trim())
                .unwrap();
        assert_eq!(super::super::split::split_unit(&inline), inline.question_id);
    }

    #[test]
    fn run_card_pins_identity_scorer_split_cost_and_exactness() {
        let fixture = V2Fixture::write(&["q-a", "q-b"]);
        let report = run_manifest(&fixture.manifest(&["q-a", "q-b"]), None).unwrap();
        let card = report.card.expect("run.jsonl runs carry a card");
        let wire = serde_json::to_value(&card).unwrap();
        let identity = &wire["identity"];
        assert_eq!(identity["set"], V2_DATASET_ID);
        assert_eq!(
            identity["tier"], "fixture",
            "tier comes from the competitor cards"
        );
        assert_eq!(identity["datasetRevision"], "fixture-v2");
        assert_eq!(
            identity["runJsonlSha256"],
            sha256_hex_of(&std::fs::read(&fixture.run_jsonl).unwrap())
        );
        assert_eq!(identity["corpora"][0]["corpusId"], V2_CORPUS_ID);
        assert_eq!(
            identity["corpora"][0]["sha256"],
            sha256_hex_of(&std::fs::read(&fixture.corpus_path).unwrap())
        );
        assert_eq!(identity["cleaning"][0]["manifestId"], "fixture-cleaning-v1");
        assert_eq!(identity["cleaning"][0]["kept"], 2);
        let split = super::super::split::expected_split(V2_DATASET_ID, V2_CORPUS_ID).as_str();
        assert_eq!(identity["split"]["label"], split);
        assert_eq!(identity["split"]["ruleId"], "oneiron-bench.split.v1");
        assert_eq!(
            identity["split"]["saltSha256"],
            sha256_hex_of(super::super::split::SPLIT_SALT.as_bytes())
        );
        assert_eq!(identity["seeds"], serde_json::json!([]));
        assert_eq!(identity["questionsWithQuestionTime"], 2);
        assert!(
            identity["commit"]
                .as_str()
                .is_some_and(|sha| sha.len() == 40)
        );
        let pins = &wire["pins"];
        assert_eq!(pins["scorer"]["scorerId"], "beam-fixed-scorer");
        assert_eq!(
            pins["tokenizer"],
            oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID
        );
        assert_eq!(pins["packBudgets"], serde_json::json!([131072]));
        assert_eq!(pins["judges"].as_array().unwrap().len(), 2);
        assert_eq!(wire["exactness"]["itemsChecked"], 2);
        assert_eq!(wire["exactness"]["mismatches"], 0);
        assert_eq!(wire["exactness"]["evidenceIdsUnresolved"], 0);
        let cost = wire["cost"].as_array().unwrap();
        assert_eq!(cost.len(), 2, "one cost row per competitor");
        for row in cost {
            assert_eq!(row["questions"], 2);
            assert!(row["packTokens"].as_u64().unwrap() > 0);
            assert_eq!(row["reprefillTokens"], 0);
            assert!(row["elapsedUsP95"].as_u64() >= row["elapsedUsP50"].as_u64());
        }
        assert!(card.result_dir.is_none(), "no resultsRoot, no folder");
    }

    #[test]
    fn result_folder_is_named_by_commit_and_never_overwritten() {
        let fixture = V2Fixture::write(&["q-a"]);
        let mut raw: serde_json::Value = serde_json::from_str(CONTRACT_MANIFEST_JSON).unwrap();
        raw["runId"] = serde_json::json!(V2_RUN_ID);
        raw["dataset"]["path"] = serde_json::json!(fixture.run_jsonl);
        raw["caseIds"] = serde_json::json!(["q-a"]);
        raw["outputs"]["packsJsonl"] = serde_json::json!(fixture.packs_jsonl);
        raw["outputs"]["resultsRoot"] = serde_json::json!(fixture.path().join("results"));
        let manifest = parse_manifest_json(&raw.to_string()).unwrap();
        let report = run_manifest(&manifest, None).unwrap();
        let card = report.card.as_ref().unwrap();
        let dir = card.result_dir.clone().expect("resultsRoot names a folder");
        let commit = card.identity.commit.clone().unwrap();
        let split = super::super::split::expected_split(V2_DATASET_ID, V2_CORPUS_ID).as_str();
        let expected_tail = Path::new(V2_DATASET_ID).join("fixture").join(split);
        assert!(dir.ends_with(&expected_tail), "{}", dir.display());
        let commit_folder = dir
            .strip_prefix(fixture.path().join("results"))
            .unwrap()
            .components()
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        assert!(commit_folder.starts_with(&commit), "{commit_folder}");
        for file in [
            "card.json",
            "report.json",
            "packs.jsonl",
            "cost.json",
            "exactness.json",
            "split.json",
            "cleaning.json",
        ] {
            assert!(dir.join(file).exists(), "{file} written");
        }
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("card.json")).unwrap()).unwrap();
        assert_eq!(written["identity"]["commit"], commit.as_str());
        let error = run_manifest(&manifest, None)
            .expect_err("a second run into the same folder must refuse")
            .to_string();
        assert!(error.contains("never overwritten"), "{error}");
    }
}
