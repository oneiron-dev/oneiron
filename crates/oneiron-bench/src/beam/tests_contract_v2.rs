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
            "split": "dev",
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
        let error = read_run_jsonl_records(&fixture.run_jsonl)
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
}
