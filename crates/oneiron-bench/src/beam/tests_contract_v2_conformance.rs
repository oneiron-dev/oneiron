//! Adapter conformance: a directory written by oneiron-eval's LoCoMo adapter
//! (fixtures/contract_v2_locomo, synthetic text) runs end to end through the
//! bench, and engine refusals surface as named, per-item or per-question facts.

#[cfg(test)]
mod tests {
    use super::super::tests_contract_v2::tests::{V2Fixture, v2_corpus_items};
    use super::super::*;
    use std::path::Path;

    fn conformance_manifest(packs: &Path) -> RunManifest {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/contract_v2_locomo");
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(base.join("locomo.run.json")).unwrap())
                .unwrap();
        raw["dataset"]["path"] = serde_json::json!(base.join("run.jsonl"));
        raw["outputs"] = serde_json::json!({"packsJsonl": packs});
        parse_manifest_json(&raw.to_string()).unwrap()
    }

    #[test]
    fn locomo_adapter_output_runs_byte_exact_with_three_keys_and_a_reader_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let packs = dir.path().join("packs.jsonl");
        let report = run_manifest(&conformance_manifest(&packs), None).expect("conformance run");
        assert_eq!(
            report.dataset.base_vaults, 1,
            "one conversation, one base vault"
        );
        assert_eq!(report.dataset.forks, 7);
        let exactness = report.exactness.as_ref().unwrap();
        assert_eq!(exactness.items_checked, 4);
        assert!(exactness.is_exact());
        // The question with "last friday" is refused by the temporal reader,
        // reported per question, and every other question still runs.
        let refused: Vec<_> = report
            .cases
            .iter()
            .filter(|case| {
                matches!(&case.arms[0].outcome, ArmOutcome::NotReady { not_ready }
                    if not_ready.component == "temporal_reader"
                        && not_ready.reason.contains("last friday"))
            })
            .map(|case| case.case_id.as_str())
            .collect();
        assert_eq!(refused, ["locomo:conv-1:q0005"]);
        let card = report.card.as_ref().unwrap();
        assert_eq!(card.cost[0].refused, 1);
        assert_eq!(card.identity.set, "locomo");
        assert_eq!(card.identity.tier, "locomo");
        assert_eq!(card.identity.cleaning[0].manifest_id, "locomo-cleaning-v1");
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&packs)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 6, "the refused question writes no pack");
        let corrected = rows
            .iter()
            .find(|row| row["question_id"] == "locomo:conv-1:q0001")
            .unwrap();
        assert_eq!(
            corrected["gold"]["answer_keys"],
            serde_json::json!({"original": ["2023"], "audit-corrected": ["2022"], "locomo-refined": ["2022"]})
        );
        let adversarial = rows
            .iter()
            .find(|row| row["question_id"] == "locomo:conv-1:q0003")
            .unwrap();
        assert_eq!(adversarial["gold"]["labels"]["scored_apart"], true);
        assert_eq!(adversarial["gold"]["labels"]["paper_category_id"], 5);
        assert_eq!(
            adversarial["gold"]["answer_keys"],
            serde_json::json!({"category-5": []})
        );
        assert!(
            rows.iter()
                .all(|row| row["split"] == "heldout" || row["split"] == "dev")
        );
    }

    #[test]
    fn an_item_the_write_gate_refuses_is_named_and_fails_the_run() {
        let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
        let fixture = V2Fixture::write(&["q-a"]);
        let mut items = v2_corpus_items();
        let text = format!("my token is {token}");
        items[1]["text"] = serde_json::json!(text);
        items[1]["source_sha256"] =
            serde_json::json!(super::super::load::sha256_hex(text.as_bytes()));
        let corpus = super::super::tests_contract_v2::tests::corpus_jsonl(&items);
        std::fs::write(&fixture.corpus_path, &corpus).unwrap();
        let run = std::fs::read_to_string(&fixture.run_jsonl).unwrap();
        let old = super::super::load::sha256_hex(
            super::super::tests_contract_v2::tests::corpus_jsonl(&v2_corpus_items()).as_bytes(),
        );
        std::fs::write(
            &fixture.run_jsonl,
            run.replace(&old, &super::super::load::sha256_hex(corpus.as_bytes())),
        )
        .unwrap();
        let error = run_manifest(&fixture.manifest(&["q-a"]), None)
            .expect_err("a refused item fails the run")
            .to_string();
        assert!(error.contains("refused 1 of 2 corpus items"), "{error}");
        assert!(error.contains("m-2"), "{error}");
        assert!(
            !error.contains(&token),
            "the refusal never echoes the secret: {error}"
        );
    }
}
