//! PPR-VAD tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::eval004_record_json;
    use super::super::*;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::ExitCode;

    fn ppr_vad_test_documents() -> (serde_json::Value, serde_json::Value) {
        let ids: Vec<_> = (1_u8..=20)
            .map(|byte| format!("{byte:02x}").repeat(16))
            .collect();
        let records: Vec<_> = ids
            .iter()
            .map(|id| eval004_record_json(id, 1, "sweep corpus"))
            .collect();
        let edges: Vec<_> = ids.iter().skip(1).enumerate().map(|(index, id)| serde_json::json!({
            "source": ids[0], "target": id, "kind": 9, "weight": 1.0,
            "vad": {"valence": 0.0, "arousal": if index == 18 { 1.0 } else { 0.0 }, "dominance": 0.0}
        })).collect();
        let fixture_json = serde_json::json!({
            "schemaVersion": SCHEMA_VERSION,
            "fixtureId": "ppr-vad-test", "description": "Synthetic wiring test, not empirical evidence",
            "records": records, "pprVadEdges": edges,
            "cases": [
                {"caseId": "salient", "query": "salient query", "limit": 15, "tokenBudget": 4096,
                 "expectedMinResults": 0, "pprVadQuery": {"subset": "emotionally_salient",
                 "seeds": [ids[0]], "depth": 1, "relevantIds": [ids[19]]}},
                {"caseId": "neutral", "query": "neutral query", "limit": 15, "tokenBudget": 4096,
                 "expectedMinResults": 0, "pprVadQuery": {"subset": "neutral",
                 "seeds": [ids[0]], "depth": 1, "relevantIds": [ids[1]]}}
            ]
        });
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("valid sweep test input");
        manifest_json["dataset"]["fixtureId"] = serde_json::json!("ppr-vad-test");
        manifest_json["caseIds"] = serde_json::json!(["salient", "neutral"]);
        manifest_json["arms"] = serde_json::json!(["ppr_vad_sweep"]);
        let mut competitor = manifest_json["competitors"][0].clone();
        competitor["arm"] = serde_json::json!("ppr_vad_sweep");
        competitor["card"]["axes"]["retrievalK"] = serde_json::json!(15);
        competitor["card"]["comparator"]["baselineCompetitorId"] =
            competitor["competitorId"].clone();
        manifest_json["competitors"] = serde_json::json!([competitor]);
        (fixture_json, manifest_json)
    }

    pub(crate) fn ppr_vad_test_manifest_path(dir: &Path) -> PathBuf {
        let (fixture_json, mut manifest_json) = ppr_vad_test_documents();
        let data_dir = dir.join("data");
        std::fs::create_dir(&data_dir).expect("fixture directory");
        std::fs::write(data_dir.join("fixture.json"), fixture_json.to_string())
            .expect("fixture file");
        manifest_json["dataset"]["path"] = serde_json::json!("data/fixture.json");
        let path = dir.join("run.json");
        std::fs::write(&path, manifest_json.to_string()).expect("manifest file");
        path
    }

    #[test]
    fn ppr_vad_sweep_public_run_command_loads_relative_fixture() {
        let dir = tempfile::tempdir().expect("fixture directory");
        let path = ppr_vad_test_manifest_path(dir.path());
        assert_eq!(
            run(&["run".to_owned(), path.to_string_lossy().into_owned()]),
            ExitCode::SUCCESS
        );
        // The CLI never falls back to the built-in fixture on a missing path.
        std::fs::remove_file(dir.path().join("data/fixture.json")).expect("remove fixture");
        assert_eq!(
            run(&["run".to_owned(), path.to_string_lossy().into_owned()]),
            ExitCode::FAILURE
        );
    }
}
