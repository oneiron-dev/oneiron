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
    fn deterministic_arm_exercises_serialized_128k_budget_path() {
        let fixture = parse_fixture_json(BUILTIN_FIXTURE_JSON).expect("fixture parses");
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let tempdir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(tempdir.path(), beam_vault_config()).expect("vault opens");
        let loaded = load_dataset(&vault, &manifest, Some(&fixture)).expect("fixture loads");

        // The arm's own call (arms.rs): the case's query vector from the loaded dataset.
        let query_vector = loaded
            .query_vector_by_case_id
            .get(&fixture.cases[0].case_id)
            .map(Vec::as_slice);
        let pack = run_deterministic_context_pack(&vault, &fixture.cases[0], query_vector)
            .expect("deterministic run");
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
}
