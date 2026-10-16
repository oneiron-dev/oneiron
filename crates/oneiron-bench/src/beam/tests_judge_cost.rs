//! Judge and cost tests.

#[cfg(test)]
pub(crate) mod tests {

    use super::super::*;

    #[test]
    fn manifest_rejects_char_count_token_estimates_for_scored_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["tokenAccounting"]["source"] =
            serde_json::json!("char_count_estimate");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("char-count token estimates must be rejected");

        assert!(matches!(err, BeamError::InvalidManifest { .. }));
    }

    #[test]
    fn not_ready_scores_are_unmeasured_and_do_not_publish_zero_overall() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert!(deterministic["scoring"]["overallScore"].as_f64().is_some());

        for competitor_id in ["agentic-adapter", "chat-adapter"] {
            let typed_competitor = report.cases[0]
                .competitors
                .iter()
                .find(|competitor| competitor.competitor_id == competitor_id)
                .expect("not-ready competitor report");
            let arm = report.cases[0]
                .arms
                .iter()
                .find(|arm| arm.arm.as_str() == typed_competitor.arm.as_str())
                .expect("not-ready arm report");
            assert!(matches!(&arm.outcome, ArmOutcome::NotReady { .. }));

            let competitor = competitors
                .iter()
                .find(|competitor| competitor["competitorId"] == competitor_id)
                .expect("not-ready competitor");
            assert!(competitor["scoring"]["overallScore"].is_null());

            let abilities = competitor["scoring"]["abilities"]
                .as_array()
                .expect("abilities array");
            assert!(!abilities.is_empty());
            for ability in abilities {
                assert!(ability["score"].is_null());
                assert!(ability["passed"].is_null());
            }
        }
    }

    // ZERO-RETRIEVAL = A (owner, 2026-10-16): the no-memory baseline is a real
    // row in the fixture harness, not a not-ready placeholder.
    #[test]
    fn backbone_solo_is_ready_with_an_empty_pack_and_scores_zero_coverage() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let case = &report.cases[0];
        let arm = case
            .arms
            .iter()
            .find(|arm| arm.arm == ArmKind::BackboneSolo)
            .expect("backbone-solo arm report");
        let ArmOutcome::Completed { context_pack } = &arm.outcome else {
            panic!("backbone-solo must complete in the fixture harness");
        };
        assert_eq!(context_pack.result_count, 0);
        assert_eq!(context_pack.serialized_tokens, 0);
        assert_eq!(context_pack.query_cost.output_tokens, 0);
        let solo = case
            .competitors
            .iter()
            .find(|competitor| competitor.competitor_id == "backbone-solo")
            .expect("backbone-solo competitor");
        let coverage = solo
            .scoring
            .abilities
            .iter()
            .find(|ability| ability.ability == AbilityKind::RetrievalCoverage)
            .expect("retrieval coverage");
        assert!(case.expected_min_results > 0);
        assert_eq!(coverage.score, Some(0.0));
        assert!(solo.scoring.overall_score.is_some());
    }
}
