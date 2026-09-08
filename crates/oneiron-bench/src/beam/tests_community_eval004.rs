//! Community and EVAL-004 tests.

#[cfg(test)]
pub(super) const CONTRACT_MANIFEST_JSON: &str =
    include_str!("../fixtures/beam_128k_contract.run.json");

#[cfg(test)]
pub(super) const CONTRACT_RUN_JSONL: &str =
    include_str!("../fixtures/beam_128k_contract.run.jsonl");

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use oneiron::EntityId;
    use oneiron::Vault;
    use oneiron::VaultConfig;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    #[test]
    fn empty_memory_fixture_abstains_before_score_publication() {
        let fixture = eval004_fixture(
            "eval004-empty-memory",
            "What did the empty vault remember about Project Borealis?",
            FixtureClass::EmptyMemory,
            Vec::new(),
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-empty-memory");
        let report = run_fixture_manifest(&manifest, &fixture).expect("empty fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "empty_memory_abstention");
    }

    #[test]
    fn contradictory_evidence_fixture_abstains_without_regressing_to_score() {
        let fixture = eval004_fixture(
            "eval004-contradiction",
            "What is the Atlas launch date?",
            FixtureClass::AdversarialContradiction,
            vec![
                eval004_record_json(
                    "30303030303030303030303030303030",
                    10,
                    "Atlas launch date is March 1.",
                ),
                eval004_record_json(
                    "40404040404040404040404040404040",
                    11,
                    "Atlas launch date is April 1.",
                ),
            ],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-contradiction");
        let report = run_fixture_manifest(&manifest, &fixture).expect("contradiction fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "adversarial_contradiction_abstention");
    }

    #[test]
    fn temporal_staleness_fixture_abstains_without_regressing_to_score() {
        let fixture = eval004_fixture(
            "eval004-temporal-staleness",
            "What is the current Nimbus pricing?",
            FixtureClass::TemporalStaleness,
            vec![eval004_record_json(
                "50505050505050505050505050505050",
                10_000,
                "Old Nimbus pricing was 10 credits before the current plan changed.",
            )],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-temporal-staleness");
        let report = run_fixture_manifest(&manifest, &fixture).expect("staleness fixture runs");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);

        assert_abstention_gate_passed(deterministic, "temporal_staleness_abstention");
    }

    #[test]
    fn low_confidence_fixture_abstains_via_below_threshold_context_pack() {
        let fixture = eval004_fixture(
            "eval004-low-confidence",
            "What is the Atlas launch date?",
            FixtureClass::LowConfidence,
            vec![eval004_record_json(
                "30303030303030303030303030303030",
                10,
                "Atlas launch date is March 1.",
            )],
        );
        let manifest = manifest_for_fixture_case(&fixture, "eval004-low-confidence");
        let report =
            run_fixture_manifest(&manifest, &fixture).expect("low-confidence fixture runs");

        for kind in [ArmKind::Deterministic, ArmKind::VanillaRag] {
            let arm = find_arm(&report, kind);
            let ArmOutcome::Completed { context_pack } = &arm.outcome else {
                panic!("{} arm should complete", kind.as_str());
            };
            let empty = context_pack.empty.as_ref().unwrap_or_else(|| {
                panic!("{} arm should report below-threshold empty", kind.as_str())
            });

            assert_eq!(context_pack.limit, 0);
            assert_eq!(context_pack.result_count, 0);
            assert_eq!(empty.reason, "below_threshold");
            assert!(
                empty.total_in_scope > 0,
                "{} arm should count in-scope low-confidence candidates",
                kind.as_str()
            );
        }

        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = deterministic_competitor_json(&report_json);
        assert_abstention_gate_passed(deterministic, "low_confidence_abstention");
        let vanilla = vanilla_rag_competitor_json(&report_json);
        assert_abstention_gate_passed(vanilla, "low_confidence_abstention");
    }

    pub(crate) fn find_arm(report: &BeamReport, kind: ArmKind) -> &ArmReport {
        report.cases[0]
            .arms
            .iter()
            .find(|arm| arm.arm == kind)
            .expect("arm report exists")
    }

    pub(crate) fn completed_context_pack(report: &BeamReport, kind: ArmKind) -> &ContextPackReport {
        let arm = find_arm(report, kind);
        let ArmOutcome::Completed { context_pack } = &arm.outcome else {
            panic!("{} arm should complete", kind.as_str());
        };
        context_pack
    }

    pub(crate) fn eval004_fixture(
        case_id: &str,
        query: &str,
        fixture_class: FixtureClass,
        records: Vec<serde_json::Value>,
    ) -> BeamFixture {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["fixtureId"] = serde_json::json!(case_id);
        fixture_json["description"] = serde_json::json!("EVAL-004 abstention gate fixture.");
        fixture_json["records"] = serde_json::Value::Array(records);
        fixture_json["cases"][0]["caseId"] = serde_json::json!(case_id);
        fixture_json["cases"][0]["query"] = serde_json::json!(query);
        fixture_json["cases"][0]["limit"] =
            serde_json::json!(if fixture_class == FixtureClass::LowConfidence {
                0
            } else {
                5
            });
        fixture_json["cases"][0]["tokenBudget"] = serde_json::json!(4096);
        fixture_json["cases"][0]["expectedMinResults"] = serde_json::json!(0);
        fixture_json["cases"][0]["fixtureClass"] =
            serde_json::to_value(fixture_class).expect("fixture class serializes");
        let record_ids: Vec<String> = fixture_json["records"]
            .as_array()
            .expect("records array")
            .iter()
            .map(|record| record["id"].as_str().expect("record id").to_owned())
            .collect();
        if fixture_class == FixtureClass::TemporalStaleness {
            // The window sits far from t=0 on purpose: ONE-1890 seeds the
            // system AGENT_DEF rows at the pinned timestamp 0, and a window
            // touching 0 sweeps those seeds into temporal scope, crowding the
            // case's record out of the leg's limit.
            fixture_json["cases"][0]["temporalSearch"] = serde_json::json!({
                "start": 9_999,
                "end": 10_000
            });
            fixture_json["cases"][0]["temporalEvidenceIds"] = serde_json::json!(record_ids);
        } else {
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("temporalSearch");
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("temporalEvidenceIds");
        }
        if fixture_class == FixtureClass::AdversarialContradiction {
            fixture_json["cases"][0]["opposingEvidence"] = serde_json::json!({
                "field": "txt",
                "recordIds": record_ids,
            });
        } else {
            fixture_json["cases"][0]
                .as_object_mut()
                .expect("case object")
                .remove("opposingEvidence");
        }

        parse_fixture_json(&fixture_json.to_string()).expect("EVAL-004 fixture parses")
    }

    pub(crate) fn eval004_record_json(id: &str, timestamp: u64, text: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "entityType": 8,
            "occurred": {
                "start": timestamp,
                "end": timestamp
            },
            "learnedAt": timestamp,
            "fields": {
                "txt": text,
                "lvl": "eval004",
                "at": format!("eval004-t{timestamp}")
            },
            "text": [
                {
                    "field": "txt",
                    "value": text
                }
            ]
        })
    }

    pub(crate) fn manifest_for_fixture_case(fixture: &BeamFixture, case_id: &str) -> RunManifest {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["runId"] = serde_json::json!(case_id);
        manifest_json["dataset"]["fixtureId"] = serde_json::json!(fixture.fixture_id.as_str());
        manifest_json["caseIds"] = serde_json::json!([case_id]);

        parse_manifest_json(&manifest_json.to_string()).expect("EVAL-004 manifest parses")
    }

    pub(crate) fn eval004_deterministic_competitor() -> CompetitorConfig {
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        manifest
            .competitors
            .into_iter()
            .find(|competitor| competitor.arm == ArmKind::Deterministic)
            .expect("deterministic competitor")
    }

    pub(crate) fn deterministic_competitor_json(
        report_json: &serde_json::Value,
    ) -> &serde_json::Value {
        report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array")
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor")
    }

    pub(crate) fn vanilla_rag_competitor_json(
        report_json: &serde_json::Value,
    ) -> &serde_json::Value {
        report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array")
            .iter()
            .find(|competitor| competitor["competitorId"] == "vanilla-rag")
            .expect("vanilla-rag competitor")
    }

    pub(crate) fn assert_abstention_gate_passed(
        competitor: &serde_json::Value,
        expected_gate: &str,
    ) {
        assert!(competitor["scoring"]["overallScore"].is_null());
        let abilities = competitor["scoring"]["abilities"]
            .as_array()
            .expect("abilities array");
        assert!(abilities.iter().all(|ability| ability["score"].is_null()));
        assert!(abilities.iter().any(|ability| {
            ability["ability"] == "abstention_gate"
                && ability["passed"] == true
                && ability["detail"]
                    .as_str()
                    .expect("detail string")
                    .contains(expected_gate)
        }));
        assert!(abilities.iter().any(|ability| {
            ability["ability"] == "no_regression_gate" && ability["passed"] == true
        }));
    }

    pub(crate) fn gate_case(fixture_class: FixtureClass) -> FixtureCase {
        FixtureCase {
            ppr_vad_query: None,
            case_id: format!("eval004-{}", fixture_class.gate_label()),
            query: "fixture gate query".to_owned(),
            limit: if fixture_class == FixtureClass::LowConfidence {
                0
            } else {
                5
            },
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class,
            temporal_search: (fixture_class == FixtureClass::TemporalStaleness)
                .then_some(FixtureTimeRange { start: 0, end: 1 }),
            temporal_evidence_ids: if fixture_class == FixtureClass::TemporalStaleness {
                vec!["50505050505050505050505050505050".to_owned()]
            } else {
                Vec::new()
            },
            opposing_evidence: (fixture_class == FixtureClass::AdversarialContradiction).then(
                || OpposingEvidence {
                    field: "txt".to_owned(),
                    record_ids: vec![
                        "30303030303030303030303030303030".to_owned(),
                        "40404040404040404040404040404040".to_owned(),
                    ],
                },
            ),
            offline_amortized_cost: CostComponentInput::default(),
        }
    }

    pub(crate) fn budget_score(scores: &[AbilityScoreReport]) -> &AbilityScoreReport {
        scores
            .iter()
            .find(|score| score.ability == AbilityKind::BudgetDiscipline)
            .expect("budget discipline score exists")
    }

    pub(crate) fn minimal_context_pack_report(
        result_count: usize,
        signals_used: &[&str],
        empty: Option<EmptyContextReport>,
    ) -> ContextPackReport {
        assert_eq!(
            result_count, 0,
            "use minimal_context_pack_report_with_result_ids for non-empty reports"
        );
        minimal_context_pack_report_with_result_ids(&[], signals_used, empty)
    }

    pub(crate) fn minimal_context_pack_report_with_result_ids(
        result_ids: &[&str],
        signals_used: &[&str],
        empty: Option<EmptyContextReport>,
    ) -> ContextPackReport {
        let mut stats = empty_pack_stats_report();
        stats.signals_used = signals_used
            .iter()
            .map(|signal| (*signal).to_owned())
            .collect();
        let results: Vec<ContextEntityReport> = result_ids
            .iter()
            .enumerate()
            .map(|(idx, id)| ContextEntityReport {
                id: (*id).to_owned(),
                short_id: format!("g{idx}"),
                entity_type: 8,
                score: 1.0,
            })
            .collect();

        ContextPackReport {
            token_budget: 128,
            limit: result_ids.len().max(1),
            serialized_format: "yaml".to_owned(),
            serialized_bytes: 0,
            serialized_tokens: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            query_cost: CostComponentReport {
                token_source: TokenAccountingSource::TokenizerCount,
                tokenizer_id: Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned()),
                input_tokens: 0,
                output_tokens: 0,
                target_tokens: 128,
                elapsed_us: 0,
                cost_usd: 0.0,
            },
            result_count: results.len(),
            neighbor_count: 0,
            results,
            neighbors: Vec::new(),
            stats,
            empty,
            temporal_result_ids: BTreeSet::new(),
            budgeted_text_by_entity_id: BTreeMap::new(),
        }
    }

    pub(crate) fn minimal_context_pack_report_with_temporal_result_ids(
        mut context_pack: ContextPackReport,
        temporal_result_ids: &[&str],
    ) -> ContextPackReport {
        context_pack.temporal_result_ids = temporal_result_ids
            .iter()
            .map(|id| (*id).to_owned())
            .collect();
        context_pack
    }

    #[test]
    fn ppr_community_beam_measures_final_pipeline_without_claiming_a_synthetic_win() {
        let ids: Vec<_> = (1_u8..=20)
            .map(|byte| format!("{byte:02x}").repeat(16))
            .collect();
        let records: Vec<_> = ids
            .iter()
            .map(|id| eval004_record_json(id, 1, "community corpus"))
            .collect();
        let fixture = serde_json::json!({
            "datasetId": "synthetic-community-wiring-not-empirical-evidence", "heldOut": true,
            "records": records,
            "edges": [{"source": ids[0], "target": ids[1], "kind": 4, "weight": 1.0},
                      {"source": ids[0], "target": ids[2], "kind": 11, "weight": 1.0}],
            "cases": [
                {"caseId": "preference", "subset": "preference", "depth": 1,
                 "textQuery": "community", "channelLimit": 20,
                 "orderedSeeds": [{"id": ids[0], "score": 1.0}], "relevantIds": [ids[1]]},
                {"caseId": "life-area", "subset": "life_area", "depth": 1,
                 "textQuery": "community", "channelLimit": 20,
                 "orderedSeeds": [{"id": ids[0], "score": 1.0}], "relevantIds": [ids[2]]}
            ]
        });
        let dir = tempfile::tempdir().expect("temporary fixture");
        let path = dir.path().join("community.json");
        std::fs::write(&path, fixture.to_string()).expect("fixture");
        let report = run_community_beam(&path).expect("diagnostics");
        assert_eq!(report.samples.len(), 4);
        assert_eq!(report.production_default_beta.to_bits(), 0.0_f32.to_bits());
        assert_eq!(report.final_pipeline_acceptance, Some(false));
        assert!(report.measurement_scope.contains("final PipelineBuilder"));
        assert!(
            report
                .recall_gain_percent_vs_zero
                .is_some_and(|gain| gain <= 0.0)
        );
        let parsed: CommunityBeamFixture =
            serde_json::from_value(fixture.clone()).expect("parsed fixture");
        for sample in report.samples {
            let case = parsed
                .cases
                .iter()
                .find(|case| case.case_id == sample.case_id)
                .expect("case");
            let expected_rows = community_beam_final_rows_for_test(&parsed, case, sample.beta);
            assert_eq!(
                sample.result_ids,
                expected_rows
                    .iter()
                    .map(|row| row.id.to_hex())
                    .collect::<Vec<_>>()
            );
            assert_eq!(sample.latency_ms.len(), 20);
            assert_eq!(sample.refresh_latency_ms.len(), 20);
            assert!(
                sample
                    .latency_ms
                    .iter()
                    .all(|value| value.is_finite() && *value > 0.0)
            );
            assert!(sample.p95_latency_ms.is_finite() && sample.p95_latency_ms > 0.0);
            assert!(sample.fine_entropy_bits.is_finite());
            assert!(sample.coarse_entropy_bits.is_finite());
            assert!((0.0..=1.0).contains(&sample.max_fine_fraction));
            assert!(sample.result_ids.len() <= 10);
            let expected = if sample.subset == CommunityBeamSubset::Preference {
                &ids[1]
            } else {
                &ids[2]
            };
            assert_eq!(
                sample.recall_at_10,
                if sample.result_ids.contains(expected) {
                    1.0
                } else {
                    0.0
                }
            );
        }
        let mut invalid = fixture;
        invalid["heldOut"] = serde_json::json!(false);
        std::fs::write(&path, invalid.to_string()).expect("invalid fixture");
        assert!(run_community_beam(&path).is_err());
    }

    pub(crate) fn community_beam_final_rows_for_test(
        fixture: &CommunityBeamFixture,
        case: &CommunityBeamCase,
        beta: f32,
    ) -> Vec<oneiron::ScoredEntity> {
        let dir = tempfile::tempdir().expect("oracle directory");
        let mut config = beam_vault_config();
        config.ppr_community.beta = beta;
        let vault = Vault::open(dir.path(), config).expect("oracle vault");
        let corpus = BeamFixture {
            schema_version: SCHEMA_VERSION,
            fixture_id: fixture.dataset_id.clone(),
            description: "independent final-row oracle".to_owned(),
            records: fixture.records.clone(),
            cases: Vec::new(),
            ppr_vad_edges: Vec::new(),
        };
        load_fixture_dataset(&vault, &corpus).expect("oracle corpus");
        for edge in &fixture.edges {
            let source = EntityId::from_hex(&edge.source).expect("source");
            let target = EntityId::from_hex(&edge.target).expect("target");
            let kind = oneiron::EdgeKind::try_from_u8(edge.kind).expect("kind");
            vault
                .put_edge(&source, kind, &target, edge.weight)
                .expect("edge");
            if let Some(vad) = edge.vad {
                vault
                    .set_edge_vad(&source, kind, &target, vad)
                    .expect("VAD");
            }
        }
        let seeds: Vec<_> = case
            .ordered_seeds
            .iter()
            .map(|seed| EntityId::from_hex(&seed.id).expect("seed"))
            .collect();
        vault
            .query()
            .search_text(&case.text_query, case.channel_limit)
            .expand_ppr(&seeds, case.depth)
            .with_temporal_now(1)
            .limit(10)
            .run_with_telemetry()
            .expect("final pipeline output")
            .value
    }

    #[test]
    fn ppr_community_beam_gate_is_measured_and_fails_closed_at_boundaries() {
        assert!(community_beam_gate(Some(5.0), Some(5.0), 2.0, 0.7));
        assert!(!community_beam_gate(Some(4.999), Some(0.0), 2.0, 0.7));
        assert!(!community_beam_gate(Some(5.0), Some(5.001), 2.0, 0.7));
        assert!(!community_beam_gate(Some(5.0), Some(0.0), 1.999, 0.7));
        assert!(!community_beam_gate(Some(5.0), Some(0.0), 2.0, 0.701));
        assert!(!community_beam_gate(None, Some(0.0), 2.0, 0.7));
        assert!(!community_beam_gate(Some(5.0), None, 2.0, 0.7));
        assert!(!community_beam_gate(Some(f64::NAN), Some(0.0), 2.0, 0.7));
        assert!(!community_beam_gate(
            Some(5.0),
            Some(f64::INFINITY),
            2.0,
            0.7
        ));
        assert!(!community_beam_gate(Some(5.0), Some(0.0), f64::NAN, 0.7));
        assert!(!community_beam_gate(Some(5.0), Some(0.0), 2.0, f64::NAN));
        assert_eq!(
            VaultConfig::device().ppr_community.beta.to_bits(),
            0.0_f32.to_bits()
        );
        assert_eq!(
            VaultConfig::server().ppr_community.beta.to_bits(),
            0.0_f32.to_bits()
        );
    }

    #[test]
    fn ppr_community_beam_diversity_metrics_do_not_invent_empty_graph_entropy() {
        assert_eq!(community_beam_entropy(&BTreeMap::new()), 0.0);
        let counts = BTreeMap::from([("a".to_owned(), 7), ("b".to_owned(), 3)]);
        let expected = -0.7_f64 * 0.7_f64.log2() - 0.3_f64 * 0.3_f64.log2();
        assert!((community_beam_entropy(&counts) - expected).abs() < 1e-12);
    }

    pub(crate) fn empty_pack_stats_report() -> PackStatsReport {
        PackStatsReport {
            candidates_considered: 0,
            signals_used: Vec::new(),
            query_time_us: 0,
            entities_hydrated: 0,
            neighbors_hydrated: 0,
            cosine_ghosts_dampened: 0,
            claims_suppressed: 0,
            tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
            total_tokens: 0,
            section_tokens: Vec::new(),
            item_tokens: Vec::new(),
            items_truncated: 0,
            items_truncated_reasons: Vec::new(),
            items_dropped: 0,
            items_dropped_reasons: Vec::new(),
        }
    }
}
