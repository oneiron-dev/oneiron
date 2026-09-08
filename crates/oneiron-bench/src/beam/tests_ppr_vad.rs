//! PPR-VAD tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::eval004_record_json;
    use super::super::*;
    use oneiron::EntityId;
    use oneiron::Vault;
    use oneiron::VaultConfig;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::ExitCode;

    pub(crate) fn ppr_vad_test_documents() -> (serde_json::Value, serde_json::Value) {
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
        competitor["card"]["comparator"]["baselineCompetitorId"] =
            competitor["competitorId"].clone();
        manifest_json["competitors"] = serde_json::json!([competitor]);
        (fixture_json, manifest_json)
    }

    pub(crate) fn ppr_vad_test_fixture_and_manifest() -> (BeamFixture, RunManifest) {
        let (fixture_json, manifest_json) = ppr_vad_test_documents();
        (
            parse_fixture_json(&fixture_json.to_string()).expect("sweep fixture"),
            parse_manifest_json(&manifest_json.to_string()).expect("sweep manifest"),
        )
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

    pub(crate) fn ppr_vad_production_final_rows(
        fixture: &BeamFixture,
        seeds: &[EntityId],
        depth: u32,
        alpha: f32,
    ) -> Vec<oneiron::ScoredEntity> {
        // Independent of the benchmark sampler: populate a separate vault and
        // invoke the public production endpoint, reading only its final value.
        let dir = tempfile::tempdir().expect("oracle tempdir");
        let mut config = beam_vault_config();
        config.ppr_vad_alpha = alpha;
        let vault = Vault::open(dir.path(), config).expect("oracle vault");
        load_fixture_dataset(&vault, fixture).expect("oracle corpus");
        for edge in &fixture.ppr_vad_edges {
            let source = EntityId::from_hex(&edge.source).expect("oracle source");
            let target = EntityId::from_hex(&edge.target).expect("oracle target");
            let kind = oneiron::EdgeKind::try_from_u8(edge.kind).expect("oracle edge kind");
            vault
                .put_edge(&source, kind, &target, edge.weight)
                .expect("oracle edge");
            if let Some(vad) = edge.vad {
                vault
                    .set_edge_vad(&source, kind, &target, vad)
                    .expect("oracle stored VAD");
            }
        }
        vault
            .query()
            .search_ppr(seeds, depth)
            .limit(15)
            .run_with_telemetry()
            .expect("production final retrieval")
            .value
    }

    #[test]
    fn ppr_vad_sweep_manifest_runs_five_alphas_and_reports_real_measurements() {
        let (fixture, _) = ppr_vad_test_fixture_and_manifest();
        let dir = tempfile::tempdir().expect("fixture directory");
        let path = ppr_vad_test_manifest_path(dir.path());
        // This is the same file-loading runner used by `beam run`, not the
        // in-memory fixture seam. All final-metric assertions below still hold.
        let report = run_manifest_path(&path).expect("public sweep runner");
        let sweep = report.ppr_vad_sweep.as_ref().expect("aggregate sweep");
        assert_eq!(sweep.salient_queries, 1);
        assert_eq!(sweep.neutral_queries, 1);
        assert_eq!(sweep.production_default_alpha.to_bits(), 0.0_f32.to_bits());
        assert_eq!(
            sweep.alphas.iter().map(|row| row.alpha).collect::<Vec<_>>(),
            oneiron::config::PPR_VAD_ALPHA_SWEEP
        );
        for case in &report.cases {
            let query = fixture
                .cases
                .iter()
                .find(|fixture_case| fixture_case.case_id == case.case_id)
                .and_then(|fixture_case| fixture_case.ppr_vad_query.as_ref())
                .expect("declared sweep judgments");
            let ArmOutcome::RetrievalSweep { samples, .. } = &case.arms[0].outcome else {
                panic!("sweep arm must run rather than return not_ready");
            };
            assert_eq!(
                samples
                    .iter()
                    .map(|sample| sample.alpha)
                    .collect::<Vec<_>>(),
                oneiron::config::PPR_VAD_ALPHA_SWEEP
            );
            let seeds: Vec<_> = query
                .seeds
                .iter()
                .map(|id| EntityId::from_hex(id).expect("declared seed"))
                .collect();
            for sample in samples {
                let final_rows =
                    ppr_vad_production_final_rows(&fixture, &seeds, query.depth, sample.alpha);
                let final_ids: Vec<_> = final_rows.iter().map(|row| row.id.to_hex()).collect();
                assert_eq!(sample.result_ids, final_ids);
                // Production fusion uses PPR only for candidate membership.
                // No boosts and non-claim records give identical final scores:
                // ID order selects 01..0f, including the seed, at EVERY alpha.
                // The salient target (14) remains outside the final top 15 even
                // when its raw PPR score rises. Do not manufacture a PPR win.
                let expected_ids: Vec<_> = fixture.records[..15]
                    .iter()
                    .map(|record| record.id.clone())
                    .collect();
                assert_eq!(final_ids, expected_ids);
                assert!(final_rows.iter().all(|row| row.score == 1.0));
                assert!(query.seeds.iter().all(|id| sample.result_ids.contains(id)));
                let hits = query
                    .relevant_ids
                    .iter()
                    .filter(|id| sample.result_ids.contains(id))
                    .count();
                assert_eq!(
                    sample.recall_at_15,
                    hits as f64 / query.relevant_ids.len() as f64
                );
                assert_eq!(sample.result_ids.len(), 15);
                assert_eq!(sample.latency_ms.len(), PPR_VAD_LATENCY_REPETITIONS);
                assert!(
                    sample
                        .latency_ms
                        .iter()
                        .all(|ms| ms.is_finite() && *ms >= 0.0)
                );
                assert!((0.0..=1.0).contains(&sample.recall_at_15));
            }
            assert_eq!(case.competitors[0].scoring.overall_score, None);
        }
        for (index, row) in sweep.alphas.iter().enumerate() {
            let mut measured_latencies = Vec::new();
            for case in &report.cases {
                let ArmOutcome::RetrievalSweep { samples, .. } = &case.arms[0].outcome else {
                    panic!("expected measured sweep");
                };
                measured_latencies.extend_from_slice(&samples[index].latency_ms);
            }
            assert_eq!(measured_latencies.len(), 40);
            measured_latencies.sort_by(f64::total_cmp);
            // Independently calculate nearest-rank p95 of the 40 real queries.
            assert_eq!(row.p95_latency_ms, measured_latencies[37]);
            assert!(row.p95_latency_ms.is_finite());
            assert_eq!(row.salient_recall_at_15, 0.0);
            assert_eq!(row.neutral_recall_at_15, 1.0);
            assert_eq!(row.neutral_delta_pp_vs_zero, 0.0);
            // A zero salient baseline cannot support a relative gain claim.
            assert_eq!(
                row.salient_gain_percent_vs_zero,
                if row.alpha == 0.0 { Some(0.0) } else { None }
            );
            assert!(
                !row.gate_passed,
                "the unchanged tie fixture has no final-retrieval win"
            );
        }
        let json = serde_json::to_value(&report).expect("valid sweep test input");
        assert_eq!(json["pprVadSweep"]["productionDefaultAlpha"], 0.0);
        assert_eq!(VaultConfig::device().ppr_vad_alpha, 0.0);
        assert_eq!(VaultConfig::server().ppr_vad_alpha, 0.0);
    }

    #[test]
    fn ppr_vad_retrieval_sample_matches_production_final_rows_with_multiple_seeds() {
        let (fixture, _) = ppr_vad_test_fixture_and_manifest();
        let seeds = [0, 1]
            .map(|index| EntityId::from_hex(&fixture.records[index].id).expect("fixture seed"));
        for alpha in oneiron::config::PPR_VAD_ALPHA_SWEEP {
            let (rows, _) = ppr_vad_retrieval_sample(&fixture, &seeds, 1, *alpha)
                .expect("final retrieval sample");
            let production_rows = ppr_vad_production_final_rows(&fixture, &seeds, 1, *alpha);
            assert_eq!(rows, production_rows);
            // Seeds are ordinary final candidates. The benchmark must neither
            // remove them nor backfill from a larger query or a channel trace.
            let expected_ids: Vec<_> = fixture.records[..15]
                .iter()
                .map(|record| record.id.clone())
                .collect();
            assert_eq!(
                rows.iter().map(|row| row.id.to_hex()).collect::<Vec<_>>(),
                expected_ids
            );
            assert!(
                seeds
                    .iter()
                    .all(|seed| rows.iter().any(|row| row.id == *seed))
            );
            assert!(rows.iter().all(|row| row.score == 1.0));
        }
    }

    #[test]
    fn ppr_vad_sweep_rejects_seed_relevance_judgments() {
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        let query = fixture.cases[0]
            .ppr_vad_query
            .as_mut()
            .expect("sweep query");
        query.relevant_ids = query.seeds.clone();
        assert!(matches!(
            run_fixture_manifest(&manifest, &fixture),
            Err(BeamError::InvalidFixture { reason, .. })
                if reason == "sweep relevance judgments must exclude seeds"
        ));
    }

    #[test]
    fn ppr_vad_sweep_gate_pins_boundaries_and_fails_closed() {
        assert!(ppr_vad_gate(Some(2.0), 0.0, Some(5.0)));
        assert!(!ppr_vad_gate(Some(1.999), 0.0, Some(5.0)));
        assert!(!ppr_vad_gate(Some(2.0), -0.0001, Some(5.0)));
        assert!(!ppr_vad_gate(Some(2.0), 0.0, Some(5.001)));
        assert!(!ppr_vad_gate(None, 0.0, Some(0.0)));
        assert!(!ppr_vad_gate(Some(3.0), 0.0, None));
        assert!(!ppr_vad_gate(Some(f64::NAN), 0.0, Some(0.0)));
        assert!(!ppr_vad_gate(Some(3.0), f64::NAN, Some(0.0)));
        assert!(!ppr_vad_gate(Some(3.0), 0.0, Some(f64::INFINITY)));
        assert_eq!(ppr_vad_percent_change(1.0, 0.0), None);
        assert!(
            (ppr_vad_percent_change(0.51, 0.5).expect("valid sweep test input") - 2.0).abs()
                < 1e-12
        );
        let mut latencies: Vec<_> = (1..=20).rev().map(f64::from).collect();
        assert_eq!(ppr_vad_p95(&mut latencies), 19.0);
    }

    #[test]
    fn ppr_vad_sweep_rejects_missing_subsets_and_invalid_judgments() {
        let (fixture, mut manifest) = ppr_vad_test_fixture_and_manifest();
        manifest.case_ids = vec!["salient".to_owned()];
        assert!(matches!(
            run_fixture_manifest(&manifest, &fixture),
            Err(BeamError::InvalidFixture { .. })
        ));
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        fixture.cases[0]
            .ppr_vad_query
            .as_mut()
            .expect("valid sweep test input")
            .relevant_ids
            .clear();
        assert!(matches!(
            run_fixture_manifest(&manifest, &fixture),
            Err(BeamError::InvalidFixture { .. })
        ));
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        fixture.ppr_vad_edges.clear();
        assert!(matches!(
            run_fixture_manifest(&manifest, &fixture),
            Err(BeamError::InvalidFixture { .. })
        ));
    }

    #[test]
    fn ppr_vad_sweep_rejects_structural_vad_in_fixture_validation() {
        for kind in [
            oneiron::EdgeKind::BelongsTo,
            oneiron::EdgeKind::PartOf,
            oneiron::EdgeKind::SameAs,
            oneiron::EdgeKind::Blocks,
        ] {
            for vad in [
                oneiron::Vad::NEUTRAL,
                oneiron::Vad {
                    valence: -1.0,
                    arousal: 1.0,
                    dominance: 0.0,
                },
            ] {
                let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
                fixture.ppr_vad_edges[0].kind = kind as u8;
                fixture.ppr_vad_edges[0].vad = Some(vad);
                assert!(matches!(validate_ppr_vad_fixture(&manifest, &fixture),
                        Err(BeamError::InvalidFixture { reason, .. })
                            if reason == "structural sweep edges cannot carry VAD"));
            }
        }
    }

    #[test]
    fn ppr_vad_sweep_rejects_ineffective_salience_graphs() {
        for mode in [
            "missing",
            "neutral",
            "dominance_only",
            "zero",
            "negative_zero",
            "opposes",
            "disconnected",
        ] {
            let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
            for edge in &mut fixture.ppr_vad_edges {
                match mode {
                    "missing" => edge.vad = None,
                    "neutral" => edge.vad = Some(oneiron::Vad::NEUTRAL),
                    "dominance_only" => {
                        edge.vad = Some(oneiron::Vad {
                            valence: 0.0,
                            arousal: 0.0,
                            dominance: 1.0,
                        });
                    }
                    "zero" => edge.weight = 0.0,
                    "negative_zero" => edge.weight = -0.0,
                    "opposes" => edge.kind = oneiron::EdgeKind::Opposes as u8,
                    "disconnected" => {}
                    _ => unreachable!(),
                }
            }
            if mode == "disconnected" {
                let mut edge = fixture.ppr_vad_edges.pop().expect("salient edge");
                edge.source = fixture.records[18].id.clone();
                fixture.ppr_vad_edges = vec![edge];
            }
            assert!(
                matches!(validate_ppr_vad_fixture(&manifest, &fixture),
                    Err(BeamError::InvalidFixture { reason, .. })
                        if reason.contains("must reach a positive-weight traversed semantic edge")),
                "{mode}"
            );
        }
    }

    #[test]
    fn ppr_vad_sweep_reachability_obeys_depth_direction_and_kind_budgets() {
        for bridge_kind in [
            oneiron::EdgeKind::Mentions,
            oneiron::EdgeKind::ChildOf,
            oneiron::EdgeKind::AssignedTo,
            oneiron::EdgeKind::BlockedBy,
            oneiron::EdgeKind::Blocks,
            oneiron::EdgeKind::Fulfills,
            oneiron::EdgeKind::DischargedBy,
            oneiron::EdgeKind::SameAs,
            oneiron::EdgeKind::Opposes,
        ] {
            let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
            let mut bridge = fixture.ppr_vad_edges[0].clone();
            bridge.kind = bridge_kind as u8;
            bridge.vad = None;
            let mut salient = fixture.ppr_vad_edges.last().expect("salient").clone();
            salient.source = bridge.target.clone();
            // Reverse both edges: PPR traverses incoming edges too.
            std::mem::swap(&mut bridge.source, &mut bridge.target);
            std::mem::swap(&mut salient.source, &mut salient.target);
            fixture.ppr_vad_edges = vec![bridge, salient];
            assert!(
                validate_ppr_vad_fixture(&manifest, &fixture).is_err(),
                "depth one does not traverse an edge beyond its frontier"
            );
            fixture.cases[0]
                .ppr_vad_query
                .as_mut()
                .expect("salient query")
                .depth = 2;
            let result = validate_ppr_vad_fixture(&manifest, &fixture);
            assert_eq!(
                result.is_ok(),
                bridge_kind == oneiron::EdgeKind::Mentions,
                "{bridge_kind:?}"
            );
        }
    }

    #[test]
    fn ppr_vad_sweep_reachability_obeys_production_frontier_score_cutoff() {
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        let mut edges = Vec::new();
        for index in 0..8 {
            edges.push(PprVadFixtureEdge {
                source: fixture.records[index].id.clone(),
                target: fixture.records[index + 1].id.clone(),
                kind: oneiron::EdgeKind::SetIn as u8,
                weight: 1.0,
                vad: Some(oneiron::Vad::NEUTRAL),
            });
        }
        let mut salient = fixture.ppr_vad_edges.last().expect("salient edge").clone();
        salient.source = fixture.records[8].id.clone();
        edges.push(salient);
        fixture.ppr_vad_edges = edges;
        fixture.cases[0]
            .ppr_vad_query
            .as_mut()
            .expect("salient query")
            .depth = 9;
        // Graph reachability alone accepts this depth-nine path. Production
        // stops its eight neutral SetIn hops below SCORE_EPSILON before it
        // can multiply the only salient edge, at every sweep coefficient.
        assert!(matches!(validate_ppr_vad_fixture(&manifest, &fixture),
                Err(BeamError::InvalidFixture { reason, .. })
                    if reason.contains("must reach a positive-weight traversed semantic edge")));
        let query = fixture.cases[0]
            .ppr_vad_query
            .as_ref()
            .expect("salient query");
        for &alpha in oneiron::config::PPR_VAD_ALPHA_SWEEP {
            let (_dir, vault) = ppr_vad_fixture_vault(&fixture, alpha).expect("cutoff graph");
            assert!(!ppr_vad_reaches_salient_edge(query, &vault).expect("production evidence"));
        }
        // Same depth, weights and VAD. Raising one neutral kind budget carries
        // enough real frontier mass to traverse the salient edge at depth nine.
        fixture.ppr_vad_edges[7].kind = oneiron::EdgeKind::Supports as u8;
        assert!(validate_ppr_vad_fixture(&manifest, &fixture).is_ok());
    }

    #[test]
    fn ppr_vad_evidence_uses_real_traversal_even_after_a_cached_query() {
        let (fixture, _) = ppr_vad_test_fixture_and_manifest();
        let query = fixture.cases[0]
            .ppr_vad_query
            .as_ref()
            .expect("salient query");
        let seeds = query
            .seeds
            .iter()
            .map(|id| EntityId::from_hex(id).expect("seed"))
            .collect::<Vec<_>>();
        for &alpha in oneiron::config::PPR_VAD_ALPHA_SWEEP {
            let (_dir, vault) = ppr_vad_fixture_vault(&fixture, alpha).expect("salient graph");
            let rows = vault
                .query()
                .search_ppr(&seeds, query.depth)
                .limit(15)
                .run()
                .expect("warm cache");
            let (observed_rows, effective) = vault
                .query()
                .search_ppr(&seeds, query.depth)
                .limit(15)
                .run_with_ppr_vad_evidence()
                .expect("fresh production evidence");
            assert_eq!(effective, alpha != 0.0);
            assert_eq!(
                rows.iter().map(|row| row.id).collect::<Vec<_>>(),
                observed_rows.iter().map(|row| row.id).collect::<Vec<_>>()
            );
            // Diagnostic state cannot leak into subsequent queries or alphas.
            assert_eq!(
                ppr_vad_reaches_salient_edge(query, &vault).expect("repeat evidence"),
                effective
            );
        }
    }

    #[test]
    fn ppr_vad_sweep_rejects_salience_that_rounds_to_neutral() {
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        fixture.ppr_vad_edges.last_mut().expect("salient edge").vad = Some(oneiron::Vad {
            valence: 0.0,
            arousal: f32::MIN_POSITIVE,
            dominance: 0.0,
        });
        assert!(matches!(validate_ppr_vad_fixture(&manifest, &fixture),
                Err(BeamError::InvalidFixture { reason, .. })
                    if reason.contains("must reach a positive-weight traversed semantic edge")));
    }

    #[test]
    fn ppr_vad_sweep_checks_every_selected_salient_query() {
        let (mut fixture, mut manifest) = ppr_vad_test_fixture_and_manifest();
        let mut unreachable = fixture.cases[0].clone();
        unreachable.case_id = "unreachable-salient".to_owned();
        unreachable
            .ppr_vad_query
            .as_mut()
            .expect("salient query")
            .seeds = vec![fixture.records[1].id.clone()];
        manifest.case_ids.push(unreachable.case_id.clone());
        fixture.cases.push(unreachable);
        assert!(matches!(validate_ppr_vad_fixture(&manifest, &fixture),
                Err(BeamError::InvalidFixture { reason, .. })
                    if reason.contains("unreachable-salient")));
        manifest.case_ids.pop();
        assert!(
            validate_ppr_vad_fixture(&manifest, &fixture).is_ok(),
            "unselected cases cannot manufacture or block a selected sweep"
        );
    }

    #[test]
    fn ppr_vad_sweep_reachability_caps_part_of_hops() {
        let (mut fixture, manifest) = ppr_vad_test_fixture_and_manifest();
        let mut edges = Vec::new();
        for index in 0..3 {
            edges.push(PprVadFixtureEdge {
                source: fixture.records[index].id.clone(),
                target: fixture.records[index + 1].id.clone(),
                kind: oneiron::EdgeKind::PartOf as u8,
                weight: 1.0,
                vad: None,
            });
        }
        let mut salient = fixture.ppr_vad_edges.last().expect("salient").clone();
        salient.source = fixture.records[3].id.clone();
        edges.push(salient);
        fixture.ppr_vad_edges = edges;
        fixture.cases[0]
            .ppr_vad_query
            .as_mut()
            .expect("salient query")
            .depth = 10;
        assert!(validate_ppr_vad_fixture(&manifest, &fixture).is_err());
        fixture.ppr_vad_edges[1].kind = oneiron::EdgeKind::Mentions as u8;
        assert!(validate_ppr_vad_fixture(&manifest, &fixture).is_ok());
    }

    #[test]
    fn ppr_vad_sweep_aggregate_uses_zero_baseline_and_both_subsets() {
        let case = |subset, weighted_recall| CaseReport {
            case_id: format!("arithmetic-{subset:?}"),
            query: "unit arithmetic, not empirical evidence".to_owned(),
            limit: 15,
            token_budget: 4096,
            expected_min_results: 0,
            fixture_class: FixtureClass::EvidenceSupported,
            offline_amortized_cost: not_applicable_cost(),
            competitors: Vec::new(),
            arms: vec![ArmReport {
                arm: ArmKind::PprVadSweep,
                outcome: ArmOutcome::RetrievalSweep {
                    subset,
                    samples: oneiron::config::PPR_VAD_ALPHA_SWEEP
                        .iter()
                        .map(|&alpha| PprVadCaseSample {
                            alpha,
                            recall_at_15: if alpha == 0.0 { 0.5 } else { weighted_recall },
                            latency_ms: vec![if alpha == 0.0 { 100.0 } else { 105.0 }; 20],
                            result_ids: Vec::new(),
                        })
                        .collect(),
                },
            }],
        };
        let report = ppr_vad_sweep_report(&[
            case(PprVadSubset::EmotionallySalient, 0.51),
            case(PprVadSubset::Neutral, 0.5),
        ])
        .expect("both subsets");
        assert!(!report.alphas[0].gate_passed);
        for row in report.alphas.iter().skip(1) {
            assert_eq!(row.salient_recall_at_15, 0.51);
            assert_eq!(row.neutral_recall_at_15, 0.5);
            assert_eq!(row.neutral_delta_pp_vs_zero, 0.0);
            assert_eq!(row.p95_increase_percent_vs_zero, Some(5.0));
            assert!(row.gate_passed);
        }
        let regressed = ppr_vad_sweep_report(&[
            case(PprVadSubset::EmotionallySalient, 0.51),
            case(PprVadSubset::Neutral, 0.49),
        ])
        .expect("both subsets");
        assert!(regressed.alphas.iter().all(|row| !row.gate_passed));
        assert_eq!(regressed.production_default_alpha, 0.0);
        assert!(ppr_vad_sweep_report(&[case(PprVadSubset::Neutral, 0.5)]).is_none());
    }
}
