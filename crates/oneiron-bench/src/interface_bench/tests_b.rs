//! Pinned-model tests.

#[cfg(test)]
mod tests {
    use super::super::tests_a::tests::{pinned_settings, test_row};
    use super::super::*;
    use oneiron::{ModelId, llm::ModelIdError};
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::fs;
    #[test]
    fn browse_context_exposes_all_required_gold_claims() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::BrowseThenAnswer)
            .expect("browse task");
        let GoldLabel::BrowseThenAnswer {
            required_claim_ids, ..
        } = &task.gold
        else {
            unreachable!("browse task has browse gold");
        };
        let claims = context_claims(task, &bundle.fixture).expect("context claims");

        assert_eq!(claims.len(), required_claim_ids.len());
        assert_eq!(claims.len(), 10);
    }

    #[test]
    fn fs_context_exposes_changed_after_for_provenance_rows() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| {
                matches!(
                    &task.gold,
                    GoldLabel::Provenance { field, .. } if field == "changed_after"
                )
            })
            .expect("changed_after provenance task");
        let transcript = fs_context(task, &bundle.fixture, false)
            .expect("fs context")
            .transcript;

        assert!(transcript.contains("changed_after:"));
    }

    #[test]
    fn sdk_retrieval_context_reports_real_tool_calls_under_cap() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let context = sdk_context(task, &bundle.fixture).expect("sdk context");

        assert_eq!(context.tool_calls, 1);
        assert!(context.tool_calls <= TOOL_CALL_CAP);
    }

    #[test]
    fn blind_judge_answer_normalizes_claim_paths() {
        let answer = "See /claims/claim-0001.txt and claim-0002.";
        let normalized = blind_judge_answer(answer);

        assert!(normalized.contains("claim-0001"));
        assert!(!normalized.contains("/claims/claim-0001.txt"));
    }

    #[test]
    fn blind_judge_answer_normalizes_punctuated_claim_paths() {
        let answer =
            "See (/claims/claim-0001.txt), /claims/claim_0002.txt. and [/claims/claim-0003.txt];";
        let normalized = blind_judge_answer(answer);

        assert_eq!(
            normalized,
            "See (claim-0001), claim_0002. and [claim-0003];"
        );
        assert!(!normalized.contains("/claims/"));
    }

    #[test]
    fn validate_loaded_row_rejects_class_mismatch() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let row = test_row(&task.task_id, TaskClass::MultiHop, ArmId::Sdk, 0, 10, 1.0);

        let error = validate_loaded_row(
            &row,
            task,
            &ExpectedRowIdentity {
                arm: ArmId::Sdk,
                rep_index: 0,
                memo_key: "memo",
                request_hash: "request",
                request_nonce: "nonce",
                pinned: None,
            },
        )
        .expect_err("class mismatch should reject cached row");
        assert!(error.contains("memo row mismatch"));
    }

    #[test]
    fn class_arm_table_reports_row_level_token_mean() {
        let rows = vec![
            test_row("a", TaskClass::RetrievalQa, ArmId::Sdk, 0, 10, 1.0),
            test_row("b", TaskClass::RetrievalQa, ArmId::Sdk, 0, 30, 0.8),
            test_row("c", TaskClass::RetrievalQa, ArmId::Sdk, 1, 50, 0.6),
            test_row("d", TaskClass::RetrievalQa, ArmId::Sdk, 1, 70, 0.4),
        ];
        let table = class_arm_table(&rows, FULL_REP_COUNT);
        let summary = table
            .iter()
            .find(|row| row.class == TaskClass::RetrievalQa.as_str() && row.arm == ArmId::Sdk)
            .expect("retrieval sdk summary");

        assert_eq!(summary.runs, 4);
        assert_eq!(summary.tokens_mean, 40.0);
        assert_eq!(summary.tokens_range, 60);
    }

    #[test]
    fn full_report_emits_proposed_verdict_claim_for_each_arm() {
        let bundle = build_task_bundle();
        let rows = vec![
            test_row("sdk", TaskClass::RetrievalQa, ArmId::Sdk, 0, 100, 0.8),
            test_row("fs", TaskClass::RetrievalQa, ArmId::Fs, 0, 120, 0.8),
            test_row("hybrid", TaskClass::RetrievalQa, ArmId::Hybrid, 0, 110, 0.9),
        ];
        let report = full_run_report(&bundle, rows, &RunSettings::default());
        let arms = report
            .arm_verdict_claims
            .iter()
            .map(|claim| claim.arm)
            .collect::<BTreeSet<_>>();

        assert_eq!(report.arm_verdict_claims.len(), 3);
        assert_eq!(arms, ArmId::ALL.into_iter().collect::<BTreeSet<_>>());
        assert!(
            report.arm_verdict_claims.iter().all(
                |claim| claim.band == "Proposed" && claim.claim_id.contains(claim.arm.as_str())
            )
        );
    }

    #[test]
    fn generated_task_gold_payload_uses_camel_case_fields() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let value = serde_json::to_value(task).expect("serialize task");
        let gold = value
            .get("gold")
            .and_then(Value::as_object)
            .expect("gold object");

        assert!(gold.contains_key("relevantClaimIds"));
        assert!(!gold.contains_key("relevant_claim_ids"));
    }

    #[test]
    fn token_extrapolation_targets_owner_authorized_480_run_full_campaign() {
        let rows = vec![test_row(
            "task",
            TaskClass::RetrievalQa,
            ArmId::Sdk,
            0,
            10,
            1.0,
        )];
        let extrapolation = token_burn_extrapolation(&rows, FULL_REP_COUNT);

        assert_eq!(extrapolation.full_run_equivalent_runs, 480);
        assert_eq!(extrapolation.extrapolated_full_tokens, 4_800);

        let single_rep = token_burn_extrapolation(&rows, 1);
        assert_eq!(single_rep.full_run_equivalent_runs, 240);
        assert_eq!(single_rep.extrapolated_full_tokens, 2_400);
    }

    #[test]
    fn taskgen_writes_expected_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = write_taskgen_outputs(temp.path(), &RunSettings::default()).expect("taskgen");
        assert_eq!(report.generated_claims, CLAIM_COUNT);
        for name in [
            "campaign_config.json",
            "fixture_vault.json",
            "tasks_full.json",
            "tasks_smoke.json",
            "holdout_freeze.json",
            "owner_spotcheck_sample.json",
            "taskgen_report.json",
        ] {
            assert!(temp.path().join(name).exists(), "missing {name}");
        }
    }

    #[test]
    fn pinned_config_parse_roundtrip() {
        let config = parse_pinned_model_config(
            r#"{"allowed":["z-ai/glm-5.2@r1","openai/gpt-4.1@2026-07-02"],"background_tier_enabled":true}"#,
        )
        .expect("valid pinned config parses");
        assert_eq!(config.allowed.len(), 2);
        assert_eq!(
            config.allowed,
            BTreeSet::from([
                ModelId::new("z-ai/glm-5.2@r1").expect("model id"),
                ModelId::new("openai/gpt-4.1@2026-07-02").expect("model id"),
            ])
        );
        assert!(config.background_tier_enabled);

        let disabled =
            parse_pinned_model_config(r#"{"allowed":[],"background_tier_enabled":false}"#)
                .expect("empty allowed is a valid config");
        assert!(disabled.allowed.is_empty(), "empty allowed admits nothing");
        assert!(!disabled.background_tier_enabled);

        // A malformed id reports its index and the ModelIdError source.
        let error = parse_pinned_model_config(
            r#"{"allowed":["z-ai/glm-5.2@r1","not-a-model"],"background_tier_enabled":true}"#,
        )
        .expect_err("malformed model id must reject");
        match error {
            PinnedConfigParseError::InvalidModelId {
                index,
                value,
                source,
            } => {
                assert_eq!(index, 1);
                assert_eq!(value, "not-a-model");
                assert_eq!(source, ModelIdError::MissingProviderSeparator);
            }
            other => panic!("expected InvalidModelId, got {other:?}"),
        }

        // A repeated id fires on the SECOND occurrence; no silent dedup.
        let error = parse_pinned_model_config(
            r#"{"allowed":["z-ai/glm-5.2@r1","z-ai/glm-5.2@r1"],"background_tier_enabled":false}"#,
        )
        .expect_err("duplicate pinned model must reject");
        match error {
            PinnedConfigParseError::Duplicate { index, model } => {
                assert_eq!(index, 1);
                assert_eq!(model, ModelId::new("z-ai/glm-5.2@r1").expect("model id"));
            }
            other => panic!("expected Duplicate, got {other:?}"),
        }

        // Wrong JSON types, missing fields, and unknown fields are all Json.
        for malformed in [
            r#"{"allowed":[7],"background_tier_enabled":true}"#,
            r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":"yes"}"#,
            r#"{"allowed":["z-ai/glm-5.2@r1"]}"#,
            r#"{"background_tier_enabled":true}"#,
            r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true,"extra":1}"#,
            r#"not json"#,
        ] {
            let error = parse_pinned_model_config(malformed)
                .expect_err("malformed pinned config must reject");
            assert!(
                matches!(error, PinnedConfigParseError::Json(_)),
                "expected Json for {malformed}, got {error:?}"
            );
        }
    }

    /// Coverage resolves to the ONE pinned revision a transmit is attested
    /// under: a bare wire id needs an unambiguous pin, a revisioned wire id
    /// must match the pinned revision exactly, and everything else refuses.
    #[test]
    fn pinned_coverage_is_revision_aware() {
        let config = parse_pinned_model_config(
            r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#,
        )
        .expect("valid pinned config parses");

        assert_eq!(
            pinned_model_for_wire_id(&config, "z-ai/glm-5.2").expect("covered wire id"),
            ModelId::new("z-ai/glm-5.2@r1").expect("model id"),
            "a covered wire id resolves to its full pinned revision"
        );
        assert_eq!(
            pinned_model_for_wire_id(&config, "z-ai/glm-5.2@r1").expect("exact revisioned wire id"),
            ModelId::new("z-ai/glm-5.2@r1").expect("model id"),
        );

        // Revision mismatch refuses: the unrevised provider/name pair is NOT
        // enough to cover a transmit that names another revision.
        for uncovered in ["z-ai/glm-5.2@r2", "z-ai/glm-5.3", "other/glm-5.2"] {
            assert!(
                matches!(
                    pinned_model_for_wire_id(&config, uncovered),
                    Err(PinnedCoverageError::NotCovered { .. })
                ),
                "{uncovered} must not be covered"
            );
        }

        // Two pinned revisions of the same provider/name leave the transmitted
        // revision unattested, so a bare wire id refuses instead of guessing.
        let ambiguous = parse_pinned_model_config(
            r#"{"allowed":["z-ai/glm-5.2@r1","z-ai/glm-5.2@r2"],"background_tier_enabled":true}"#,
        )
        .expect("valid pinned config parses");
        assert!(matches!(
            pinned_model_for_wire_id(&ambiguous, "z-ai/glm-5.2"),
            Err(PinnedCoverageError::AmbiguousRevision { .. })
        ));
        assert_eq!(
            pinned_model_for_wire_id(&ambiguous, "z-ai/glm-5.2@r2").expect("exact revision"),
            ModelId::new("z-ai/glm-5.2@r2").expect("model id"),
        );

        let empty = parse_pinned_model_config(r#"{"allowed":[],"background_tier_enabled":true}"#)
            .expect("empty allowed parses");
        assert!(pinned_model_for_wire_id(&empty, "z-ai/glm-5.2").is_err());
    }

    /// A pinned run transmits the SAME wire body as an unpinned run, records
    /// which pinned revision it rode under, and keys its row by a hash that
    /// binds that pin.
    #[test]
    fn pinned_run_transmits_wire_body_and_records_its_pin() {
        let settings =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#);
        let messages = vec![chat_message("system", "pinned prompt".to_owned())];
        let body = openrouter_request_body(&messages, 900, "nonce", &settings);
        let unpinned_body =
            openrouter_request_body(&messages, 900, "nonce", &RunSettings::default());

        assert_eq!(
            body.to_string(),
            unpinned_body.to_string(),
            "the transmitted body stays the campaign's exact wire shape"
        );

        let attestation = pinned_transmit_attestation(&settings, &body)
            .expect("covered transmit")
            .expect("pinned run attests its transmit");
        assert_eq!(attestation.model, "z-ai/glm-5.2@r1");
        assert_eq!(
            attestation.config_digest,
            settings
                .pinned
                .as_ref()
                .expect("pinned run")
                .config_digest(),
        );

        // The pin is bound into the request hash, so it also separates memo keys.
        let pinned_hash = request_hash(&body, Some(&attestation));
        let unpinned_hash = request_hash(&unpinned_body, None);
        assert_ne!(pinned_hash, unpinned_hash);
        assert_eq!(
            unpinned_hash,
            blake3_hex(unpinned_body.to_string().as_bytes()),
            "unpinned hashing stays byte-identical to pre-pin campaigns"
        );
    }

    /// A transmit the pin file does not cover refuses at the transmit
    /// chokepoint — a pinned run never falls back to running unpinned.
    #[test]
    fn uncovered_transmit_refuses_instead_of_running_unpinned() {
        let mut settings =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#);
        settings.model = "z-ai/glm-5.3".to_owned();
        let body = openrouter_request_body(&[], 900, "nonce", &settings);

        let error = pinned_transmit_attestation(&settings, &body)
            .expect_err("an uncovered transmitted model must refuse");
        assert!(error.contains("does not cover transmitted model `z-ai/glm-5.3`"));

        // The same refusal guards the single provider-call chokepoint, before
        // any request is spawned.
        let error = call_openrouter("test-key", &[], 900, "nonce", &settings)
            .expect_err("call_openrouter must refuse an uncovered transmit");
        assert!(error.contains("refusing to transmit unpinned"));

        // Flag parsing refuses the same way, before the run starts.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pinned.json");
        fs::write(
            &path,
            r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#,
        )
        .expect("write pinned config");
        let args = [
            "--model".to_owned(),
            "z-ai/glm-5.3".to_owned(),
            "--pinned-config".to_owned(),
            path.display().to_string(),
        ];
        let error = parse_run_flags(&args).expect_err("uncovered model must refuse the run");
        assert!(error.contains("does not cover transmitted model `z-ai/glm-5.3`"));
    }

    /// A pinned run must not reuse a row written by an unpinned run, and two
    /// pinned revisions must not share rows.
    #[test]
    fn pinned_run_refuses_rows_of_another_pinned_identity() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let nonce = request_nonce(task, arm, 0);
        let messages = vec![chat_message("system", "prompt".to_owned())];

        let unpinned = RunSettings::default();
        let pinned_r1 =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#);
        let pinned_r2 =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r2"],"background_tier_enabled":true}"#);
        let identity = |settings: &RunSettings| {
            let body = openrouter_request_body(&messages, 900, &nonce, settings);
            let pinned = pinned_transmit_attestation(settings, &body).expect("covered transmit");
            let hash = request_hash(&body, pinned.as_ref());
            let memo_key = eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &hash,
                judge_cache_key(task).as_deref(),
            );
            (pinned, hash, memo_key)
        };

        let (no_pin, unpinned_hash, unpinned_key) = identity(&unpinned);
        let (pin_r1, hash_r1, key_r1) = identity(&pinned_r1);
        let (pin_r2, hash_r2, key_r2) = identity(&pinned_r2);

        assert!(no_pin.is_none());
        assert_ne!(unpinned_hash, hash_r1, "a pin changes the request hash");
        assert_ne!(hash_r1, hash_r2, "two pinned revisions never share a hash");
        assert_ne!(unpinned_key, key_r1, "a pin changes the memo key");
        assert_ne!(
            key_r1, key_r2,
            "two pinned revisions never share a memo key"
        );

        // Row validation is the second belt: an unpinned row is refused by a
        // pinned run, a pinned row is refused by an unpinned run, and a row
        // pinned to another revision is refused too.
        let mut row = test_row(&task.task_id, task.class, arm, 0, 10, 1.0);
        row.memo_key = key_r1.clone();
        row.request_hash = hash_r1.clone();
        row.request_nonce = nonce.clone();

        let expected_r1 = ExpectedRowIdentity {
            arm,
            rep_index: 0,
            memo_key: &key_r1,
            request_hash: &hash_r1,
            request_nonce: &nonce,
            pinned: pin_r1.as_ref(),
        };

        let error = validate_loaded_row(&row, task, &expected_r1)
            .expect_err("an unpinned row must not be reused by a pinned run");
        assert!(error.contains("pinned identity mismatch"));

        row.pinned = pin_r1.clone();
        validate_loaded_row(&row, task, &expected_r1)
            .expect("the run's own pinned row is reusable");

        let error = validate_loaded_row(
            &row,
            task,
            &ExpectedRowIdentity {
                pinned: pin_r2.as_ref(),
                ..expected_r1
            },
        )
        .expect_err("another pinned revision's row must not be reused");
        assert!(error.contains("pinned identity mismatch"));

        let error = validate_loaded_row(
            &row,
            task,
            &ExpectedRowIdentity {
                pinned: None,
                ..expected_r1
            },
        )
        .expect_err("a pinned row must not be reused by an unpinned run");
        assert!(error.contains("pinned identity mismatch"));
        assert_ne!(hash_r2, hash_r1);
        assert_ne!(key_r2, key_r1);
    }

    /// The production resume path itself (`run_or_load_eval_row`) refuses a row
    /// that is not this run's pinned identity, and reuses its own row without
    /// ever reaching the provider. Offline: the refusal and the reuse both
    /// happen before any request is transmitted.
    #[test]
    fn pinned_resume_path_refuses_a_row_of_another_identity() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let settings =
            pinned_settings(r#"{"allowed":["z-ai/glm-5.2@r1"],"background_tier_enabled":true}"#);
        let dir = tempfile::tempdir().expect("tempdir");
        let row_dir = dir.path();

        // Reproduce exactly what the run computes for this task/arm/rep.
        let context = arm_context(arm, task, &bundle.fixture).expect("arm context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let body = openrouter_request_body(&messages, 900, &nonce, &settings);
        let pinned = pinned_transmit_attestation(&settings, &body).expect("covered transmit");
        let hash = request_hash(&body, pinned.as_ref());
        let memo_key = eval_memo_key(
            task,
            arm,
            0,
            &nonce,
            &hash,
            judge_cache_key(task).as_deref(),
        );

        let mut row = test_row(&task.task_id, task.class, arm, 0, 10, 1.0);
        row.memo_key = memo_key.clone();
        row.request_hash = hash;
        row.request_nonce = nonce;
        row.tool_calls = context.tool_calls;
        row.answer = "carried-over answer".to_owned();
        let row_path = row_dir.join(format!("{memo_key}.json"));

        // A row written by an UNPINNED run, sitting at this pinned run's key.
        write_json_atomic(&row_path, &row).expect("seed unpinned row");
        let error = run_or_load_eval_row(
            "test-key",
            row_dir,
            task,
            arm,
            0,
            &bundle.fixture,
            &settings,
        )
        .expect_err("a pinned run must not reuse an unpinned row");
        assert!(
            error.contains("pinned identity mismatch"),
            "unexpected error: {error}"
        );

        // The run's OWN row is reused, offline, with its pin intact.
        row.pinned = pinned.clone();
        write_json_atomic(&row_path, &row).expect("seed pinned row");
        let loaded = run_or_load_eval_row(
            "test-key",
            row_dir,
            task,
            arm,
            0,
            &bundle.fixture,
            &settings,
        )
        .expect("the run's own pinned row is reusable");
        assert_eq!(loaded.answer, "carried-over answer");
        assert_eq!(loaded.pinned, pinned);
    }

    /// Unpinned rows serialize exactly as before the pin field existed, so a
    /// resumed pre-pin campaign still loads and revalidates.
    #[test]
    fn unpinned_row_json_is_unchanged_and_pinned_row_carries_its_pin() {
        let row = test_row("task", TaskClass::RetrievalQa, ArmId::Sdk, 0, 10, 1.0);
        let value = serde_json::to_value(&row).expect("serialize row");
        assert!(
            value.get("pinned").is_none(),
            "an unpinned row must not gain a field"
        );
        let reloaded: SmokeRunRow = serde_json::from_value(value).expect("round-trip");
        assert!(reloaded.pinned.is_none());

        let mut pinned_row = row;
        pinned_row.pinned = Some(PinnedAttestation {
            model: "z-ai/glm-5.2@r1".to_owned(),
            config_digest: "digest".to_owned(),
        });
        let value = serde_json::to_value(&pinned_row).expect("serialize pinned row");
        assert_eq!(value["pinned"]["model"], json!("z-ai/glm-5.2@r1"));
        assert_eq!(value["pinned"]["configDigest"], json!("digest"));
        let reloaded: SmokeRunRow = serde_json::from_value(value).expect("round-trip");
        assert_eq!(reloaded.pinned, pinned_row.pinned);
    }
}
