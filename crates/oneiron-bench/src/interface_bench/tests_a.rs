//! Taskgen, config, and memo tests.

#[cfg(test)]
pub(crate) mod tests {
    use super::super::*;
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;
    pub(crate) fn test_row(
        task_id: &str,
        class: TaskClass,
        arm: ArmId,
        rep_index: u32,
        tokens_total: u32,
        accuracy: f64,
    ) -> SmokeRunRow {
        SmokeRunRow {
            task_id: task_id.to_owned(),
            class,
            arm,
            rep_index,
            memo_key: "memo".to_owned(),
            request_hash: "request".to_owned(),
            request_nonce: "nonce".to_owned(),
            pinned: None,
            generation_id: Some("gen-1".to_owned()),
            judge_generation_id: None,
            accuracy,
            tokens_total,
            tool_calls: 1,
            wall_clock_s: 1.0,
            answer: String::new(),
            score_detail: json!({}),
        }
    }

    pub(crate) fn pinned_settings(allowed: &str) -> RunSettings {
        let config = parse_pinned_model_config(allowed).expect("valid pinned config parses");
        let model = pinned_model_for_wire_id(&config, MODEL).expect("covered wire id");
        RunSettings {
            pinned: Some(PinnedRun {
                config,
                wire_models: BTreeMap::from([(MODEL.to_owned(), model)]),
            }),
            ..RunSettings::default()
        }
    }

    #[test]
    fn config_locks_openrouter_wandb_without_fallbacks() {
        let defaults = RunSettings::default();
        assert_eq!(defaults.model, MODEL);
        assert_eq!(defaults.provider, DEFAULT_PROVIDER);
        assert_eq!(defaults.full_reps, FULL_REP_COUNT);
        assert_eq!(defaults.full_token_ceiling(), FULL_TOKEN_CEILING);

        let config = interface_bench_1_config();
        assert_eq!(config.campaign, CAMPAIGN_ID);
        assert_eq!(config.nodes, ArmId::ALL);
        assert_eq!(config.model_binding.model, MODEL);
        assert_eq!(config.model_binding.browse_judge_model, MODEL);
        assert_eq!(
            config.model_binding.route.provider.order,
            vec!["wandb".to_owned()]
        );
        assert!(!config.model_binding.route.provider.allow_fallbacks);
        assert_eq!(config.budget_lease.tool_call_cap, TOOL_CALL_CAP);
        assert_eq!(config.budget_lease.smoke_token_ceiling, SMOKE_TOKEN_CEILING);
        assert_eq!(config.budget_lease.full_token_ceiling, FULL_TOKEN_CEILING);
    }

    #[test]
    fn campaign_config_records_model_provider_and_budget_overrides() {
        let settings = RunSettings {
            model: "example/alt-model".to_owned(),
            provider: "groq".to_owned(),
            full_reps: 1,
            pinned: None,
        };
        let config = campaign_config_for(&settings);
        assert_eq!(config.model_binding.model, "example/alt-model");
        assert_eq!(config.model_binding.browse_judge_model, "example/alt-model");
        assert_eq!(
            config.model_binding.route.provider.order,
            vec!["groq".to_owned()]
        );
        assert!(!config.model_binding.route.provider.allow_fallbacks);
        assert_eq!(
            config.budget_lease.full_token_ceiling,
            FULL_TOKEN_CEILING / 2
        );
    }

    #[test]
    fn generated_gold_labels_are_backed_by_fixture_claims() {
        let bundle = build_task_bundle();
        let claim_ids = bundle
            .fixture
            .claims
            .iter()
            .map(|claim| claim.claim_id.clone())
            .collect::<BTreeSet<_>>();
        for task in &bundle.full_tasks {
            assert!(task.generation.verified_by_construction);
            for claim_id in &task.supporting_claim_ids {
                assert!(claim_ids.contains(claim_id), "missing {claim_id}");
            }
        }
    }

    #[test]
    fn browse_accuracy_is_gated_by_citation_precheck() {
        assert_eq!(final_browse_accuracy(1.0, 0.0), 0.0);
        assert_eq!(final_browse_accuracy(0.8, 0.5), 0.5);
        assert_eq!(final_browse_accuracy(0.4, 0.9), 0.4);
    }

    #[test]
    fn fs_tool_calls_match_transcript_commands() {
        let bundle = build_task_bundle();
        let task = &bundle.smoke_tasks[0];
        let fs = fs_context(task, &bundle.fixture, false).expect("fs context");
        let hybrid = fs_context(task, &bundle.fixture, true).expect("hybrid context");

        assert_eq!(fs.tool_calls, 2);
        assert_eq!(fs.tool_calls, transcript_tool_calls(&fs.transcript));
        assert_eq!(hybrid.tool_calls, 2);
        assert_eq!(hybrid.tool_calls, transcript_tool_calls(&hybrid.transcript));
    }

    #[test]
    fn retrieval_context_exposes_full_generated_gold_set() {
        let bundle = build_task_bundle();
        let task = bundle
            .smoke_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval smoke task");
        let GoldLabel::RetrievalQa { relevant_claim_ids } = &task.gold else {
            unreachable!("retrieval task has retrieval gold");
        };
        let claims = context_claims(task, &bundle.fixture).expect("context claims");
        let transcript = fs_context(task, &bundle.fixture, false)
            .expect("fs context")
            .transcript;

        assert_eq!(claims.len(), relevant_claim_ids.len());
        assert!(relevant_claim_ids.iter().all(|id| transcript.contains(id)));
    }

    #[test]
    fn memo_key_and_request_hash_are_rep_distinct() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let settings = RunSettings::default();
        let nonce_0 = request_nonce(task, arm, 0);
        let nonce_1 = request_nonce(task, arm, 1);
        let request_hash_0 = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce_0, &settings)
                .to_string()
                .as_bytes(),
        );
        let request_hash_1 = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce_1, &settings)
                .to_string()
                .as_bytes(),
        );
        let memo_key_0 = eval_memo_key(
            task,
            arm,
            0,
            &nonce_0,
            &request_hash_0,
            judge_cache_key(task).as_deref(),
        );
        let memo_key_1 = eval_memo_key(
            task,
            arm,
            1,
            &nonce_1,
            &request_hash_1,
            judge_cache_key(task).as_deref(),
        );

        assert_ne!(nonce_0, nonce_1);
        assert_ne!(request_hash_0, request_hash_1);
        assert_ne!(memo_key_0, memo_key_1);
    }

    #[test]
    fn parse_run_flags_defaults_reproduce_pinned_campaign() {
        let (out_dir, settings) = parse_run_flags(&[]).expect("defaults parse");
        assert_eq!(out_dir, PathBuf::from(DEFAULT_OUT_DIR));
        assert_eq!(settings.model, MODEL);
        assert_eq!(settings.provider, DEFAULT_PROVIDER);
        assert_eq!(settings.full_reps, FULL_REP_COUNT);
        assert_eq!(settings.full_run_count(), 480);
        assert_eq!(settings.full_token_ceiling(), FULL_TOKEN_CEILING);
    }

    #[test]
    fn parse_run_flags_accepts_model_provider_and_reps_overrides() {
        let args = [
            "--out",
            "custom-out",
            "--model",
            "example/alt-model",
            "--provider",
            "groq",
            "--reps",
            "1",
        ]
        .map(String::from);
        let (out_dir, settings) = parse_run_flags(&args).expect("overrides parse");
        assert_eq!(out_dir, PathBuf::from("custom-out"));
        assert_eq!(settings.model, "example/alt-model");
        assert_eq!(settings.provider, "groq");
        assert_eq!(settings.full_reps, 1);
        assert_eq!(settings.full_run_count(), 240);
        assert_eq!(settings.full_token_ceiling(), FULL_TOKEN_CEILING / 2);
    }

    #[test]
    fn parse_run_flags_rejects_invalid_flags() {
        assert!(parse_run_flags(&["--reps".to_owned(), "0".to_owned()]).is_err());
        assert!(parse_run_flags(&["--reps".to_owned(), "two".to_owned()]).is_err());
        assert!(parse_run_flags(&["--reps".to_owned()]).is_err());
        assert!(parse_run_flags(&["--model".to_owned()]).is_err());
        assert!(parse_run_flags(&["--model".to_owned(), String::new()]).is_err());
        assert!(parse_run_flags(&["--provider".to_owned(), String::new()]).is_err());
        assert!(parse_run_flags(&["--bogus".to_owned()]).is_err());
    }

    #[test]
    fn parse_run_flags_bounds_reps_to_supported_range() {
        let (_, settings) =
            parse_run_flags(&["--reps".to_owned(), "8".to_owned()]).expect("max reps parse");
        assert_eq!(settings.full_reps, MAX_FULL_REPS);

        let error = parse_run_flags(&["--reps".to_owned(), "9".to_owned()])
            .expect_err("reps above bound should reject");
        assert!(error.contains("between 1 and 8"));

        let error = parse_run_flags(&["--reps".to_owned(), "0".to_owned()])
            .expect_err("zero reps should reject");
        assert!(error.contains("between 1 and 8"));
    }

    #[test]
    fn taskgen_flags_stay_out_dir_only() {
        assert!(parse_out_dir(&["--model".to_owned(), "example/alt-model".to_owned()]).is_err());
    }

    #[test]
    fn default_request_body_is_byte_identical_to_pinned_campaign() {
        let messages = vec![chat_message("system", "pinned prompt".to_owned())];
        let body = openrouter_request_body(&messages, 900, "nonce", &RunSettings::default());
        let pinned = json!({
            "model": "z-ai/glm-5.2",
            "messages": messages,
            "temperature": REQUEST_TEMPERATURE,
            "max_tokens": 900,
            "provider": {
                "order": ["wandb"],
                "allow_fallbacks": false
            },
            "user": "nonce"
        });

        assert_eq!(body.to_string(), pinned.to_string());
        assert_eq!(
            blake3_hex(body.to_string().as_bytes()),
            blake3_hex(pinned.to_string().as_bytes())
        );
    }

    #[test]
    fn provider_override_keeps_fallbacks_disabled() {
        let settings = RunSettings {
            provider: "groq".to_owned(),
            ..RunSettings::default()
        };
        let lock = settings.provider_lock();
        assert_eq!(lock.order, vec!["groq".to_owned()]);
        assert!(!lock.allow_fallbacks);

        let body = openrouter_request_body(&[], 900, "nonce", &settings);
        assert_eq!(body["provider"]["order"], json!(["groq"]));
        assert_eq!(body["provider"]["allow_fallbacks"], json!(false));
    }

    #[test]
    fn memo_key_separates_model_and_provider_overrides() {
        let bundle = build_task_bundle();
        let task = &bundle.full_tasks[0];
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let memo_key_for = |settings: &RunSettings| {
            let request_hash = blake3_hex(
                openrouter_request_body(&messages, 900, &nonce, settings)
                    .to_string()
                    .as_bytes(),
            );
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        };

        let default_key = memo_key_for(&RunSettings::default());
        let model_key = memo_key_for(&RunSettings {
            model: "example/alt-model".to_owned(),
            ..RunSettings::default()
        });
        let provider_key = memo_key_for(&RunSettings {
            provider: "groq".to_owned(),
            ..RunSettings::default()
        });

        assert_ne!(default_key, model_key);
        assert_ne!(default_key, provider_key);
        assert_ne!(model_key, provider_key);
    }

    #[test]
    fn full_report_records_effective_model_provider_and_reps() {
        let bundle = build_task_bundle();
        let settings = RunSettings {
            model: "example/alt-model".to_owned(),
            provider: "groq".to_owned(),
            full_reps: 1,
            pinned: None,
        };
        let rows = vec![test_row(
            "task",
            TaskClass::RetrievalQa,
            ArmId::Sdk,
            0,
            100,
            0.8,
        )];
        let report = full_run_report(&bundle, rows, &settings);

        assert_eq!(report.model, "example/alt-model");
        assert_eq!(report.provider.order, vec!["groq".to_owned()]);
        assert!(!report.provider.allow_fallbacks);
        assert_eq!(report.reps_per_task_arm, 1);
        assert_eq!(report.expected_runs, 240);
        assert_eq!(report.budget.run_token_ceiling, FULL_TOKEN_CEILING / 2);
        assert!(
            report
                .class_arm_table
                .iter()
                .all(|summary| summary.reps == 1)
        );
    }

    #[test]
    fn browse_memo_key_includes_judge_prompt_version() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::BrowseThenAnswer)
            .expect("browse task");
        let arm = ArmId::Fs;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let request_hash = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce, &RunSettings::default())
                .to_string()
                .as_bytes(),
        );

        assert_eq!(
            judge_cache_key(task).as_deref(),
            Some(BROWSE_JUDGE_PROMPT_VERSION)
        );
        assert_ne!(
            eval_memo_key(task, arm, 0, &nonce, &request_hash, None),
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        );
    }

    #[test]
    fn non_browse_memo_key_omits_judge_prompt_version() {
        let bundle = build_task_bundle();
        let task = bundle
            .full_tasks
            .iter()
            .find(|task| task.class == TaskClass::RetrievalQa)
            .expect("retrieval task");
        let arm = ArmId::Sdk;
        let context = arm_context(arm, task, &bundle.fixture).expect("context");
        let messages = vec![
            chat_message("system", shared_system_prompt(arm)),
            chat_message("user", eval_user_prompt(task, &context)),
        ];
        let nonce = request_nonce(task, arm, 0);
        let request_hash = blake3_hex(
            openrouter_request_body(&messages, 900, &nonce, &RunSettings::default())
                .to_string()
                .as_bytes(),
        );

        assert_eq!(judge_cache_key(task), None);
        assert_eq!(
            eval_memo_key(task, arm, 0, &nonce, &request_hash, None),
            eval_memo_key(
                task,
                arm,
                0,
                &nonce,
                &request_hash,
                judge_cache_key(task).as_deref(),
            )
        );
    }
}
