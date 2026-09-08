//! Judge and cost tests.

use super::*;

#[cfg(test)]
pub(crate) mod tests {
    use super::super::tests_community_eval004::tests::find_arm;
    use super::super::*;
    use oneiron::ContextPack;
    use oneiron::PackStats;
    use oneiron::context_pack::PackItemAccounting;
    use sha2::Digest;
    use sha2::Sha256;
    use std::collections::BTreeSet;

    #[test]
    fn report_records_real_query_tokens_target_tokens_and_cost_boundaries() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let deterministic = find_arm(&report, ArmKind::Deterministic);
        let ArmOutcome::Completed { context_pack } = &deterministic.outcome else {
            panic!("deterministic arm should complete");
        };
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic_competitor = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert_eq!(
            context_pack.query_cost.input_tokens,
            oneiron::count_context_pack_tokens("BEAM deterministic context pack") as u64
        );
        assert_eq!(
            context_pack.query_cost.tokenizer_id.as_deref(),
            Some(oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID)
        );
        assert_eq!(
            context_pack.query_cost.output_tokens,
            context_pack.serialized_tokens
        );
        assert_eq!(
            context_pack.query_cost.target_tokens,
            BEAM_128K_TOKEN_BUDGET as u64
        );
        assert_eq!(
            deterministic_competitor["costs"]["query"]["tokenSource"],
            "tokenizer_count"
        );
        assert_eq!(
            deterministic_competitor["costs"]["query"]["elapsedUs"],
            context_pack.query_cost.elapsed_us
        );
        assert_eq!(
            deterministic_competitor["costs"]["offline"]["tokenSource"],
            "fixture_declared_zero"
        );
        assert_eq!(
            deterministic_competitor["costs"]["judge"]["tokenSource"],
            "fixture_declared_zero"
        );
        assert_eq!(deterministic_competitor["costs"]["totalCostUsd"], 0.0);
        assert!(
            deterministic_competitor["costs"]["query"]["elapsedUs"]
                .as_u64()
                .expect("elapsedUs is u64")
                > 0
        );
    }

    #[test]
    fn query_cost_elapsed_uses_serialized_pass_only() {
        let case = FixtureCase {
            ppr_vad_query: None,
            case_id: "elapsed_boundary".to_owned(),
            query: "BEAM deterministic context pack".to_owned(),
            limit: 1,
            token_budget: 128,
            expected_min_results: 0,
            pending_vector_count: 0,
            query_embedding: None,
            fixture_class: FixtureClass::EvidenceSupported,
            temporal_search: None,
            temporal_evidence_ids: Vec::new(),
            opposing_evidence: None,
            offline_amortized_cost: CostComponentInput::default(),
        };
        let pack = BudgetedContextPack {
            raw: ContextPack {
                retrieval_quality: Default::default(),
                results: Vec::new(),
                neighbors: Vec::new(),
                stats: PackStats {
                    candidates_considered: 0,
                    signals_used: Vec::new(),
                    query_time_us: 11,
                    entities_hydrated: 0,
                    neighbors_hydrated: 0,
                    cosine_ghosts_dampened: 0,
                    claims_suppressed: 0,
                    tokens: oneiron::PackTokenStats::default(),
                    items_truncated: PackItemAccounting::item_budget(),
                    items_dropped: PackItemAccounting::token_budget(),
                },
                empty: None,
            },
            serialized: Vec::new(),
            serialized_tokens: 7,
            serialized_stats: PackStats {
                candidates_considered: 0,
                signals_used: Vec::new(),
                query_time_us: 11,
                entities_hydrated: 0,
                neighbors_hydrated: 0,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                tokens: oneiron::PackTokenStats {
                    tokenizer_id: oneiron::DEFAULT_CONTEXT_PACK_TOKENIZER_ID.to_owned(),
                    total_tokens: 7,
                    sections: Vec::new(),
                    items: Vec::new(),
                },
                items_truncated: PackItemAccounting::item_budget(),
                items_dropped: PackItemAccounting::token_budget(),
            },
            serialized_elapsed_us: 13,
            serialized_ids: SerializedContextPackIds::default(),
            temporal_result_ids: BTreeSet::new(),
        };

        let report = query_cost_report(&case, &pack);

        assert_eq!(report.elapsed_us, 13);
    }

    #[test]
    fn report_arm_outcome_payload_uses_camel_case_fields() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let arms = report_json["cases"][0]["arms"]
            .as_array()
            .expect("arms array");
        let deterministic = arms
            .iter()
            .find(|arm| arm["arm"] == "deterministic")
            .expect("deterministic arm");
        let agentic = arms
            .iter()
            .find(|arm| arm["arm"] == "agentic")
            .expect("agentic arm");

        assert!(deterministic["outcome"].get("contextPack").is_some());
        assert!(deterministic["outcome"].get("context_pack").is_none());
        assert!(agentic["outcome"].get("notReady").is_some());
        assert!(agentic["outcome"].get("not_ready").is_none());
    }

    #[test]
    fn report_records_scorer_version_and_public_parity_status() {
        let report = run_builtin_smoke().expect("BEAM smoke report");
        let report_json = serde_json::to_value(&report).expect("report serializes");
        let competitors = report_json["cases"][0]["competitors"]
            .as_array()
            .expect("competitors array");
        let deterministic = competitors
            .iter()
            .find(|competitor| competitor["competitorId"] == "deterministic-context-pack")
            .expect("deterministic competitor");

        assert_eq!(report_json["scorer"]["version"], BEAM_SCORER_VERSION);
        assert_eq!(deterministic["card"]["publicParityStatus"], "fixture_only");
        assert_eq!(
            deterministic["scoring"]["scorerVersion"],
            BEAM_SCORER_VERSION
        );
        assert!(
            deterministic["scoring"]["abilities"]
                .as_array()
                .expect("abilities array")
                .iter()
                .any(|ability| ability["ability"] == "retrieval_coverage")
        );
    }

    #[test]
    fn manifest_rejects_char_count_token_estimates_for_scored_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["tokenAccounting"]["source"] =
            serde_json::json!("char_count_estimate");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("char-count token estimates must be rejected");

        assert!(
            err.to_string()
                .contains("model-scored competitor rows must not use char_count_estimate")
        );
    }

    #[test]
    fn manifest_requires_token_accounting_for_completed_rows() {
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]
            .as_object_mut()
            .expect("card object")
            .remove("tokenAccounting");
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("completed rows must declare token accounting");

        assert!(
            err.to_string()
                .contains("completed competitor rows must declare tokenAccounting")
        );
    }

    #[test]
    fn manifest_rejects_non_tokenizer_accounting_for_deterministic_rows() {
        for source in ["provider_usage", "fixture_declared_zero", "not_applicable"] {
            let mut manifest_json: serde_json::Value =
                serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
            manifest_json["competitors"][0]["card"]["tokenAccounting"]["source"] =
                serde_json::json!(source);
            let err = parse_manifest_json(&manifest_json.to_string())
                .expect_err("deterministic rows must use tokenizer_count accounting");

            assert!(
                err.to_string()
                    .contains("completed competitor rows must declare tokenizer_count")
            );
        }
    }

    #[test]
    fn majority_of_three() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Verdict {
            Keep,
            Discard,
            Revise,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum JudgeCallFailed {
            Timeout,
            Refusal,
        }

        for votes in [
            [Verdict::Keep, Verdict::Keep, Verdict::Discard],
            [Verdict::Keep, Verdict::Discard, Verdict::Keep],
            [Verdict::Discard, Verdict::Keep, Verdict::Keep],
        ] {
            let mut calls = Vec::new();
            let decision = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
                calls.push(index);
                Ok(votes[index])
            })
            .expect("two agreeing votes decide the judgment");

            assert_eq!(calls, vec![0, 1, 2]);
            assert_eq!(decision.verdict, Verdict::Keep);
            assert_eq!(decision.vote_count, 2);
        }

        let mut calls = Vec::new();
        let decision = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            Ok(Verdict::Keep)
        })
        .expect("unanimous votes decide the judgment");

        // The first two votes already agree; the third call still happens and the tally is the
        // winning verdict's, not the number of attempted calls.
        assert_eq!(calls, vec![0, 1, 2]);
        assert_eq!(decision.verdict, Verdict::Keep);
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            Ok([Verdict::Keep, Verdict::Discard, Verdict::Revise][index])
        })
        .expect_err("three distinct verdicts cannot reach a majority");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::Tie { votes } => {
                assert_eq!(votes, [Verdict::Keep, Verdict::Discard, Verdict::Revise]);
            }
            MajorityVoteError::CallFailures { attempts } => {
                panic!("expected a typed tie, got call failures {attempts:?}")
            }
        }

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            if index == 1 {
                Err(JudgeCallFailed::Refusal)
            } else {
                Ok(Verdict::Keep)
            }
        })
        .expect_err("a failed call emits no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Ok(Verdict::Keep));
                assert_eq!(attempts[1], Err(JudgeCallFailed::Refusal));
                assert_eq!(attempts[2], Ok(Verdict::Keep));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }

        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            match index {
                0 => Err(JudgeCallFailed::Timeout),
                1 => Ok(Verdict::Discard),
                _ => Err(JudgeCallFailed::Refusal),
            }
        })
        .expect_err("multiple failed calls emit no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Err(JudgeCallFailed::Timeout));
                assert_eq!(attempts[1], Ok(Verdict::Discard));
                assert_eq!(attempts[2], Err(JudgeCallFailed::Refusal));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }

        // A failure at index 0 does not short-circuit: indices 1 and 2 still run, their real
        // outcomes are carried back, and their agreement is not promoted to a verdict.
        let mut calls = Vec::new();
        let error = super::majority_of_three::<Verdict, JudgeCallFailed, _>(|index| {
            calls.push(index);
            if index == 0 {
                Err(JudgeCallFailed::Timeout)
            } else {
                Ok(Verdict::Keep)
            }
        })
        .expect_err("a failed first call emits no verdict");

        assert_eq!(calls, vec![0, 1, 2]);
        match error {
            MajorityVoteError::CallFailures { attempts } => {
                assert_eq!(attempts[0], Err(JudgeCallFailed::Timeout));
                assert_eq!(attempts[1], Ok(Verdict::Keep));
                assert_eq!(attempts[2], Ok(Verdict::Keep));
            }
            MajorityVoteError::Tie { votes } => {
                panic!("expected typed call failures, got a tie {votes:?}")
            }
        }
    }

    #[test]
    fn answer_prompt_pinned_on_card() {
        fn majority_card(prompt: &str) -> JudgeMetadata {
            JudgeMetadata {
                judge_id: "beam-llm-judge".to_owned(),
                version: "v1".to_owned(),
                notes: "Three-vote LLM judgment; answer prompt pinned.".to_owned(),
                answer_prompt: Some(AnswerPromptPin::from_exact_text(prompt)),
                vote_count: 3,
            }
        }

        fn assert_card_rejected(card: &JudgeMetadata, prompt: &str) {
            let mut calls = 0_usize;
            let error = run_majority_judge_card::<&str, &str, _>(card, prompt, |_| {
                calls += 1;
                Ok("keep")
            })
            .expect_err("an invalid majority card is rejected before any judge call");

            assert_eq!(calls, 0);
            match error {
                MajorityJudgeError::Card(BeamError::JudgeCardInvalid { .. }) => {}
                other => panic!("expected a typed card rejection, got {other:?}"),
            }
        }

        let prompt = "Answer the question.\n\n  Cite each claim as [id].\n";
        let card = majority_card(prompt);
        let mut hasher = Sha256::new();
        hasher.update(prompt.as_bytes());
        let expected_digest = hex_lower(&hasher.finalize());

        let card_json = serde_json::to_value(&card).expect("judge metadata serializes");
        assert_eq!(card_json["voteCount"], 3);
        assert_eq!(card_json["answerPrompt"]["content"], prompt);
        assert_eq!(card_json["answerPrompt"]["sha256"], expected_digest);

        let restored: JudgeMetadata =
            serde_json::from_value(card_json).expect("judge metadata round-trips");
        assert_eq!(restored, card);

        let mut calls = Vec::new();
        let decision = run_majority_judge_card::<&str, &str, _>(&card, prompt, |index| {
            calls.push(index);
            Ok("keep")
        })
        .expect("the pinned prompt admits the judgment");

        assert_eq!(calls, vec![0, 1, 2]);
        assert_eq!(decision.verdict, "keep");
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);

        // One byte of drift is a different answer prompt.
        assert_card_rejected(&card, &format!("{prompt} "));

        let mut empty_pin = card.clone();
        empty_pin.answer_prompt = Some(AnswerPromptPin::from_exact_text(""));
        assert_card_rejected(&empty_pin, "");

        let mut malformed_digest = card.clone();
        malformed_digest.answer_prompt = Some(AnswerPromptPin {
            content: prompt.to_owned(),
            sha256: "not-a-sha256-digest".to_owned(),
        });
        assert_card_rejected(&malformed_digest, prompt);

        let mut wrong_digest = card.clone();
        wrong_digest.answer_prompt = Some(AnswerPromptPin {
            content: prompt.to_owned(),
            sha256: AnswerPromptPin::from_exact_text("another prompt").sha256,
        });
        assert_card_rejected(&wrong_digest, prompt);

        let mut missing_pin = card.clone();
        missing_pin.answer_prompt = None;
        assert_card_rejected(&missing_pin, prompt);

        for vote_count in [0_u8, 1, 2, 4] {
            let mut wrong_votes = card.clone();
            wrong_votes.vote_count = vote_count;
            assert_card_rejected(&wrong_votes, prompt);
        }

        // Existing fixed-scorer fixture cards stay non-LLM, single-vote cards.
        let manifest = parse_manifest_json(BUILTIN_MANIFEST_JSON).expect("manifest parses");
        let competitor = &manifest.competitors[0];
        let fixture_card = competitor.card.as_ref().expect("carded competitor");
        assert_eq!(fixture_card.judge.answer_prompt, None);
        assert_eq!(fixture_card.judge.vote_count, single_judge_vote());

        // The generic gate rejects vote-count-three cards without a valid pin even though
        // `run_majority_judge_card` is never invoked for them.
        let mut manifest_json: serde_json::Value =
            serde_json::from_str(BUILTIN_MANIFEST_JSON).expect("manifest JSON");
        manifest_json["competitors"][0]["card"]["judge"]["voteCount"] = serde_json::json!(3);
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("three-vote cards must pin the answer prompt");
        assert!(matches!(err, BeamError::InvalidManifest { .. }));

        manifest_json["competitors"][0]["card"]["judge"]["answerPrompt"] = serde_json::json!({
            "content": prompt,
            "sha256": "not-a-sha256-digest"
        });
        let err = parse_manifest_json(&manifest_json.to_string())
            .expect_err("three-vote cards must pin a well-formed digest");
        assert!(matches!(err, BeamError::InvalidManifest { .. }));

        manifest_json["competitors"][0]["card"]["judge"]["answerPrompt"] = serde_json::json!({
            "content": prompt,
            "sha256": expected_digest
        });
        parse_manifest_json(&manifest_json.to_string())
            .expect("a three-vote card with a valid pin is accepted");

        for vote_count in [0, 2, 4] {
            manifest_json["competitors"][0]["card"]["judge"]["voteCount"] =
                serde_json::json!(vote_count);
            let err = parse_manifest_json(&manifest_json.to_string())
                .expect_err("only single-vote and majority-vote cards are accepted");
            assert!(matches!(err, BeamError::InvalidManifest { .. }));
        }
    }

    #[test]
    fn dial481_confound_regression() {
        // The judge identity, version, and instructions are held fixed across both cards; only the
        // answer-generation prompt moves, which is the confound this regression pins down.
        fn majority_card(prompt: &str) -> JudgeMetadata {
            JudgeMetadata {
                judge_id: "beam-llm-judge".to_owned(),
                version: "v1".to_owned(),
                notes: "Score only grounded claims; ignore style.".to_owned(),
                answer_prompt: Some(AnswerPromptPin::from_exact_text(prompt)),
                vote_count: 3,
            }
        }

        let item = "beam_128k_context_pack_smoke";
        let candidate = "Enterprise renewals drove the revenue increase.";
        let prompt_a = "Answer strictly from the retrieved context.\n";
        let prompt_b = "Answer from the retrieved context, then add a summary.\n";

        let card_a = majority_card(prompt_a);
        let card_b = majority_card(prompt_b);
        let json_a = serde_json::to_value(&card_a).expect("card A serializes");
        let json_b = serde_json::to_value(&card_b).expect("card B serializes");

        assert_ne!(card_a.answer_prompt, card_b.answer_prompt);
        assert_ne!(json_a, json_b);
        assert_eq!(card_a.judge_id, card_b.judge_id);
        assert_eq!(card_a.version, card_b.version);
        assert_eq!(card_a.notes, card_b.notes);

        let mut calls = Vec::new();
        let error = run_majority_judge_card::<&str, &str, _>(&card_a, prompt_b, |index| {
            calls.push((index, item, candidate));
            Ok("keep")
        })
        .expect_err("a card pinned to prompt A cannot judge a prompt B generation");

        // No comparison or scored result can be emitted behind a stale answer-prompt pin.
        assert!(calls.is_empty());
        match error {
            MajorityJudgeError::Card(BeamError::JudgeCardInvalid { .. }) => {}
            other => panic!("expected a typed card rejection, got {other:?}"),
        }

        // The stale card is not repaired in place; it still pins prompt A and stays ineligible.
        let pin_a = AnswerPromptPin::from_exact_text(prompt_a);
        assert_eq!(card_a.answer_prompt, Some(pin_a));
        assert!(card_a.require_majority_vote_card(prompt_b).is_err());
        assert!(card_a.require_majority_vote_card(prompt_a).is_ok());

        // Eligibility returns only by rebuilding the card from prompt B.
        let mut calls = Vec::new();
        let decision = run_majority_judge_card::<&str, &str, _>(&card_b, prompt_b, |index| {
            calls.push((index, item, candidate));
            Ok("keep")
        })
        .expect("the rebuilt card admits the judgment");

        assert_eq!(calls.len(), JUDGE_VOTE_COUNT);
        assert_eq!(calls[0], (0, item, candidate));
        assert_eq!(calls[1], (1, item, candidate));
        assert_eq!(calls[2], (2, item, candidate));
        assert_eq!(decision.verdict, "keep");
        assert_eq!(decision.vote_count, JUDGE_VOTE_COUNT);
    }

    #[test]
    fn fixture_rejects_char_count_offline_amortized_cost_accounting() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
            serde_json::json!("char_count_estimate");
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("char-count offline cost token estimates must be rejected");

        assert!(
            err.to_string()
                .contains("case offlineAmortizedCost must not use char_count_estimate")
        );
    }

    #[test]
    fn fixture_rejects_nonzero_metrics_for_zero_offline_cost_sources() {
        for source in ["fixture_declared_zero", "not_applicable"] {
            let mut fixture_json: serde_json::Value =
                serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
            fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
                serde_json::json!(source);
            fixture_json["cases"][0]["offlineAmortizedCost"]["inputTokens"] = serde_json::json!(1);
            let err = parse_fixture_json(&fixture_json.to_string())
                .expect_err("zero-source offline costs must have zero metrics");

            assert!(
                err.to_string()
                    .contains("must declare zero tokens, elapsed time, and cost")
            );
        }
    }

    #[test]
    fn fixture_rejects_costs_too_large_to_normalize() {
        let mut fixture_json: serde_json::Value =
            serde_json::from_str(BUILTIN_FIXTURE_JSON).expect("fixture JSON");
        fixture_json["cases"][0]["offlineAmortizedCost"]["tokenSource"] =
            serde_json::json!("provider_usage");
        fixture_json["cases"][0]["offlineAmortizedCost"]["costUsd"] = serde_json::json!(f64::MAX);
        let err = parse_fixture_json(&fixture_json.to_string())
            .expect_err("overflowing normalization boundary must be rejected");

        assert!(
            err.to_string()
                .contains("case offlineAmortizedCost.costUsd is too large to normalize safely")
        );
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

        for competitor_id in ["backbone-solo", "agentic-adapter", "chat-adapter"] {
            let competitor = competitors
                .iter()
                .find(|competitor| competitor["competitorId"] == competitor_id)
                .expect("not-ready competitor");
            assert!(competitor["scoring"]["overallScore"].is_null());

            let abilities = competitor["scoring"]["abilities"]
                .as_array()
                .expect("abilities array");
            assert_eq!(abilities.len(), 3);
            for ability in abilities {
                assert!(ability["score"].is_null());
                assert!(ability["passed"].is_null());
                assert!(
                    ability["detail"]
                        .as_str()
                        .expect("detail string")
                        .contains("could not be scored")
                );
            }
        }
    }
}
