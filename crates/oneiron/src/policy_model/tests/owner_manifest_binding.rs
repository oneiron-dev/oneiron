//! Owner manifest trust: world scoping, forgery/misspelling fail-closed, bindings, generation params, staleness, owner model.

use super::*;
use crate::error::RelayError;

#[test]
fn reads_vault_manifest_not_caller_config() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3b),
        &documented_owner_manifest(
            vec![owner_row(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
            )],
            Vec::new(),
        ),
    )?;

    let prompt = vault
        .policy_model_prompt(&PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers for the ending.",
        ))?
        .expect("a documented plane produces a prompt");
    // The system message is the owner's document, verbatim and nothing else.
    assert_eq!(prompt.system, OWNER_DOCUMENT);
    assert_eq!(prompt.user, "This reply contains spoilers for the ending.");
    // The rows travel alongside so an answer can be routed, not as prompt text.
    assert_eq!(prompt.rubric_rows.len(), 1);
    assert_eq!(prompt.rubric_rows[0].row_ref, "owner:spoilers");
    assert_eq!(
        prompt.rubric_rows[0].text,
        "Avoid spoilers in outbound content."
    );
    assert!(
        !prompt
            .system
            .contains("Avoid spoilers in outbound content.")
    );
    Ok(())
}

#[test]
fn active_owner_rows_resolve_scoped_world_override() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3c),
        &documented_owner_manifest(
            vec![
                owner_row("owner:mode", "Avoid formal language."),
                scoped_owner_row("owner:mode", "Avoid casual language.", "work"),
            ],
            Vec::new(),
        ),
    )?;

    let prompt = vault
        .policy_model_prompt(
            &PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work"),
        )?
        .expect("prompt");
    let texts: Vec<&str> = prompt
        .rubric_rows
        .iter()
        .map(|row| row.text.as_str())
        .collect();
    assert!(texts.contains(&"Avoid casual language."));
    assert!(!texts.contains(&"Avoid formal language."));
    Ok(())
}

#[test]
fn unknown_owner_manifest_action_drops_the_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3d),
        &enabled_owner_manifest(vec![owner_row_with_action(
            "owner:bad-action",
            "Malformed owner action.",
            "reword_retry",
        )]),
    )?;

    let classify_err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("ordinary reply"))
        .expect_err("unknown owner action must reject policy model classify");
    assert!(
        matches!(
            classify_err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_rows",
                ..
            })
        ),
        "unexpected error: {classify_err}"
    );
    Ok(())
}

#[test]
fn forged_owner_rows_reject_classify_on_an_enabled_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3e),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            (
                Value::from(gate::POLICY_OWNER_POLICY_ROWS_KEY),
                Value::Map(vec![(Value::from("not"), Value::from("rows"))]),
            ),
        ]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers.",
        ))
        .expect_err("dropped owner-policy rows must reject classify");
    assert!(
        matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_rows",
                ..
            })
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn a_misspelled_owner_row_key_fails_the_plane_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // `acton` is not `action`. Ignoring it would silently demote a Block row
    // to the gentle Warn default, so the whole table is dropped instead.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x60),
        &enabled_owner_manifest(vec![owner_row_with_unknown_key(
            "owner:spoilers",
            "Avoid spoilers in outbound content.",
            "acton",
            "block",
        )]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content(
            "This reply contains spoilers.",
        ))
        .expect_err("an unknown owner-row key must never be ignored");
    assert!(
        matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_rows",
                ..
            })
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn a_misspelled_owner_pattern_key_fails_the_plane_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x64),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:spoilers", "Avoid spoilers.")]),
            owner_patterns(vec![Value::Map(vec![
                (Value::from("id"), Value::from("owner.spoilers")),
                (Value::from("pattern"), Value::from("(?i)spoiler")),
                (Value::from("category"), Value::from("owner:spoilers")),
                // `rol` is not `role`: silently defaulting it would change what
                // the rule is allowed to do.
                (Value::from("rol"), Value::from("decide")),
            ])]),
        ]),
    )?;

    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("an unknown pattern key must never be ignored");
    assert!(
        matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_patterns",
                ..
            })
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_pattern_naming_no_row_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x65),
        &patterned_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            vec![owner_pattern(
                "owner.invented",
                "(?i)spoiler",
                "owner:invented",
                Some("decide"),
            )],
        ),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("a rule naming no row must be refused");
    assert!(
        matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "pattern_rule_category",
                reason: "names a category this plane does not publish"
            })
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_pattern_that_does_not_compile_is_a_configuration_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x66),
        &patterned_owner_manifest(
            vec![owner_row("owner:spoilers", "Avoid spoilers.")],
            vec![owner_pattern(
                "owner.broken",
                "spoiler(",
                "owner:spoilers",
                None,
            )],
        ),
    )?;
    let err = vault
        .classify_policy_model(PolicyClassifyRequest::outbound_content("a spoiler"))
        .expect_err("an uncompilable rule must be refused");
    assert!(
        matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "pattern_rule_pattern",
                reason: "is not a valid regular expression"
            })
        ),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn an_owner_rule_scoped_out_of_this_world_is_matched_but_cannot_act() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The rule names a row that only exists in the `work` world. In any other
    // world the row is not in play, so the rule is recorded and inert.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x67),
        &patterned_owner_manifest(
            vec![scoped_owner_row(
                "owner:work-only",
                "Avoid spoilers at work.",
                "work",
            )],
            vec![owner_pattern(
                "owner.work-only",
                "(?i)spoiler",
                "owner:work-only",
                Some("decide"),
            )],
        ),
    )?;

    let elsewhere = vault.classify_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;
    assert_eq!(elsewhere.decision, PolicyClassifyDecision::Allow);
    let audit = elsewhere.audit.as_deref().expect("the match is recorded");
    assert_eq!(
        audit.matched_pattern_ids,
        vec!["owner.work-only".to_owned()]
    );
    assert_eq!(audit.acting_pattern_role, None);

    let at_work = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("a reply with spoilers").with_world_ref("work"),
    )?;
    assert_eq!(at_work.decision, PolicyClassifyDecision::Warn);
    Ok(())
}

#[test]
fn content_binding_excludes_identity_fields_but_binds_world() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("fixture-content-one-1574");
    let head = vault.classify_policy_model(request)?;
    assert_eq!(
        bytes_to_hex_lower(&head.binding.content_hash),
        "c33efbed3117a75cddf884f2211386e24acd6e9461a56401347aa51f8050874b"
    );

    let world = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("fixture-content-one-1574")
            .with_world_ref("world-a"),
    )?;
    assert_eq!(
        bytes_to_hex_lower(&world.binding.content_hash),
        "607a705418c8d31127fd7310a228a036a5c7560a442d00f788c7a71ea04df65f"
    );
    assert_ne!(head.binding.content_hash, world.binding.content_hash);
    Ok(())
}

#[test]
fn persona_independent_verdict() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x3f), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");
    let first = vault.classify_policy_model(request.clone().with_caller_ref("companion"))?;
    let second = vault.classify_policy_model(request.with_caller_ref("cli-agent"))?;
    assert_eq!(first.decision, second.decision);
    assert_eq!(first.category, second.category);
    assert_eq!(first.binding, second.binding);
    Ok(())
}

#[test]
fn safeguard_model_binding_swappable() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x72),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let llm_request = |config: &PolicyModelConfig| -> Result<LlmRequest> {
        Ok(vault
            .policy_model_llm_request(&request, config)?
            .expect("a documented plane produces a request"))
    };

    let default_request = llm_request(&PolicyModelConfig::default())?;
    assert_eq!(
        default_request.envelope.tier.resolved().as_str(),
        "gpt-oss-safeguard-20b"
    );
    assert_eq!(
        default_request.model.as_str(),
        "oneiron/gpt-oss-safeguard-20b@default"
    );

    for (selector, tier, model) in [
        (
            "openrouter:meta/llama-guard-4",
            "openrouter:meta/llama-guard-4",
            "openrouter/meta.llama-guard-4@configured",
        ),
        (
            "endpoint:https://guard.local/v1",
            "endpoint:https://guard.local/v1",
            "endpoint/guard.local.v1@configured",
        ),
        (
            "on-device:qwen3guard-stream-0.6b",
            "on-device:qwen3guard-stream-0.6b",
            "on-device/qwen3guard-stream-0.6b@configured",
        ),
    ] {
        let config = PolicyModelConfig {
            safeguard_binding: SafeguardModelBinding::parse(selector).expect("binding parses"),
            ..PolicyModelConfig::default()
        };
        let built = llm_request(&config)?;
        assert_eq!(built.envelope.tier.resolved().as_str(), tier);
        assert_eq!(built.model.as_str(), model);
    }
    Ok(())
}

#[test]
fn generation_parameters_are_configuration_not_engine_constants() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x48),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");

    // The default sends no output cap at all — a reasoning safeguard model
    // needs room to think before it answers.
    let default_params = vault
        .policy_model_llm_request(&request, &PolicyModelConfig::default())?
        .expect("request")
        .params;
    assert!(!default_params.contains_key("max_output_tokens"));
    assert_eq!(
        default_params
            .get("reasoning_effort")
            .map(ToString::to_string),
        Some("\"medium\"".to_owned())
    );
    assert_eq!(
        default_params.get("temperature").map(ToString::to_string),
        Some("0.0".to_owned())
    );

    let tuned = PolicyModelConfig {
        generation: PolicyGenerationParams {
            reasoning_effort: PolicyReasoningEffort::High,
            temperature: 0.25,
            max_output_tokens: Some(4096),
        },
        ..PolicyModelConfig::default()
    };
    let tuned_params = vault
        .policy_model_llm_request(&request, &tuned)?
        .expect("request")
        .params;
    assert_eq!(
        tuned_params
            .get("reasoning_effort")
            .map(ToString::to_string),
        Some("\"high\"".to_owned())
    );
    assert_eq!(
        tuned_params
            .get("max_output_tokens")
            .map(ToString::to_string),
        Some("4096".to_owned())
    );
    Ok(())
}

#[test]
fn a_plane_never_ships_another_planes_vocabulary() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x63),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;

    let request = vault
        .policy_model_llm_request(
            &PolicyClassifyRequest::outbound_content("ordinary reply"),
            &PolicyModelConfig::default(),
        )?
        .expect("request");
    let rendered = serde_json::to_string(&request.envelope.response_format)
        .expect("response format serializes");
    assert!(
        !rendered.contains("hosted_legal"),
        "a local owner-plane vault must not be handed the hosted legal \
         vocabulary; schema was: {rendered}"
    );
    assert!(rendered.contains("owner:jargon"));

    // The hosted relay rubric DOES carry it — that plane is the whole reason
    // the vocabulary exists — and carries only the categories ITS policy
    // publishes.
    let hosted_policy = hosted_serious_crime_block();
    let hosted_prompt = super::prompt::render_classify_prompt(
        &PolicyClassifyRequest::outbound_content("ordinary reply"),
        &hosted_policy.policy_document,
        hosted_rubric_rows(&hosted_policy),
        PolicyOutputContract::CategoryJson,
    );
    let hosted_rendered = serde_json::to_string(
        &hosted_prompt
            .llm_request(&PolicyModelConfig::default())
            .envelope
            .response_format,
    )
    .expect("response format serializes");
    assert!(hosted_rendered.contains(HOSTED_SERIOUS_CRIME_LABEL));
    assert!(!hosted_rendered.contains("hosted_legal/ncii"));
    assert!(!hosted_rendered.contains("owner:jargon"));
    Ok(())
}

#[test]
fn verdict_stale_on_policy_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    put_policy_manifest_bytes(
        &vault,
        test_id(0x40),
        &enabled_owner_manifest(vec![owner_row("owner:ordinary", "Avoid ordinary wording.")]),
    )?;
    assert!(vault.policy_model_verdict_is_stale(&verdict, &request)?);
    Ok(())
}

#[test]
fn a_disabled_plane_never_reports_a_stale_verdict() -> Result<()> {
    // The binding covers the WHOLE manifest frontier, so an edit the disabled
    // plane can never act on used to report its clean allow as stale — and the
    // caller would re-derive its way back to the identical clean allow. A
    // plane that decides nothing has nothing that can go out of date.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![owner_row("owner:jargon", "Avoid jargon.")]),
        ]),
    )?;
    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    // The manifest moves — new rows, a document, a whole new frontier — and
    // the plane stays off.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &base_policy_manifest(vec![
            owner_policy_enabled(false),
            owner_rows(vec![
                owner_row("owner:jargon", "Avoid jargon, firmly."),
                owner_row_with_action("owner:spoilers", "Block spoilers.", "block"),
            ]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
        ]),
    )?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);
    Ok(())
}

#[test]
fn a_verdict_minted_while_the_plane_was_on_is_stale_once_it_is_off() -> Result<()> {
    // The opt-OUT transition. A disabled plane returns the inert clean allow
    // and nothing else, so a `Block` in a caller's hand was decided while the
    // plane was ON. Reading it fresh after the owner switched the plane off
    // would let a rule they retired keep blocking their own content — the
    // sovereignty violation this predicate exists to catch.
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("This reply contains spoilers.");
    let live = vec![
        owner_policy_enabled(true),
        owner_rows(vec![owner_row_with_action(
            "owner:spoilers",
            "Avoid spoilers.",
            "block",
        )]),
        owner_patterns(vec![owner_pattern(
            "owner.spoilers",
            "(?i)spoiler",
            "owner:spoilers",
            Some("decide"),
        )]),
    ];
    put_policy_manifest_bytes(&vault, test_id(0x4b), &base_policy_manifest(live.clone()))?;
    let blocked = vault.classify_policy_model(request.clone())?;
    assert_eq!(blocked.decision, PolicyClassifyDecision::Block);
    assert!(!vault.policy_model_verdict_is_stale(&blocked, &request)?);

    // Nothing about the rules changes; the owner just opts out.
    let mut opted_out = live;
    opted_out[0] = owner_policy_enabled(false);
    put_policy_manifest_bytes(&vault, test_id(0x4b), &base_policy_manifest(opted_out))?;
    assert!(
        vault.policy_model_verdict_is_stale(&blocked, &request)?,
        "a block minted by a live plane must not survive the owner turning it off",
    );

    // The clean allow the disabled plane itself produces is still fresh: it is
    // exactly what re-deriving would return, so reporting it stale would only
    // send the caller round a loop.
    let inert = vault.classify_policy_model(request.clone())?;
    assert_eq!(inert.decision, PolicyClassifyDecision::Allow);
    assert!(!vault.policy_model_verdict_is_stale(&inert, &request)?);
    Ok(())
}

#[test]
fn verdict_stale_when_the_owner_document_changes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &documented_owner_manifest(vec![owner_row("owner:jargon", "Avoid jargon.")], Vec::new()),
    )?;
    let verdict = vault.classify_policy_model(request.clone())?;
    assert!(!vault.policy_model_verdict_is_stale(&verdict, &request)?);

    // One byte of the document is a different policy, and every verdict decided
    // under the old one is stale.
    let amended = format!("{OWNER_DOCUMENT}!");
    put_policy_manifest_bytes(
        &vault,
        test_id(0x41),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row("owner:jargon", "Avoid jargon.")]),
            owner_document(&amended),
            owner_contract("category_json"),
        ]),
    )?;
    assert!(vault.policy_model_verdict_is_stale(&verdict, &request)?);
    Ok(())
}

#[test]
fn verdict_stale_on_request_context_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let world_request =
        PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("work");
    let world_verdict = vault.classify_policy_model(world_request)?;
    let changed_world_request =
        PolicyClassifyRequest::outbound_content("ordinary reply").with_world_ref("personal");
    assert!(vault.policy_model_verdict_is_stale(&world_verdict, &changed_world_request)?);
    Ok(())
}

#[test]
fn verdict_stale_on_safeguard_selector_change() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let openrouter = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
        ..PolicyModelConfig::default()
    };
    let endpoint = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("endpoint:https://guard.local/v1")
            .expect("endpoint binding"),
        ..PolicyModelConfig::default()
    };

    let verdict = vault.classify_policy_model_with_config(request.clone(), &openrouter)?;
    assert!(!vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &openrouter)?);
    assert!(vault.policy_model_verdict_is_stale_with_config(&verdict, &request, &endpoint)?);
    Ok(())
}

#[test]
fn owner_row_verdict_from_the_model_binds_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x71),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);
    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &lease("policy-owner-row"),
    ))?;
    // A row that names no action only asks to be told about.
    assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
    assert_eq!(
        verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:jargon".to_owned()
        }
    );
    assert_eq!(verdict.plane(), Some(PolicyPlane::OwnerPolicy));
    Ok(())
}

#[test]
fn the_row_decides_the_action_not_the_model() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // The model says "violation"; the ROW says what a violation of it costs.
    // There is no channel for a model to pick `Block` over a `Warn` row.
    put_policy_manifest_bytes(
        &vault,
        test_id(0x43),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:jargon",
                "Avoid nautical jargon.",
                "warn",
            )],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);
    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("row-decides"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Warn);
    Ok(())
}

#[test]
fn an_owner_answer_naming_no_row_fails_the_plane_open() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x44),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:invented"}"#);

    // Sovereign plane: an unusable answer never blocks, it just means the plane
    // did not run.
    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &PolicyModelConfig::default(),
        &backend,
        &lease("policy-invented-row"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert!(outcome.custom_tier_skipped);
    Ok(())
}

#[test]
fn backend_request_model_uses_configured_safeguard_selector() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x45),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;
    let backend = RecordingPolicyBackend::new(r#"{"violation":0,"policy_category":null}"#);
    let config = PolicyModelConfig {
        safeguard_binding: SafeguardModelBinding::parse("openrouter:meta/llama-guard-4")
            .expect("openrouter binding"),
        ..PolicyModelConfig::default()
    };

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("ordinary reply"),
        &config,
        &backend,
        &lease("policy-selector-routing"),
    ))?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert_eq!(
        backend.seen_model.lock().expect("seen model").as_deref(),
        Some("openrouter/meta.llama-guard-4@configured")
    );
    // What the model was SENT is the owner's document, with nothing prepended.
    assert_eq!(
        backend.seen_system.lock().expect("seen system").as_deref(),
        Some(OWNER_DOCUMENT)
    );
    Ok(())
}

#[test]
fn model_down_skips_the_owner_plane_and_ships_the_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x46),
        &documented_owner_manifest(
            vec![owner_row(
                "owner:spoilers",
                "Avoid spoilers in outbound content.",
            )],
            Vec::new(),
        ),
    )?;

    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &lease("policy-model-down"),
    ))?;

    // Nothing exists beneath the owner plane to fall back to, so a downed
    // safeguard model means the plane did not run — marked, not hidden.
    assert_eq!(outcome.action, PolicyEnforcementAction::Allow);
    assert!(outcome.custom_tier_skipped);
    assert_eq!(
        outcome.final_content.as_deref(),
        Some("This reply contains spoilers.")
    );
    Ok(())
}

#[test]
fn an_owner_decide_rule_still_verdicts_with_the_model_down() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x49),
        &base_policy_manifest(vec![
            owner_policy_enabled(true),
            owner_rows(vec![owner_row_with_action(
                "owner:spoilers",
                "Avoid spoilers.",
                "block",
            )]),
            owner_document(OWNER_DOCUMENT),
            owner_contract("category_json"),
            owner_patterns(vec![owner_pattern(
                "owner.spoilers",
                "(?i)spoiler",
                "owner:spoilers",
                Some("decide"),
            )]),
        ]),
    )?;

    let outcome = block_on(vault.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This reply contains spoilers."),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &lease("decide-during-outage"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(!outcome.custom_tier_skipped);
    Ok(())
}
