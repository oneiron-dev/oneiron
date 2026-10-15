//! Owner manifest trust: world scoping, forgery/misspelling fail-closed, bindings, generation params, staleness, owner model.

use super::*;
use crate::error::RelayError;

fn project_owner_row(row_ref: &str, text: &str, project_ref: &str) -> Value {
    let mut row = owner_row(row_ref, text);
    let Value::Map(ref mut fields) = row else {
        unreachable!()
    };
    fields.push((Value::from("project_ref"), Value::from(project_ref)));
    row
}

#[test]
fn project_pattern_verdict_uses_project_action_not_world_action() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut world_row = scoped_owner_row("owner:mode", "World action.", "work");
    let Value::Map(ref mut fields) = world_row else {
        unreachable!()
    };
    fields.push((Value::from("action"), Value::from("block")));
    let mut project_row = project_owner_row("owner:mode", "Project action.", "p-1");
    let Value::Map(ref mut fields) = project_row else {
        unreachable!()
    };
    fields.push((Value::from("action"), Value::from("route_to_help")));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x96),
        &patterned_owner_manifest(
            vec![
                owner_row("owner:mode", "Vault action."),
                world_row,
                project_row,
            ],
            vec![owner_pattern(
                "owner.mode",
                "review-needed",
                "owner:mode",
                Some("decide"),
            )],
        ),
    )?;
    let request = PolicyClassifyRequest::outbound_content("review-needed").with_world_ref("work");
    assert_eq!(
        vault.classify_policy_model(request.clone())?.decision,
        PolicyClassifyDecision::Block
    );
    assert_eq!(
        vault
            .classify_policy_model(request.with_project_ref("p-1"))?
            .decision,
        PolicyClassifyDecision::Block,
    );
    Ok(())
}

fn precedence_row(composition: &str) -> (Value, Value) {
    (
        Value::from("owner_policy_precedence"),
        Value::Map(vec![
            (Value::from("composition"), Value::from(composition)),
            (Value::from("vault_cap"), Value::Boolean(true)),
        ]),
    )
}

#[test]
fn manifest_precedence_switches_world_project_composition_but_never_relaxes_vault() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rows = vec![
        owner_row_with_action("owner:mode", "Vault cap.", "block"),
        scoped_owner_row("owner:mode", "World rule.", "work"),
        project_owner_row("owner:mode", "Project rule.", "p-1"),
    ];
    let manifest =
        |composition| documented_owner_manifest(rows.clone(), vec![precedence_row(composition)]);
    put_policy_manifest_bytes(
        &vault,
        gate::default_policy_manifest_id()?,
        &manifest("nested_narrowing"),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply")
        .with_world_ref("work")
        .with_project_ref("p-1");
    let policy = |vault: &Vault| -> Result<(String, crate::gate::OwnerRowAction)> {
        let txn = vault.store.env.read_txn()?;
        let resolved = gate::resolve_policy_manifest(&vault.store, &txn)?;
        let row = resolved
            .active_owner_policy_rows_for_scope(Some("work"), Some("p-1"))
            .into_iter()
            .find(|row| row.row_ref == "owner:mode")
            .expect("owner row");
        Ok((row.text, row.action))
    };
    assert_eq!(
        policy(&vault)?,
        (
            "Vault cap.\nWorld rule.\nProject rule.".into(),
            crate::gate::OwnerRowAction::Block
        )
    );
    let prompt = vault.policy_model_prompt(&request)?.expect("owner prompt");
    assert_eq!(
        prompt.rubric_rows[0].text,
        "Vault cap.\nWorld rule.\nProject rule."
    );
    let nested_hash = gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
        .read_frontier_hash()?;
    put_policy_manifest_bytes(
        &vault,
        gate::default_policy_manifest_id()?,
        &manifest("most_specific_vault_capped"),
    )?;
    assert_eq!(
        policy(&vault)?,
        (
            "Vault cap.\nProject rule.".into(),
            crate::gate::OwnerRowAction::Block
        )
    );
    assert_ne!(
        nested_hash,
        gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?
            .read_frontier_hash()?
    );
    assert_eq!(
        vault
            .policy_model_prompt(&request)?
            .expect("owner prompt")
            .rubric_rows[0]
            .text,
        "Vault cap.\nProject rule."
    );
    let mut combined = project_owner_row("owner:mode", "World-project rule.", "p-1");
    let Value::Map(ref mut fields) = combined else {
        unreachable!()
    };
    fields.push((Value::from("world_ref"), Value::from("work")));
    let mut combined_rows = rows;
    combined_rows.push(combined);
    put_policy_manifest_bytes(
        &vault,
        gate::default_policy_manifest_id()?,
        &documented_owner_manifest(
            combined_rows,
            vec![precedence_row("most_specific_vault_capped")],
        ),
    )?;
    assert_eq!(
        policy(&vault)?,
        (
            "Vault cap.\nWorld-project rule.".into(),
            crate::gate::OwnerRowAction::Block
        )
    );
    Ok(())
}

#[test]
fn malformed_precedence_fails_closed_instead_of_selecting_project() -> Result<()> {
    for bad in [
        Value::Map(vec![
            (
                Value::from("composition"),
                Value::from("most_specific_vault_capped"),
            ),
            (Value::from("vault_cap"), Value::Boolean(false)),
        ]),
        Value::Map(vec![
            (Value::from("composition"), Value::from("invalid")),
            (Value::from("vault_cap"), Value::Boolean(true)),
        ]),
    ] {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            test_id(0x98),
            &documented_owner_manifest(
                vec![
                    owner_row("owner:mode", "Vault."),
                    project_owner_row("owner:mode", "Project.", "p-1"),
                ],
                vec![(Value::from("owner_policy_precedence"), bad)],
            ),
        )?;
        let txn = vault.store.env.read_txn()?;
        let resolved = gate::resolve_policy_manifest(&vault.store, &txn)?;
        assert!(resolved.is_fail_closed());
        assert!(
            resolved
                .active_owner_policy_rows_for_scope(None, Some("p-1"))
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn same_ref_and_project_in_one_manifest_drops_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x91),
        &enabled_owner_manifest(vec![
            project_owner_row("owner:mode", "First.", "p-1"),
            project_owner_row("owner:mode", "Second.", "p-1"),
        ]),
    )?;
    let err = vault
        .classify_policy_model(
            PolicyClassifyRequest::outbound_content("reply").with_project_ref("p-1"),
        )
        .expect_err("duplicate project row must not silently shadow");
    assert!(matches!(
        err,
        Error::Relay(RelayError::PolicyManifestInvalid {
            field: "owner_policy_rows",
            ..
        })
    ));
    Ok(())
}

#[test]
fn same_ref_and_project_across_manifests_drops_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    for (id, text) in [(0x92, "First."), (0x93, "Second.")] {
        put_policy_manifest_bytes(
            &vault,
            test_id(id),
            &enabled_owner_manifest(vec![project_owner_row("owner:mode", text, "p-1")]),
        )?;
    }
    let rtxn = vault.store.env.read_txn()?;
    let policy = gate::resolve_policy_manifest(&vault.store, &rtxn)?;
    assert!(policy.owner_policy_rows_dropped());
    assert!(
        policy
            .active_owner_policy_rows_for_scope(None, Some("p-1"))
            .is_empty()
    );
    Ok(())
}

#[test]
fn malformed_project_scope_drops_rows_instead_of_widening_them() -> Result<()> {
    for invalid in [Value::Nil, Value::from(""), Value::from(37)] {
        let (_tmp, vault) = temp_vault();
        let mut row = owner_row("owner:mode", "Never widen into vault scope.");
        let Value::Map(ref mut fields) = row else {
            unreachable!()
        };
        fields.push((Value::from("project_ref"), invalid));
        put_policy_manifest_bytes(&vault, test_id(0x94), &enabled_owner_manifest(vec![row]))?;
        let err = vault
            .classify_policy_model(PolicyClassifyRequest::outbound_content("reply"))
            .expect_err("invalid project ref must not create vault-wide row");
        assert!(matches!(
            err,
            Error::Relay(RelayError::PolicyManifestInvalid {
                field: "owner_policy_rows",
                ..
            })
        ));
    }
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
    let other_caller = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("fixture-content-one-1574")
            .with_caller_ref("unrelated-person"),
    )?;
    assert_eq!(head.binding.content_hash, other_caller.binding.content_hash);

    let world = vault.classify_policy_model(
        PolicyClassifyRequest::outbound_content("fixture-content-one-1574")
            .with_world_ref("world-a"),
    )?;
    assert_ne!(world.binding.content_hash, [0; 32]);
    assert_ne!(head.binding.content_hash, world.binding.content_hash);
    Ok(())
}

#[test]
fn project_binding_changes_with_project_but_not_caller() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let plain = PolicyClassifyRequest::outbound_content("identical reply");
    let first = plain.clone().with_project_ref("p-1");
    let second = plain.clone().with_project_ref("p-2");
    let plain_binding = vault.classify_policy_model(plain)?.binding;
    let first_binding = vault.classify_policy_model(first.clone())?.binding;
    let second_binding = vault.classify_policy_model(second)?.binding;
    assert_ne!(first_binding.content_hash, plain_binding.content_hash);
    assert_ne!(first_binding.content_hash, second_binding.content_hash);
    assert_eq!(
        first_binding.read_frontier_hash,
        plain_binding.read_frontier_hash
    );
    assert_eq!(
        first_binding,
        vault
            .classify_policy_model(first.with_caller_ref("different"))?
            .binding
    );
    Ok(())
}

#[test]
fn project_scope_changes_policy_frontier_even_when_not_selected() -> Result<()> {
    let (_plain_tmp, plain_vault) = temp_vault();
    let (_scoped_tmp, scoped_vault) = temp_vault();
    put_policy_manifest_bytes(
        &plain_vault,
        test_id(0x95),
        &enabled_owner_manifest(vec![owner_row("owner:mode", "Vault mode.")]),
    )?;
    put_policy_manifest_bytes(
        &scoped_vault,
        test_id(0x95),
        &enabled_owner_manifest(vec![project_owner_row("owner:mode", "Vault mode.", "p-1")]),
    )?;
    let request = PolicyClassifyRequest::outbound_content("ordinary reply");
    let plain = plain_vault.classify_policy_model(request.clone())?;
    let scoped = scoped_vault.classify_policy_model(request)?;
    assert_ne!(
        plain.binding.read_frontier_hash,
        scoped.binding.read_frontier_hash
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
