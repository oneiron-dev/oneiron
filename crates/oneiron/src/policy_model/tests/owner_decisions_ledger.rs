//! Owner-plane decisions: exactly-one-row ledger, category/row-ref rules, block/help, notices and receipts.

use super::*;

#[test]
fn a_bare_classify_then_the_enforce_door_leaves_exactly_one_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x94), &spoiler_manifest("block"))?;
    let request = PolicyClassifyRequest::outbound_content("a reply with spoilers");

    let verdict = vault.classify_policy_model(request.clone())?;
    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    let after_classify = gate_receipts(&vault)?;
    assert_eq!(
        after_classify.len(),
        1,
        "the door that MADE the decision writes its row"
    );
    assert_eq!(after_classify[0].outcome, "owner_plane_block");
    assert!(has_trace(&after_classify[0], "gate.policy_model.block"));

    // The enforce door records nothing: the decision is already in the ledger.
    let outcome = vault.enforce_policy_model_verdict(
        request,
        &PolicyModelConfig::default(),
        verdict,
        false,
    )?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert_eq!(outcome.receipt_ref, None);
    assert_eq!(
        gate_receipts(&vault)?.len(),
        1,
        "one decision, one row — not two under two outcomes"
    );
    Ok(())
}

#[test]
fn a_bare_classify_of_an_inert_clean_allow_writes_nothing() -> Result<()> {
    // The silence rule is the enforcement path's, unchanged: an allow that
    // learned nothing has nothing to tell anyone.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x95), &spoiler_manifest("block"))?;

    let verdict =
        vault.classify_policy_model(PolicyClassifyRequest::outbound_content(CLEAN_CONTENT))?;

    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(verdict.audit.is_none());
    assert!(gate_receipts(&vault)?.is_empty());
    Ok(())
}

#[test]
fn a_bare_classify_whose_model_did_not_answer_still_receipts_the_fail_open() -> Result<()> {
    // The verdict a downed model produces is exactly the one the silence rule
    // drops: a clean allow that learned nothing. But it is the SOVEREIGN PLANE
    // FALLING OPEN, and content shipped because nothing looked at it is the
    // fact the owner is most owed. No pattern here, so nothing else would
    // carry it either.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x99),
        &documented_owner_manifest(
            vec![owner_row("owner:jargon", "Avoid nautical jargon.")],
            Vec::new(),
        ),
    )?;

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(CLEAN_CONTENT),
        &PolicyModelConfig::default(),
        &FailingPolicyBackend,
        &lease("bare-classify-fail-open"),
    ))?;

    assert_eq!(verdict.decision, PolicyClassifyDecision::Allow);
    assert!(
        verdict.audit.is_none(),
        "nothing was learned — which is precisely why the silence rule would have dropped it"
    );
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1, "the fail-open is recorded, not silent");
    assert!(has_trace(&receipts[0], "gate.policy_model.model_skipped"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.owner_plane_fail_open"
    ));
    Ok(())
}

/// The byte bound stops the JOIN, not just the parse.
///
/// `parse_model_answer` bounds the text it is handed — but `response_text`
/// builds that text from every part first, so a backend returning many parts
/// paid the whole allocation before the parser ever looked. A bound checked
/// after the string exists is a semantic bound wearing a memory bound's name.
///
/// Driven at `response_text` directly, because the two bounds are
/// INDISTINGUISHABLE from outside: with the join bound removed the parser
/// still refuses the same body and the relay still degrades identically. What
/// differs is whether the allocation happened, and only this seam can see it.
/// The end-to-end version of this test passed with the fix removed.
#[test]
fn a_flood_of_response_parts_is_stopped_while_joining() {
    // Each part is small and perfectly legal alone; only the SUM passes the
    // bound, which is the case a per-part check would miss.
    let part = "x".repeat(4096);
    let parts = (super::contract::POLICY_MODEL_ANSWER_PARSE_MAX_BYTES / 4096) + 2;
    let content: Vec<ContentPart> = (0..parts)
        .map(|_| ContentPart::Text { text: part.clone() })
        .collect();
    assert!(
        super::prompt::response_text(&multi_part_response(content)).is_none(),
        "the join gives up rather than building a string the parser will only reject"
    );

    // A multi-part answer that FITS still joins, so this is a flood stop and
    // not a new one-part contract.
    let ordinary = vec![
        ContentPart::Text {
            text: r#"{"violation":0,"#.to_owned(),
        },
        ContentPart::Text {
            text: r#""policy_category":null}"#.to_owned(),
        },
    ];
    assert_eq!(
        super::prompt::response_text(&multi_part_response(ordinary)).as_deref(),
        Some(r#"{"violation":0,"policy_category":null}"#),
        "parts still join into one answer"
    );
}

/// A shared category label names the concern, not one row, so it resolves to
/// the row that GOVERNS it — the first registered — rather than whichever row
/// the map happened to write last.
#[test]
fn a_shared_category_canonicalizes_to_the_governing_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let policy = HostedLegalPolicy {
        output_contract: Some(PolicyOutputContract::RationaleJson),
        rows: vec![
            hosted_row(
                "hosted:first",
                "serious_crime",
                HostedLegalAction::Block,
                "Withhold credible facilitation of serious violence.",
            ),
            hosted_row(
                "hosted:second",
                "serious_crime",
                HostedLegalAction::Block,
                "Withhold credible facilitation of mass harm.",
            ),
        ],
        ..hosted_serious_crime_block()
    };
    // Cites the shared label and BOTH row refs: three citations naming two
    // rows, one of which is named twice.
    let backend = static_backend(
        r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["serious_crime","hosted:first","hosted:second"],"confidence":"high","rationale":"why"}"#,
    );
    let budget = lease("shared-category");
    let pass = relay_pass(
        &vault,
        BOMB_CONTENT,
        &hosted_edge_registry(policy),
        &PolicyModelConfig::default(),
        Some(tier(&backend, &budget)),
    )?;

    let audit = pass
        .boundary_verdict()
        .expect("hosted pass")
        .audit
        .as_deref()
        .expect("audit");
    assert_eq!(
        audit.model_rule_ids,
        vec!["serious_crime".to_owned(), "hosted:second".to_owned()],
        "the shared label resolves to the FIRST row, so citing it and \
         `hosted:first` is one rule; `hosted:second` is the other"
    );
    Ok(())
}

/// A `row_ref` the notice layer cannot carry is refused at REGISTRATION.
///
/// `safe_notice_row_ref` drops an over-long ref and lets the verdict stand, so
/// accepting one here buys a host notices that cannot say which of its rows
/// acted. Registration is the moment that is visible and fixable.
/// A `row_ref` that spells another row's CATEGORY is refused at registration.
///
/// Citations resolve through one map keyed by spelling, and a hosted row is
/// citable under its ref, its bare category and its qualified category. If one
/// row's ref equals another row's alias the two meanings collide there and the
/// ref wins — so a citation of the CONCERN canonicalizes to an unrelated row.
/// That is a misattribution in the audit, not a lost citation, which is the
/// worse of the two failures.
#[test]
fn a_row_ref_that_spells_another_rows_category_is_refused_at_registration() {
    for colliding_ref in ["serious_crime", "hosted_legal/serious_crime"] {
        let mut registry = fixture_edge_service_registry();
        let err = registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                hosted_policy(vec![
                    hosted_row(
                        "hosted:governing",
                        "serious_crime",
                        HostedLegalAction::Block,
                        "Withhold credible facilitation of serious violence.",
                    ),
                    hosted_row(
                        colliding_ref,
                        "other_concern",
                        HostedLegalAction::Warn,
                        "An unrelated row whose REF spells the other row's concern.",
                    ),
                ]),
            )
            .expect_err("a ref that spells a category must be refused");
        assert!(
            format!("{err}").contains("row_ref"),
            "unexpected error for {colliding_ref:?}: {err}"
        );
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
    }

    // A row citable under its own category is the ordinary case and still
    // registers — the rule is about one row's ref spelling ANOTHER's concern.
    let mut registry = fixture_edge_service_registry();
    registry
        .register_hosted_legal_policy(HOSTED_EDGE_SERVICE, hosted_serious_crime_block())
        .expect("the ordinary shape is untouched");
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());

    // And a row whose ref IS its own category is not ambiguous at all: both
    // spellings name that one row, which is what the map should record. The
    // first version of this check refused it, which rejected the most natural
    // way to write a single-concern row.
    for self_ref in ["serious_crime", "hosted_legal/serious_crime"] {
        let mut registry = fixture_edge_service_registry();
        registry
            .register_hosted_legal_policy(
                HOSTED_EDGE_SERVICE,
                hosted_policy(vec![hosted_row(
                    self_ref,
                    "serious_crime",
                    HostedLegalAction::Block,
                    "Withhold credible facilitation of serious violence.",
                )]),
            )
            .unwrap_or_else(|err| panic!("a row may spell its OWN category ({self_ref:?}): {err}"));
        assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_some());
    }
}

#[test]
fn a_row_ref_longer_than_a_notice_can_carry_is_refused_at_registration() {
    let mut registry = fixture_edge_service_registry();
    let long_ref = format!("hosted:{}", "x".repeat(GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN));
    let err = registry
        .register_hosted_legal_policy(
            HOSTED_EDGE_SERVICE,
            hosted_policy(vec![hosted_row(
                &long_ref,
                "serious_crime",
                HostedLegalAction::Block,
                "Withhold facilitation of mass harm.",
            )]),
        )
        .expect_err("a ref no notice could carry must be refused");
    assert!(
        format!("{err}").contains("row_ref"),
        "unexpected error: {err}"
    );
    assert!(registry.hosted_legal_policy(HOSTED_EDGE_IDENTITY).is_none());
}

/// An answer larger than the engine agreed to read is refused BEFORE
/// deserialization, not after.
///
/// The rule-id count bound runs on a value `serde_json` has already built, so
/// it is a semantic bound and not a memory one. This bound runs on the raw
/// text, which is the only place a body the engine never agreed to hold can
/// still be stopped.
///
/// Driven at the PARSER rather than through a relay pass on purpose. A body
/// big enough to matter is refused by the relay for other reasons too, so an
/// end-to-end test here would pass with the bound removed and prove nothing —
/// which is exactly the trap that let two guards ship this round believing
/// they were covered.
#[test]
fn an_answer_past_the_byte_bound_is_unreadable_rather_than_deserialized() {
    let bound = super::contract::POLICY_MODEL_ANSWER_PARSE_MAX_BYTES;
    // Valid JSON that WOULD parse: an over-long rationale is truncated, not
    // refused, so nothing but the byte bound can stop this one.
    let rationale = "x".repeat(bound);
    let flood = format!(
        r#"{{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["serious_crime"],"confidence":"high","rationale":"{rationale}"}}"#
    );
    assert!(flood.len() > bound);
    let refused = super::contract::parse_model_answer(
        super::contract::PolicyOutputContract::RationaleJson,
        &flood,
    );
    assert!(
        refused.is_err(),
        "a body past the bound is refused before serde sees it"
    );

    // And an answer of the same SHAPE that fits still reads, so the bound is a
    // flood stop and not a new contract.
    let ordinary = r#"{"violation":1,"policy_category":"hosted_legal/serious_crime","rule_ids":["serious_crime"],"confidence":"high","rationale":"step-by-step instructions"}"#;
    assert!(
        super::contract::parse_model_answer(
            super::contract::PolicyOutputContract::RationaleJson,
            ordinary,
        )
        .is_ok(),
        "an honest answer is orders of magnitude below the bound"
    );
}

/// The owner plane re-checks its frontier in the receipt transaction, and
/// FAILS OPEN when it moved.
///
/// Same window F107 closed on the relay: the verdict binds a frontier and the
/// row is written later. The answer differs by plane. The hosted plane is
/// fail-closed, so it degrades and halts. This plane is sovereign — the caller
/// already has its verdict and has acted on it — so a concurrent manifest edit
/// must not retroactively overturn it. The row is written either way; it just
/// carries the frontier it can actually reproduce, and says the frontier moved.
///
/// The manifest moves DURING the model call, which is the window an owner
/// editing a row lands in. The seed uses the id the moving backend rewrites,
/// so the frontier moves rather than a second manifest appearing beside it.
#[test]
fn a_bare_classify_row_records_a_frontier_that_moved_without_degrading() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x48), &spoilers_manifest("block"))?;
    let backend = ManifestMovingBackend {
        vault: &vault,
        manifest: spoilers_manifest("warn"),
        body: r#"{"violation":1,"policy_category":"owner:spoilers"}"#,
        keep_moving: false,
        calls: AtomicUsize::new(0),
    };
    let budget = lease("owner-frontier-recheck");

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content(CLEAN_CONTENT),
        &PolicyModelConfig::default(),
        &backend,
        &budget,
    ))?;

    // FAIL OPEN: the caller keeps the answer its own policy gave. A manifest
    // edit landing mid-call does not retroactively overturn it.
    assert_ne!(verdict.decision, PolicyClassifyDecision::Allow);

    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert!(
        has_trace(&receipts[0], "gate.policy_model.owner_plane_frontier_moved"),
        "the row says the frontier moved rather than asserting a dead one: {:?}",
        receipts[0]
    );
    Ok(())
}

#[test]
fn a_bare_model_classify_records_the_row_its_verdict_carries() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        test_id(0x96),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:jargon",
                "Avoid nautical jargon.",
                "block",
            )],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);

    let verdict = block_on(vault.classify_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &lease("bare-model-classify"),
    ))?;

    assert_eq!(verdict.decision, PolicyClassifyDecision::Block);
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].outcome, "owner_plane_block");
    // Which dial produced the decision. These rows are newly written by the
    // bare doors, so a consumer has no other place to learn whether the model
    // was consulted for everything or only behind a pattern — and the two say
    // different things about what was NOT examined.
    assert!(
        has_trace(
            &receipts[0],
            "gate.policy_model.owner_plane.classifier_mode.classify_all"
        ),
        "the bare row names the owner dial it was decided under: {:?}",
        receipts[0]
    );
    Ok(())
}

#[test]
fn the_classify_and_enforce_doors_still_leave_exactly_one_row() -> Result<()> {
    // The guard against putting the receipt in a shared pass: both enforce
    // entries build their verdict the same way the bare doors do, and both
    // record at enforcement. Neither may pick up a second row.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x97), &spoiler_manifest("block"))?;

    let outcome =
        vault.enforce_policy_model(PolicyClassifyRequest::outbound_content("spoilers ahead"))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.receipt_ref.is_some());
    assert_eq!(gate_receipts(&vault)?.len(), 1, "no-model enforce entry");

    let (_tmp2, vault2) = temp_vault();
    put_policy_manifest_bytes(
        &vault2,
        test_id(0x98),
        &documented_owner_manifest(
            vec![owner_row_with_action(
                "owner:jargon",
                "Avoid nautical jargon.",
                "block",
            )],
            Vec::new(),
        ),
    )?;
    let backend = static_backend(r#"{"violation":1,"policy_category":"owner:jargon"}"#);
    let outcome = block_on(vault2.enforce_policy_model_with_backend(
        PolicyClassifyRequest::outbound_content("This answer uses nautical phrasing."),
        &PolicyModelConfig::default(),
        &backend,
        &lease("enforce-with-backend-one-row"),
    ))?;
    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.receipt_ref.is_some());
    assert_eq!(gate_receipts(&vault2)?.len(), 1, "with-model enforce entry");
    Ok(())
}

#[test]
fn owner_block_withholds_and_names_the_owner_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x34), &spoiler_manifest("block"))?;

    let outcome = vault.enforce_policy_model(
        PolicyClassifyRequest::outbound_content("a reply with spoilers")
            .with_caller_ref("agent:relay"),
    )?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.outbound_halted);
    assert!(outcome.pre_display_block);
    assert_eq!(outcome.final_content, None);
    assert_eq!(
        outcome.verdict.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    assert_eq!(
        outcome.barge_in_kill,
        Some(PolicyBargeInKill {
            cancel_tts: true,
            flush_playout_buffer: true,
            cancel_llm: true
        })
    );

    let reader_notices: Vec<_> = outcome
        .system_notices
        .iter()
        .filter(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
        .collect();
    assert_eq!(reader_notices.len(), 1);
    let notice = reader_notices[0];
    assert_eq!(notice.notice_type, SYSTEM_NOTICE_TYPE_BLOCK);
    assert_eq!(
        notice.policy_plane.as_deref(),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert_eq!(notice.row_ref.as_deref(), Some("owner:spoilers"));
    assert!(notice.body.contains("owner:spoilers"));

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = gate_receipts(&vault)?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].receipt_id, receipt_ref);
    assert_eq!(receipts[0].outcome, "block");
    assert_eq!(receipts[0].actor.as_deref(), Some("agent:relay"));
    assert!(has_trace(&receipts[0], "gate.policy_model.block"));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.plane.owner_policy"
    ));
    // The rule that fired is named, and the role it acted in.
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_matched.owner.spoilers"
    ));
    assert!(has_trace(
        &receipts[0],
        "gate.policy_model.pattern_role.decide"
    ));
    Ok(())
}

#[test]
fn owner_route_to_help_halts_with_a_help_card() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x35), &spoiler_manifest("route_to_help"))?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::RouteToHelp);
    assert!(outcome.outbound_halted);
    assert_eq!(outcome.final_content, None);
    let routing = outcome.help_routing.expect("help routing");
    assert_eq!(
        routing.category,
        PolicyVerdictCategory::OwnerPolicy {
            row_ref: "owner:spoilers".to_owned()
        }
    );
    assert_eq!(routing.diagnosis, None);
    assert!(routing.persona_present);
    assert_eq!(
        outcome.system_notices[0].notice_type,
        SYSTEM_NOTICE_TYPE_HELP_CARD
    );
    assert_eq!(
        outcome.system_notice.as_deref(),
        Some(POLICY_MODEL_HELP_CARD_NOTICE)
    );
    assert!(outcome.receipt_ref.is_some());
    Ok(())
}

#[test]
fn every_notice_is_system_voiced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x36), &spoiler_manifest("block"))?;
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    assert_eq!(outcome.notice_voice, Some(PolicyEnforcementVoice::System));
    assert!(
        outcome
            .system_notices
            .iter()
            .all(|notice| notice.voice == SYSTEM_NOTICE_VOICE_SYSTEM)
    );
    Ok(())
}

#[test]
fn notice_names_the_row_but_never_quotes_its_text_or_the_pattern() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let row_text = "Withhold anything mentioning the unreleased product name.";
    put_policy_manifest_bytes(
        &vault,
        test_id(0x37),
        &patterned_owner_manifest(
            vec![owner_row_with_action("owner:embargo", row_text, "block")],
            vec![owner_pattern(
                "owner.embargo",
                "(?i)unreleased",
                "owner:embargo",
                Some("decide"),
            )],
        ),
    )?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "the unreleased thing ships in March",
    ))?;

    // One notice, one body, both readers: the model is told exactly what the
    // person is told. What neither gets is the row's prose or the rule's source.
    assert_eq!(outcome.system_notices.len(), 1);
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.audience, SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL);
    assert!(notice.body.contains("owner:embargo"));
    assert!(!notice.body.contains(row_text));
    assert!(!notice.body.contains("(?i)unreleased"));
    let receipts = gate_receipts(&vault)?;
    assert!(
        !receipts[0]
            .policy_trace
            .iter()
            .any(|trace| trace.contains("(?i)")),
        "a receipt must never carry the pattern source"
    );
    Ok(())
}

#[test]
fn receipt_carries_the_notice_and_its_plane() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x38), &spoiler_manifest("block"))?;
    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    let receipt_ref = outcome.receipt_ref.expect("block receipt");
    let receipts = gate_receipts(&vault)?;
    let receipt = receipts
        .iter()
        .find(|receipt| receipt.receipt_id == receipt_ref)
        .expect("block gate receipt");
    assert_eq!(
        receipt.fields.get("system_notice_type").map(String::as_str),
        Some(SYSTEM_NOTICE_TYPE_BLOCK)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_channel")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_CHANNEL)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_audience")
            .map(String::as_str),
        Some(SYSTEM_NOTICE_AUDIENCE_USER_AND_MODEL)
    );
    assert_eq!(
        receipt
            .fields
            .get("system_notice_policy_plane")
            .map(String::as_str),
        Some(PolicyPlane::OwnerPolicy.as_str())
    );
    assert!(has_trace(receipt, "gate.system_notice.policy_block"));
    Ok(())
}

#[test]
fn owner_notice_carries_only_the_configured_setting_change_offer() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x39), &spoiler_manifest("block"))?;
    let request = || PolicyClassifyRequest::outbound_content("a reply with spoilers");

    // The engine knows no product routes, so it offers none by default.
    let bare = vault.enforce_policy_model(request())?;
    assert!(bare.system_notices[0].setting_change_offer.is_none());

    let offer = GateSystemNoticeAction {
        label: "Change policy setting".to_owned(),
        target: "https://host.example.test/settings/policy".to_owned(),
    };
    let configured = vault.enforce_policy_model_with_config(
        request(),
        &PolicyModelConfig {
            owner_setting_change_offer: Some(offer.clone()),
            ..PolicyModelConfig::default()
        },
    )?;
    assert_eq!(
        configured.system_notices[0].setting_change_offer.as_ref(),
        Some(&offer)
    );
    Ok(())
}

#[test]
fn an_unusable_setting_change_offer_is_dropped_not_fatal() -> Result<()> {
    // `owner_setting_change_offer` is a plain `pub` field: nothing validates
    // it before it is copied into every owner notice, and the ledger's own
    // check runs at APPEND. A broken convenience LINK would therefore fail the
    // whole gate write and lose the block it was attached to. It is dropped
    // instead, exactly as an oversized row ref is.
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(&vault, test_id(0x3b), &spoiler_manifest("block"))?;
    for offer in [
        GateSystemNoticeAction {
            label: "   ".to_owned(),
            target: "https://host.example.test/settings/policy".to_owned(),
        },
        GateSystemNoticeAction {
            label: "Change policy setting".to_owned(),
            target: String::new(),
        },
        GateSystemNoticeAction {
            label: "l".repeat(GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN + 1),
            target: "https://host.example.test/settings/policy".to_owned(),
        },
        GateSystemNoticeAction {
            label: "Change policy setting".to_owned(),
            target: format!(
                "https://host.example.test/{}",
                "t".repeat(GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN)
            ),
        },
    ] {
        let outcome = vault.enforce_policy_model_with_config(
            PolicyClassifyRequest::outbound_content("a reply with spoilers"),
            &PolicyModelConfig {
                owner_setting_change_offer: Some(offer),
                ..PolicyModelConfig::default()
            },
        )?;
        // The verdict survives whole; only the affordance is gone.
        assert_eq!(outcome.action, PolicyEnforcementAction::Block);
        assert!(outcome.receipt_ref.is_some());
        assert!(outcome.system_notices[0].setting_change_offer.is_none());
    }
    Ok(())
}

#[test]
fn owner_notice_omits_oversized_row_ref_without_aborting_block() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let long_row_ref = format!("owner:{}", "x".repeat(GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN));
    put_policy_manifest_bytes(
        &vault,
        test_id(0x3a),
        &patterned_owner_manifest(
            vec![owner_row_with_action(
                &long_row_ref,
                "Withhold this oversized policy row.",
                "block",
            )],
            vec![owner_pattern(
                "owner.oversized",
                "(?i)spoiler",
                &long_row_ref,
                Some("decide"),
            )],
        ),
    )?;

    let outcome = vault.enforce_policy_model(PolicyClassifyRequest::outbound_content(
        "a reply with spoilers",
    ))?;

    assert_eq!(outcome.action, PolicyEnforcementAction::Block);
    assert!(outcome.receipt_ref.is_some());
    let notice = &outcome.system_notices[0];
    assert_eq!(notice.row_ref, None);
    assert!(!notice.body.contains(&long_row_ref));
    assert_eq!(notice.body, POLICY_MODEL_OWNER_BLOCK_NOTICE);
    Ok(())
}
