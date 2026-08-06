use super::*;

fn receipt() -> ReceiptRecord {
    ReceiptRecord {
        receipt_id: "gate:abc".to_owned(),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: 42,
        actor: Some("owner".to_owned()),
        on_behalf_of: Some("owner".to_owned()),
        outcome: "held".to_owned(),
        job_ref: None,
        trigger_ref: Some("brief:party".to_owned()),
        policy_trace: vec!["quiet_hours".to_owned()],
        fields: BTreeMap::new(),
    }
}

fn receipt_view() -> Result<Of336Component> {
    Ok(Of336Component::ReceiptView(ReceiptViewComponent::new(
        "receipt-view-1",
        receipt(),
        vec![
            ReceiptDeepLink::new(
                ReceiptDeepLinkKind::Brief,
                "brief:party",
                "Open brief",
                ViewTimeResolution::Active,
            )?,
            ReceiptDeepLink::new(
                ReceiptDeepLinkKind::Share,
                "share:revoked",
                "Open share",
                ViewTimeResolution::Revoked,
            )?,
        ],
    )?))
}

fn ask_card() -> Result<ConsentAskCard> {
    ConsentAskCard::new(
        "ask-1",
        "owner",
        "Want me to invite Yuki?",
        "Invite text preview",
        "invite",
        Vec::new(),
    )
    .map(|card| {
        card.with_counterparty_ref("contact:yuki")
            .with_channel("slack")
            .with_origin_receipt_ref("intent:invite-yuki")
    })
}

fn bundle_card() -> Result<BundleApproveCard> {
    BundleApproveCard::new(
        "bundle-1",
        "owner",
        "Party invite bundle",
        "brief:party",
        "invite",
        vec![
            BundleSendItem::new("send:1", "contact:yuki", "slack", "Invite Yuki")?,
            BundleSendItem::new("send:2", "contact:ren", "email", "Invite Ren")?,
        ],
        Vec::new(),
    )
}

fn authenticated_person(
    vault: &crate::Vault,
    seed: u8,
    principal_ref: &str,
) -> crate::consent::AuthenticatedOwner {
    let actor = crate::test_util::entity(seed);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            principal_ref.as_bytes(),
        )
        .expect("seed authenticated person");
    vault
        .authenticate_owner(
            actor,
            principal_ref,
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("authenticate person")
}

fn owner_context() -> (
    tempfile::TempDir,
    crate::Vault,
    crate::consent::AuthenticatedOwner,
) {
    let (dir, vault) =
        crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
    let owner = authenticated_person(&vault, 0x71, "owner");
    (dir, vault, owner)
}

fn evaluate_ask_action(
    card: &ConsentAskCard,
    request: &ConsentActionRequest,
) -> Result<ConsentActionEvaluation> {
    let (_dir, _vault, owner) = owner_context();
    card.evaluate_action(request, &owner)
}

fn evaluate_bundle_action(
    card: &BundleApproveCard,
    request: &ConsentActionRequest,
) -> Result<ConsentActionEvaluation> {
    let (_dir, _vault, owner) = owner_context();
    card.evaluate_action(request, &owner)
}

#[test]
fn rcpt3_components_render_for_all_three_adapters() -> Result<()> {
    let components = vec![
        receipt_view()?,
        Of336Component::ConsentAsk(ask_card()?),
        Of336Component::BundleApprove(bundle_card()?),
    ];
    let adapters = [
        Of336SurfaceAdapter::EiriSpecCareRegister,
        Of336SurfaceAdapter::DashboardAtomKitAudit,
        Of336SurfaceAdapter::McpUi,
    ];

    for component in &components {
        for adapter in adapters {
            let rendered = component.render(adapter)?;
            assert_eq!(rendered.protocol_version, OF336_PROTOCOL_VERSION);
            assert_eq!(rendered.adapter, adapter);
            assert_eq!(rendered.component_kind, component.kind());
            assert_eq!(rendered.component_id, component.component_id());
            assert!(!rendered.fallback_text.is_empty());
            assert!(!rendered.tree.is_null());
        }
    }

    Ok(())
}

#[test]
fn non_principal_shared_slack_approve_is_refused_at_the_door() -> Result<()> {
    let card = ask_card()?;
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "coworker".to_owned(),
        },
        ConsentSurface::SharedSlack,
        100,
    )?;

    assert_eq!(
        evaluate_ask_action(&card, &request)
            .expect_err("self-attested coworker must not reach evaluation")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    Ok(())
}

#[test]
fn escalator_selection_emits_grant_mint_intent() -> Result<()> {
    let card = ask_card()?;
    let request = ConsentActionRequest::new(
        "ask-1",
        "escalate_always_this_verb_class",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::EiriConversation,
        101,
    )?;

    let evaluation = evaluate_ask_action(&card, &request)?;
    assert_eq!(evaluation.decision, ConsentActionDecision::GrantMintIntent);
    let intent = evaluation
        .grant_mint_intent
        .expect("grant mint intent emitted");
    assert_eq!(intent.principal_ref, "owner");
    assert_eq!(
        intent.scope,
        GrantMintIntentScope::VerbClass {
            verb_class: "invite".to_owned()
        }
    );

    Ok(())
}

#[test]
fn beneficiary_cannot_confirm_always_this_verb_class() -> Result<()> {
    let card = ask_card()?.with_counterparty_ref("owner");
    let request = ConsentActionRequest::new(
        "ask-1",
        "escalate_always_this_verb_class",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::EiriConversation,
        102,
    )?;

    let evaluation = evaluate_ask_action(&card, &request)?;
    assert_eq!(
        evaluation.decision,
        ConsentActionDecision::NoopBeneficiaryConfirm
    );
    assert!(evaluation.grant_mint_intent.is_none());
    assert_eq!(evaluation.receipt.outcome, "no_op_beneficiary_confirm");
    assert_eq!(
        evaluation.receipt.fields.get("reason").map(String::as_str),
        Some("consent_beneficiary:self_grant")
    );
    assert!(
        evaluation
            .receipt
            .policy_trace
            .contains(&"consent_beneficiary:self_grant".to_owned())
    );

    Ok(())
}

#[test]
fn beneficiary_cannot_confirm_always_this_channel() -> Result<()> {
    let card = ask_card()?.with_counterparty_ref("owner");
    let request = ConsentActionRequest::new(
        "ask-1",
        "escalate_always_this_channel",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisChannel),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::Dashboard,
        103,
    )?;

    let evaluation = evaluate_ask_action(&card, &request)?;
    assert_eq!(
        evaluation.decision,
        ConsentActionDecision::NoopBeneficiaryConfirm
    );
    assert!(evaluation.grant_mint_intent.is_none());
    assert_eq!(evaluation.receipt.outcome, "no_op_beneficiary_confirm");
    assert_eq!(
        evaluation.receipt.fields.get("reason").map(String::as_str),
        Some("consent_beneficiary:self_grant")
    );
    assert!(
        evaluation
            .receipt
            .policy_trace
            .contains(&"consent_beneficiary:self_grant".to_owned())
    );

    Ok(())
}

#[test]
fn non_beneficiary_can_confirm_widening_scope() -> Result<()> {
    let card = ask_card()?;
    let request = ConsentActionRequest::new(
        "ask-1",
        "escalate_always_this_channel",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisChannel),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::McpUi,
        104,
    )?;

    let evaluation = evaluate_ask_action(&card, &request)?;
    assert_eq!(evaluation.decision, ConsentActionDecision::GrantMintIntent);
    assert_eq!(
        evaluation
            .grant_mint_intent
            .expect("grant mint intent emitted")
            .scope,
        GrantMintIntentScope::Channel {
            channel: "slack".to_owned()
        }
    );

    Ok(())
}

#[test]
fn bundle_scope_choice_emits_rcpt4_consumable_intent() -> Result<()> {
    let card = bundle_card()?;
    let request = ConsentActionRequest::new(
        "bundle-1",
        "approve_bundle_brief_verb_class",
        ConsentActionKind::BundleApprove(BundleApprovalScope::BriefVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::Dashboard,
        102,
    )?;

    let evaluation = evaluate_bundle_action(&card, &request)?;
    let intent = evaluation
        .grant_mint_intent
        .expect("bundle grant mint intent emitted");
    assert_eq!(
        intent.scope,
        GrantMintIntentScope::BriefVerbClass {
            brief_ref: "brief:party".to_owned(),
            verb_class: "invite".to_owned()
        }
    );

    Ok(())
}

#[test]
fn receipt_view_preserves_view_time_revoked_link_state() -> Result<()> {
    let component = match receipt_view()? {
        Of336Component::ReceiptView(component) => component,
        _ => unreachable!("fixture is receipt view"),
    };
    assert!(
        component
            .links
            .iter()
            .any(|link| link.resolution == ViewTimeResolution::Revoked)
    );
    assert!(component.fallback_text().contains("revoked"));

    Ok(())
}

#[test]
fn forged_typed_action_mismatch_is_rejected_before_grant_mint() -> Result<()> {
    let card = ask_card()?;
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Escalate(ConsentScopeEscalator::AlwaysThisVerbClass),
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::EiriConversation,
        103,
    )?;

    assert!(matches!(
        evaluate_ask_action(&card, &request),
        Err(Error::InvalidConfig(message))
            if message.contains("payload does not match declared typed action")
    ));

    Ok(())
}

#[test]
fn blank_principal_never_authenticates() {
    let (_dir, _vault, owner) = owner_context();
    assert!(
        !ConsentActorIdentity::SurfaceActor {
            actor_ref: String::new(),
        }
        .authenticates_owner("", &owner)
    );
    assert!(
        !ConsentActorIdentity::VoicePath {
            speaker_ref: String::new(),
            owner_voice_print_verified: true,
        }
        .authenticates_owner("", &owner)
    );
}

#[test]
fn voice_path_uses_store_authentication_not_the_request_boolean() -> Result<()> {
    let card = ask_card()?;
    let (_dir, vault, owner) = owner_context();
    let attacker = authenticated_person(&vault, 0x72, "attacker");
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::VoicePath {
            speaker_ref: "owner".to_owned(),
            owner_voice_print_verified: false,
        },
        ConsentSurface::Voice,
        103,
    )?;

    assert_eq!(
        card.evaluate_action(&request, &attacker)
            .expect_err("caller voice claim must not authenticate another principal")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    assert_eq!(
        card.evaluate_action(&request, &owner)?.decision,
        ConsentActionDecision::ApprovedOnce,
        "the host-authenticated owner handle is authority, not the request boolean"
    );
    Ok(())
}

#[test]
fn atom_kit_buttons_use_safe_self_ui_action_ids() -> Result<()> {
    let card = ask_card()?;
    let rendered =
        Of336Component::ConsentAsk(card).render(Of336SurfaceAdapter::DashboardAtomKitAudit)?;
    let text = serde_json::to_string(&rendered.tree).expect("rendered JSON");
    assert!(text.contains("consent_grant_mint"));
    assert!(!text.contains("javascript"));

    assert!(crate::lens::SelfUiOptionValue::new("just_once").is_ok());
    Ok(())
}

/// TARGET B pin: identical caller text is refused under the wrong authenticated
/// principal and succeeds only under the FIX2 store-resolved owner handle.
#[test]
fn principal_self_attestation_is_refused_and_store_authenticated_actor_succeeds() -> Result<()> {
    let card = ask_card()?;
    let (_dir, vault, owner) = owner_context();
    let attacker = authenticated_person(&vault, 0x72, "attacker");
    let request = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "owner".to_owned(),
        },
        ConsentSurface::EiriConversation,
        104,
    )?;

    assert_eq!(
        card.evaluate_action(&request, &attacker)
            .expect_err("self-attested owner text must not authenticate")
            .kind(),
        crate::error::ErrorKind::ConsentUnauthenticatedActor
    );
    assert_eq!(
        card.evaluate_action(&request, &owner)?.decision,
        ConsentActionDecision::ApprovedOnce,
        "the same actor text succeeds only with the store-authenticated owner"
    );
    Ok(())
}

/// FIX-9 stays pinned at the deserializer door: actor identity is a tagged
/// variant, never an untagged free-text claim.
#[test]
fn consent_actor_identity_pin_is_not_a_free_text_claim() {
    let untagged = serde_json::json!({
        "component_id": "ask-1",
        "action_id": "approve_once",
        "action": "approve",
        "actor": { "actor_ref": "owner" },
        "surface": "eiri_conversation",
        "occurred_at": 104
    });
    assert!(serde_json::from_value::<ConsentActionRequest>(untagged).is_err());

    let tagged = serde_json::json!({
        "component_id": "ask-1",
        "action_id": "approve_once",
        "action": "approve",
        "actor": { "identity": "surface_actor", "actor_ref": "owner" },
        "surface": "eiri_conversation",
        "occurred_at": 104
    });
    assert!(matches!(
        serde_json::from_value::<ConsentActionRequest>(tagged)
            .expect("tagged surface actor request"),
        ConsentActionRequest {
            actor: ConsentActorIdentity::SurfaceActor { actor_ref },
            ..
        } if actor_ref == "owner"
    ));
}

// ---------------------------------------------------------------------------
// ONE-1812 [BK-01] — the calendar grant-mint seam
// ---------------------------------------------------------------------------

#[test]
fn grant_mint_intent_calendar_sentence_is_bounded() {
    // "share my work calendar fully with Yura", already resolved upstream.
    let intent = calendar_grant_mint_intent(
        "person:yura",
        "consent-ask:calendar-share",
        "share_calendar",
        Some("gate:abc"),
        "calendar:work",
        DisclosureRung::Full,
    )
    .expect("one sentence mints one intent");

    assert_eq!(intent.principal_ref, "person:yura");
    assert_eq!(
        intent.scope,
        GrantMintIntentScope::Calendar {
            calendar_ref: "calendar:work".to_owned(),
            rung: DisclosureRung::Full,
        }
    );

    // Exactly one (calendar_ref, audience, rung) triple on the wire, and no
    // settings grid: the scope object carries three keys and nothing else.
    let json = serde_json::to_value(&intent).expect("serialize intent");
    let scope = json
        .get("scope")
        .expect("scope")
        .as_object()
        .expect("object");
    let mut keys: Vec<&str> = scope.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["calendar_ref", "rung", "scope"]);
    assert_eq!(scope.get("scope").and_then(Value::as_str), Some("calendar"));
    assert_eq!(scope.get("rung").and_then(Value::as_str), Some("full"));

    // Blank refs are rejected rather than minting an unbounded grant.
    for (principal, component, action, calendar) in [
        ("", "c", "a", "calendar:work"),
        ("person:yura", "  ", "a", "calendar:work"),
        ("person:yura", "c", "", "calendar:work"),
        ("person:yura", "c", "a", ""),
    ] {
        assert!(
            calendar_grant_mint_intent(
                principal,
                component,
                action,
                None,
                calendar,
                DisclosureRung::Busy
            )
            .is_err(),
            "blank ref must not mint a grant intent"
        );
    }
}

#[test]
fn calendar_scope_is_not_an_outbound_grant_scope() {
    use crate::outbound_grant::StandingOutboundGrantScope;

    // A read grant must never become a standing permission to send.
    let scope = GrantMintIntentScope::Calendar {
        calendar_ref: "calendar:work".to_owned(),
        rung: DisclosureRung::Slots,
    };
    assert!(StandingOutboundGrantScope::from_grant_mint_scope(&scope).is_err());
}
