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
fn non_principal_shared_slack_approve_is_noop_receipted() -> Result<()> {
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

    let evaluation = card.evaluate_action(&request)?;
    assert_eq!(evaluation.decision, ConsentActionDecision::NoopNonPrincipal);
    assert!(evaluation.grant_mint_intent.is_none());
    assert_eq!(evaluation.receipt.outcome, "no_op_non_principal");
    assert_eq!(evaluation.receipt.actor.as_deref(), Some("coworker"));
    assert_eq!(evaluation.receipt.on_behalf_of.as_deref(), Some("owner"));
    assert_eq!(
        evaluation.receipt.fields.get("surface").map(String::as_str),
        Some("shared_slack")
    );
    assert!(
        evaluation
            .receipt
            .policy_trace
            .contains(&"principal_auth:actor_mismatch".to_owned())
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

    let evaluation = card.evaluate_action(&request)?;
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

    let evaluation = card.evaluate_action(&request)?;
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

    let evaluation = card.evaluate_action(&request)?;
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

    let evaluation = card.evaluate_action(&request)?;
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

    let evaluation = card.evaluate_action(&request)?;
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
        card.evaluate_action(&request),
        Err(Error::InvalidConfig(message))
            if message.contains("payload does not match declared typed action")
    ));

    Ok(())
}

#[test]
fn blank_principal_never_authenticates() {
    assert!(
        !ConsentActorIdentity::SurfaceActor {
            actor_ref: String::new(),
        }
        .authenticates_principal("")
    );
    assert!(
        !ConsentActorIdentity::VoicePath {
            speaker_ref: String::new(),
            owner_voice_print_verified: true,
        }
        .authenticates_principal("")
    );
}

#[test]
fn voice_path_requires_enrolled_owner_voice_print() -> Result<()> {
    let card = ask_card()?;
    let unverified = ConsentActionRequest::new(
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
        card.evaluate_action(&unverified)?.decision,
        ConsentActionDecision::NoopNonPrincipal
    );

    let verified = ConsentActionRequest::new(
        "ask-1",
        "approve_once",
        ConsentActionKind::Approve,
        ConsentActorIdentity::VoicePath {
            speaker_ref: "owner".to_owned(),
            owner_voice_print_verified: true,
        },
        ConsentSurface::Voice,
        104,
    )?;
    assert_eq!(
        card.evaluate_action(&verified)?.decision,
        ConsentActionDecision::ApprovedOnce
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
