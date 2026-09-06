use super::*;

mod failure_integrity;

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

// ── ONE-1887 surfaced-failure card ──────────────────────────────────────────

/// The witnessed message body the card must NEVER copy inline.
const QA_MESSAGE_BODY: &str = "witnessed-qa-body";

fn card_vault() -> (tempfile::TempDir, crate::Vault) {
    crate::test_util::open_test_vault_with(crate::VaultConfig::device())
}

/// One terminally failed attempt plus the run tree that renders it.
fn failed_run(vault: &crate::Vault) -> Result<(AttemptId, RunTree)> {
    use crate::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt, FailOutcome};
    use crate::dreamer_runner::{
        DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
    };

    let EnqueueDreamerAttemptOutcome::Enqueued(status) =
        DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
            attempt_type: "failing.worker".to_owned(),
            input: rmpv::Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-card".to_owned()),
            now: 10,
        })?
    else {
        panic!("expected a fresh enqueue");
    };
    let queue = crate::AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "card-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected a claim");
    };
    assert_eq!(claimed.id, status.attempt.id);
    let FailOutcome::Failed(failed) = queue.fail(FailAttempt {
        id: claimed.id,
        lease_owner: "card-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: "detector.stable_code".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected a terminal failure");
    };
    let tree = crate::run_tree::RunTreeAdapter::new(vault).read_run("run-card")?;
    Ok((failed.id, tree))
}

fn put_container(vault: &crate::Vault, seed: u8, entity_type: u8) -> Result<EntityId> {
    let id = crate::test_util::entity(seed);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(Vec::new()))
        .expect("encode empty container map");
    vault.put_entity(
        &id,
        entity_type,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    Ok(id)
}

fn put_actor(vault: &crate::Vault, seed: u8) -> Result<EntityId> {
    let id = crate::test_util::entity(seed);
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"qa-actor",
    )?;
    Ok(id)
}

/// A witnessed MESSAGE inside `container`, optionally carrying an `AuthoredBy`
/// edge. System-authored rows carry none by design.
fn put_qa_message(
    vault: &crate::Vault,
    seed: u8,
    container: EntityId,
    author: Option<EntityId>,
    occurred_at: u64,
    order: u32,
) -> Result<EntityId> {
    let id = crate::test_util::entity(seed);
    let body = crate::gate::canonical_witness_message_body_for_test(
        "user",
        "dialogue",
        QA_MESSAGE_BODY,
        true,
        order,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(
            &id,
            crate::temporal::TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            occurred_at,
            &body,
        )
        .commit()?;
    vault.put_edge(&id, EdgeKind::PartOf, &container, 1.0)?;
    if let Some(author) = author {
        vault.put_edge(&id, EdgeKind::AuthoredBy, &author, 1.0)?;
    }
    Ok(id)
}

fn card_input(
    failing_attempt_id: AttemptId,
    tree: RunTree,
    qa: HealerQaFeed,
) -> SurfacedFailureCardInput {
    SurfacedFailureCardInput {
        failure_class: FailureClass::Permanent,
        consecutive_transients: 0,
        pathology: None,
        tree,
        failing_attempt_id,
        diagnosis: FailureDiagnosisState::ReservedHealerSlot,
        blocked_reports: Vec::new(),
        qa,
    }
}

fn qa_entry(message_ref: EntityId, actor_ref: EntityId, occurred_at: u64) -> HealerQaEntryRef {
    HealerQaEntryRef {
        message_ref: message_ref.to_hex(),
        actor_ref: actor_ref.to_hex(),
        occurred_at,
    }
}

#[test]
fn surfaced_failure_card_carries_marked_tree_diagnosis_and_qa_refs() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let turn = put_container(&vault, 0x65, crate::registry::ENTITY_TYPE_TURN)?;
    vault.put_edge(&turn, EdgeKind::ChildOf, &thread, 1.0)?;
    let actor = put_actor(&vault, 0x66)?;
    // Direct MESSAGE→thread membership, and the MESSAGE→TURN→CONVERSATION hop.
    let direct = put_qa_message(&vault, 0x67, thread, Some(actor), 100, 0)?;
    let nested = put_qa_message(&vault, 0x68, turn, Some(actor), 200, 1)?;

    let card = surfaced_failure_card(
        &vault,
        card_input(
            failing,
            tree,
            HealerQaFeed {
                thread_ref: thread.to_hex(),
                entries: vec![qa_entry(direct, actor, 100), qa_entry(nested, actor, 200)],
            },
        ),
    )?;

    assert_eq!(card.schema_version, SURFACED_FAILURE_CARD_SCHEMA_VERSION);
    assert_eq!(card.diagram.marker.attempt_id, failing_hex(failing));
    assert_eq!(
        card.diagram.marker.kind,
        crate::run_tree::RunTreeNodeMarkerKind::Failing
    );
    assert_eq!(card.diagnosis, FailureDiagnosisState::ReservedHealerSlot);
    assert_eq!(card.failure_class, FailureClass::Permanent);
    assert_eq!(card.qa.thread_ref, thread.to_hex());
    assert_eq!(card.qa.entries.len(), 2, "both hop shapes are members");
    assert_eq!(card.pathology, None);
    Ok(())
}

fn failing_hex(id: AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

#[test]
fn surfaced_failure_card_orders_qa_entries_deterministically() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    // Two messages share an instant, so the message ref breaks the tie.
    let later = put_qa_message(&vault, 0x67, thread, Some(actor), 300, 0)?;
    let tied_high = put_qa_message(&vault, 0x69, thread, Some(actor), 100, 1)?;
    let tied_low = put_qa_message(&vault, 0x68, thread, Some(actor), 100, 2)?;

    let card = surfaced_failure_card(
        &vault,
        card_input(
            failing,
            tree,
            HealerQaFeed {
                thread_ref: thread.to_hex(),
                entries: vec![
                    qa_entry(later, actor, 300),
                    qa_entry(tied_high, actor, 100),
                    qa_entry(tied_low, actor, 100),
                ],
            },
        ),
    )?;

    let ordered: Vec<&str> = card
        .qa
        .entries
        .iter()
        .map(|entry| entry.message_ref.as_str())
        .collect();
    assert_eq!(
        ordered,
        vec![
            tied_low.to_hex().as_str(),
            tied_high.to_hex().as_str(),
            later.to_hex().as_str(),
        ],
        "entries order by (occurred_at, message_ref)"
    );
    Ok(())
}

#[test]
fn surfaced_failure_card_rejects_message_ref_from_other_thread() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let turn = put_container(&vault, 0x65, crate::registry::ENTITY_TYPE_TURN)?;
    let conversation = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let outer = put_container(&vault, 0x6b, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let foreign = put_container(&vault, 0x6a, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    vault.put_edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)?;
    vault.put_edge(&conversation, EdgeKind::ChildOf, &outer, 1.0)?;
    let actor = put_actor(&vault, 0x66)?;
    // MESSAGE -> TURN -> CONVERSATION -> outer CONVERSATION.
    let message = put_qa_message(&vault, 0x67, turn, Some(actor), 100, 0)?;

    let card_for = |thread: EntityId| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![qa_entry(message, actor, 100)],
                },
            ),
        )
    };

    // An unrelated thread is not a member at any hop count.
    assert_eq!(
        card_for(foreign)
            .expect_err("a message from another thread is not a member")
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    // Exactly two hops bind: MESSAGE -> TURN -> CONVERSATION.
    assert!(card_for(conversation).is_ok());
    // Three hops do not: the membership walk stops at two.
    assert_eq!(
        card_for(outer)
            .expect_err("membership is bounded at two hops")
            .kind(),
        crate::ErrorKind::InvalidConfig
    );
    Ok(())
}

#[test]
fn surfaced_failure_card_rejects_actor_or_timestamp_not_witnessed_by_message() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    let impostor = put_actor(&vault, 0x6c)?;
    let message = put_qa_message(&vault, 0x67, thread, Some(actor), 100, 0)?;

    for entry in [
        qa_entry(message, impostor, 100),
        qa_entry(message, actor, 101),
    ] {
        let error = surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![entry],
                },
            ),
        )
        .expect_err("author and instant must both be witnessed by the message");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    }
    Ok(())
}

#[test]
fn system_authored_message_fails_card_validation() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    // System-authored rows carry no AuthoredBy edge by design.
    let system = put_qa_message(&vault, 0x67, thread, None, 100, 0)?;

    let error = surfaced_failure_card(
        &vault,
        card_input(
            failing,
            tree,
            HealerQaFeed {
                thread_ref: thread.to_hex(),
                entries: vec![qa_entry(system, actor, 100)],
            },
        ),
    )
    .expect_err("an unwitnessed message cannot be attributed on a card");
    assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    Ok(())
}

#[test]
fn surfaced_failure_card_refs_are_deterministic_and_domain_separated() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let feed = HealerQaFeed {
        thread_ref: thread.to_hex(),
        entries: Vec::new(),
    };

    let first = surfaced_failure_card(&vault, card_input(failing, tree.clone(), feed.clone()))?;
    let second = surfaced_failure_card(&vault, card_input(failing, tree, feed))?;

    assert_eq!(
        first.card_ref, second.card_ref,
        "correlation keys are stable"
    );
    assert_eq!(first.case_ref, second.case_ref);
    assert_ne!(
        first.card_ref, first.case_ref,
        "the two domains keep the keys distinct for the same attempt"
    );
    // Re-derivable by any party from the failing attempt alone, with no store.
    assert_eq!(first.card_ref, failure_card_ref(failing));
    assert_eq!(first.case_ref, failure_case_ref(failing));
    assert_eq!(first.card_ref.len(), 32);
    Ok(())
}

#[test]
fn reserved_healer_slot_is_not_rendered_as_not_run() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let feed = HealerQaFeed {
        thread_ref: thread.to_hex(),
        entries: Vec::new(),
    };

    let card = surfaced_failure_card(&vault, card_input(failing, tree, feed))?;

    assert_eq!(card.diagnosis, FailureDiagnosisState::ReservedHealerSlot);
    assert_ne!(card.diagnosis, FailureDiagnosisState::NotRun);
    let wire = serde_json::to_string(&card.diagnosis).expect("diagnosis serializes");
    assert_eq!(
        wire, "\"reserved_healer_slot\"",
        "a reserved slot is its own explicit token, not a generic failure string"
    );
    Ok(())
}

#[test]
fn surfaced_failure_card_serialization_contains_no_inline_transcript() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    let message = put_qa_message(&vault, 0x67, thread, Some(actor), 100, 0)?;

    let card = surfaced_failure_card(
        &vault,
        card_input(
            failing,
            tree,
            HealerQaFeed {
                thread_ref: thread.to_hex(),
                entries: vec![qa_entry(message, actor, 100)],
            },
        ),
    )?;
    let wire = serde_json::to_string(&card).expect("card serializes");

    // The card REFERENCES the witnessed MESSAGE; it never copies its body.
    assert!(wire.contains(&message.to_hex()));
    assert!(!wire.contains(QA_MESSAGE_BODY), "no inline transcript body");
    assert!(!wire.contains("content"), "no transcript content field");
    assert!(!wire.contains("prompt"), "no prompt copy");
    assert!(!wire.contains("patch"), "no repair patch body");
    Ok(())
}
