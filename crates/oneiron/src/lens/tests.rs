use proptest::prelude::*;
use serde_json::json;

use super::*;

fn id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("valid atom id")
}

fn handle(value: &str) -> LensHandleName {
    LensHandleName::new(value).expect("valid handle")
}

fn render_id(value: &str) -> LensRenderId {
    LensRenderId::new(value).expect("valid render id")
}

fn backing_ref_id(value: &str) -> LensBackingRefId {
    LensBackingRefId::new(value).expect("valid backing ref id")
}

fn media_handle(value: &str) -> LensMediaHandle {
    LensMediaHandle::new(value).expect("valid media handle")
}

fn control_id(value: &str) -> SelfUiControlId {
    SelfUiControlId::new(value).expect("valid control id")
}

fn action_id(value: &str) -> SelfUiActionId {
    SelfUiActionId::new(value).expect("valid action id")
}

fn option_value(value: &str) -> SelfUiOptionValue {
    SelfUiOptionValue::new(value).expect("valid option value")
}

fn text(value: &str) -> LensText {
    LensText::new(value).expect("valid text")
}

fn generated_ui_node(value: &str, parent: Option<&str>, child_refs: &[&str]) -> GeneratedUiNode {
    GeneratedUiNode {
        id: id(value),
        parent: parent.map(id),
        atom: LensAtom::StatusDot(status()),
        fallback_text: text(value),
        bindings: Vec::new(),
        child_refs: child_refs.iter().map(|child| id(child)).collect(),
    }
}

fn action(command: &str) -> SelfUiAction {
    SelfUiAction {
        command: action_id(command),
        args: Vec::new(),
    }
}

fn finite(value: f64) -> FiniteF64 {
    FiniteF64::new(value).expect("valid finite number")
}

fn actor_key(value: &str) -> ScopedReadActorKey {
    ScopedReadActorKey::new(value).expect("valid actor key")
}

fn test_entity_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid entity id")
}

fn put_person(vault: &crate::Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )
}

fn put_profile_claim(vault: &crate::Vault, id: &EntityId, subject: &EntityId) -> Result<()> {
    let body = crate::claim::ClaimBody::new(
        "profile.likes",
        crate::claim::ClaimSubject::Entity(*subject),
        rmpv::Value::from("tea"),
        0.75,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    vault.put_claim(
        id,
        &body,
        crate::temporal::TimeRange { start: 1, end: 1 },
        2,
    )
}

fn backing_target_for(
    vault: &crate::Vault,
    id: &EntityId,
    kind: LensBackingTargetKind,
) -> Result<LensBackingTarget> {
    let rtxn = vault.store.env.read_txn()?;
    let value = vault
        .store
        .short_ids_reverse
        .get(&rtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let (short_id, content_hash) = crate::batch::parse_short_id_value(&value)?;
    match kind {
        LensBackingTargetKind::Entity => {
            LensBackingTarget::entity(*id, short_id.to_owned(), content_hash)
        }
        LensBackingTargetKind::Claim => {
            LensBackingTarget::claim(*id, short_id.to_owned(), content_hash)
        }
    }
}

fn test_vault() -> (tempfile::TempDir, crate::Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
}

fn status() -> StatusDotAtom {
    StatusDotAtom {
        status: LensStatus::Approved,
        label: Some(text("approved")),
    }
}

fn seal() -> SealAtom {
    SealAtom {
        level: SealLevel::Actor,
        label: text("actor-sealed"),
    }
}

fn rows_at_collection_limit_with_one_cell_each() -> Vec<LedgerRowAtom> {
    (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| LedgerRowAtom {
            cells: vec![LedgerCell {
                label: text(&format!("label-{index}")),
                value: text("value"),
            }],
            status: None,
            seal: None,
        })
        .collect()
}

fn sections_at_collection_limit_with_one_line_each() -> Vec<SectionAtom> {
    (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| SectionAtom {
            title: text(&format!("section-{index}")),
            lines: vec![text(&format!("line-{index}"))],
        })
        .collect()
}

fn options_at_collection_limit() -> Vec<SelfUiOption> {
    (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| SelfUiOption {
            value: option_value(&format!("option-{index}")),
            label: text(&format!("Option {index}")),
        })
        .collect()
}

fn sample_atoms() -> Vec<LensAtom> {
    vec![
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(text("Hello Ada"))],
        }),
        LensAtom::LedgerRow(LedgerRowAtom {
            cells: vec![LedgerCell {
                label: text("predicate"),
                value: text("works_at"),
            }],
            status: Some(status()),
            seal: Some(seal()),
        }),
        LensAtom::ClaimLine(ClaimLineAtom {
            subject: text("Ada"),
            predicate: text("works_at"),
            value: text("Analytical Engines"),
            status: status(),
            seal: Some(seal()),
        }),
        LensAtom::StatusDot(status()),
        LensAtom::Seal(seal()),
        LensAtom::MetaLine(MetaLineAtom {
            label: text("source"),
            value: text("vault"),
        }),
        LensAtom::DossierSection(SectionAtom {
            title: text("Profile"),
            lines: vec![text("Mathematician")],
        }),
        LensAtom::ThreadEntry(ThreadEntryAtom {
            author: text("Dreamer"),
            body: text("Proposed update"),
            timestamp: Some(text("2026-07-03T00:00:00Z")),
            seal: Some(seal()),
        }),
        LensAtom::Sheet(CollectionAtom {
            title: text("Claims"),
            rows: Vec::new(),
        }),
        LensAtom::Slip(SectionAtom {
            title: text("Slip"),
            lines: Vec::new(),
        }),
        LensAtom::Receipt(ReceiptAtom {
            title: text("Receipt"),
            lines: vec![MetaLineAtom {
                label: text("hash"),
                value: text("abc123"),
            }],
            seal: Some(seal()),
        }),
        LensAtom::Charter(SectionAtom {
            title: text("Charter"),
            lines: vec![text("Read only")],
        }),
        LensAtom::Postmark(PostmarkAtom {
            label: text("learned"),
            timestamp: text("2026-07-03T00:00:00Z"),
        }),
        LensAtom::PackLine(PackLineAtom {
            pack: text("crm"),
            summary: text("installed"),
            status: LensStatus::Complete,
        }),
        LensAtom::AnswerSheet(AnswerSheetAtom {
            question: text("Who?"),
            answer: text("Ada"),
            citations: vec![LensHandleRef {
                name: handle("claim_set"),
                role: LensHandleRole::ClaimSet,
            }],
        }),
        LensAtom::TwoClocks(TwoClocksAtom {
            occurred_at: text("1843"),
            learned_at: text("2026"),
        }),
        LensAtom::NeighborhoodGraph(NeighborhoodGraphAtom {
            nodes: vec![GraphNode {
                id: handle("ada"),
                label: text("Ada"),
            }],
            edges: Vec::new(),
        }),
        LensAtom::AsofScrubber(AsofScrubberAtom {
            value: text("now"),
            min: None,
            max: None,
        }),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
        LensAtom::VoiceLine(VoiceLineAtom {
            speaker: text("Ada"),
            text: text("hello"),
            vad: Some(VadBadge::Neutral),
        }),
        LensAtom::QuickFilter(QuickFilterAtom {
            id: control_id("status_filter"),
            label: text("Status"),
            options: vec![SelfUiOption {
                value: option_value("approved"),
                label: text("Approved"),
            }],
            selected: vec![option_value("approved")],
            action: action("filter_status"),
        }),
        LensAtom::InspectorSheet(InspectorAtom {
            title: text("Inspector"),
            sections: Vec::new(),
        }),
        LensAtom::InspectorRail(InspectorAtom {
            title: text("Rail"),
            sections: Vec::new(),
        }),
        LensAtom::InspectorTrail(InspectorAtom {
            title: text("Trail"),
            sections: Vec::new(),
        }),
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: control_id("refresh"),
            label: text("Refresh"),
            action: action("refresh_lens"),
        })),
        LensAtom::Media(MediaAtom {
            handle: media_handle("engine-media-1"),
            alt: text("Portrait"),
        }),
    ]
}

#[test]
fn atom_kind_catalog_matches_closed_enum() {
    let atoms = sample_atoms();
    assert_eq!(atoms.len(), GENERATED_LENS_ATOM_KINDS.len());
    assert_eq!(
        GeneratedUiPrimitive::ALL.len(),
        GENERATED_LENS_ATOM_KINDS.len()
    );

    let mut unique = HashSet::new();
    for ((atom, expected_kind), expected_primitive) in atoms
        .iter()
        .zip(GENERATED_LENS_ATOM_KINDS)
        .zip(GeneratedUiPrimitive::ALL)
    {
        let observed_kind = atom.kind();
        assert_eq!(observed_kind, *expected_kind);
        assert_eq!(atom.primitive(), *expected_primitive);
        assert_eq!(expected_primitive.as_str(), *expected_kind);
        assert!(
            unique.insert(observed_kind),
            "duplicate kind {observed_kind}"
        );

        let value = serde_json::to_value(atom).expect("atom encodes");
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some(observed_kind)
        );
        let decoded: LensAtom = serde_json::from_value(value).expect("atom decodes");
        assert_eq!(decoded.kind(), observed_kind);
    }
}

#[test]
fn render_principal_key_selection_must_be_held_by_principal() {
    let human_key = actor_key("human-viewer");
    let agent_key = ScopedReadActorKey::with_actor_class("task-agent", "agent").expect("agent key");

    let human = LensPrincipalBinding::human_view(
        "human-viewer",
        human_key.clone(),
        vec![human_key.clone()],
    )
    .expect("human binding");
    assert_eq!(human.kind(), LensActingPrincipalKind::HumanView);
    assert_eq!(human.selected_read_key(), &human_key);

    let agent =
        LensPrincipalBinding::agent_task("task-agent", agent_key.clone(), vec![agent_key.clone()])
            .expect("agent binding");
    assert_eq!(agent.kind(), LensActingPrincipalKind::AgentTask);

    assert!(
        LensPrincipalBinding::agent_task("task-agent", human_key, vec![agent_key]).is_err(),
        "over-scope render key selection must fail containment"
    );
    assert!(
        LensPrincipalBinding::human_view(" ", actor_key("viewer"), vec![actor_key("viewer")])
            .is_err(),
        "blank principal refs cannot bind a render"
    );
    assert!(
        LensPrincipalBinding::human_view("viewer", actor_key("viewer"), Vec::new()).is_err(),
        "principal bindings must name at least one held read key"
    );
    assert!(
        LensPrincipalBinding::human_view(
            "viewer-a",
            actor_key("viewer-a"),
            vec![actor_key("viewer-b")]
        )
        .is_err(),
        "held read keys must belong to the acting principal"
    );
    assert!(
        LensPrincipalBinding::human_view(
            "viewer",
            ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key"),
            vec![ScopedReadActorKey::with_actor_class("viewer", "agent").expect("agent key")]
        )
        .is_err(),
        "human renders must not bind an agent-class read key"
    );
}

#[test]
fn forged_and_foreign_backing_ref_tokens_do_not_resolve() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(7);
    put_person(&vault, &target_id)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
    let token = frame.mint_backing_ref(
        &scoped_read,
        handle("visible-person"),
        LensHandleRole::ActionTarget,
        backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;

    let resolved = frame.resolve_backing_ref_token(&scoped_read, &token)?;
    assert_eq!(resolved.target().entity_id(), &target_id);

    let foreign_token = LensBackingRefToken {
        render_id: render_id("render-b"),
        ref_id: token.ref_id().clone(),
    };
    assert!(
        frame
            .resolve_backing_ref_token(&scoped_read, &foreign_token)
            .is_err(),
        "a token minted for another render must not select this render's target"
    );

    let forged_token = LensBackingRefToken {
        render_id: render_id("render-a"),
        ref_id: backing_ref_id("ref-999"),
    };
    assert!(
        frame
            .resolve_backing_ref_token(&scoped_read, &forged_token)
            .is_err(),
        "a token absent from the host backing table must not resolve"
    );

    let other_key = actor_key("other-viewer");
    let other_read = vault.scoped_read(other_key);
    assert!(
        frame
            .resolve_backing_ref_token(&other_read, &token)
            .is_err(),
        "render-bound selections must be rechecked under the acting principal key"
    );

    Ok(())
}

#[test]
fn lens_actions_resolve_only_host_bound_handles() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(8);
    put_person(&vault, &target_id)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);
    let target = backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?;
    let expected_short_ref = target.short_ref();
    frame.mint_backing_ref(
        &scoped_read,
        handle("selected-person"),
        LensHandleRole::ActionTarget,
        target.clone(),
    )?;
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("selected-person"),
                LensHandleRole::ActionTarget,
                target.clone(),
            )
            .is_err(),
        "one handle must not bind multiple backing refs in a render"
    );
    frame.mint_backing_ref(
        &scoped_read,
        handle("visible-set"),
        LensHandleRole::EntitySet,
        target,
    )?;

    let action = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("selected-person"))],
    };
    let approved = frame.approve_action(&scoped_read, &action)?;
    assert_eq!(approved.command().as_str(), "remember");
    match &approved.args()[0] {
        LensApprovedActionArg::BackingRef(backing_ref) => {
            assert_eq!(backing_ref.target().entity_id(), &target_id);
            assert_eq!(backing_ref.target().short_ref(), expected_short_ref);
        }
        other => panic!("expected host backing ref, got {other:?}"),
    }

    let forged = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("cl999"))],
    };
    assert!(
        frame.approve_action(&scoped_read, &forged).is_err(),
        "lens-supplied ids that were never host-bound must fail at the action boundary"
    );
    let wrong_role = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("visible-set"))],
    };
    assert!(
        frame.approve_action(&scoped_read, &wrong_role).is_err(),
        "only action-target handles can become approved backing refs"
    );

    Ok(())
}

#[test]
fn backing_refs_recheck_short_ref_and_target_kind_under_scoped_read() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let subject_id = test_entity_id(9);
    let claim_id = test_entity_id(10);
    put_person(&vault, &subject_id)?;
    put_profile_claim(&vault, &claim_id, &subject_id)?;

    let viewer_key = actor_key("viewer");
    let scoped_read = vault.scoped_read(viewer_key.clone());
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key])?;
    let mut frame = LensRenderFrame::new(render_id("render-a"), principal);

    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("wrong-kind"),
                LensHandleRole::ActionTarget,
                backing_target_for(&vault, &subject_id, LensBackingTargetKind::Claim)?,
            )
            .is_err(),
        "claim backing refs must resolve to claim entities"
    );
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("claim-as-entity"),
                LensHandleRole::ActionTarget,
                backing_target_for(&vault, &claim_id, LensBackingTargetKind::Entity)?,
            )
            .is_err(),
        "entity backing refs must not hide claim targets"
    );

    let mut drifted = backing_target_for(&vault, &subject_id, LensBackingTargetKind::Entity)?;
    drifted.entity_id = claim_id;
    assert!(
        frame
            .mint_backing_ref(
                &scoped_read,
                handle("drifted-short-ref"),
                LensHandleRole::ActionTarget,
                drifted,
            )
            .is_err(),
        "short refs must hydrate back to the host-selected entity"
    );

    Ok(())
}

#[test]
fn lens_execution_rejects_write_imports_and_host_writes_name_gate_chokepoint() -> Result<()> {
    let boundary = LensExecutionBoundary::read_only(vec![
        LensHostImport::ScopedRead,
        LensHostImport::ResolveBackingRef,
        LensHostImport::EmitAtom,
    ])?;
    assert_eq!(boundary.imports().len(), 3);

    assert!(
        LensExecutionBoundary::read_only(vec![
            LensHostImport::ScopedRead,
            LensHostImport::BatchWrite,
        ])
        .is_err(),
        "lens execution must expose zero write imports"
    );

    let action = LensApprovedAction {
        command: action_id("propose_claim"),
        args: Vec::new(),
    };
    let write = action.into_host_mediated_write(LensGateWriteChokepoint::CheckClaimPolicyForWrite);
    assert_eq!(
        write.chokepoint(),
        LensGateWriteChokepoint::CheckClaimPolicyForWrite
    );

    Ok(())
}

#[test]
fn allowed_atom_kit_round_trips_json_and_msgpack() {
    let mut root = LensNode::new(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Vault"),
            rows: Vec::new(),
        }),
    );
    root.children = sample_atoms()
        .into_iter()
        .enumerate()
        .map(|(index, atom)| LensNode::new(id(&format!("atom-{index}")), atom))
        .collect();

    let lens = GeneratedLens::new(root).expect("valid lens");
    let json = serde_json::to_vec(&lens).expect("json encode");
    let decoded: GeneratedLens = serde_json::from_slice(&json).expect("json decode");
    assert_eq!(decoded, lens);

    let msgpack = rmp_serde::to_vec_named(&lens).expect("msgpack encode");
    let decoded: GeneratedLens = rmp_serde::from_slice(&msgpack).expect("msgpack decode");
    assert_eq!(decoded, lens);

    let positional_msgpack = rmp_serde::to_vec(&lens).expect("positional msgpack encode");
    let decoded: GeneratedLens =
        rmp_serde::from_slice(&positional_msgpack).expect("positional msgpack decode");
    assert_eq!(decoded, lens);
}

#[test]
fn generated_ui_card_round_trips_segments_and_content_parts() -> Result<()> {
    let mut root = LensNode::with_fallback_text(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Card"),
            rows: Vec::new(),
        }),
        text("Card fallback"),
    );
    root.children.push(LensNode::with_fallback_text(
        id("body"),
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![
                LensTextSpan::Literal(text("Hello ")),
                LensTextSpan::Interpolation {
                    key: handle("display_name"),
                    fallback: text("Ada"),
                },
            ],
        }),
        text("Hello Ada"),
    ));
    root.children.push(LensNode::with_fallback_text(
        id("image"),
        LensAtom::Media(MediaAtom {
            handle: media_handle("engine-media-portrait"),
            alt: text("Portrait of Ada"),
        }),
        text("Portrait of Ada"),
    ));

    let card = GeneratedUiCard::card(render_id("card-1"), root)?;
    let encoded = serde_json::to_vec(&card).expect("card encodes");
    let decoded: GeneratedUiCard = serde_json::from_slice(&encoded).expect("card decodes");
    assert_eq!(decoded, card);

    let render = decoded.render()?;
    assert_eq!(render.root, id("root"));
    assert_eq!(render.nodes.len(), 3);
    assert_eq!(render.nodes[1].parent, Some(id("root")));
    assert_eq!(render.nodes[0].child_refs, vec![id("body"), id("image")]);

    let render_value = serde_json::to_value(&render).expect("render encodes");
    assert!(
        render_value.to_string().contains("fallbackText"),
        "flat wire must expose fallbackText per node"
    );
    let render_round_trip: GeneratedUiRender =
        serde_json::from_value(render_value).expect("render decodes");
    assert_eq!(render_round_trip, render);

    let segments = render.segments();
    assert_eq!(segments.len(), 5);
    assert!(matches!(segments[0], GeneratedUiSegment::CardStart(_)));
    assert!(matches!(segments[1], GeneratedUiSegment::CardElement(_)));
    assert!(matches!(
        segments.last(),
        Some(GeneratedUiSegment::CardStateUpdate(_))
    ));
    assert_eq!(GeneratedUiRender::from_segments(&segments)?, render);

    let content_parts = render.content_parts()?;
    assert_eq!(content_parts.len(), segments.len());
    for (part, segment) in content_parts.iter().zip(segments.iter()) {
        let crate::llm::ContentPart::Text { text } = part else {
            panic!("generated-ui segments must lower to OF-126 text content parts");
        };
        assert_eq!(
            serde_json::from_str::<GeneratedUiSegment>(text).expect("segment decodes"),
            *segment
        );
    }

    Ok(())
}

#[test]
fn generated_ui_prebuilt_shorthand_expands_server_side_into_tree() -> Result<()> {
    let shorthand = json!({
        "protocolVersion": GENERATED_UI_WIRE_VERSION,
        "catalog": "lens_atom_kit",
        "cardId": "summary-card",
        "prebuilt": {
            "name": "summary_card",
            "props": {
                "title": "Consent summary",
                "body": "Approve one send to Ada.",
                "details": [
                    { "label": "principal", "value": "user:ada" },
                    { "label": "scope", "value": "just_once" }
                ]
            }
        }
    });

    let card: GeneratedUiCard =
        serde_json::from_value(shorthand).expect("prebuilt shorthand decodes");
    let card_value = serde_json::to_value(&card).expect("expanded card encodes");
    assert!(
        card_value.get("tree").is_some(),
        "server-side shorthand must serialize as the 01A tree"
    );
    assert!(
        card_value.get("prebuilt").is_none(),
        "prebuilt names must not leak into the client wire payload"
    );

    let render = card.render()?;
    assert_eq!(render.nodes.len(), 4);
    assert_eq!(render.nodes[0].id, id("summary-card-root"));
    assert_eq!(
        render.nodes[0].atom.primitive(),
        GeneratedUiPrimitive::Sheet
    );
    assert_eq!(
        render.nodes[0].child_refs,
        vec![
            id("summary-card-body"),
            id("summary-card-detail-0"),
            id("summary-card-detail-1")
        ]
    );
    assert_eq!(
        render.nodes[1].atom.primitive(),
        GeneratedUiPrimitive::TextBlock
    );
    assert_eq!(
        render.nodes[2].atom.primitive(),
        GeneratedUiPrimitive::MetaLine
    );
    assert_eq!(
        render.nodes[3].atom.primitive(),
        GeneratedUiPrimitive::MetaLine
    );

    Ok(())
}

#[test]
fn generated_ui_capability_negotiation_degrades_unsupported_primitives() -> Result<()> {
    let mut root = LensNode::with_fallback_text(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Unsupported root"),
            rows: Vec::new(),
        }),
        text("Unsupported root"),
    );
    root.children.push(LensNode::with_fallback_text(
        id("media"),
        LensAtom::Media(MediaAtom {
            handle: media_handle("engine-media-portrait"),
            alt: text("Portrait"),
        }),
        text("Portrait fallback"),
    ));
    root.children.push(LensNode::with_fallback_text(
        id("action"),
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: control_id("approve"),
            label: text("Approve"),
            action: action("approve_once"),
        })),
        text("Approve fallback"),
    ));

    let card = GeneratedUiCard::card(render_id("degrade-card"), root)?;
    let surface = GeneratedUiSurfaceCapabilities::text_only();
    let render = card.render_for_surface(&surface)?;

    assert_eq!(render.nodes.len(), 3);
    assert!(
        render
            .nodes
            .iter()
            .all(|node| node.atom.primitive() == GeneratedUiPrimitive::TextBlock),
        "unsupported primitives should lower to text fallbacks"
    );
    assert_eq!(render.nodes[0].child_refs, vec![id("media"), id("action")]);
    assert_eq!(
        render.nodes[0].fallback_text.as_str(),
        "Unsupported root",
        "fallbackText remains explicit on the degraded node"
    );
    let LensAtom::TextBlock(atom) = &render.nodes[1].atom else {
        panic!("media should degrade to text_block");
    };
    assert_eq!(
        atom.fallback_text(),
        "Portrait fallback",
        "degraded text must use the node fallback"
    );
    let segments = card.segments_for_surface(&surface)?;
    assert_eq!(GeneratedUiRender::from_segments(&segments)?, render);

    Ok(())
}

#[test]
fn generated_ui_segment_stream_rejects_incoherent_sequences() -> Result<()> {
    let mut root = LensNode::with_fallback_text(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Card"),
            rows: Vec::new(),
        }),
        text("Card fallback"),
    );
    root.children.push(LensNode::with_fallback_text(
        id("body"),
        LensAtom::StatusDot(status()),
        text("Body"),
    ));

    let render = GeneratedUiCard::card(render_id("card-1"), root)?.render()?;
    let segments = render.segments();

    let mut wrong_element_card = segments.clone();
    if let GeneratedUiSegment::CardElement(element) = &mut wrong_element_card[1] {
        element.card_id = render_id("foreign-card");
    } else {
        panic!("expected card element");
    }
    assert!(
        GeneratedUiRender::from_segments(&wrong_element_card).is_err(),
        "streamed elements must not belong to another card"
    );

    let mut wrong_state_root = segments.clone();
    if let Some(GeneratedUiSegment::CardStateUpdate(state)) = wrong_state_root.last_mut() {
        state.data_model.root = id("foreign-root");
    } else {
        panic!("expected state update");
    }
    assert!(
        GeneratedUiRender::from_segments(&wrong_state_root).is_err(),
        "stream state root must agree with card_start"
    );

    let mut wrong_state_card = segments.clone();
    if let Some(GeneratedUiSegment::CardStateUpdate(state)) = wrong_state_card.last_mut() {
        state.card_id = render_id("foreign-card");
    } else {
        panic!("expected state update");
    }
    assert!(
        GeneratedUiRender::from_segments(&wrong_state_card).is_err(),
        "stream state card_id must agree with card_start"
    );

    let mut wrong_state_count = segments.clone();
    if let Some(GeneratedUiSegment::CardStateUpdate(state)) = wrong_state_count.last_mut() {
        state.data_model.node_count += 1;
    } else {
        panic!("expected state update");
    }
    assert!(
        GeneratedUiRender::from_segments(&wrong_state_count).is_err(),
        "stream state nodeCount must agree with card_start"
    );

    let mut duplicate_start = segments.clone();
    duplicate_start.insert(1, duplicate_start[0].clone());
    assert!(
        GeneratedUiRender::from_segments(&duplicate_start).is_err(),
        "a stream must contain exactly one card_start"
    );

    let mut state_before_elements = segments.clone();
    let state = state_before_elements.pop().expect("state update");
    state_before_elements.insert(1, state);
    assert!(
        GeneratedUiRender::from_segments(&state_before_elements).is_err(),
        "state update must not arrive before all card elements"
    );

    let mut missing_element = segments.clone();
    missing_element.remove(1);
    assert!(
        GeneratedUiRender::from_segments(&missing_element).is_err(),
        "element count must match card_start nodeCount"
    );

    let mut missing_state = segments;
    missing_state.pop();
    assert!(
        GeneratedUiRender::from_segments(&missing_state).is_err(),
        "stream must end with card_state_update"
    );

    Ok(())
}

#[test]
fn generated_ui_segment_stream_enforces_aggregate_budget() {
    let mut root = generated_ui_node("root", None, &["child"]);
    root.bindings = (0..(MAX_LENS_COLLECTION_ITEMS - 1))
        .map(|index| LensHandleRef {
            name: handle(&format!("binding-{index}")),
            role: LensHandleRole::ClaimSet,
        })
        .collect();

    let mut child = generated_ui_node("child", Some("root"), &[]);
    child.atom = LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(text("x"))],
    });

    let segments = vec![
        GeneratedUiSegment::CardStart(GeneratedUiCardStart {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            catalog: GeneratedUiCatalog::LensAtomKit,
            card_id: render_id("card-1"),
            root: id("root"),
            node_count: 2,
            fallback_text: text("root"),
        }),
        GeneratedUiSegment::CardElement(Box::new(GeneratedUiCardElement {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            card_id: render_id("card-1"),
            node: root,
        })),
        GeneratedUiSegment::CardElement(Box::new(GeneratedUiCardElement {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            card_id: render_id("card-1"),
            node: child,
        })),
        GeneratedUiSegment::CardStateUpdate(GeneratedUiCardStateUpdate {
            protocol_version: GENERATED_UI_WIRE_VERSION,
            card_id: render_id("card-1"),
            data_model: GeneratedUiDataModel {
                root: id("root"),
                node_count: 2,
                catalog: GeneratedUiCatalog::LensAtomKit,
            },
        }),
    ];

    assert!(
        segments.iter().all(|segment| segment.validate().is_ok()),
        "individual segments stay under per-segment limits"
    );
    assert!(
        GeneratedUiRender::from_segments(&segments).is_err(),
        "stream validation must preserve one aggregate lens budget across elements"
    );
}

#[test]
fn generated_ui_flat_tree_rejects_non_tree_topologies() {
    assert!(
        GeneratedUiRender::new(
            render_id("self-ref"),
            GeneratedUiCatalog::LensAtomKit,
            id("root"),
            vec![generated_ui_node("root", None, &["root"])],
        )
        .is_err(),
        "flat tree must reject self-referencing child refs"
    );

    assert!(
        GeneratedUiRender::new(
            render_id("multi-parent"),
            GeneratedUiCatalog::LensAtomKit,
            id("root"),
            vec![
                generated_ui_node("root", None, &["left", "right"]),
                generated_ui_node("left", Some("root"), &["leaf"]),
                generated_ui_node("right", Some("root"), &["leaf"]),
                generated_ui_node("leaf", Some("left"), &[]),
            ],
        )
        .is_err(),
        "flat tree must reject multiple parents for a node"
    );

    assert!(
        GeneratedUiRender::new(
            render_id("parent-mismatch"),
            GeneratedUiCatalog::LensAtomKit,
            id("root"),
            vec![
                generated_ui_node("root", None, &[]),
                generated_ui_node("child", Some("root"), &[]),
            ],
        )
        .is_err(),
        "flat tree parent refs must be reciprocal with child refs"
    );

    assert!(
        GeneratedUiRender::new(
            render_id("orphan-cycle"),
            GeneratedUiCatalog::LensAtomKit,
            id("root"),
            vec![
                generated_ui_node("root", None, &[]),
                generated_ui_node("orphan-a", Some("orphan-b"), &["orphan-b"]),
                generated_ui_node("orphan-b", Some("orphan-a"), &["orphan-a"]),
            ],
        )
        .is_err(),
        "flat tree must reject disconnected orphan islands"
    );
}

#[test]
fn generated_ui_flat_tree_enforces_depth_and_aggregate_budget() {
    let mut deep_nodes = Vec::with_capacity(MAX_LENS_TREE_DEPTH + 1);
    for index in 0..=MAX_LENS_TREE_DEPTH {
        let name = format!("node-{index}");
        let parent = (index > 0).then(|| format!("node-{}", index - 1));
        let child = (index < MAX_LENS_TREE_DEPTH).then(|| format!("node-{}", index + 1));
        deep_nodes.push(GeneratedUiNode {
            id: id(&name),
            parent: parent.as_deref().map(id),
            atom: LensAtom::StatusDot(status()),
            fallback_text: text(&name),
            bindings: Vec::new(),
            child_refs: child.iter().map(|child| id(child)).collect(),
        });
    }
    assert!(
        GeneratedUiRender::new(
            render_id("too-deep"),
            GeneratedUiCatalog::LensAtomKit,
            id("node-0"),
            deep_nodes,
        )
        .is_err(),
        "flat tree depth must share the nested tree cap"
    );

    let mut over_budget = generated_ui_node("root", None, &[]);
    over_budget.atom = LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(text("x"))],
    });
    over_budget.bindings = (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| LensHandleRef {
            name: handle(&format!("binding-{index}")),
            role: LensHandleRole::ClaimSet,
        })
        .collect();
    assert!(
        GeneratedUiRender::new(
            render_id("over-budget"),
            GeneratedUiCatalog::LensAtomKit,
            id("root"),
            vec![over_budget],
        )
        .is_err(),
        "flat tree must enforce one aggregate lens collection budget"
    );
}

#[test]
fn generated_lens_requires_fallback_text_per_node() {
    let missing = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "atom": {
                "kind": "text_block",
                "props": {
                    "spans": [{ "type": "literal", "value": "hello" }]
                }
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(missing).is_err(),
        "fallbackText must be mandatory on every node"
    );

    let blank = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": " ",
            "atom": {
                "kind": "text_block",
                "props": {
                    "spans": [{ "type": "literal", "value": "hello" }]
                }
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(blank).is_err(),
        "fallbackText must not be blank"
    );
}

#[test]
fn fallback_text_requirement_bumps_atom_kit_version() {
    let lens = GeneratedLens::new(LensNode::with_fallback_text(
        id("root"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
        text("loading"),
    ))
    .expect("valid lens");
    assert_eq!(lens.kit_version(), 2);

    let legacy_v1_without_fallback = json!({
        "kit_version": 1,
        "root": {
            "id": "root",
            "atom": {
                "kind": "throbber",
                "props": { "label": "loading" }
            }
        }
    });
    let error = serde_json::from_value::<GeneratedLens>(legacy_v1_without_fallback)
        .expect_err("legacy v1 wire shape must not decode as v2");
    assert!(
        error
            .to_string()
            .contains("unsupported generated lens atom kit version 1"),
        "legacy incompatible node shape must fail by version, not share v2 semantics: {error}"
    );
}

#[test]
fn text_block_allows_one_escaped_interpolation_only() {
    let ok = LensAtom::TextBlock(TextBlockAtom {
        spans: vec![
            LensTextSpan::Literal(text("Hello ")),
            LensTextSpan::Interpolation {
                key: handle("display_name"),
                fallback: text("Ada"),
            },
        ],
    });
    assert!(ok.validate().is_ok());

    let bad = json!({
        "kind": "text_block",
        "props": {
            "spans": [
                { "type": "interpolation", "value": { "key": "first", "fallback": "First" } },
                { "type": "interpolation", "value": { "key": "second", "fallback": "Second" } }
            ]
        }
    });
    assert!(
        serde_json::from_value::<LensAtom>(bad).is_err(),
        "text blocks must expose a single escaped interpolation point"
    );
}

#[test]
fn generated_ui_rejects_unknown_segment_and_raw_media_url_shapes() {
    let unknown_segment = json!({
        "segment": "open_url",
        "payload": { "url": "https://attacker.example" }
    });
    assert!(
        serde_json::from_value::<GeneratedUiSegment>(unknown_segment).is_err(),
        "segment kind must be a closed enum"
    );

    for segment in [
        json!({
            "segment": "card_start",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "catalog": "lens_atom_kit",
                "cardId": "card-1",
                "root": "root",
                "nodeCount": 1,
                "fallbackText": "root"
            }
        }),
        json!({
            "segment": "card_element",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "cardId": "card-1",
                "node": {
                    "id": "root",
                    "atom": {
                        "kind": "throbber",
                        "props": { "label": "loading" }
                    },
                    "fallbackText": "loading"
                }
            }
        }),
        json!({
            "segment": "card_state_update",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION + 1,
                "cardId": "card-1",
                "dataModel": {
                    "root": "root",
                    "nodeCount": 1,
                    "catalog": "lens_atom_kit"
                }
            }
        }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiSegment>(segment).is_err(),
            "segment payloads must reject unsupported generated-ui wire versions"
        );
    }

    for segment in [
        json!({
            "segment": "card_start",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION,
                "catalog": "lens_atom_kit",
                "cardId": "card-1",
                "root": "root",
                "nodeCount": 0,
                "fallbackText": "root"
            }
        }),
        json!({
            "segment": "card_state_update",
            "payload": {
                "protocolVersion": GENERATED_UI_WIRE_VERSION,
                "cardId": "card-1",
                "dataModel": {
                    "root": "root",
                    "nodeCount": 0,
                    "catalog": "lens_atom_kit"
                }
            }
        }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiSegment>(segment).is_err(),
            "segment payloads must reject zero nodeCount"
        );
    }

    let zero_node_data_model = json!({
        "root": "root",
        "nodeCount": 0,
        "catalog": "lens_atom_kit"
    });
    assert!(
        serde_json::from_value::<GeneratedUiDataModel>(zero_node_data_model).is_err(),
        "generated-ui data model must reject zero nodeCount"
    );

    let raw_url_handle = json!({
        "kind": "media",
        "props": {
            "handle": "https://attacker.example/pixel.png",
            "alt": "pixel"
        }
    });
    assert!(
        serde_json::from_value::<LensAtom>(raw_url_handle).is_err(),
        "media handles must be engine-owned tokens, not raw URLs"
    );

    let raw_url_prop = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "pixel",
            "atom": {
                "kind": "media",
                "props": {
                    "handle": "engine-media-pixel",
                    "url": "https://attacker.example/pixel.png",
                    "alt": "pixel"
                }
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(raw_url_prop).is_err(),
        "media atoms must not accept raw URL leaves"
    );
}

proptest! {
    #[test]
    fn generated_ui_fuzz_rejects_url_shaped_media_handles(
        scheme in "https?",
        host in "[a-z]{1,12}",
        path in "[a-z0-9/_-]{0,24}",
    ) {
        let url = format!("{scheme}://{host}.example/{path}");
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "remote media",
                "atom": {
                    "kind": "media",
                    "props": {
                        "handle": url,
                        "alt": "remote media"
                    }
                }
            }
        });

        prop_assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "URL-shaped media handles must be rejected"
        );
    }
}

#[test]
fn unsafe_raw_atom_variants_are_rejected() {
    for kind in [
        "raw_script",
        "script",
        "network_request",
        "storage_read",
        "eval",
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "unsafe atom",
                "atom": {
                    "kind": kind,
                    "props": {
                        "code": "fetch('https://attacker.example')"
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "unsafe atom kind {kind} should be rejected"
        );
    }
}

#[test]
fn raw_script_network_storage_eval_props_are_rejected() {
    for forbidden_prop in [
        "on_click", "script", "src", "href", "fetch", "storage", "eval",
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" },
                            forbidden_prop: "javascript:alert(1)"
                        }
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw prop {forbidden_prop} should be rejected"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" }
                        },
                        forbidden_prop: "javascript:alert(1)"
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw self.ui envelope prop {forbidden_prop} should be rejected"
        );

        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": "refresh_lens" }
                        }
                    },
                    forbidden_prop: "javascript:alert(1)"
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "raw atom envelope prop {forbidden_prop} should be rejected"
        );
    }
}

#[test]
fn self_ui_action_ids_reject_reserved_capability_names() {
    for command in [
        "javascript",
        "javaScript",
        "eval",
        "run_eval",
        "runEval",
        "fetch",
        "fetch_url",
        "fetchUrl",
        "URLFetch",
        "network",
        "network.fetch",
        "networkFetch",
        "storage",
        "storage_read",
        "storageRead",
        "read_storage",
        "local_storage",
        "localStorage",
        "session_storage",
        "raw-script",
        "rawScript",
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "refresh",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "button",
                        "props": {
                            "id": "refresh",
                            "label": "Refresh",
                            "action": { "command": command }
                        }
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "reserved command {command} should be rejected"
        );
    }
}

#[test]
fn non_capability_tokens_allow_reserved_domain_values() {
    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "fetch",
            "fallbackText": "Backend",
            "atom": {
                "kind": "quick_filter",
                "props": {
                    "id": "network",
                    "label": "Backend",
                    "options": [{ "value": "storage", "label": "Storage" }],
                    "selected": ["storage"],
                    "action": {
                        "command": "filter_backend",
                        "args": [
                            { "type": "token", "value": "storage" },
                            { "type": "handle", "value": "network" }
                        ]
                    }
                }
            }
        }
    });

    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_ok(),
        "reserved domain words should be allowed outside capability fields"
    );
}

#[test]
fn self_ui_rejects_selected_values_outside_options() {
    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "Status",
            "atom": {
                "kind": "quick_filter",
                "props": {
                    "id": "filter",
                    "label": "Status",
                    "options": [{ "value": "approved", "label": "Approved" }],
                    "selected": ["rejected"],
                    "action": { "command": "filter_status" }
                }
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_err(),
        "quick filter selected values outside options should be rejected"
    );

    for attempted in [
        json!({
            "control": "segmented",
            "props": {
                "id": "segmented",
                "label": "Mode",
                "options": [{ "value": "compact", "label": "Compact" }],
                "selected": "expanded",
                "action": { "command": "set_mode" }
            }
        }),
        json!({
            "control": "select",
            "props": {
                "id": "select",
                "label": "Mode",
                "options": [{ "value": "compact", "label": "Compact" }],
                "selected": "expanded",
                "action": { "command": "set_mode" }
            }
        }),
    ] {
        assert!(
            serde_json::from_value::<SelfUiControl>(attempted).is_err(),
            "selected values outside options should be rejected"
        );
    }
}

#[test]
fn quick_filter_rejects_duplicate_selected_values() {
    let props = json!({
        "id": "filter",
        "label": "Status",
        "options": [{ "value": "approved", "label": "Approved" }],
        "selected": ["approved", "approved"],
        "action": { "command": "filter_status" }
    });

    assert!(
        serde_json::from_value::<QuickFilterAtom>(props.clone()).is_err(),
        "standalone quick filters should reject duplicate selected values"
    );

    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "Status",
            "atom": {
                "kind": "quick_filter",
                "props": props
            }
        }
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_err(),
        "quick filters should reject duplicate selected values"
    );
}

#[test]
fn self_ui_controls_round_trip_and_numbers_are_finite() {
    let controls = vec![
        SelfUiControl::Button(ButtonControl {
            id: control_id("button"),
            label: text("Button"),
            action: SelfUiAction {
                command: action_id("button_action"),
                args: vec![SelfUiValue::Number(finite(1.25))],
            },
        }),
        SelfUiControl::Toggle(ToggleControl {
            id: control_id("toggle"),
            label: text("Toggle"),
            checked: true,
            action: action("toggle_action"),
        }),
        SelfUiControl::Segmented(SegmentedControl {
            id: control_id("segmented"),
            label: text("Segmented"),
            options: vec![SelfUiOption {
                value: option_value("one"),
                label: text("One"),
            }],
            selected: Some(option_value("one")),
            action: action("segmented_action"),
        }),
        SelfUiControl::Select(SelectControl {
            id: control_id("select"),
            label: text("Select"),
            options: vec![SelfUiOption {
                value: option_value("two"),
                label: text("Two"),
            }],
            selected: Some(option_value("two")),
            action: action("select_action"),
        }),
        SelfUiControl::Slider(SliderControl {
            id: control_id("slider"),
            label: text("Slider"),
            min: finite(0.0),
            max: finite(10.0),
            step: finite(0.5),
            value: finite(5.0),
            action: action("slider_action"),
        }),
        SelfUiControl::TextInput(TextInputControl {
            id: control_id("text_input"),
            label: text("Text"),
            placeholder: Some(text("Type here")),
            value: Some(text("value")),
            action: action("text_action"),
        }),
    ];

    for (index, control) in controls.into_iter().enumerate() {
        let lens = GeneratedLens::new(LensNode::new(
            id(&format!("control-{index}")),
            LensAtom::SelfUi(control),
        ))
        .expect("valid self.ui lens");

        let json = serde_json::to_vec(&lens).expect("json encode");
        let decoded: GeneratedLens = serde_json::from_slice(&json).expect("json decode");
        assert_eq!(decoded, lens);
    }
}

#[test]
fn self_ui_rejects_non_finite_numbers_and_invalid_sliders() {
    let value = rmpv::Value::Map(vec![
        (rmpv::Value::from("type"), rmpv::Value::from("number")),
        (rmpv::Value::from("value"), rmpv::Value::F64(f64::NAN)),
    ]);
    let mut msgpack = Vec::new();
    rmpv::encode::write_value(&mut msgpack, &value).expect("msgpack encode");
    assert!(
        rmp_serde::from_slice::<SelfUiValue>(&msgpack).is_err(),
        "non-finite self.ui numbers should be rejected"
    );

    for props in [
        json!({ "min": 10.0, "max": 0.0, "step": 1.0, "value": 5.0 }),
        json!({ "min": 0.0, "max": 10.0, "step": 0.0, "value": 5.0 }),
        json!({ "min": 0.0, "max": 10.0, "step": 1.0, "value": 11.0 }),
    ] {
        let attempted = json!({
            "kit_version": LENS_ATOM_KIT_VERSION,
            "root": {
                "id": "root",
                "fallbackText": "Slider",
                "atom": {
                    "kind": "self_ui",
                    "props": {
                        "control": "slider",
                        "props": {
                            "id": "slider",
                            "label": "Slider",
                            "min": props["min"],
                            "max": props["max"],
                            "step": props["step"],
                            "value": props["value"],
                            "action": { "command": "slider_action" }
                        }
                    }
                }
            }
        });

        assert!(
            serde_json::from_value::<GeneratedLens>(attempted).is_err(),
            "invalid slider bounds should be rejected"
        );
    }
}

#[test]
fn generated_lens_rejects_root_before_version_and_oversized_trees() {
    let root_first = r#"{
            "root": {
                "id": "root",
                "atom": {
                    "kind": "throbber",
                    "props": { "label": "loading" }
                }
            },
            "kit_version": 1
        }"#;

    assert!(
        serde_json::from_str::<GeneratedLens>(root_first).is_err(),
        "root before kit_version should be rejected before tree allocation"
    );

    let mut root = LensNode::new(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("too-wide"),
            rows: Vec::new(),
        }),
    );
    root.children = (0..=MAX_LENS_NODE_COUNT)
        .map(|index| {
            LensNode::new(
                id(&format!("node-{index}")),
                LensAtom::Throbber(ThrobberAtom {
                    label: text("loading"),
                }),
            )
        })
        .collect();

    assert!(
        GeneratedLens::new(root).is_err(),
        "oversized lens trees should be rejected"
    );

    let mut root = LensNode::new(
        id("root"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
    );
    root.children = (0..MAX_LENS_NODE_COUNT)
        .map(|index| {
            LensNode::new(
                id(&format!("standalone-node-{index}")),
                LensAtom::Throbber(ThrobberAtom {
                    label: text("loading"),
                }),
            )
        })
        .collect();
    let encoded = serde_json::to_value(&root).expect("node encodes");
    assert!(
        serde_json::from_value::<LensNode>(encoded).is_err(),
        "standalone lens nodes should enforce tree node budgets"
    );
}

#[test]
fn generated_lens_rejects_duplicate_node_ids() {
    let mut root = LensNode::new(
        id("root"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
    );
    root.children = vec![
        LensNode::new(
            id("duplicate"),
            LensAtom::Throbber(ThrobberAtom {
                label: text("first"),
            }),
        ),
        LensNode::new(
            id("duplicate"),
            LensAtom::Throbber(ThrobberAtom {
                label: text("second"),
            }),
        ),
    ];

    assert!(
        GeneratedLens::new(root.clone()).is_err(),
        "generated lens trees should reject duplicate node ids"
    );

    let encoded = serde_json::to_value(&root).expect("node encodes");
    assert!(
        serde_json::from_value::<LensNode>(encoded).is_err(),
        "standalone lens nodes should reject duplicate node ids"
    );
}

#[test]
fn generated_lens_rejects_aggregate_collection_budget() {
    let root = LensNode::new(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("too-many-total-items"),
            rows: rows_at_collection_limit_with_one_cell_each(),
        }),
    );

    assert!(
        GeneratedLens::new(root).is_err(),
        "nested collection totals over budget should be rejected"
    );

    let atom = LensAtom::Sheet(CollectionAtom {
        title: text("too-many-total-items"),
        rows: rows_at_collection_limit_with_one_cell_each(),
    });
    let encoded = serde_json::to_value(&atom).expect("atom encodes");
    assert!(
        serde_json::from_value::<LensAtom>(encoded).is_err(),
        "standalone atoms should enforce aggregate collection totals"
    );

    let atom = CollectionAtom {
        title: text("too-many-total-items"),
        rows: rows_at_collection_limit_with_one_cell_each(),
    };
    let encoded = serde_json::to_value(&atom).expect("collection encodes");
    assert!(
        serde_json::from_value::<CollectionAtom>(encoded).is_err(),
        "standalone collection props should enforce aggregate collection totals"
    );

    let atom = InspectorAtom {
        title: text("too-many-total-items"),
        sections: sections_at_collection_limit_with_one_line_each(),
    };
    let encoded = serde_json::to_value(&atom).expect("inspector encodes");
    assert!(
        serde_json::from_value::<InspectorAtom>(encoded).is_err(),
        "standalone inspector props should enforce aggregate collection totals"
    );

    let atom = QuickFilterAtom {
        id: control_id("filter"),
        label: text("too-many-total-items"),
        options: options_at_collection_limit(),
        selected: vec![option_value("option-0")],
        action: action("filter_status"),
    };
    let encoded = serde_json::to_value(&atom).expect("quick filter encodes");
    assert!(
        serde_json::from_value::<QuickFilterAtom>(encoded).is_err(),
        "standalone quick filter props should enforce aggregate collection totals"
    );
}

#[test]
fn generated_lens_rejects_oversized_collections_during_deserialization() {
    let rows = (0..=MAX_LENS_COLLECTION_ITEMS)
        .map(|_| json!({ "cells": [] }))
        .collect::<Vec<_>>();
    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "too-wide",
            "atom": {
                "kind": "sheet",
                "props": {
                    "title": "too-wide",
                    "rows": rows
                }
            }
        }
    });

    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_err(),
        "oversized collections should fail while decoding"
    );
}

#[test]
fn neighborhood_graph_rejects_dangling_and_duplicate_edges() {
    let graph_with_dangling_edge = NeighborhoodGraphAtom {
        nodes: vec![GraphNode {
            id: handle("ada"),
            label: text("Ada"),
        }],
        edges: vec![GraphEdge {
            from: handle("ada"),
            to: handle("missing"),
            label: text("knows"),
        }],
    };

    assert!(
        GeneratedLens::new(LensNode::new(
            id("root"),
            LensAtom::NeighborhoodGraph(graph_with_dangling_edge.clone()),
        ))
        .is_err(),
        "dangling graph edges should be rejected"
    );

    let encoded = serde_json::to_value(LensAtom::NeighborhoodGraph(
        graph_with_dangling_edge.clone(),
    ))
    .expect("atom encodes");
    assert!(
        serde_json::from_value::<LensAtom>(encoded).is_err(),
        "standalone graph atoms should reject dangling edges"
    );

    let encoded = serde_json::to_value(&graph_with_dangling_edge).expect("graph encodes");
    assert!(
        serde_json::from_value::<NeighborhoodGraphAtom>(encoded).is_err(),
        "standalone graph props should reject dangling edges"
    );

    let graph_with_duplicate_nodes = NeighborhoodGraphAtom {
        nodes: vec![
            GraphNode {
                id: handle("ada"),
                label: text("Ada"),
            },
            GraphNode {
                id: handle("ada"),
                label: text("Ada duplicate"),
            },
        ],
        edges: Vec::new(),
    };

    assert!(
        GeneratedLens::new(LensNode::new(
            id("root"),
            LensAtom::NeighborhoodGraph(graph_with_duplicate_nodes.clone()),
        ))
        .is_err(),
        "duplicate graph nodes should be rejected"
    );

    let encoded = serde_json::to_value(&graph_with_duplicate_nodes).expect("graph encodes");
    assert!(
        serde_json::from_value::<NeighborhoodGraphAtom>(encoded).is_err(),
        "standalone graph props should reject duplicate node ids"
    );
}

#[test]
fn standalone_self_ui_actions_reject_oversized_args() {
    let args = (0..=MAX_LENS_COLLECTION_ITEMS)
        .map(|_| json!({ "type": "bool", "value": true }))
        .collect::<Vec<_>>();
    let attempted = json!({
        "command": "bulk_set",
        "args": args
    });

    assert!(
        serde_json::from_value::<SelfUiAction>(attempted).is_err(),
        "standalone self.ui actions should enforce arg bounds"
    );
}

#[test]
fn generated_lens_deserialize_rejects_unsupported_versions_and_oversized_text() {
    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION + 1,
        "root": {
            "id": "root",
            "fallbackText": "loading",
            "atom": {
                "kind": "throbber",
                "props": {
                    "label": "loading"
                }
            }
        }
    });

    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_err(),
        "unsupported kit version should be rejected"
    );

    let attempted = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "root": {
            "id": "root",
            "fallbackText": "loading",
            "atom": {
                "kind": "throbber",
                "props": {
                    "label": "x".repeat(MAX_LENS_TEXT_BYTES + 1)
                }
            }
        }
    });

    assert!(
        serde_json::from_value::<GeneratedLens>(attempted).is_err(),
        "oversized text should be rejected during deserialization"
    );
}
