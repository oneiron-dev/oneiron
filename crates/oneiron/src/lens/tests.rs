use std::collections::HashSet;

use proptest::prelude::*;
use serde_json::json;

use super::atom::MAX_LENS_TEXT_BYTES;
use super::validate::MAX_LENS_NODE_COUNT;
use super::wire_ids::{MAX_LENS_COLLECTION_ITEMS, MAX_LENS_TREE_DEPTH};
use super::*;
use crate::{Error, Result, claim::ScopedReadActorKey, entity_id::EntityId};

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
        state_bindings: Vec::new(),
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

use crate::test_util::entity as test_entity_id;

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
        LensAtom::ResultSet(GeneratedUiResultSetAtom {
            rows: Vec::new(),
            select_all: GeneratedUiResultSetSelectAll::Disabled {},
            action_bar: Vec::new(),
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
                actions: Vec::new(),
                state: GeneratedUiStateSnapshot::default(),
                lifecycle: GeneratedUiCardLifecycle::initial(),
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
            state_bindings: Vec::new(),
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
                    "catalog": "lens_atom_kit",
                    "lifecycle": { "phase": "active", "revision": 0 }
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
                    "catalog": "lens_atom_kit",
                    "lifecycle": { "phase": "active", "revision": 0 }
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
        "catalog": "lens_atom_kit",
        "lifecycle": { "phase": "active", "revision": 0 }
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

// ── ONE-1436 typed action/event backchannel + card lifecycle ─────────────────

fn state_key(value: &str) -> SelfUiStateKey {
    SelfUiStateKey::new(value).expect("valid state key")
}

fn toggle_atom(control: &str, command: &str) -> LensAtom {
    LensAtom::SelfUi(SelfUiControl::Toggle(ToggleControl {
        id: control_id(control),
        label: text(control),
        checked: false,
        action: action(command),
    }))
}

fn button_atom(control: &str, command: SelfUiAction) -> LensAtom {
    LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
        id: control_id(control),
        label: text(control),
        action: command,
    }))
}

fn card_root(children: Vec<LensNode>) -> LensNode {
    let mut root = LensNode::with_fallback_text(
        id("root"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Card"),
            rows: Vec::new(),
        }),
        text("Card"),
    );
    root.children = children;
    root
}

fn declaration(
    element: &str,
    action_name: &str,
    tier: GeneratedUiActionTier,
    declared: SelfUiAction,
) -> GeneratedUiActionDeclaration {
    GeneratedUiActionDeclaration {
        element_id: id(element),
        action_id: action_id(action_name),
        tier,
        action: declared,
    }
}

fn remind_toggle() -> LensNode {
    let mut toggle = LensNode::with_fallback_text(
        id("remind"),
        toggle_atom("remind", "reminder.toggle"),
        text("Remind me"),
    );
    toggle.state_bindings = vec![SelfUiBinding {
        state_key: state_key("remind"),
        property: SelfUiBindableProperty::Checked,
    }];
    toggle
}

/// One interactive card: a local-tier toggle bound to a declared boolean `$state` key.
fn remind_card() -> Result<GeneratedUiCard> {
    GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![remind_toggle()]))?,
        vec![declaration(
            "remind",
            "reminder.toggle",
            GeneratedUiActionTier::Local,
            action("reminder.toggle"),
        )],
        [(state_key("remind"), SelfUiStateValue::Bool(false))]
            .into_iter()
            .collect(),
    )
}

fn viewer_frame(card_id: &str) -> Result<(ScopedReadActorKey, LensRenderFrame)> {
    let viewer_key = actor_key("viewer");
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key.clone()])?;
    Ok((
        viewer_key,
        LensRenderFrame::new(render_id(card_id), principal),
    ))
}

fn toggle_event(patch: Vec<GeneratedUiStatePatch>) -> GeneratedUiActionEvent {
    GeneratedUiActionEvent {
        card_id: render_id("card-1"),
        element_id: id("remind"),
        action_id: action_id("reminder.toggle"),
        patch,
        occurred_at: 17,
    }
}

fn set_remind(value: bool) -> Vec<GeneratedUiStatePatch> {
    vec![GeneratedUiStatePatch::Replace {
        path: "/$state/remind".to_string(),
        value: SelfUiStateValue::Bool(value),
    }]
}

#[test]
fn typed_action_event_matches_declared_set() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);

    let card = remind_card()?;
    let render = card.render()?;
    assert_eq!(
        render.protocol_version, 2,
        "the wire version is bumped to 2"
    );
    assert_eq!(
        LENS_ATOM_KIT_VERSION, 3,
        "the atom-kit version moves to 3 for result_set"
    );
    assert_eq!(render.actions.len(), 1);
    assert_eq!(render.lifecycle.phase, GeneratedUiCardPhase::Active);

    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &toggle_event(set_remind(true)),
    )?;
    let GeneratedUiValidatedAction::Local { state, .. } = &validated else {
        panic!("a local declaration must resolve to a local state result");
    };
    assert_eq!(
        state.get(&state_key("remind")),
        Some(&SelfUiStateValue::Bool(true))
    );

    for (event, reason) in [
        (
            GeneratedUiActionEvent {
                action_id: action_id("reminder.dismiss"),
                ..toggle_event(Vec::new())
            },
            "undeclared action ids never resolve",
        ),
        (
            GeneratedUiActionEvent {
                element_id: id("root"),
                ..toggle_event(Vec::new())
            },
            "a declared action resolves only for its own element",
        ),
        (
            GeneratedUiActionEvent {
                element_id: id("ghost"),
                ..toggle_event(Vec::new())
            },
            "the named element must exist in the render",
        ),
        (
            GeneratedUiActionEvent {
                card_id: render_id("card-2"),
                ..toggle_event(Vec::new())
            },
            "an event must name the card it was rendered from",
        ),
    ] {
        assert!(
            frame
                .validate_action_event(
                    &scoped_read,
                    frame.principal(),
                    &render,
                    &render.state,
                    &event,
                )
                .is_err(),
            "{reason}"
        );
    }

    // An action id is declared exactly once: a duplicate never reaches a frame.
    let duplicated = declaration(
        "remind",
        "reminder.toggle",
        GeneratedUiActionTier::Local,
        action("reminder.toggle"),
    );
    assert!(
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![remind_toggle()]))?,
            vec![duplicated.clone(), duplicated],
            [(state_key("remind"), SelfUiStateValue::Bool(false))]
                .into_iter()
                .collect(),
        )
        .is_err(),
        "an action id must be declared exactly once"
    );

    // The embedded SelfUiAction must match the manifest entry exactly.
    let mut drifted = render.clone();
    drifted.actions[0].action = action("reminder.snooze");
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &drifted,
                &drifted.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "a declaration whose command differs from the element's embedded action is not resolvable"
    );
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_ok(),
        "the drift rejection is caused by the drift, not by the event"
    );

    // A declaration is only offered on a surface that can actually render its control.
    let degraded = card.render_for_surface(&GeneratedUiSurfaceCapabilities::text_only())?;
    assert!(
        degraded.actions.is_empty(),
        "a degraded element offers no action manifest entry"
    );

    Ok(())
}

#[test]
fn forged_action_and_actor_are_rejected() -> Result<()> {
    // Positive control: the honest shape parses, so the rejections below are the
    // forged field's doing and not a malformed baseline.
    let honest = json!({
        "cardId": "card-1",
        "elementId": "remind",
        "actionId": "reminder.toggle",
        "occurredAt": 1
    });
    let parsed: GeneratedUiActionEvent =
        serde_json::from_value(honest).expect("the honest event shape decodes");
    assert_eq!(parsed.occurred_at, 1);
    assert!(parsed.patch.is_empty());

    // Nothing about authority is expressible on the wire.
    for forged in [
        json!({ "actor": "user:root" }),
        json!({ "authority": "owner" }),
        json!({ "command": "vault.delete" }),
        json!({ "approval": true }),
        json!({ "emitter": "user:root" }),
        json!({ "source": "trusted" }),
        json!({ "script": "alert(1)" }),
        json!({ "url": "https://attacker.example" }),
    ] {
        let mut event = json!({
            "cardId": "card-1",
            "elementId": "remind",
            "actionId": "reminder.toggle",
            "occurredAt": 1
        });
        for (key, value) in forged.as_object().expect("forged field object") {
            event
                .as_object_mut()
                .expect("event object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiActionEvent>(event).is_err(),
            "action events must not carry {forged}"
        );
    }

    // The patch op is closed too: nothing rides alongside path/value.
    assert!(
        serde_json::from_value::<GeneratedUiStatePatch>(
            json!({ "op": "replace", "path": "/$state/remind", "value": {"type":"bool","value":true} })
        )
        .is_ok(),
        "the honest patch shape decodes"
    );
    assert!(
        serde_json::from_value::<GeneratedUiStatePatch>(json!({
            "op": "replace",
            "path": "/$state/remind",
            "value": {"type":"bool","value":true},
            "actor": "user:root"
        }))
        .is_err(),
        "state patches must not smuggle extra fields"
    );

    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = remind_card()?.render()?;

    // The emitter is stamped from the host frame, never supplied alongside the event.
    let intruder_key = actor_key("intruder");
    let intruder = LensPrincipalBinding::human_view(
        "intruder",
        intruder_key.clone(),
        vec![intruder_key.clone()],
    )?;
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                &intruder,
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "only the frame's own principal binding may stamp a validated action"
    );
    assert!(
        frame
            .validate_action_event(
                &vault.scoped_read(intruder_key),
                frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "the read key must be the acting principal's selected key"
    );
    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &toggle_event(Vec::new()),
    )?;
    assert_eq!(
        validated.emitter(),
        frame.principal(),
        "every validated action carries the host-bound emitter"
    );

    // A render minted for a different frame is not this frame's to adjudicate.
    let foreign_frame = LensRenderFrame::new(render_id("card-9"), frame.principal().clone());
    assert!(
        foreign_frame
            .validate_action_event(
                &scoped_read,
                foreign_frame.principal(),
                &render,
                &render.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "a render must belong to the frame validating its events"
    );

    // State paths are exact: undeclared keys, wrapper segments, and nesting all fail.
    for (path, reason) in [
        ("/$state/secret", "undeclared keys are rejected"),
        (
            "/$state/values/remind",
            "there is no values wrapper segment",
        ),
        ("/$state/remind/nested", "state paths are never nested"),
        ("/remind", "paths must be rooted at /$state/"),
        ("/$state/", "an empty key is not a state key"),
    ] {
        let event = toggle_event(vec![GeneratedUiStatePatch::Replace {
            path: path.to_string(),
            value: SelfUiStateValue::Bool(true),
        }]);
        assert!(
            frame
                .validate_action_event(
                    &scoped_read,
                    frame.principal(),
                    &render,
                    &render.state,
                    &event,
                )
                .is_err(),
            "{path}: {reason}"
        );
    }

    // Declared types are fixed, and remove/replace need a present key.
    let retyped = toggle_event(vec![GeneratedUiStatePatch::Replace {
        path: "/$state/remind".to_string(),
        value: SelfUiStateValue::Text(text("yes")),
    }]);
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &retyped,
            )
            .is_err(),
        "a patch may not change a declared $state type"
    );
    let removed_twice = toggle_event(vec![
        GeneratedUiStatePatch::Remove {
            path: "/$state/remind".to_string(),
        },
        GeneratedUiStatePatch::Replace {
            path: "/$state/remind".to_string(),
            value: SelfUiStateValue::Bool(true),
        },
    ]);
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &render,
                &render.state,
                &removed_twice,
            )
            .is_err(),
        "replace must address a present key"
    );

    // Archived cards are terminal for events too.
    let archived = GeneratedUiRender::interactive(
        render.card_id,
        render.catalog,
        render.root,
        render.nodes,
        render.actions,
        render.state,
        GeneratedUiCardLifecycle::new(
            GeneratedUiCardPhase::Archived,
            4,
            Some(GeneratedUiArchiveReason::Expired),
        )?,
    )?;
    assert!(
        frame
            .validate_action_event(
                &scoped_read,
                frame.principal(),
                &archived,
                &archived.state,
                &toggle_event(Vec::new()),
            )
            .is_err(),
        "an archived card accepts no further events"
    );

    Ok(())
}

#[test]
fn local_state_bind_round_trip() -> Result<()> {
    let card = remind_card()?;
    let card_value = serde_json::to_value(&card).expect("card encodes");
    assert_eq!(
        card_value["$state"]["remind"],
        json!({ "type": "bool", "value": false }),
        "$state is the flattened key map itself"
    );
    assert!(
        card_value["$state"].get("values").is_none(),
        "$state must never serialize a values wrapper"
    );
    assert_eq!(
        card_value["tree"]["root"]["children"][0]["$bind"][0],
        json!({ "stateKey": "remind", "property": "checked" }),
        "node bindings ride the literal $bind wire key"
    );
    let decoded: GeneratedUiCard = serde_json::from_value(card_value).expect("card decodes");
    assert_eq!(decoded, card);

    let render = decoded.render()?;
    let render_value = serde_json::to_value(&render).expect("render encodes");
    assert_eq!(
        render_value["$state"]["remind"],
        json!({"type":"bool","value":false})
    );
    assert_eq!(
        render_value["lifecycle"],
        json!({"phase":"active","revision":0})
    );
    assert_eq!(
        render_value["nodes"][1]["$bind"][0],
        json!({ "stateKey": "remind", "property": "checked" })
    );
    let render_round_trip: GeneratedUiRender =
        serde_json::from_value(render_value).expect("render decodes");
    assert_eq!(render_round_trip, render);

    // card_state_update carries the manifest, flattened $state, and lifecycle.
    let segments = render.segments();
    let Some(GeneratedUiSegment::CardStateUpdate(update)) = segments.last() else {
        panic!("the segment stream must end with card_state_update");
    };
    assert_eq!(update.data_model.actions, render.actions);
    assert_eq!(update.data_model.state, render.state);
    assert_eq!(update.data_model.lifecycle, render.lifecycle);
    assert_eq!(GeneratedUiRender::from_segments(&segments)?, render);

    // The hand-written LensNode seed carries $bind through both msgpack forms.
    let named = rmp_serde::to_vec_named(&card.tree).expect("msgpack encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&named).expect("msgpack decode"),
        card.tree
    );
    let positional = rmp_serde::to_vec(&card.tree).expect("positional msgpack encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&positional).expect("positional msgpack decode"),
        card.tree
    );

    // Bindings must reference a declared key whose type the property accepts.
    let bound = |binding: SelfUiBinding, value: SelfUiStateValue| -> Result<GeneratedUiCard> {
        let mut toggle = remind_toggle();
        toggle.state_bindings = vec![binding];
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![toggle]))?,
            vec![declaration(
                "remind",
                "reminder.toggle",
                GeneratedUiActionTier::Local,
                action("reminder.toggle"),
            )],
            [(state_key("remind"), value)].into_iter().collect(),
        )
    };
    assert!(
        bound(
            SelfUiBinding {
                state_key: state_key("nope"),
                property: SelfUiBindableProperty::Checked,
            },
            SelfUiStateValue::Bool(false),
        )
        .is_err(),
        "$bind must reference a declared $state key"
    );
    assert!(
        bound(
            SelfUiBinding {
                state_key: state_key("remind"),
                property: SelfUiBindableProperty::Text,
            },
            SelfUiStateValue::Bool(false),
        )
        .is_err(),
        "the bindable-property table is closed over value types"
    );

    // $bind belongs to controls only.
    let mut plain =
        LensNode::with_fallback_text(id("note"), LensAtom::StatusDot(status()), text("note"));
    plain.state_bindings = vec![SelfUiBinding {
        state_key: state_key("remind"),
        property: SelfUiBindableProperty::Checked,
    }];
    assert!(
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![plain]))?,
            Vec::new(),
            [(state_key("remind"), SelfUiStateValue::Bool(false))]
                .into_iter()
                .collect(),
        )
        .is_err(),
        "$bind descriptors are only valid on self.ui controls"
    );

    // There is no evaluator: computed/expression keys are not part of the closed shape.
    let bare = json!({
        "protocolVersion": GENERATED_UI_WIRE_VERSION,
        "catalog": "lens_atom_kit",
        "cardId": "card-1",
        "tree": { "kit_version": LENS_ATOM_KIT_VERSION, "root": {
            "id": "root",
            "atom": { "kind": "throbber", "props": { "label": "loading" } },
            "fallbackText": "loading"
        }}
    });
    assert!(
        serde_json::from_value::<GeneratedUiCard>(bare.clone()).is_ok(),
        "the baseline card without interactivity still decodes"
    );
    for evaluator_key in ["$computed", "$expr", "$script"] {
        let mut attempted = bare.clone();
        attempted.as_object_mut().expect("card object").insert(
            evaluator_key.to_string(),
            json!({ "remind": "state.remind" }),
        );
        assert!(
            serde_json::from_value::<GeneratedUiCard>(attempted).is_err(),
            "{evaluator_key} is not a generated-ui field"
        );
    }

    Ok(())
}

#[test]
fn action_tiers_do_not_auto_forward() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(11);
    put_person(&vault, &target_id)?;

    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);
    frame.mint_backing_ref(
        &scoped_read,
        handle("selected-person"),
        LensHandleRole::ActionTarget,
        backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;

    let remember = SelfUiAction {
        command: action_id("remember"),
        args: vec![SelfUiValue::Handle(handle("selected-person"))],
    };
    let summarize = SelfUiAction {
        command: action_id("summarize"),
        args: vec![SelfUiValue::Text(text("today"))],
    };

    let card = GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![
            remind_toggle(),
            LensNode::with_fallback_text(
                id("save"),
                button_atom("save", remember.clone()),
                text("Save"),
            ),
            LensNode::with_fallback_text(
                id("ask"),
                button_atom("ask", summarize.clone()),
                text("Ask"),
            ),
        ]))?,
        vec![
            declaration(
                "remind",
                "reminder.toggle",
                GeneratedUiActionTier::Local,
                action("reminder.toggle"),
            ),
            declaration(
                "save",
                "remember",
                GeneratedUiActionTier::DeterministicTool,
                remember.clone(),
            ),
            declaration(
                "ask",
                "summarize",
                GeneratedUiActionTier::ModelRoundTrip,
                summarize,
            ),
        ],
        [(state_key("remind"), SelfUiStateValue::Bool(false))]
            .into_iter()
            .collect(),
    )?;
    let render = card.render()?;

    let event = |element: &str, action_name: &str, patch: Vec<GeneratedUiStatePatch>| {
        GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id(element),
            action_id: action_id(action_name),
            patch,
            occurred_at: 7,
        }
    };
    let validate = |event: &GeneratedUiActionEvent| {
        frame.validate_action_event(
            &scoped_read,
            frame.principal(),
            &render,
            &render.state,
            event,
        )
    };

    // local: the typed state snapshot moves, and nothing else does.
    let local = validate(&event("remind", "reminder.toggle", set_remind(true)))?;
    let GeneratedUiValidatedAction::Local { state, .. } = &local else {
        panic!("the local tier must stay local");
    };
    assert_eq!(
        state.get(&state_key("remind")),
        Some(&SelfUiStateValue::Bool(true))
    );

    // deterministic_tool: a typed existing-verb trigger, still behind the write chokepoint.
    let deterministic = validate(&event("save", "remember", Vec::new()))?;
    let GeneratedUiValidatedAction::DeterministicTool {
        action: approved, ..
    } = &deterministic
    else {
        panic!("the deterministic tier must yield an approved action");
    };
    assert_eq!(approved.command().as_str(), "remember");
    let LensApprovedActionArg::BackingRef(backing_ref) = &approved.args()[0] else {
        panic!("handle args resolve through the host backing table");
    };
    assert_eq!(backing_ref.target().entity_id(), &target_id);
    let mediated = approved
        .clone()
        .into_host_mediated_write(LensGateWriteChokepoint::EvaluateGate);
    assert_eq!(
        mediated.chokepoint(),
        LensGateWriteChokepoint::EvaluateGate,
        "a deterministic write still has to be routed through a named gate chokepoint"
    );

    // model_round_trip: exactly the four structured callback fields, and no tool call.
    let model = validate(&event("ask", "summarize", Vec::new()))?;
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = &model else {
        panic!("the model tier must yield an agent callback");
    };
    assert_eq!(callback.action_name.as_str(), "summarize");
    assert_eq!(
        callback.resolved_params,
        vec![LensApprovedActionArg::Text(text("today"))]
    );
    assert_eq!(callback.source_card_id, render_id("card-1"));
    assert_eq!(callback.source_element_id, id("ask"));

    // Trigger tiers take their arguments from the declaration alone.
    for element_and_action in [("save", "remember"), ("ask", "summarize")] {
        assert!(
            validate(&event(
                element_and_action.0,
                element_and_action.1,
                set_remind(true)
            ))
            .is_err(),
            "only local actions may carry a $state patch"
        );
    }

    // And a local action can never reach the host backing table.
    assert!(
        GeneratedUiCard::card(
            render_id("card-1"),
            card_root(vec![LensNode::with_fallback_text(
                id("save"),
                button_atom("save", remember.clone()),
                text("Save"),
            )]),
        )?
        .with_interactivity(
            vec![declaration(
                "save",
                "remember",
                GeneratedUiActionTier::Local,
                remember,
            )],
            GeneratedUiStateSnapshot::default(),
        )
        .is_err(),
        "a local action may not declare host handle arguments"
    );

    Ok(())
}

#[test]
fn card_lifecycle_transition_table() -> Result<()> {
    use GeneratedUiArchiveReason::{Completed, Dismissed, Expired};
    use GeneratedUiCardPhase::{Active, Archived, Generating, Responded};

    // The canonical sequence, with the revision advancing on every hop.
    let generating = GeneratedUiCardLifecycle::new(Generating, 0, None)?;
    let active = generating.transition(Active, None)?;
    let responded = active.transition(Responded, None)?;
    let archived = responded.transition(Archived, Some(Completed))?;
    assert_eq!(
        (active.revision, responded.revision, archived.revision),
        (1, 2, 3)
    );
    assert_eq!(archived.archive_reason, Some(Completed));

    // Completion and expiry are archive reasons, not competing phases.
    let expired = active.transition(Archived, Some(Expired))?;
    assert_eq!(expired.phase, Archived);
    assert_eq!(expired.archive_reason, Some(Expired));

    // Archived is terminal.
    for phase in [Generating, Active, Responded, Archived] {
        assert!(archived.transition(phase, None).is_err());
        assert!(archived.transition(phase, Some(Dismissed)).is_err());
    }

    // Backwards and self transitions are illegal.
    assert!(responded.transition(Active, None).is_err());
    assert!(active.transition(Generating, None).is_err());
    assert!(active.transition(Active, None).is_err());

    // Archive reasons are required on archived and forbidden everywhere else.
    assert!(active.transition(Archived, None).is_err());
    assert!(active.transition(Responded, Some(Completed)).is_err());
    assert!(GeneratedUiCardLifecycle::new(Archived, 1, None).is_err());
    assert!(GeneratedUiCardLifecycle::new(Active, 1, Some(Completed)).is_err());

    // The same table holds on the wire.
    assert!(
        serde_json::from_value::<GeneratedUiCardLifecycle>(
            json!({ "phase": "archived", "revision": 2 })
        )
        .is_err(),
        "archived lifecycles must name their reason"
    );
    assert!(
        serde_json::from_value::<GeneratedUiCardLifecycle>(
            json!({ "phase": "active", "revision": 2, "archiveReason": "expired" })
        )
        .is_err(),
        "archive reasons never ride a non-archived phase"
    );

    // The initial completed tree emits active; later revisions ride the same stream.
    let render = remind_card()?.render()?;
    assert_eq!(render.lifecycle, GeneratedUiCardLifecycle::initial());
    let responded_render = GeneratedUiRender::interactive(
        render.card_id.clone(),
        render.catalog,
        render.root.clone(),
        render.nodes.clone(),
        render.actions.clone(),
        render.state.clone(),
        render.lifecycle.transition(Responded, None)?,
    )?;
    let segments = responded_render.segments();
    let update =
        serde_json::to_value(segments.last().expect("card_state_update")).expect("segment encodes");
    assert_eq!(
        update["payload"]["dataModel"]["lifecycle"],
        json!({ "phase": "responded", "revision": 1 }),
        "the lifecycle revision is observable in card_state_update"
    );
    assert_eq!(
        GeneratedUiRender::from_segments(&segments)?,
        responded_render
    );

    Ok(())
}

#[test]
fn card_lifecycle_is_required_on_the_wire_and_gated_at_validate() -> Result<()> {
    use GeneratedUiArchiveReason::{Dismissed, Expired};
    use GeneratedUiCardPhase::{Active, Archived, Responded};

    let render = remind_card()?.render()?;
    let archived_lifecycle = render
        .lifecycle
        .transition(Responded, None)?
        .transition(Archived, Some(Dismissed))?;
    let archived = GeneratedUiRender::interactive(
        render.card_id.clone(),
        render.catalog,
        render.root.clone(),
        render.nodes.clone(),
        render.actions.clone(),
        render.state,
        archived_lifecycle.clone(),
    )?;
    let data_model = |lifecycle: GeneratedUiCardLifecycle| GeneratedUiDataModel {
        root: archived.root.clone(),
        node_count: archived.nodes.len(),
        catalog: archived.catalog,
        actions: archived.actions.clone(),
        state: archived.state.clone(),
        lifecycle,
    };
    let without_lifecycle = |value: &serde_json::Value| {
        let mut object = value
            .as_object()
            .expect("v2 payloads encode as objects")
            .clone();
        object
            .remove("lifecycle")
            .expect("lifecycle rides the v2 wire");
        serde_json::Value::Object(object)
    };

    // An archived card whose lifecycle is missing must be rejected at parse. Healing it
    // to active/rev 0 would resurrect a terminal card at a closed-schema boundary.
    let encoded_render = serde_json::to_value(&archived).expect("render encodes");
    assert_eq!(encoded_render["lifecycle"]["phase"], json!("archived"));
    assert!(
        serde_json::from_value::<GeneratedUiRender>(without_lifecycle(&encoded_render)).is_err(),
        "a render without a lifecycle must not parse as active/rev 0"
    );
    let encoded_model =
        serde_json::to_value(data_model(archived_lifecycle)).expect("data model encodes");
    assert!(
        serde_json::from_value::<GeneratedUiDataModel>(without_lifecycle(&encoded_model)).is_err(),
        "a data model without a lifecycle must not parse as active/rev 0"
    );

    // The engine may not emit lifecycles its own reader rejects: both halves of the
    // phase/reason invariant are gated at validate, not only at parse.
    for smuggled in [
        GeneratedUiCardLifecycle {
            phase: Active,
            revision: 1,
            archive_reason: Some(Expired),
        },
        GeneratedUiCardLifecycle {
            phase: Archived,
            revision: 1,
            archive_reason: None,
        },
    ] {
        let mut forged_render = archived.clone();
        forged_render.lifecycle = smuggled.clone();
        assert!(
            forged_render.validate().is_err(),
            "render validate must gate the lifecycle phase/reason invariant"
        );
        assert!(
            data_model(smuggled).validate().is_err(),
            "data model validate must gate the lifecycle phase/reason invariant"
        );
    }

    Ok(())
}

// ── ONE-1438 universal select-to-agent ───────────────────────────────────────

fn binding(name: &str, role: LensHandleRole) -> LensHandleRef {
    LensHandleRef {
        name: handle(name),
        role,
    }
}

/// A two-node render whose leaf advertises `bindings`. Selection needs nothing else
/// from a card: the node, its declared handles, and the frame's own backing table.
fn selectable_render(
    card: &str,
    atom: &str,
    bindings: Vec<LensHandleRef>,
) -> Result<GeneratedUiRender> {
    let mut leaf = generated_ui_node(atom, Some("root"), &[]);
    leaf.bindings = bindings;
    GeneratedUiRender::new(
        render_id(card),
        GeneratedUiCatalog::LensAtomKit,
        id("root"),
        vec![generated_ui_node("root", None, &[atom]), leaf],
    )
}

fn selection(card: &str, atom: &str, name: &str) -> LensAtomSelectionRequest {
    LensAtomSelectionRequest {
        card_id: render_id(card),
        atom_id: id(atom),
        handle: handle(name),
    }
}

/// A frame holding one host-minted `visible-set` row over a readable person.
fn selection_fixture(
    vault: &crate::Vault,
    target_id: &EntityId,
    role: LensHandleRole,
) -> Result<(ScopedReadActorKey, LensRenderFrame, String)> {
    put_person(vault, target_id)?;
    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    let target = backing_target_for(vault, target_id, LensBackingTargetKind::Entity)?;
    let short_ref = target.short_ref();
    frame.mint_backing_ref(
        &vault.scoped_read(viewer_key.clone()),
        handle("visible-set"),
        role,
        target,
    )?;
    Ok((viewer_key, frame, short_ref))
}

#[test]
fn selecting_a_bound_atom_returns_structured_read_reach() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(12);
    let (viewer_key, frame, expected_short_ref) =
        selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "people", "visible-set"),
    )?;

    assert_eq!(read_handle.render_id(), &render_id("card-1"));
    assert_eq!(read_handle.atom_id(), &id("people"));
    assert_eq!(read_handle.reach(), LensReadReach::EntitySet);
    assert_eq!(read_handle.target_kind(), LensBackingTargetKind::Entity);
    assert_eq!(
        read_handle.short_ref(),
        expected_short_ref,
        "the short ref is a locator the principal already resolves under ScopedRead"
    );

    // The payload is exactly that metadata: a locator, never the stored body it locates.
    let encoded = serde_json::to_value(&read_handle).expect("read handle encodes");
    let mut keys = encoded
        .as_object()
        .expect("read handles encode as objects")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "atomId",
            "backingToken",
            "reach",
            "renderId",
            "shortRef",
            "targetKind"
        ]
    );
    let entity_hex = target_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let flat = encoded.to_string();
    for leaked in ["person", entity_hex.as_str(), "screenshot", "authority"] {
        assert!(
            !flat.contains(leaked),
            "a read handle must not disclose {leaked}"
        );
    }

    // Serialize-only: a read handle is engine-issued and can never be re-submitted.
    assert!(
        serde_json::from_value::<serde_json::Value>(encoded)
            .expect("json round trips as a value")
            .is_object(),
        "the encoded shape stays plain data with no client-side constructor"
    );

    Ok(())
}

#[test]
fn selection_requests_never_carry_a_target() {
    // Positive control: the honest shape is three names and nothing else.
    let honest = json!({
        "cardId": "card-1",
        "atomId": "people",
        "handle": "visible-set"
    });
    let parsed: LensAtomSelectionRequest =
        serde_json::from_value(honest.clone()).expect("the honest selection shape decodes");
    assert_eq!(parsed.card_id, render_id("card-1"));
    assert_eq!(parsed.atom_id, id("people"));
    assert_eq!(parsed.handle, handle("visible-set"));

    for forged in [
        json!({ "entityId": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "body": "the note says ..." }),
        json!({ "screenshot": "data:image/png;base64,AAAA" }),
        json!({ "writeToken": "tok-1" }),
        json!({ "authority": "owner" }),
        json!({ "query": "claim.subject == person" }),
        json!({ "shortRef": "ab:01" }),
        json!({ "target": { "entityId": "x" } }),
        json!({ "role": "action_target" }),
        json!({ "backingToken": { "render_id": "card-1", "ref_id": "ref-0" } }),
    ] {
        let mut request = honest.clone();
        for (key, value) in forged.as_object().expect("forged field object") {
            request
                .as_object_mut()
                .expect("request object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "atom selections must not carry {forged}"
        );
    }

    // Missing names are not healed either: all three are required.
    for absent in ["cardId", "atomId", "handle"] {
        let mut request = honest.clone();
        request
            .as_object_mut()
            .expect("request object")
            .remove(absent);
        assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "a selection without {absent} must not decode"
        );
    }
}

#[test]
fn selection_proves_one_resolution_path() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(13);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &render,
                &selection("card-1", "people", "visible-set")
            )
            .is_ok(),
        "the honest triple resolves, so every rejection below is the forgery's doing"
    );

    // Arbitrary ids never sweep past the render: only the exact triple resolves.
    for (card, atom, name, reason) in [
        (
            "card-2",
            "people",
            "visible-set",
            "a selection names its own card",
        ),
        (
            "card-1",
            "ghost",
            "visible-set",
            "the atom must exist in the render",
        ),
        (
            "card-1",
            "root",
            "visible-set",
            "another node's binding is not this one's",
        ),
        (
            "card-1",
            "people",
            "cl999",
            "an unadvertised handle resolves to nothing",
        ),
        (
            "card-1",
            "people",
            "visible-person",
            "a host row the node never advertised is not selectable",
        ),
    ] {
        assert!(
            frame
                .select_atom(&scoped_read, &render, &selection(card, atom, name))
                .is_err(),
            "{reason}"
        );
    }

    // A node that advertises the same handle twice is ambiguous about its reach.
    let duplicated = selectable_render(
        "card-1",
        "people",
        vec![
            binding("visible-set", LensHandleRole::EntitySet),
            binding("visible-set", LensHandleRole::Timeline),
        ],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &duplicated,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "duplicate node bindings must not resolve to either reach"
    );

    // The node's declared role has to be the role the host actually bound.
    let role_swapped = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::Timeline)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &role_swapped,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "a node cannot relabel the reach of a host-minted row"
    );

    // A render this frame never emitted is not this frame's to select from.
    let foreign_render = selectable_render(
        "card-9",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &foreign_render,
                &selection("card-9", "people", "visible-set")
            )
            .is_err(),
        "a render must belong to the frame resolving its selections"
    );

    // Another principal's read key never drives this frame.
    assert!(
        frame
            .select_atom(
                &vault.scoped_read(actor_key("intruder")),
                &render,
                &selection("card-1", "people", "visible-set"),
            )
            .is_err(),
        "selections resolve only under the acting principal's selected read key"
    );

    Ok(())
}

#[test]
fn action_target_bindings_never_become_read_handles() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(14);
    let (viewer_key, frame, _) =
        selection_fixture(&vault, &target_id, LensHandleRole::ActionTarget)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::ActionTarget)],
    )?;
    assert!(
        frame
            .select_atom(
                &scoped_read,
                &render,
                &selection("card-1", "people", "visible-set")
            )
            .is_err(),
        "an action-target binding is reach for the action backchannel, not a selection"
    );
    assert!(
        LensReadReach::try_from(LensHandleRole::ActionTarget).is_err(),
        "the read-reach enum excludes ActionTarget by construction"
    );
    for (role, reach) in [
        (LensHandleRole::ClaimSet, LensReadReach::ClaimSet),
        (LensHandleRole::EntitySet, LensReadReach::EntitySet),
        (LensHandleRole::Timeline, LensReadReach::Timeline),
        (LensHandleRole::QueryResult, LensReadReach::QueryResult),
    ] {
        assert_eq!(LensReadReach::try_from(role)?, reach);
    }

    // The same row still resolves through the action path it was minted for.
    let approved = frame.approve_action(
        &scoped_read,
        &SelfUiAction {
            command: action_id("remember"),
            args: vec![SelfUiValue::Handle(handle("visible-set"))],
        },
    )?;
    assert!(
        matches!(&approved.args()[0], LensApprovedActionArg::BackingRef(_)),
        "selection and approval stay separate paths over one backing table"
    );

    Ok(())
}

#[test]
fn read_handles_reresolve_and_never_widen() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(15);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    let render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "people", "visible-set"),
    )?;

    let resolved = frame.resolve_read_handle(&scoped_read, &render, &read_handle)?;
    assert_eq!(resolved.target().entity_id(), &target_id);
    assert_eq!(resolved.handle(), &handle("visible-set"));

    // Switching principals fails the handle rather than widening its scope.
    assert!(
        frame
            .resolve_read_handle(
                &vault.scoped_read(actor_key("intruder")),
                &render,
                &read_handle
            )
            .is_err(),
        "an issued handle is re-checked under the acting principal at use time"
    );

    // A later render revision that drops or relabels the binding revokes the handle.
    for (later, reason) in [
        (
            selectable_render("card-1", "people", Vec::new())?,
            "a node that stopped advertising the handle stops honoring it",
        ),
        (
            selectable_render(
                "card-1",
                "people",
                vec![binding("visible-set", LensHandleRole::ActionTarget)],
            )?,
            "a relabelled binding cannot launder read reach into action reach",
        ),
        (
            selectable_render(
                "card-1",
                "elsewhere",
                vec![binding("visible-set", LensHandleRole::EntitySet)],
            )?,
            "the handle's own atom must still carry the binding",
        ),
    ] {
        assert!(
            frame
                .resolve_read_handle(&scoped_read, &later, &read_handle)
                .is_err(),
            "{reason}"
        );
    }

    // A target whose stored content moved no longer hydrates the short ref the handle
    // was issued against: the handle fails rather than following the entity forward.
    vault.put_entity(
        &target_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 2, end: 2 },
        2,
        b"person, revised",
    )?;
    assert!(
        frame
            .resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "a stale short ref stops resolving instead of widening onto the new content"
    );

    // A twin frame over the same render id never host-minted that token. A twin that
    // *did* mint one is the harder case, covered next.
    let twin = LensRenderFrame::new(render_id("card-1"), frame.principal().clone());
    assert!(
        twin.resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "a token is only resolvable through the backing table that minted it"
    );

    Ok(())
}

/// A frame is not a capability. Render ids derive from card ids, so re-rendering a card
/// yields a *second* frame with the same render id, and `ref-{len}` numbers every
/// backing table from zero — a later frame's first mint carries the very token an older
/// handle holds. Nothing in the token separates the two rows, so re-resolution has to
/// re-prove the metadata the handle recorded at issue time.
#[test]
fn stale_handles_never_launder_onto_a_later_frames_row() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let issued_id = test_entity_id(18);
    let other_id = test_entity_id(19);
    put_person(&vault, &other_id)?;

    let (viewer_key, frame, issued_short_ref) =
        selection_fixture(&vault, &issued_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let entity_set_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )?;
    let action_target_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::ActionTarget)],
    )?;
    let timeline_render = selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::Timeline)],
    )?;
    let read_handle = frame.select_atom(
        &scoped_read,
        &entity_set_render,
        &selection("card-1", "people", "visible-set"),
    )?;

    // Each twin re-mints the issued handle's token under a row it never proved: a
    // different target, action reach, or different read reach over the same target.
    for (role, target_id, render, reason) in [
        (
            LensHandleRole::EntitySet,
            &other_id,
            &entity_set_render,
            "a same-named row over a different entity is not the row the handle proved",
        ),
        (
            LensHandleRole::ActionTarget,
            &issued_id,
            &action_target_render,
            "a row rebound as an action target never keeps honoring a read handle",
        ),
        (
            LensHandleRole::Timeline,
            &issued_id,
            &timeline_render,
            "a row that kept the target but changed reach cannot re-scope an issued handle",
        ),
    ] {
        let (_, mut twin) = viewer_frame("card-1")?;
        let token = twin.mint_backing_ref(
            &scoped_read,
            handle("visible-set"),
            role,
            backing_target_for(&vault, target_id, LensBackingTargetKind::Entity)?,
        )?;
        assert_eq!(
            &token,
            frame.backing_refs()[0].token(),
            "the twin's first mint collides with the token the issued handle carries, \
             so the rejection below is the metadata re-proof's doing"
        );
        assert!(
            twin.resolve_read_handle(&scoped_read, render, &read_handle)
                .is_err(),
            "{reason}"
        );
    }

    // The twin frames are healthy hosts, not broken ones: reach a twin issues itself
    // resolves through it, and it points where that twin bound it.
    let (_, mut twin) = viewer_frame("card-1")?;
    twin.mint_backing_ref(
        &scoped_read,
        handle("visible-set"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault, &other_id, LensBackingTargetKind::Entity)?,
    )?;
    let reissued = twin.select_atom(
        &scoped_read,
        &entity_set_render,
        &selection("card-1", "people", "visible-set"),
    )?;
    assert_eq!(
        twin.resolve_read_handle(&scoped_read, &entity_set_render, &reissued)?
            .target()
            .entity_id(),
        &other_id,
    );
    assert_eq!(read_handle.short_ref(), issued_short_ref);
    assert_ne!(
        reissued.short_ref(),
        read_handle.short_ref(),
        "the two handles differ only in the metadata re-resolution now re-proves"
    );

    Ok(())
}

#[test]
fn selected_read_context_rides_a_callback_without_becoming_approval() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let target_id = test_entity_id(16);
    let (viewer_key, frame, _) = selection_fixture(&vault, &target_id, LensHandleRole::EntitySet)?;
    let scoped_read = vault.scoped_read(viewer_key);

    // One node is both the model-tier control and the selectable atom.
    let summarize = SelfUiAction {
        command: action_id("summarize"),
        args: vec![SelfUiValue::Text(text("today"))],
    };
    let mut ask = LensNode::with_fallback_text(
        id("ask"),
        button_atom("ask", summarize.clone()),
        text("Ask"),
    );
    ask.bindings = vec![binding("visible-set", LensHandleRole::EntitySet)];
    let render = GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![ask]))?,
        vec![declaration(
            "ask",
            "summarize",
            GeneratedUiActionTier::ModelRoundTrip,
            summarize,
        )],
        GeneratedUiStateSnapshot::default(),
    )?
    .render()?;

    let read_handle = frame.select_atom(
        &scoped_read,
        &render,
        &selection("card-1", "ask", "visible-set"),
    )?;
    let validated = frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        &render,
        &render.state,
        &GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id("ask"),
            action_id: action_id("summarize"),
            patch: Vec::new(),
            occurred_at: 3,
        },
    )?;
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = &validated else {
        panic!("the model tier must yield an agent callback");
    };
    assert!(
        callback.selected_context.is_empty(),
        "a validated action carries no selection the host did not attach"
    );

    let carried = frame.with_selected_context(
        &scoped_read,
        &render,
        callback.clone(),
        vec![read_handle.clone()],
    )?;
    assert_eq!(carried.selected_context, vec![read_handle.clone()]);
    assert_eq!(
        carried.resolved_params,
        vec![LensApprovedActionArg::Text(text("today"))],
        "context never becomes a resolved parameter"
    );
    assert_eq!(carried.action_name.as_str(), "summarize");

    // A callback minted by another render is not this frame's to enrich.
    let foreign_callback = GeneratedUiAgentCallback {
        source_card_id: render_id("card-9"),
        ..carried
    };
    assert!(
        frame
            .with_selected_context(
                &scoped_read,
                &render,
                foreign_callback,
                vec![read_handle.clone()]
            )
            .is_err(),
        "selected context must ride a callback from this render frame"
    );

    // Attaching is a re-proof: a handle the current render no longer honors is refused.
    assert!(
        frame
            .with_selected_context(
                &scoped_read,
                &selectable_render("card-1", "ask", Vec::new())?,
                callback.clone(),
                vec![read_handle],
            )
            .is_err(),
        "context is re-resolved at attach time, never trusted from an earlier turn"
    );

    Ok(())
}

#[test]
fn bound_control_values_stay_inside_their_declared_domain() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key);

    let mode = || {
        let mut node = LensNode::with_fallback_text(
            id("mode"),
            LensAtom::SelfUi(SelfUiControl::Select(SelectControl {
                id: control_id("mode"),
                label: text("Mode"),
                options: ["fast", "careful"]
                    .into_iter()
                    .map(|value| SelfUiOption {
                        value: option_value(value),
                        label: text(value),
                    })
                    .collect(),
                selected: None,
                action: action("mode.pick"),
            })),
            text("Mode"),
        );
        node.state_bindings = vec![SelfUiBinding {
            state_key: state_key("mode"),
            property: SelfUiBindableProperty::Selected,
        }];
        node
    };
    let level = || {
        let mut node = LensNode::with_fallback_text(
            id("level"),
            LensAtom::SelfUi(SelfUiControl::Slider(SliderControl {
                id: control_id("level"),
                label: text("Level"),
                min: finite(0.0),
                max: finite(10.0),
                step: finite(0.5),
                value: finite(5.0),
                action: action("level.set"),
            })),
            text("Level"),
        );
        node.state_bindings = vec![SelfUiBinding {
            state_key: state_key("level"),
            property: SelfUiBindableProperty::Value,
        }];
        node
    };
    let card = |chosen: &str, at: f64| -> Result<GeneratedUiCard> {
        GeneratedUiCard::interactive(
            render_id("card-1"),
            GeneratedLens::new(card_root(vec![mode(), level()]))?,
            vec![
                declaration(
                    "mode",
                    "mode.pick",
                    GeneratedUiActionTier::Local,
                    action("mode.pick"),
                ),
                declaration(
                    "level",
                    "level.set",
                    GeneratedUiActionTier::Local,
                    action("level.set"),
                ),
            ],
            [
                (
                    state_key("mode"),
                    SelfUiStateValue::Token(option_value(chosen)),
                ),
                (state_key("level"), SelfUiStateValue::Number(finite(at))),
            ]
            .into_iter()
            .collect(),
        )
    };

    // Assembly already refuses a bound value the control itself could never hold.
    assert!(card("fast", 5.0).is_ok(), "the honest card assembles");
    for (chosen, at, reason) in [
        (
            "sloppy",
            5.0,
            "a bound token must be one of the control's own options",
        ),
        (
            "fast",
            5.25,
            "a bound number must land on the slider's step grid",
        ),
        (
            "fast",
            11.0,
            "a bound number must stay inside the slider's range",
        ),
        ("fast", -0.5, "the range is closed below too"),
    ] {
        assert!(card(chosen, at).is_err(), "{reason}");
    }

    // And the same domain holds against a client patch, where the type agrees but the
    // value does not: type equality was never the whole conformance rule.
    let render = card("fast", 5.0)?.render()?;
    let event = |element: &str, action_name: &str, patch: Vec<GeneratedUiStatePatch>| {
        GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id(element),
            action_id: action_id(action_name),
            patch,
            occurred_at: 5,
        }
    };
    let validate = |event: &GeneratedUiActionEvent| {
        frame.validate_action_event(
            &scoped_read,
            frame.principal(),
            &render,
            &render.state,
            event,
        )
    };
    let replace = |key: &str, value: SelfUiStateValue| {
        vec![GeneratedUiStatePatch::Replace {
            path: format!("/$state/{key}"),
            value,
        }]
    };

    assert!(
        validate(&event(
            "mode",
            "mode.pick",
            replace("mode", SelfUiStateValue::Token(option_value("careful"))),
        ))
        .is_ok(),
        "an offered option is still selectable"
    );
    assert!(
        validate(&event(
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(7.5))),
        ))
        .is_ok(),
        "an on-grid number is still settable"
    );

    for (element, action_name, patch, reason) in [
        (
            "mode",
            "mode.pick",
            replace("mode", SelfUiStateValue::Token(option_value("sloppy"))),
            "a patch must not select an option the control never offered",
        ),
        (
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(5.25))),
            "a patch must not move a slider off its declared step",
        ),
        (
            "level",
            "level.set",
            replace("level", SelfUiStateValue::Number(finite(10.5))),
            "a patch must not move a slider past its declared max",
        ),
        (
            "mode",
            "mode.pick",
            vec![GeneratedUiStatePatch::Remove {
                path: "/$state/mode".to_string(),
            }],
            "a patch must not strand a bound control with no value",
        ),
    ] {
        assert!(
            validate(&event(element, action_name, patch)).is_err(),
            "{reason}"
        );
    }

    Ok(())
}

// ── ONE-1926 selectable result-set atom ──────────────────────────────────────

fn row_id(value: &str) -> LensResultSetRowId {
    LensResultSetRowId::new(value).expect("valid row id")
}

fn result_set_row(row: &str, target: &str) -> GeneratedUiResultSetRow {
    GeneratedUiResultSetRow {
        id: row_id(row),
        label: text(row),
        target_handle: handle(target),
    }
}

fn within_filter(predicate: &str) -> GeneratedUiResultSetSelectAll {
    GeneratedUiResultSetSelectAll::WithinFilter {
        predicate_handle: handle(predicate),
    }
}

fn result_set_atom(
    rows: Vec<GeneratedUiResultSetRow>,
    select_all: GeneratedUiResultSetSelectAll,
    action_bar: &[&str],
) -> GeneratedUiResultSetAtom {
    GeneratedUiResultSetAtom {
        rows,
        select_all,
        action_bar: action_bar.iter().map(|value| action_id(value)).collect(),
    }
}

/// One result-set node: the atom plus the backing handles *it* advertises.
fn result_set_node(
    node: &str,
    atom: GeneratedUiResultSetAtom,
    bindings: Vec<LensHandleRef>,
) -> LensNode {
    let mut node =
        LensNode::with_fallback_text(id(node), LensAtom::ResultSet(atom), text("Results"));
    node.bindings = bindings;
    node
}

fn archive_button() -> LensNode {
    LensNode::with_fallback_text(
        id("archive"),
        button_atom("archive", action("archive.selected")),
        text("Archive"),
    )
}

fn archive_declaration(tier: GeneratedUiActionTier) -> GeneratedUiActionDeclaration {
    declaration("archive", "archive", tier, action("archive.selected"))
}

/// The default result set: two claim rows, a host-declared select-all predicate, and an
/// action bar allowlisting the self.ui-hosted deterministic action next door.
fn claim_rows_bindings() -> Vec<LensHandleRef> {
    vec![
        binding("claim-a", LensHandleRole::ClaimSet),
        binding("claim-b", LensHandleRole::ClaimSet),
        binding("filter", LensHandleRole::QueryResult),
    ]
}

fn result_set_card_with(
    atom: GeneratedUiResultSetAtom,
    bindings: Vec<LensHandleRef>,
    actions: Vec<GeneratedUiActionDeclaration>,
) -> Result<GeneratedUiCard> {
    GeneratedUiCard::interactive(
        render_id("card-1"),
        GeneratedLens::new(card_root(vec![
            result_set_node("results", atom, bindings),
            archive_button(),
        ]))?,
        actions,
        GeneratedUiStateSnapshot::default(),
    )
}

fn result_set_card() -> Result<GeneratedUiCard> {
    result_set_card_with(
        result_set_atom(
            vec![
                result_set_row("row-1", "claim-a"),
                result_set_row("row-2", "claim-b"),
            ],
            within_filter("filter"),
            &["archive"],
        ),
        claim_rows_bindings(),
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )
}

/// A frame over `card-1` holding host-minted rows for two claims, one entity set, one
/// query-result predicate, and one timeline — one row per selectable reach.
fn result_set_fixture(
    vault: &crate::Vault,
) -> Result<(ScopedReadActorKey, LensRenderFrame, EntityId)> {
    let subject = test_entity_id(40);
    let claim_a = test_entity_id(41);
    let claim_b = test_entity_id(42);
    let people = test_entity_id(43);
    put_person(vault, &subject)?;
    put_profile_claim(vault, &claim_a, &subject)?;
    put_profile_claim(vault, &claim_b, &subject)?;
    put_person(vault, &people)?;

    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    let scoped_read = vault.scoped_read(viewer_key.clone());
    for (name, role, target, kind) in [
        (
            "claim-a",
            LensHandleRole::ClaimSet,
            &claim_a,
            LensBackingTargetKind::Claim,
        ),
        (
            "claim-b",
            LensHandleRole::ClaimSet,
            &claim_b,
            LensBackingTargetKind::Claim,
        ),
        (
            "people",
            LensHandleRole::EntitySet,
            &people,
            LensBackingTargetKind::Entity,
        ),
        (
            "filter",
            LensHandleRole::QueryResult,
            &people,
            LensBackingTargetKind::Entity,
        ),
        (
            "history",
            LensHandleRole::Timeline,
            &people,
            LensBackingTargetKind::Entity,
        ),
    ] {
        frame.mint_backing_ref(
            &scoped_read,
            handle(name),
            role,
            backing_target_for(vault, target, kind)?,
        )?;
    }
    Ok((viewer_key, frame, people))
}

fn explicit(rows: &[&str]) -> GeneratedUiResultSetSelection {
    GeneratedUiResultSetSelection::Explicit {
        row_ids: rows.iter().map(|value| row_id(value)).collect(),
    }
}

fn result_set_event(
    action_name: &str,
    selection: GeneratedUiResultSetSelection,
) -> GeneratedUiResultSetActionEvent {
    GeneratedUiResultSetActionEvent {
        action: GeneratedUiActionEvent {
            card_id: render_id("card-1"),
            element_id: id("archive"),
            action_id: action_id(action_name),
            patch: Vec::new(),
            occurred_at: 23,
        },
        selection,
    }
}

fn v2_only_root() -> LensNode {
    LensNode::with_fallback_text(
        id("root"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
        text("loading"),
    )
}

fn standalone_result_set_root() -> LensNode {
    result_set_node(
        "root",
        result_set_atom(
            vec![result_set_row("row-1", "claim-a")],
            within_filter("filter"),
            &[],
        ),
        vec![
            binding("claim-a", LensHandleRole::ClaimSet),
            binding("filter", LensHandleRole::QueryResult),
        ],
    )
}

#[test]
fn result_set_catalog_negotiates_v3_only() -> Result<()> {
    assert_eq!(LENS_ATOM_KIT_VERSION, 3, "result_set mints catalog v3");
    assert_eq!(
        GENERATED_LENS_ATOM_KINDS.last(),
        Some(&RESULT_SET_ATOM_KIND),
        "the wire name is appended once, at the end of the closed catalog"
    );
    assert_eq!(
        GeneratedUiPrimitive::ResultSet.as_str(),
        RESULT_SET_ATOM_KIND
    );
    assert_eq!(GeneratedUiPrimitive::ResultSet.minimum_catalog_version(), 3);
    for primitive in GeneratedUiPrimitive::ALL {
        if *primitive == GeneratedUiPrimitive::ResultSet {
            continue;
        }
        assert_eq!(
            primitive.minimum_catalog_version(),
            2,
            "the kit bump must not raise an existing primitive's minimum: {primitive:?}"
        );
    }

    let card = result_set_card()?;
    assert!(
        GeneratedUiSurfaceCapabilities::all_atom_kit().supports(GeneratedUiPrimitive::ResultSet),
        "a fully negotiated catalog-3 surface renders result sets"
    );
    assert!(card.render().is_ok(), "the honest surface renders");

    // A result set never lowers to fallback text: every surface that cannot render it
    // gets the one rejection, before any row or handle is serialized.
    for (surface, reason) in [
        (
            GeneratedUiSurfaceCapabilities::text_only(),
            "a text-only surface has no result-set primitive",
        ),
        (
            GeneratedUiSurfaceCapabilities::new(
                GeneratedUiCatalog::LensAtomKit,
                3,
                vec![
                    GeneratedUiPrimitive::TextBlock,
                    GeneratedUiPrimitive::Sheet,
                    GeneratedUiPrimitive::SelfUi,
                ],
            ),
            "a catalog-3 surface whose primitive list omits result_set still refuses",
        ),
        (
            GeneratedUiSurfaceCapabilities::new(
                GeneratedUiCatalog::LensAtomKit,
                2,
                GeneratedUiPrimitive::ALL.to_vec(),
            ),
            "listing the primitive cannot substitute for negotiating catalog 3",
        ),
    ] {
        assert!(
            !surface.supports(GeneratedUiPrimitive::ResultSet),
            "{reason}"
        );
        let error = card
            .render_for_surface(&surface)
            .expect_err("an unsupported result set must not render");
        assert!(
            error.to_string().contains(LENS_RESULT_SET_UNSUPPORTED),
            "{reason}: {error}"
        );
    }

    Ok(())
}

#[test]
fn v2_tree_remains_v2_after_result_set_kit_bump() -> Result<()> {
    assert_eq!(
        GENERATED_UI_WIRE_VERSION, 2,
        "the generated-ui wire version is untouched by the atom-kit bump"
    );

    let v2_only = GeneratedLens::new(v2_only_root())?;
    assert_eq!(
        v2_only.kit_version(),
        2,
        "a tree of pre-v3 atoms keeps declaring 2 after the bump"
    );
    let mixed = card_root(vec![LensNode::with_fallback_text(
        id("loading"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
        text("loading"),
    )]);
    assert_eq!(
        GeneratedLens::new(mixed)?.kit_version(),
        2,
        "a whole v2 card still stamps 2"
    );
    assert_eq!(
        GeneratedLens::new(standalone_result_set_root())?.kit_version(),
        3,
        "a tree containing result_set stamps 3"
    );

    // And a v2-declared envelope cannot smuggle a v3 atom past negotiation.
    let smuggled = json!({
        "kit_version": 2,
        "root": serde_json::to_value(&standalone_result_set_root()).expect("node encodes"),
    });
    assert!(
        serde_json::from_value::<GeneratedLens>(smuggled).is_err(),
        "a v2-declared envelope cannot carry result_set"
    );

    Ok(())
}

#[test]
fn lens_envelope_accepts_supported_versions_and_rejects_underdeclaration() -> Result<()> {
    let v2_node = serde_json::to_value(&v2_only_root()).expect("node encodes");
    let v3_node = serde_json::to_value(&standalone_result_set_root()).expect("node encodes");

    for (version, root, reason) in [
        (2, &v2_node, "the oldest supported envelope still decodes"),
        (3, &v2_node, "a v2 tree may over-declare up to the constant"),
        (3, &v3_node, "a v3 tree decodes at its own version"),
    ] {
        let envelope = json!({ "kit_version": version, "root": root });
        let lens: GeneratedLens =
            serde_json::from_value(envelope).unwrap_or_else(|error| panic!("{reason}: {error}"));
        assert_eq!(lens.kit_version(), version, "{reason}");
    }

    // Under-declaration is caught after decode, against the atoms actually present.
    let error = serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": 2,
        "root": &v3_node,
    }))
    .expect_err("an under-declared envelope must not decode");
    assert!(
        error.to_string().contains("must be at least 3"),
        "under-declaration is rejected by contained atoms, not by the constant: {error}"
    );

    // Outside the supported window the rejection message is unchanged.
    for version in [0u16, 1, LENS_ATOM_KIT_VERSION + 1, u16::MAX] {
        let error = serde_json::from_value::<GeneratedLens>(json!({
            "kit_version": version,
            "root": &v2_node,
        }))
        .expect_err("out-of-window versions must not decode");
        assert!(
            error.to_string().contains(&format!(
                "unsupported generated lens atom kit version {version}"
            )),
            "the landed rejection message is preserved: {error}"
        );
    }

    // The positional (msgpack seq) deserializer negotiates the same window.
    let lens = GeneratedLens::new(standalone_result_set_root())?;
    let positional = rmp_serde::to_vec(&lens).expect("positional encode");
    assert_eq!(
        rmp_serde::from_slice::<GeneratedLens>(&positional).expect("positional decode"),
        lens
    );

    Ok(())
}

#[test]
fn result_set_explicit_selection_is_rendered_id_set() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    let plan = frame.validate_result_set_action(
        &scoped_read,
        &render,
        &result_set_event("archive", explicit(&["row-2", "row-1"])),
    )?;

    let GeneratedUiResultSetScope::Explicit { row_ids, selected } = plan.scope() else {
        panic!("an explicit selection must resolve to an explicit scope");
    };
    assert_eq!(
        row_ids
            .iter()
            .map(LensResultSetRowId::as_str)
            .collect::<Vec<_>>(),
        ["row-1", "row-2"],
        "the plan records the deduplicated row-id set, not the client's ordering"
    );
    assert_eq!(selected.len(), 2);
    for read_handle in selected {
        assert_eq!(
            read_handle.atom_id(),
            &id("results"),
            "reach is issued against the rendered result set, never a sibling node"
        );
        assert_eq!(read_handle.render_id(), &render_id("card-1"));
        assert_eq!(read_handle.reach(), LensReadReach::ClaimSet);
        assert_eq!(read_handle.target_kind(), LensBackingTargetKind::Claim);
    }

    // Row ids are opaque echoes: only handles the *rendered atom* named are resolved.
    let entity_rows = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "people")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    let plan = frame.validate_result_set_action(
        &scoped_read,
        &entity_rows,
        &result_set_event("archive", explicit(&["row-1"])),
    )?;
    let GeneratedUiResultSetScope::Explicit { selected, .. } = plan.scope() else {
        panic!("an explicit selection must resolve to an explicit scope");
    };
    assert_eq!(selected[0].reach(), LensReadReach::EntitySet);

    // Timeline, query-result, and action-target rows are not selectable row reach.
    for (name, role, reason) in [
        (
            "history",
            LensHandleRole::Timeline,
            "a timeline row is not claim-set or entity-set reach",
        ),
        (
            "filter",
            LensHandleRole::QueryResult,
            "a query-result row is select-all reach, not row reach",
        ),
    ] {
        let render = result_set_card_with(
            result_set_atom(
                vec![result_set_row("row-1", name)],
                GeneratedUiResultSetSelectAll::Disabled {},
                &["archive"],
            ),
            vec![binding(name, role)],
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool,
            )],
        )?
        .render()?;
        assert!(
            frame
                .validate_result_set_action(
                    &scoped_read,
                    &render,
                    &result_set_event("archive", explicit(&["row-1"])),
                )
                .is_err(),
            "{reason}"
        );
    }

    Ok(())
}

#[test]
fn result_set_rejects_empty_duplicate_and_foreign_row_ids() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &render,
                &result_set_event("archive", explicit(&["row-1"])),
            )
            .is_ok(),
        "the honest single-row selection is the positive control"
    );

    for (selection, reason) in [
        (explicit(&[]), "an explicit fire with zero rows is invalid"),
        (
            explicit(&["row-1", "row-1"]),
            "a repeated row id is never counted twice",
        ),
        (
            explicit(&["row-9"]),
            "a row id absent from this rendered atom resolves to nothing",
        ),
        (
            explicit(&["row-1", "row-9"]),
            "one foreign id poisons the whole selection",
        ),
    ] {
        assert!(
            frame
                .validate_result_set_action(
                    &scoped_read,
                    &render,
                    &result_set_event("archive", selection)
                )
                .is_err(),
            "{reason}"
        );
    }

    // An empty result set is a valid atom; it just has no row to fire against.
    let empty = result_set_card_with(
        result_set_atom(Vec::new(), GeneratedUiResultSetSelectAll::Disabled {}, &[]),
        Vec::new(),
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?;
    assert!(empty.render().is_ok(), "an empty result set is valid");

    Ok(())
}

#[test]
fn result_set_select_all_uses_declared_host_predicate() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    let plan = frame.validate_result_set_action(
        &scoped_read,
        &render,
        &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
    )?;
    let GeneratedUiResultSetScope::Predicate { predicate } = plan.scope() else {
        panic!("select-all must resolve to a predicate scope");
    };
    assert_eq!(
        predicate.reach(),
        LensReadReach::QueryResult,
        "the predicate is the host's declared query-result handle"
    );
    assert_eq!(predicate.atom_id(), &id("results"));

    // Disabled select-all rejects the event outright.
    let disabled = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "claim-a")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("claim-a", LensHandleRole::ClaimSet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &disabled,
                &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
            )
            .is_err(),
        "a disabled select-all has no predicate to take"
    );

    // A predicate the node advertised at any other role is not select-all reach.
    let wrong_role = result_set_card_with(
        result_set_atom(Vec::new(), within_filter("people"), &["archive"]),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .validate_result_set_action(
                &scoped_read,
                &wrong_role,
                &result_set_event("archive", GeneratedUiResultSetSelection::AllWithinFilter {}),
            )
            .is_err(),
        "select-all requires exactly query-result reach"
    );

    Ok(())
}

#[test]
fn result_set_free_form_filter_is_unrepresentable() {
    // Positive control: a select-all event is a mode tag and nothing else.
    let honest = json!({
        "action": {
            "cardId": "card-1",
            "elementId": "archive",
            "actionId": "archive",
            "occurredAt": 1
        },
        "selection": { "mode": "all_within_filter" }
    });
    let parsed: GeneratedUiResultSetActionEvent =
        serde_json::from_value(honest.clone()).expect("the honest select-all event decodes");
    assert_eq!(
        parsed.selection,
        GeneratedUiResultSetSelection::AllWithinFilter {}
    );

    for forged in [
        json!({ "query": "claim.subject == person" }),
        json!({ "expression": "1 == 1" }),
        json!({ "filter": { "where": "all" } }),
        json!({ "where": "all" }),
        json!({ "entity_id": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "entityId": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "body": "the note says ..." }),
        json!({ "predicate_handle": "filter" }),
        json!({ "replacement_handle": "other-filter" }),
        json!({ "row_ids": ["row-1"] }),
    ] {
        let mut event = honest.clone();
        let selection = event
            .get_mut("selection")
            .and_then(serde_json::Value::as_object_mut)
            .expect("selection object");
        for (key, value) in forged.as_object().expect("forged field object") {
            selection.insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiResultSetActionEvent>(event).is_err(),
            "a select-all selection must not carry {forged}"
        );
    }

    // The same closure holds on the explicit arm and on the whole event envelope.
    for forged in [
        json!({ "mode": "explicit", "row_ids": ["row-1"], "query": "x" }),
        json!({ "mode": "explicit", "row_ids": ["row-1"], "predicate_handle": "filter" }),
        json!({ "mode": "explicit" }),
        json!({ "mode": "unbounded" }),
        json!({ "row_ids": ["row-1"] }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiResultSetSelection>(forged.clone()).is_err(),
            "an explicit selection must not decode as {forged}"
        );
    }
    for forged in [
        json!({ "actor": "owner" }),
        json!({ "authority": "owner" }),
        json!({ "command": "archive" }),
        json!({ "approval": "granted" }),
        json!({ "verb": "gated_actor_write" }),
        json!({ "source": "agent" }),
        json!({ "chokepoint": "evaluate_gate" }),
    ] {
        let mut event = honest.clone();
        for (key, value) in forged.as_object().expect("forged field object") {
            event
                .as_object_mut()
                .expect("event object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<GeneratedUiResultSetActionEvent>(event).is_err(),
            "a result-set action event must not carry {forged}"
        );
    }

    // A rendered atom's select-all is equally closed.
    for forged in [
        json!({ "mode": "within_filter", "predicate_handle": "filter", "query": "x" }),
        json!({ "mode": "within_filter" }),
        json!({ "mode": "disabled", "predicate_handle": "filter" }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedUiResultSetSelectAll>(forged.clone()).is_err(),
            "a select-all declaration must not decode as {forged}"
        );
    }
}

#[test]
fn result_set_collections_obey_caps_and_budget() -> Result<()> {
    let oversized_rows = (0..=MAX_LENS_COLLECTION_ITEMS)
        .map(|index| json!({ "id": format!("row-{index}"), "label": "row", "target_handle": "claim-a" }))
        .collect::<Vec<_>>();
    assert!(
        serde_json::from_value::<LensAtom>(json!({
            "kind": "result_set",
            "props": { "rows": oversized_rows, "select_all": { "mode": "disabled" } }
        }))
        .is_err(),
        "rows are capped by the shared bounded-collection deserializer"
    );

    let oversized_bar = (0..=MAX_LENS_COLLECTION_ITEMS)
        .map(|index| json!(format!("archive-{index}")))
        .collect::<Vec<_>>();
    assert!(
        serde_json::from_value::<LensAtom>(json!({
            "kind": "result_set",
            "props": { "rows": [], "select_all": { "mode": "disabled" }, "action_bar": oversized_bar }
        }))
        .is_err(),
        "the action bar is capped too"
    );

    let oversized_selection = (0..=MAX_LENS_COLLECTION_ITEMS)
        .map(|index| json!(format!("row-{index}")))
        .collect::<Vec<_>>();
    assert!(
        serde_json::from_value::<GeneratedUiResultSetSelection>(json!({
            "mode": "explicit",
            "row_ids": oversized_selection
        }))
        .is_err(),
        "event row ids are capped by the same deserializer"
    );

    // And the aggregate lens budget is charged, not just the per-collection cap.
    let rows_at = |count: usize| {
        (0..count)
            .map(|index| result_set_row(&format!("row-{index}"), "claim-a"))
            .collect::<Vec<_>>()
    };
    let node_with = |count: usize| {
        result_set_node(
            "root",
            result_set_atom(
                rows_at(count),
                GeneratedUiResultSetSelectAll::Disabled {},
                &[],
            ),
            vec![binding("claim-a", LensHandleRole::ClaimSet)],
        )
    };
    assert!(
        GeneratedLens::new(node_with(MAX_LENS_COLLECTION_ITEMS - 1)).is_ok(),
        "one binding plus rows may reach the aggregate budget exactly"
    );
    assert!(
        GeneratedLens::new(node_with(MAX_LENS_COLLECTION_ITEMS)).is_err(),
        "result set rows charge the same aggregate lens collection budget"
    );

    Ok(())
}

#[test]
fn result_set_row_id_uses_lens_token_rules() {
    for value in [
        "r".to_string(),
        "row-1".to_string(),
        "row.1_2-3".to_string(),
        "r".repeat(128),
    ] {
        assert!(
            LensResultSetRowId::new(value.clone()).is_ok(),
            "{value} is a valid lens token"
        );
    }
    for (value, reason) in [
        (String::new(), "row ids must not be empty"),
        ("r".repeat(129), "row ids obey the 128-byte token cap"),
        ("row/1".to_string(), "path separators are not lens tokens"),
        ("row 1".to_string(), "spaces are not lens tokens"),
        ("rów".to_string(), "row ids are ASCII only"),
    ] {
        assert!(LensResultSetRowId::new(value).is_err(), "{reason}");
    }

    // Row ids carry no capability flag: they are display echoes, not action names.
    assert!(
        LensResultSetRowId::new("storage").is_ok(),
        "a row id is not a capability name"
    );
    assert!(
        SelfUiActionId::new("storage").is_err(),
        "action ids keep their capability rejection"
    );
}

#[test]
fn result_set_render_rejects_duplicate_row_ids_and_undeclared_handles() -> Result<()> {
    assert!(
        result_set_card().is_ok(),
        "the honest result-set card is the positive control"
    );

    // Duplicate row ids never reach a render, in the atom or on the wire.
    assert!(
        LensAtom::result_set(result_set_atom(
            vec![
                result_set_row("row-1", "claim-a"),
                result_set_row("row-1", "claim-b"),
            ],
            GeneratedUiResultSetSelectAll::Disabled {},
            &[],
        ))
        .is_err(),
        "duplicate row ids are rejected at construction"
    );
    assert!(
        serde_json::from_value::<LensAtom>(json!({
            "kind": "result_set",
            "props": {
                "rows": [
                    { "id": "row-1", "label": "a", "target_handle": "claim-a" },
                    { "id": "row-1", "label": "b", "target_handle": "claim-b" }
                ],
                "select_all": { "mode": "disabled" }
            }
        }))
        .is_err(),
        "duplicate row ids are rejected on the wire"
    );

    // Every handle a row or a select-all names must be one this node declared once.
    for (atom, bindings, reason) in [
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                GeneratedUiResultSetSelectAll::Disabled {},
                &[],
            ),
            Vec::new(),
            "a row handle the node never advertised resolves to nothing",
        ),
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                GeneratedUiResultSetSelectAll::Disabled {},
                &[],
            ),
            vec![
                binding("claim-a", LensHandleRole::ClaimSet),
                binding("claim-a", LensHandleRole::EntitySet),
            ],
            "an ambiguous double declaration offers no single reach",
        ),
        (
            result_set_atom(Vec::new(), within_filter("filter"), &[]),
            Vec::new(),
            "an undeclared select-all predicate is rejected too",
        ),
        (
            result_set_atom(
                vec![result_set_row("row-1", "claim-a")],
                within_filter("filter"),
                &[],
            ),
            vec![binding("claim-a", LensHandleRole::ClaimSet)],
            "declaring the rows does not declare the predicate",
        ),
    ] {
        assert!(
            GeneratedLens::new(result_set_node("results", atom, bindings)).is_err(),
            "{reason}"
        );
    }

    Ok(())
}

#[test]
fn result_set_default_fallback_text_is_stable() {
    for atom in [
        result_set_atom(Vec::new(), GeneratedUiResultSetSelectAll::Disabled {}, &[]),
        result_set_atom(
            vec![
                result_set_row("row-1", "claim-a"),
                result_set_row("row-2", "claim-b"),
            ],
            within_filter("filter"),
            &["archive"],
        ),
    ] {
        let atom = LensAtom::ResultSet(atom);
        assert_eq!(
            atom.default_fallback_text().as_str(),
            "result set",
            "the fallback is a static literal, never row labels or a row count"
        );
        assert_eq!(atom.kind(), RESULT_SET_ATOM_KIND);
    }
}

#[test]
fn result_set_action_bar_accepts_only_tier2_gated_writes() -> Result<()> {
    assert!(
        result_set_card().is_ok(),
        "a deterministic-tool, self.ui-hosted action is allowlistable"
    );
    assert!(
        result_set_card_with(
            result_set_atom(Vec::new(), GeneratedUiResultSetSelectAll::Disabled {}, &[]),
            Vec::new(),
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_ok(),
        "an empty action bar is valid"
    );

    let bar = |ids: &[&str]| {
        result_set_atom(
            vec![result_set_row("row-1", "claim-a")],
            GeneratedUiResultSetSelectAll::Disabled {},
            ids,
        )
    };
    let claim_a = || vec![binding("claim-a", LensHandleRole::ClaimSet)];

    for (tier, reason) in [
        (
            GeneratedUiActionTier::Local,
            "a local action is not a gated write",
        ),
        (
            GeneratedUiActionTier::ModelRoundTrip,
            "a model round trip is a trigger, not a gated write",
        ),
    ] {
        assert!(
            result_set_card_with(
                bar(&["archive"]),
                claim_a(),
                vec![archive_declaration(tier)]
            )
            .is_err(),
            "{reason}"
        );
    }
    assert!(
        result_set_card_with(
            bar(&["archive"]),
            claim_a(),
            vec![declaration(
                "archive",
                "purge",
                GeneratedUiActionTier::DeterministicTool,
                action("archive.selected"),
            )],
        )
        .is_err(),
        "an undeclared action id cannot be allowlisted"
    );
    assert!(
        result_set_card_with(
            bar(&["archive", "archive"]),
            claim_a(),
            vec![archive_declaration(
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_err(),
        "an action bar must not repeat an id"
    );

    // Nor may two result sets in the same card claim the same action id.
    let two_sets = card_root(vec![
        result_set_node("results", bar(&["archive"]), claim_a()),
        result_set_node("mirror", bar(&["archive"]), claim_a()),
        archive_button(),
    ]);
    assert!(
        GeneratedLens::new(two_sets).is_err(),
        "one action id must be allowlisted by at most one result set"
    );

    // The landed gates still decide what is interactive: the atom hosts no action, so a
    // declaration naming the result set element is rejected as a non-self.ui element.
    assert!(
        result_set_card_with(
            bar(&["archive"]),
            claim_a(),
            vec![declaration(
                "results",
                "archive",
                GeneratedUiActionTier::DeterministicTool,
                action("archive.selected"),
            )],
        )
        .is_err(),
        "generated-ui action declarations must still reference a self.ui control"
    );

    Ok(())
}

#[test]
fn result_set_emitter_is_frame_principal() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;

    let plan = frame.validate_result_set_action(
        &scoped_read,
        &render,
        &result_set_event("archive", explicit(&["row-1"])),
    )?;
    assert_eq!(
        plan.emitter(),
        frame.principal(),
        "the emitter is stamped from the frame, never read from event json"
    );
    assert_eq!(
        plan.action().emitter(),
        frame.principal(),
        "the landed action validation stamps the same principal"
    );

    // A different principal's scope is not this frame's scope.
    assert!(
        frame
            .validate_result_set_action(
                &vault.scoped_read(actor_key("intruder")),
                &render,
                &result_set_event("archive", explicit(&["row-1"])),
            )
            .is_err(),
        "a switched read key never reaches the selection path"
    );

    // A frame for another render cannot borrow this render's rows.
    let (_, other) = viewer_frame("card-2")?;
    assert!(
        other
            .validate_result_set_action(
                &scoped_read,
                &render,
                &result_set_event("archive", explicit(&["row-1"])),
            )
            .is_err(),
        "a render belongs to exactly one frame"
    );

    Ok(())
}

#[test]
fn result_set_tick_is_not_approval() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;
    let event = result_set_event("archive", explicit(&["row-1", "row-2"]));

    // Ticking rows yields a plan and only a plan: no approved action, no chokepoint, no
    // receipt. The plan is engine-owned — its fields are private and it has no
    // constructor, no `Deserialize`, and no `approve` or `execute`.
    let plan = frame.validate_result_set_action(&scoped_read, &render, &event)?;
    assert_eq!(
        plan,
        frame.validate_result_set_action(&scoped_read, &render, &event)?,
        "validation is pure: ticking twice changes nothing"
    );
    assert!(matches!(
        plan.action(),
        GeneratedUiValidatedAction::DeterministicTool { .. }
    ));

    // The receipt only exists once dispatch re-proves the plan.
    let write = frame.dispatch_result_set_action(&scoped_read, &render, &event)?;
    assert_eq!(
        write.action().command().as_str(),
        "archive",
        "the command is the engine-authored declaration id"
    );
    assert_eq!(
        write.action().args().len(),
        2,
        "one backing ref per freshly re-resolved target, and no client argument"
    );
    for arg in write.action().args() {
        assert!(
            matches!(arg, LensApprovedActionArg::BackingRef(_)),
            "selection contributes host backing refs only"
        );
    }
    assert_eq!(
        write.chokepoint(),
        LensGateWriteChokepoint::CheckClaimPolicyForWrite,
        "a claim anywhere in scope routes through claim policy"
    );

    // A selection over non-claim targets derives the other chokepoint.
    let entity_render = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "people")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert_eq!(
        frame
            .dispatch_result_set_action(
                &scoped_read,
                &entity_render,
                &result_set_event("archive", explicit(&["row-1"])),
            )?
            .chokepoint(),
        LensGateWriteChokepoint::EvaluateGate,
        "an entity-only scope evaluates the gate"
    );

    Ok(())
}

#[test]
fn result_set_scope_is_rechecked_before_dispatch() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, people_id) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = result_set_card()?.render()?;
    let event = result_set_event("archive", explicit(&["row-1"]));

    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &render, &event)
            .is_ok(),
        "the honest dispatch is the positive control"
    );

    // A later render revision that drops the row, drops the binding, moves the atom, or
    // swaps the predicate fails closed rather than reusing proved reach.
    for (later, reason) in [
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-2", "claim-b")],
                    within_filter("filter"),
                    &["archive"],
                ),
                claim_rows_bindings(),
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "a removed row is not selectable",
        ),
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-1", "claim-a")],
                    GeneratedUiResultSetSelectAll::Disabled {},
                    &["archive"],
                ),
                vec![binding("claim-a", LensHandleRole::Timeline)],
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "a relabelled binding cannot launder claim-set reach",
        ),
        (
            result_set_card_with(
                result_set_atom(
                    vec![result_set_row("row-1", "claim-a")],
                    within_filter("filter"),
                    &[],
                ),
                claim_rows_bindings(),
                vec![archive_declaration(
                    GeneratedUiActionTier::DeterministicTool,
                )],
            )?,
            "an action the result set no longer allowlists resolves to nothing",
        ),
    ] {
        assert!(
            frame
                .dispatch_result_set_action(&scoped_read, &later.render()?, &event)
                .is_err(),
            "{reason}"
        );
    }

    // A switched principal, a cross-render frame, and a twin frame all fail closed.
    assert!(
        frame
            .dispatch_result_set_action(&vault.scoped_read(actor_key("intruder")), &render, &event)
            .is_err(),
        "dispatch re-checks the acting principal"
    );
    let twin = LensRenderFrame::new(render_id("card-1"), frame.principal().clone());
    assert!(
        twin.dispatch_result_set_action(&scoped_read, &render, &event)
            .is_err(),
        "a frame that never minted the row cannot dispatch against it"
    );

    // A target whose stored content moved stops hydrating the short ref the plan proved.
    let moved = result_set_card_with(
        result_set_atom(
            vec![result_set_row("row-1", "people")],
            GeneratedUiResultSetSelectAll::Disabled {},
            &["archive"],
        ),
        vec![binding("people", LensHandleRole::EntitySet)],
        vec![archive_declaration(
            GeneratedUiActionTier::DeterministicTool,
        )],
    )?
    .render()?;
    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &moved, &event)
            .is_ok(),
        "the entity scope dispatches before the target moves"
    );
    vault.put_entity(
        &people_id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 2, end: 2 },
        2,
        b"person, revised",
    )?;
    assert!(
        frame
            .dispatch_result_set_action(&scoped_read, &moved, &event)
            .is_err(),
        "a stale short ref stops resolving instead of following the entity forward"
    );

    Ok(())
}

#[test]
fn result_set_has_no_push_delivery() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = result_set_fixture(&vault)?;
    let scoped_read = vault.scoped_read(viewer_key);

    // Construct.
    let card = result_set_card()?;
    let render = card.render()?;
    let event = result_set_event("archive", explicit(&["row-1"]));

    // Tick, then fire. The only value either step yields is a plan and then one
    // host-mediated write: no board update, subscription, WAKE/CARRIER frame,
    // owner-feed frame, or transport output exists to be produced.
    let plan = frame.validate_result_set_action(&scoped_read, &render, &event)?;
    let write: LensHostMediatedWrite =
        frame.dispatch_result_set_action(&scoped_read, &render, &event)?;
    assert!(matches!(
        plan.scope(),
        GeneratedUiResultSetScope::Explicit { .. }
    ));
    assert_eq!(
        write.chokepoint(),
        LensGateWriteChokepoint::CheckClaimPolicyForWrite,
        "the receipt names a host write chokepoint, not a delivery channel"
    );

    // Nothing a result set puts on the wire names a push channel.
    for encoded in [
        serde_json::to_string(&card).expect("card encodes"),
        serde_json::to_string(&render).expect("render encodes"),
        serde_json::to_string(&card.segments()?).expect("segments encode"),
        serde_json::to_string(&event).expect("event encodes"),
    ] {
        for pushed in [
            "subscription",
            "subscribe",
            "wake",
            "carrier",
            "tag_sub",
            "board",
            "feed",
            "dispatcher",
        ] {
            assert!(
                !encoded.to_ascii_lowercase().contains(pushed),
                "a result set must not name {pushed}"
            );
        }
    }

    // And lens execution still links zero write imports, so no push path is reachable.
    for import in [
        LensHostImport::VaultWrite,
        LensHostImport::BatchWrite,
        LensHostImport::EvaluateGate,
        LensHostImport::CheckClaimPolicyForWrite,
    ] {
        assert!(
            LensExecutionBoundary::read_only(vec![LensHostImport::ScopedRead, import]).is_err(),
            "lens execution must expose zero write imports"
        );
    }

    Ok(())
}

proptest! {
    #[test]
    fn generated_ui_fuzz_rejects_extra_atom_selection_fields(
        field in "[a-zA-Z][a-zA-Z0-9_]{0,16}",
        value in "[a-zA-Z0-9 :/._-]{0,32}",
    ) {
        prop_assume!(!["cardId", "atomId", "handle"].contains(&field.as_str()));

        let mut request = json!({
            "cardId": "card-1",
            "atomId": "people",
            "handle": "visible-set"
        });
        request
            .as_object_mut()
            .expect("request object")
            .insert(field, json!(value));

        prop_assert!(
            serde_json::from_value::<LensAtomSelectionRequest>(request).is_err(),
            "an atom selection carries three names and nothing else"
        );
    }
}
