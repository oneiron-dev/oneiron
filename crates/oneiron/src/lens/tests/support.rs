//! Shared fixtures and helpers for the lens behaviour tests.

use super::super::wire_ids::MAX_LENS_COLLECTION_ITEMS;
use super::*;
use crate::test_util::entity as test_entity_id;
use crate::{Error, Result, claim::ScopedReadActorKey, entity_id::EntityId};

pub(super) fn id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("valid atom id")
}

pub(super) fn handle(value: &str) -> LensHandleName {
    LensHandleName::new(value).expect("valid handle")
}

pub(super) fn render_id(value: &str) -> LensRenderId {
    LensRenderId::new(value).expect("valid render id")
}

pub(super) fn backing_ref_id(value: &str) -> LensBackingRefId {
    LensBackingRefId::new(value).expect("valid backing ref id")
}

pub(super) fn media_handle(value: &str) -> LensMediaHandle {
    LensMediaHandle::new(value).expect("valid media handle")
}

pub(super) fn control_id(value: &str) -> SelfUiControlId {
    SelfUiControlId::new(value).expect("valid control id")
}

pub(super) fn action_id(value: &str) -> SelfUiActionId {
    SelfUiActionId::new(value).expect("valid action id")
}

pub(super) fn option_value(value: &str) -> SelfUiOptionValue {
    SelfUiOptionValue::new(value).expect("valid option value")
}

pub(super) fn text(value: &str) -> LensText {
    LensText::new(value).expect("valid text")
}

pub(super) fn generated_ui_node(
    value: &str,
    parent: Option<&str>,
    child_refs: &[&str],
) -> GeneratedUiNode {
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

pub(super) fn action(command: &str) -> SelfUiAction {
    SelfUiAction {
        command: action_id(command),
        args: Vec::new(),
    }
}

pub(super) fn finite(value: f64) -> FiniteF64 {
    FiniteF64::new(value).expect("valid finite number")
}

pub(super) fn actor_key(value: &str) -> ScopedReadActorKey {
    ScopedReadActorKey::new(value).expect("valid actor key")
}

pub(super) fn put_person(vault: &crate::Vault, id: &EntityId) -> Result<()> {
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )
}

pub(super) fn put_profile_claim(
    vault: &crate::Vault,
    id: &EntityId,
    subject: &EntityId,
) -> Result<()> {
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

pub(super) fn backing_target_for(
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

pub(super) fn test_vault() -> (tempfile::TempDir, crate::Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
}

pub(super) fn status() -> StatusDotAtom {
    StatusDotAtom {
        status: LensStatus::Approved,
        label: Some(text("approved")),
    }
}

pub(super) fn seal() -> SealAtom {
    SealAtom {
        level: SealLevel::Actor,
        label: text("actor-sealed"),
    }
}

pub(super) fn rows_at_collection_limit_with_one_cell_each() -> Vec<LedgerRowAtom> {
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

pub(super) fn sections_at_collection_limit_with_one_line_each() -> Vec<SectionAtom> {
    (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| SectionAtom {
            title: text(&format!("section-{index}")),
            lines: vec![text(&format!("line-{index}"))],
        })
        .collect()
}

pub(super) fn options_at_collection_limit() -> Vec<SelfUiOption> {
    (0..MAX_LENS_COLLECTION_ITEMS)
        .map(|index| SelfUiOption {
            value: option_value(&format!("option-{index}")),
            label: text(&format!("Option {index}")),
        })
        .collect()
}

pub(super) fn sample_atoms() -> Vec<LensAtom> {
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

pub(super) fn state_key(value: &str) -> SelfUiStateKey {
    SelfUiStateKey::new(value).expect("valid state key")
}

pub(super) fn toggle_atom(control: &str, command: &str) -> LensAtom {
    LensAtom::SelfUi(SelfUiControl::Toggle(ToggleControl {
        id: control_id(control),
        label: text(control),
        checked: false,
        action: action(command),
    }))
}

pub(super) fn button_atom(control: &str, command: SelfUiAction) -> LensAtom {
    LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
        id: control_id(control),
        label: text(control),
        action: command,
    }))
}

pub(super) fn card_root(children: Vec<LensNode>) -> LensNode {
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

pub(super) fn declaration(
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

pub(super) fn remind_toggle() -> LensNode {
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
pub(super) fn remind_card() -> Result<GeneratedUiCard> {
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

pub(super) fn viewer_frame(card_id: &str) -> Result<(ScopedReadActorKey, LensRenderFrame)> {
    let viewer_key = actor_key("viewer");
    let principal =
        LensPrincipalBinding::human_view("viewer", viewer_key.clone(), vec![viewer_key.clone()])?;
    Ok((
        viewer_key,
        LensRenderFrame::new(render_id(card_id), principal),
    ))
}

pub(super) fn toggle_event(patch: Vec<GeneratedUiStatePatch>) -> GeneratedUiActionEvent {
    GeneratedUiActionEvent {
        card_id: render_id("card-1"),
        element_id: id("remind"),
        action_id: action_id("reminder.toggle"),
        patch,
        occurred_at: 17,
    }
}

pub(super) fn set_remind(value: bool) -> Vec<GeneratedUiStatePatch> {
    vec![GeneratedUiStatePatch::Replace {
        path: "/$state/remind".to_string(),
        value: SelfUiStateValue::Bool(value),
    }]
}

pub(super) fn binding(name: &str, role: LensHandleRole) -> LensHandleRef {
    LensHandleRef {
        name: handle(name),
        role,
    }
}

/// A two-node render whose leaf advertises `bindings`. Selection needs nothing else
/// from a card: the node, its declared handles, and the frame's own backing table.
pub(super) fn selectable_render(
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

pub(super) fn selection(card: &str, atom: &str, name: &str) -> LensAtomSelectionRequest {
    LensAtomSelectionRequest {
        card_id: render_id(card),
        atom_id: id(atom),
        handle: handle(name),
    }
}

/// A frame holding one host-minted `visible-set` row over a readable person.
pub(super) fn selection_fixture(
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

pub(super) fn row_id(value: &str) -> LensResultSetRowId {
    LensResultSetRowId::new(value).expect("valid row id")
}

pub(super) fn result_set_row(row: &str, target: &str) -> GeneratedUiResultSetRow {
    GeneratedUiResultSetRow {
        id: row_id(row),
        label: text(row),
        target_handle: handle(target),
    }
}

pub(super) fn within_filter(predicate: &str) -> GeneratedUiResultSetSelectAll {
    GeneratedUiResultSetSelectAll::WithinFilter {
        predicate_handle: handle(predicate),
    }
}

pub(super) fn result_set_atom(
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
pub(super) fn result_set_node(
    node: &str,
    atom: GeneratedUiResultSetAtom,
    bindings: Vec<LensHandleRef>,
) -> LensNode {
    let mut node =
        LensNode::with_fallback_text(id(node), LensAtom::ResultSet(atom), text("Results"));
    node.bindings = bindings;
    node
}

pub(super) fn archive_button() -> LensNode {
    LensNode::with_fallback_text(
        id("archive"),
        button_atom("archive", action("archive.selected")),
        text("Archive"),
    )
}

pub(super) fn archive_declaration(tier: GeneratedUiActionTier) -> GeneratedUiActionDeclaration {
    declaration("archive", "archive", tier, action("archive.selected"))
}

/// The default result set: two claim rows, a host-declared select-all predicate, and an
/// action bar allowlisting the self.ui-hosted deterministic action next door.
pub(super) fn claim_rows_bindings() -> Vec<LensHandleRef> {
    vec![
        binding("claim-a", LensHandleRole::ClaimSet),
        binding("claim-b", LensHandleRole::ClaimSet),
        binding("filter", LensHandleRole::QueryResult),
    ]
}

pub(super) fn result_set_card_with(
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

pub(super) fn result_set_card() -> Result<GeneratedUiCard> {
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
pub(super) fn result_set_fixture(
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

pub(super) fn explicit(rows: &[&str]) -> GeneratedUiResultSetSelection {
    GeneratedUiResultSetSelection::Explicit {
        row_ids: rows.iter().map(|value| row_id(value)).collect(),
    }
}

pub(super) fn result_set_event(
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

pub(super) fn v2_only_root() -> LensNode {
    LensNode::with_fallback_text(
        id("root"),
        LensAtom::Throbber(ThrobberAtom {
            label: text("loading"),
        }),
        text("loading"),
    )
}

pub(super) fn standalone_result_set_root() -> LensNode {
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
