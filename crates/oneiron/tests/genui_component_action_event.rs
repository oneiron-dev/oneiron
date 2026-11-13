//! GENUI-COMPONENT-ACTIONS at the event gate: a client event for a quick
//! filter's or an app component's action resolves against the card's manifest,
//! exactly as a `self.ui` control's does. The gate reads the element's own
//! action, so an element that carries none, or carries another one than its
//! declaration names, is refused.
//!
//! The component atom is built from the wire (`serde_json`) because its action
//! field is new, so this file compiles on main and its red run shows the
//! refusals. `cargo test --locked -p oneiron --all-features --test
//! genui_component_action_event`.

use oneiron::claim::ScopedReadActorKey;
use oneiron::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiActionEvent, GeneratedUiActionTier, GeneratedUiCard, GeneratedUiCatalog,
    GeneratedUiCatalogDescriptor, GeneratedUiCatalogName, GeneratedUiCatalogVersion,
    GeneratedUiComponentName, GeneratedUiComponentSchema, GeneratedUiPrimitive, GeneratedUiRender,
    GeneratedUiStatePatch, GeneratedUiStateSnapshot, GeneratedUiSurfaceCapabilities,
    GeneratedUiValidatedAction, LensAtom, LensAtomId, LensNode, LensPrincipalBinding,
    LensRenderFrame, LensRenderId, LensText, LensTextSpan, QuickFilterAtom, SelfUiAction,
    SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOption, SelfUiOptionValue,
    SelfUiStateKey, SelfUiStateValue, TextBlockAtom,
};
use oneiron::{Vault, VaultConfig};
use serde_json::{Value, json};

const CARD: &str = "stores-card";

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn atom_id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("atom id")
}

fn option(value: &str) -> SelfUiOptionValue {
    SelfUiOptionValue::new(value).expect("option value")
}

fn token(value: &str) -> SelfUiStateValue {
    serde_json::from_value(json!({ "type": "token", "value": value })).expect("token state value")
}

fn state_key(value: &str) -> SelfUiStateKey {
    SelfUiStateKey::new(value).expect("state key")
}

fn action(command: &str) -> SelfUiAction {
    SelfUiAction {
        command: SelfUiActionId::new(command).expect("action id"),
        args: Vec::new(),
    }
}

fn declaration(
    element: &str,
    command: &str,
    tier: GeneratedUiActionTier,
) -> GeneratedUiActionDeclaration {
    GeneratedUiActionDeclaration {
        element_id: atom_id(element),
        action_id: SelfUiActionId::new(command).expect("action id"),
        tier,
        action: action(command),
    }
}

fn status_filter() -> LensNode {
    LensNode::new(
        atom_id("status"),
        LensAtom::QuickFilter(QuickFilterAtom {
            id: SelfUiControlId::new("status").expect("control id"),
            label: text("Status"),
            options: vec![
                SelfUiOption {
                    value: option("open"),
                    label: text("Open"),
                },
                SelfUiOption {
                    value: option("closed"),
                    label: text("Closed"),
                },
            ],
            selected: vec![option("open")],
            action: action("stores.filter"),
        }),
    )
}

/// The stores app's list foot, carrying `action` as its wire does.
fn list_foot_atom(action: Value) -> LensAtom {
    serde_json::from_value(json!({
        "kind": "component",
        "props": {
            "catalog": "stores",
            "name": "list_foot",
            "props": { "label": "show 10 more" },
            "action": action,
        },
    }))
    .expect("an app component that carries an action decodes")
}

fn more_action() -> Value {
    json!({ "command": "stores.more", "args": [] })
}

fn more_button() -> LensNode {
    LensNode::new(
        atom_id("more"),
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new("more").expect("control id"),
            label: text("show 10 more"),
            action: action("stores.more"),
        })),
    )
}

fn render(
    children: Vec<LensNode>,
    actions: Vec<GeneratedUiActionDeclaration>,
) -> GeneratedUiRender {
    let mut root = LensNode::new(
        atom_id("stores"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Stores"),
            rows: Vec::new(),
        }),
    );
    root.children = children;
    let state: GeneratedUiStateSnapshot =
        [(state_key("status"), token("open"))].into_iter().collect();
    let card = GeneratedUiCard::interactive(
        LensRenderId::new(CARD).expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        actions,
        state,
    )
    .expect("the manifest declares each element's own action");
    let surface = GeneratedUiSurfaceCapabilities::for_catalog(
        GeneratedUiCatalogDescriptor {
            catalog: GeneratedUiCatalog::App(
                GeneratedUiCatalogName::new("stores").expect("catalog name"),
            ),
            catalog_version: GeneratedUiCatalogVersion::new("1.0.0").expect("catalog semver"),
            components: vec![GeneratedUiComponentSchema {
                name: GeneratedUiComponentName::new("list_foot").expect("component name"),
                schema: json!({}),
            }],
        },
        GeneratedUiPrimitive::ALL.to_vec(),
    );
    card.render_for_surface(&surface)
        .expect("render for the stores app")
}

fn event(
    element: &str,
    command: &str,
    patch: Vec<GeneratedUiStatePatch>,
) -> GeneratedUiActionEvent {
    GeneratedUiActionEvent {
        card_id: LensRenderId::new(CARD).expect("card id"),
        element_id: atom_id(element),
        action_id: SelfUiActionId::new(command).expect("action id"),
        patch,
        occurred_at: 17,
    }
}

/// The viewer's frame over the card, and the vault its scoped read comes from.
fn viewer_frame() -> (
    tempfile::TempDir,
    Vault,
    ScopedReadActorKey,
    LensRenderFrame,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let key = ScopedReadActorKey::new("viewer").expect("actor key");
    let principal = LensPrincipalBinding::human_view("viewer", key.clone(), vec![key.clone()])
        .expect("viewer principal");
    let frame = LensRenderFrame::new(LensRenderId::new(CARD).expect("card id"), principal);
    (dir, vault, key, frame)
}

fn validate(
    render: &GeneratedUiRender,
    event: &GeneratedUiActionEvent,
) -> oneiron::Result<GeneratedUiValidatedAction> {
    let (_dir, vault, key, frame) = viewer_frame();
    let scoped_read = vault.scoped_read(key);
    frame.validate_action_event(
        &scoped_read,
        frame.principal(),
        render,
        &render.state,
        event,
    )
}

fn node_mut<'a>(render: &'a mut GeneratedUiRender, id: &str) -> &'a mut LensAtom {
    &mut render
        .nodes
        .iter_mut()
        .find(|node| node.id.as_str() == id)
        .expect("node in render")
        .atom
}

#[test]
fn quick_filter_choice_reaches_the_server_as_a_local_state_patch() {
    let render = render(
        vec![status_filter()],
        vec![declaration(
            "status",
            "stores.filter",
            GeneratedUiActionTier::Local,
        )],
    );
    let patch = vec![GeneratedUiStatePatch::Replace {
        path: "/$state/status".to_string(),
        value: token("closed"),
    }];
    let validated = validate(&render, &event("status", "stores.filter", patch))
        .expect("the quick filter's own action sends");
    let GeneratedUiValidatedAction::Local { state, .. } = validated else {
        panic!("a local declaration resolves to a local state result");
    };
    assert_eq!(state.get(&state_key("status")), Some(&token("closed")));
}

#[test]
fn component_action_resolves_to_its_tool_declaration() {
    let render = render(
        vec![LensNode::with_fallback_text(
            atom_id("foot"),
            list_foot_atom(more_action()),
            text("show 10 more"),
        )],
        vec![declaration(
            "foot",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    );
    let validated = validate(&render, &event("foot", "stores.more", Vec::new()))
        .expect("the component's own action sends");
    let GeneratedUiValidatedAction::DeterministicTool { action, .. } = validated else {
        panic!("a deterministic-tool declaration resolves to an approved action");
    };
    assert_eq!(action.command().as_str(), "stores.more");
}

#[test]
fn event_for_a_component_carrying_another_action_is_refused() {
    let mut render = render(
        vec![LensNode::with_fallback_text(
            atom_id("foot"),
            list_foot_atom(more_action()),
            text("show 10 more"),
        )],
        vec![declaration(
            "foot",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    );
    *node_mut(&mut render, "foot") = list_foot_atom(json!({ "command": "stores.all", "args": [] }));
    assert!(
        validate(&render, &event("foot", "stores.more", Vec::new())).is_err(),
        "the element must carry the very action its declaration names"
    );
}

#[test]
fn event_for_an_element_that_carries_no_action_is_refused() {
    let mut render = render(
        vec![more_button()],
        vec![declaration(
            "more",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    );
    validate(&render, &event("more", "stores.more", Vec::new()))
        .expect("the control's action sends");
    *node_mut(&mut render, "more") = LensAtom::TextBlock(TextBlockAtom {
        spans: vec![LensTextSpan::Literal(text("show 10 more"))],
    });
    assert!(
        validate(&render, &event("more", "stores.more", Vec::new())).is_err(),
        "a text block carries no action, so no event may name it"
    );
}
