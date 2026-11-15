//! GENUI-COMPONENT-ACTIONS: the card's manifest may declare an action for every
//! element that carries one. Before, it accepted only a `self.ui` control, so a
//! quick filter's own action could never send, and an app component could not
//! carry one at all (a foot's "show 10 more"). Now a quick filter and an app
//! component that declares an action stand beside the controls: the manifest
//! names the element's own action, the render keeps the declaration while the
//! surface draws the element, and a lowered element loses it.
//!
//! The cards here are built from the wire (`serde_json`) where the field is new,
//! so this file compiles on main and its red run shows the refusals.

use oneiron_lens_wire::lens::atom::{
    CollectionAtom, LensAtom, LensNode, LensText, LensTextSpan, QuickFilterAtom, TextBlockAtom,
};
use oneiron_lens_wire::lens::generated_ui::{
    GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier, GeneratedUiCard,
    GeneratedUiCatalog, GeneratedUiCatalogDescriptor, GeneratedUiCatalogVersion,
    GeneratedUiComponentSchema, GeneratedUiPrimitive, GeneratedUiRender, GeneratedUiStateSnapshot,
    GeneratedUiSurfaceCapabilities, SelfUiStateValue,
};
use oneiron_lens_wire::lens::self_ui::{SelfUiAction, SelfUiOption};
use oneiron_lens_wire::lens::wire_ids::{
    GeneratedUiCatalogName, GeneratedUiComponentName, LensAtomId, LensRenderId, SelfUiActionId,
    SelfUiControlId, SelfUiOptionValue, SelfUiStateKey,
};
use serde_json::{Value, json};

const CATALOG: &str = "stores";
const COMPONENT: &str = "list_foot";

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn atom_id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("atom id")
}

fn option(value: &str) -> SelfUiOptionValue {
    SelfUiOptionValue::new(value).expect("option value")
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

/// A quick filter over the stores list; its choice is card `$state`.
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

/// The app's list foot component, as its wire carries it.
fn list_foot_wire(action: Option<Value>) -> Value {
    let mut props = json!({
        "catalog": CATALOG,
        "name": COMPONENT,
        "props": { "label": "show 10 more" },
    });
    if let Some(action) = action {
        props["action"] = action;
    }
    json!({ "kind": "component", "props": props })
}

fn list_foot(action: Option<Value>) -> LensNode {
    let atom = serde_json::from_value::<LensAtom>(list_foot_wire(action))
        .expect("an app component that carries an action decodes");
    LensNode::with_fallback_text(atom_id("foot"), atom, text("show 10 more"))
}

fn more_action() -> Value {
    json!({ "command": "stores.more", "args": [] })
}

fn stores_tree(children: Vec<LensNode>) -> GeneratedLens {
    let mut root = LensNode::new(
        atom_id("stores"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Stores"),
            rows: Vec::new(),
        }),
    );
    root.children = children;
    GeneratedLens::new(root).expect("generated lens")
}

fn filter_state() -> GeneratedUiStateSnapshot {
    let open = serde_json::from_value::<SelfUiStateValue>(json!({
        "type": "token",
        "value": "open"
    }))
    .expect("token state value");
    [(SelfUiStateKey::new("status").expect("state key"), open)]
        .into_iter()
        .collect()
}

fn card(
    children: Vec<LensNode>,
    actions: Vec<GeneratedUiActionDeclaration>,
) -> Result<GeneratedUiCard, impl std::fmt::Debug> {
    GeneratedUiCard::interactive(
        LensRenderId::new("stores-card").expect("card id"),
        stores_tree(children),
        actions,
        filter_state(),
    )
}

/// A surface that draws the stores app's catalog, list foot included.
fn stores_surface() -> GeneratedUiSurfaceCapabilities {
    GeneratedUiSurfaceCapabilities::for_catalog(
        GeneratedUiCatalogDescriptor {
            catalog: GeneratedUiCatalog::App(
                GeneratedUiCatalogName::new(CATALOG).expect("catalog name"),
            ),
            catalog_version: GeneratedUiCatalogVersion::new("1.0.0").expect("catalog semver"),
            components: vec![GeneratedUiComponentSchema {
                name: GeneratedUiComponentName::new(COMPONENT).expect("component name"),
                schema: json!({}),
            }],
        },
        GeneratedUiPrimitive::ALL.to_vec(),
    )
}

fn declared_elements(render: &GeneratedUiRender) -> Vec<&str> {
    render
        .actions
        .iter()
        .map(|declaration| declaration.element_id.as_str())
        .collect()
}

/// The index of node `id` in a serialized render's `nodes`.
fn node_index(wire: &Value, id: &str) -> usize {
    wire["nodes"]
        .as_array()
        .expect("render nodes")
        .iter()
        .position(|node| node["id"] == id)
        .expect("node in render")
}

#[test]
fn quick_filter_action_in_the_manifest_assembles_and_renders() {
    let card = card(
        vec![status_filter()],
        vec![declaration(
            "status",
            "stores.filter",
            GeneratedUiActionTier::Local,
        )],
    )
    .expect("a manifest may declare a quick filter's own action");
    let render = card.render().expect("render");
    assert_eq!(
        declared_elements(&render),
        vec!["status"],
        "a surface that draws the quick filter keeps its declaration"
    );
    let wire = serde_json::to_value(&render).expect("serialize render");
    serde_json::from_value::<GeneratedUiRender>(wire).expect("the decoded render proves it again");
}

#[test]
fn component_action_in_the_manifest_assembles_and_renders_on_its_app_surface() {
    let card = card(
        vec![list_foot(Some(more_action()))],
        vec![declaration(
            "foot",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    )
    .expect("a manifest may declare an app component's own action");
    let render = card
        .render_for_surface(&stores_surface())
        .expect("render for the stores app");
    assert_eq!(declared_elements(&render), vec!["foot"]);
    let wire = serde_json::to_value(&render).expect("serialize render");
    assert_eq!(
        wire["nodes"][node_index(&wire, "foot")]["atom"]["props"]["action"],
        more_action(),
        "the component's action is on the wire beside its props"
    );
    serde_json::from_value::<GeneratedUiRender>(wire).expect("the decoded render proves it again");
}

#[test]
fn lowered_component_drops_its_action_declaration() {
    let card = card(
        vec![list_foot(Some(more_action())), status_filter()],
        vec![
            declaration(
                "foot",
                "stores.more",
                GeneratedUiActionTier::DeterministicTool,
            ),
            declaration("status", "stores.filter", GeneratedUiActionTier::Local),
        ],
    )
    .expect("card");
    let render = card
        .render_for_surface(&GeneratedUiSurfaceCapabilities::all_atom_kit())
        .expect("render for a surface without the stores catalog");
    assert_eq!(
        declared_elements(&render),
        vec!["status"],
        "the foot lowered to text and carries no action, so its declaration leaves the render"
    );
    let foot = render
        .nodes
        .iter()
        .find(|node| node.id.as_str() == "foot")
        .expect("foot node");
    assert!(matches!(foot.atom, LensAtom::TextBlock(_)));
}

#[test]
fn component_action_that_differs_from_its_declaration_is_refused() {
    let mismatched = card(
        vec![list_foot(Some(
            json!({ "command": "stores.all", "args": [] }),
        ))],
        vec![declaration(
            "foot",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    );
    assert!(
        mismatched.is_err(),
        "the manifest may declare only the component's own action"
    );
}

#[test]
fn decoded_render_whose_component_action_differs_is_refused() {
    let render = card(
        vec![list_foot(Some(more_action()))],
        vec![declaration(
            "foot",
            "stores.more",
            GeneratedUiActionTier::DeterministicTool,
        )],
    )
    .expect("card")
    .render_for_surface(&stores_surface())
    .expect("render");
    let mut wire = serde_json::to_value(&render).expect("serialize render");
    let foot = node_index(&wire, "foot");
    wire["nodes"][foot]["atom"]["props"]["action"] = json!({ "command": "stores.all", "args": [] });
    assert!(
        serde_json::from_value::<GeneratedUiRender>(wire).is_err(),
        "a render whose component action differs from its declaration must not decode"
    );
}

#[test]
fn declaration_on_an_element_without_an_action_is_refused() {
    let text_line = LensNode::new(
        atom_id("note"),
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![LensTextSpan::Literal(text("12 of 14 in"))],
        }),
    );
    assert!(
        card(
            vec![text_line],
            vec![declaration(
                "note",
                "stores.more",
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_err(),
        "a text block carries no action"
    );
    assert!(
        card(
            vec![list_foot(None)],
            vec![declaration(
                "foot",
                "stores.more",
                GeneratedUiActionTier::DeterministicTool
            )],
        )
        .is_err(),
        "a component that declares no action has none to send"
    );
}

#[test]
fn component_without_an_action_keeps_its_wire_shape() {
    let atom = serde_json::from_value::<LensAtom>(list_foot_wire(None)).expect("component");
    assert_eq!(
        serde_json::to_value(&atom).expect("serialize component"),
        list_foot_wire(None),
        "a component with no action serializes as it did before the field existed"
    );
}
