//! GENUI-STATE-PERSIST at the event gate: a pick in a composed card is card
//! state only, and it reaches the agent with the card's one action. A model
//! round trip's callback carries the card's `$state` as the event found it,
//! after the local events that moved it.
//!
//! Red on main: the callback has no `state` field, so this file does not
//! build there. `cargo test --locked -p oneiron --all-features --test
//! genui_round_trip_state`.

use oneiron::claim::ScopedReadActorKey;
use oneiron::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiActionEvent, GeneratedUiActionTier, GeneratedUiCard, GeneratedUiRender,
    GeneratedUiStatePatch, GeneratedUiStateSnapshot, GeneratedUiSurfaceCapabilities,
    GeneratedUiValidatedAction, LensAtom, LensAtomId, LensNode, LensPrincipalBinding,
    LensRenderFrame, LensRenderId, LensText, SelfUiAction, SelfUiActionId, SelfUiBindableProperty,
    SelfUiBinding, SelfUiControl, SelfUiControlId, SelfUiStateKey, SelfUiStateValue, ToggleControl,
};
use oneiron::{Vault, VaultConfig};
use serde_json::json;

const CARD: &str = "stores-card";

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn atom_id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("atom id")
}

fn state_key(value: &str) -> SelfUiStateKey {
    SelfUiStateKey::new(value).expect("state key")
}

fn flag(value: bool) -> SelfUiStateValue {
    serde_json::from_value(json!({ "type": "bool", "value": value })).expect("bool state value")
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

/// A store's pick: a toggle whose `checked` is the `$state` key of its id.
fn pick(id: &str, label: &str) -> LensNode {
    let mut node = LensNode::new(
        atom_id(id),
        LensAtom::SelfUi(SelfUiControl::Toggle(ToggleControl {
            id: SelfUiControlId::new(id).expect("control id"),
            label: text(label),
            checked: false,
            action: action("stores.pick"),
        })),
    );
    node.state_bindings = vec![SelfUiBinding {
        state_key: state_key(id),
        property: SelfUiBindableProperty::Checked,
    }];
    node
}

/// The card's one action: it goes back to the agent that composed the card.
fn send_button() -> LensNode {
    LensNode::new(
        atom_id("send"),
        LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
            id: SelfUiControlId::new("send").expect("control id"),
            label: text("Use these stores"),
            action: action("stores.send"),
        })),
    )
}

/// Two stores to pick from and the card's one action, both picks off.
fn render() -> GeneratedUiRender {
    let mut root = LensNode::new(
        atom_id("stores"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Stores"),
            rows: Vec::new(),
        }),
    );
    root.children = vec![
        pick("north", "North store"),
        pick("south", "South store"),
        send_button(),
    ];
    let state: GeneratedUiStateSnapshot = [
        (state_key("north"), flag(false)),
        (state_key("south"), flag(false)),
    ]
    .into_iter()
    .collect();
    let card = GeneratedUiCard::interactive(
        LensRenderId::new(CARD).expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        vec![
            declaration("north", "stores.pick", GeneratedUiActionTier::Local),
            declaration("south", "stores.pick", GeneratedUiActionTier::Local),
            declaration("send", "stores.send", GeneratedUiActionTier::ModelRoundTrip),
        ],
        state,
    )
    .expect("the manifest declares each element's own action");
    card.render_for_surface(&GeneratedUiSurfaceCapabilities::all_atom_kit())
        .expect("render for the whole atom kit")
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

fn picked(key: &str) -> GeneratedUiStatePatch {
    GeneratedUiStatePatch::Replace {
        path: format!("/$state/{key}"),
        value: flag(true),
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

/// The host's step for one event: validate it against the card's current
/// `$state`, and hold the next state a local action leaves.
fn send(
    render: &GeneratedUiRender,
    state: &mut GeneratedUiStateSnapshot,
    event: &GeneratedUiActionEvent,
) -> GeneratedUiValidatedAction {
    let (_dir, vault, key, frame) = viewer_frame();
    let scoped_read = vault.scoped_read(key);
    let validated = frame
        .validate_action_event(&scoped_read, frame.principal(), render, state, event)
        .expect("the card's own action validates");
    if let GeneratedUiValidatedAction::Local { state: next, .. } = &validated {
        *state = next.clone();
    }
    validated
}

#[test]
fn the_round_trip_carries_the_picks_the_card_holds() {
    let render = render();
    let mut state = render.state.clone();
    send(
        &render,
        &mut state,
        &event("north", "stores.pick", vec![picked("north")]),
    );
    assert_eq!(state.get(&state_key("north")), Some(&flag(true)));

    let validated = send(
        &render,
        &mut state,
        &event("send", "stores.send", Vec::new()),
    );
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = validated else {
        panic!("the card's one action goes back to the agent");
    };
    assert_eq!(callback.action_name.as_str(), "stores.send");
    assert_eq!(
        callback.state, state,
        "the agent reads the card's picks with its action"
    );
    assert_eq!(callback.state.get(&state_key("north")), Some(&flag(true)));
    assert_eq!(callback.state.get(&state_key("south")), Some(&flag(false)));
}

#[test]
fn an_untouched_card_sends_its_initial_state() {
    let render = render();
    let mut state = render.state.clone();
    let validated = send(
        &render,
        &mut state,
        &event("send", "stores.send", Vec::new()),
    );
    let GeneratedUiValidatedAction::ModelRoundTrip { callback, .. } = validated else {
        panic!("the card's one action goes back to the agent");
    };
    assert_eq!(callback.state, render.state);
}
