//! GENUI-STATE-PERSIST (Engine ruling 14 Nov 05:40, item 2): a live
//! re-render of the same subscription carries the replaced card's `$state`
//! over, key by key, where the new render declares the key with the same
//! kind and its `$bind`s accept the value. Any other key keeps the new
//! render's initial value, and a key the new render does not declare is
//! dropped.
//!
//! Red on the base (#7709's head with this file): `carry_state` does not
//! exist, so the file does not build.
//! `cargo test --locked -p oneiron-lens-wire --all-features --test
//! genui_state_carry`.

use oneiron_lens_wire::lens::atom::{CollectionAtom, FiniteF64, LensAtom, LensNode, LensText};
use oneiron_lens_wire::lens::generated_ui::{
    GeneratedLens, GeneratedUiActionDeclaration, GeneratedUiActionTier, GeneratedUiCard,
    GeneratedUiRender, GeneratedUiStateSnapshot, SelfUiBindableProperty, SelfUiBinding,
    SelfUiStateValue,
};
use oneiron_lens_wire::lens::self_ui::{
    SegmentedControl, SelfUiAction, SelfUiControl, SelfUiOption,
};
use oneiron_lens_wire::lens::wire_ids::{
    LensAtomId, LensRenderId, SelfUiActionId, SelfUiControlId, SelfUiOptionValue, SelfUiStateKey,
};

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn token(value: &str) -> SelfUiStateValue {
    SelfUiStateValue::Token(SelfUiOptionValue::new(value).expect("option value"))
}

fn note(value: &str) -> SelfUiStateValue {
    SelfUiStateValue::Text(text(value))
}

fn state(entries: Vec<(&str, SelfUiStateValue)>) -> GeneratedUiStateSnapshot {
    entries
        .into_iter()
        .map(|(key, value)| (SelfUiStateKey::new(key).expect("state key"), value))
        .collect()
}

fn pace_action() -> SelfUiAction {
    SelfUiAction {
        command: SelfUiActionId::new("pace.set").expect("action id"),
        args: Vec::new(),
    }
}

/// A walk-planner card: a segmented control offering `paces`, its selection
/// bound to the `pace` key, beside the card's declared `initial` `$state`.
fn planner(paces: &[&str], initial: GeneratedUiStateSnapshot) -> GeneratedUiRender {
    let mut pace = LensNode::with_fallback_text(
        LensAtomId::new("pace").expect("atom id"),
        LensAtom::SelfUi(SelfUiControl::Segmented(SegmentedControl {
            id: SelfUiControlId::new("pace").expect("control id"),
            label: text("Pace"),
            options: paces
                .iter()
                .map(|value| SelfUiOption {
                    value: SelfUiOptionValue::new(*value).expect("option value"),
                    label: text(value),
                })
                .collect(),
            selected: None,
            action: pace_action(),
        })),
        text("Pace"),
    );
    pace.state_bindings = vec![SelfUiBinding {
        state_key: SelfUiStateKey::new("pace").expect("state key"),
        property: SelfUiBindableProperty::Selected,
    }];
    let mut root = LensNode::with_fallback_text(
        LensAtomId::new("root").expect("atom id"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Walk"),
            rows: Vec::new(),
        }),
        text("Walk"),
    );
    root.children = vec![pace];
    GeneratedUiCard::interactive(
        LensRenderId::new("walk-planner").expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        vec![GeneratedUiActionDeclaration {
            element_id: LensAtomId::new("pace").expect("atom id"),
            action_id: SelfUiActionId::new("pace.set").expect("action id"),
            tier: GeneratedUiActionTier::Local,
            action: pace_action(),
        }],
        initial,
    )
    .expect("a planner card")
    .render()
    .expect("render")
}

/// What the person set on the card the re-render replaces.
fn previous() -> GeneratedUiStateSnapshot {
    state(vec![
        ("pace", token("brisk")),
        ("note", note("after lunch")),
    ])
}

#[test]
fn a_re_render_carries_each_key_it_declares_with_the_same_kind() {
    let mut render = planner(
        &["easy", "brisk"],
        state(vec![("pace", token("easy")), ("note", note("none yet"))]),
    );
    assert_eq!(render.carry_state(&previous()), 2);
    assert_eq!(render.state, previous());

    // The carried render is a valid card: it decodes again, every `$bind`
    // proved against the carried state.
    let wire = serde_json::to_value(&render).expect("serialize render");
    let decoded: GeneratedUiRender = serde_json::from_value(wire).expect("the render decodes");
    assert_eq!(decoded.state, previous());
}

#[test]
fn a_key_whose_kind_changed_keeps_the_new_renders_value() {
    let count = SelfUiStateValue::Number(FiniteF64::new(3.0).expect("finite"));
    let mut render = planner(
        &["easy", "brisk"],
        state(vec![("pace", token("easy")), ("note", count.clone())]),
    );
    assert_eq!(render.carry_state(&previous()), 1);
    assert_eq!(
        render.state,
        state(vec![("pace", token("brisk")), ("note", count)])
    );
}

#[test]
fn a_value_the_new_control_no_longer_offers_is_not_carried() {
    let mut render = planner(
        &["easy", "steady"],
        state(vec![("pace", token("easy")), ("note", note("none yet"))]),
    );
    assert_eq!(render.carry_state(&previous()), 1);
    assert_eq!(
        render.state,
        state(vec![("pace", token("easy")), ("note", note("after lunch"))]),
        "the control never draws an option it does not offer"
    );
}

#[test]
fn a_key_the_new_render_does_not_declare_is_dropped() {
    let mut render = planner(
        &["easy", "brisk"],
        state(vec![
            ("pace", token("easy")),
            ("north", SelfUiStateValue::Bool(false)),
        ]),
    );
    assert_eq!(render.carry_state(&previous()), 1);
    assert_eq!(
        render.state,
        state(vec![
            ("pace", token("brisk")),
            ("north", SelfUiStateValue::Bool(false)),
        ]),
        "`note` is not declared, and `north` keeps its initial value"
    );
}
