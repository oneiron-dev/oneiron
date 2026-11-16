//! GENUI-INTERP-KEY: in a generated card, a text block's one escaped interpolation
//! reads `$state`. The key names a declared `$state` key, the card proves it at
//! assembly, a decoded render proves it again, and a client patch can never remove
//! the key a text block reads. A bool has no single text form, so it is refused.

use oneiron_lens_wire::lens::atom::{
    FiniteF64, LensAtom, LensNode, LensText, LensTextSpan, TextBlockAtom,
};
use oneiron_lens_wire::lens::generated_ui::{
    GeneratedLens, GeneratedUiCard, GeneratedUiRender, GeneratedUiStatePatch,
    GeneratedUiStateSnapshot, LensElementRef, SelfUiStateValue, apply_generated_ui_state_patch,
    validate_generated_ui_state_bindings,
};
use oneiron_lens_wire::lens::wire_ids::{LensAtomId, LensHandleName, LensRenderId, SelfUiStateKey};
use serde_json::json;

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn number(value: f64) -> SelfUiStateValue {
    SelfUiStateValue::Number(FiniteF64::new(value).expect("finite number"))
}

/// The designed foot of a store table: `12 of 14 in`, where 12 follows the picks.
fn foot_count_root(key: &str) -> LensNode {
    LensNode::new(
        LensAtomId::new("foot").expect("atom id"),
        LensAtom::TextBlock(TextBlockAtom {
            spans: vec![
                LensTextSpan::Interpolation {
                    key: LensHandleName::new(key).expect("interpolation key"),
                    fallback: text("12"),
                },
                LensTextSpan::Literal(text(" of 14 in")),
            ],
        }),
    )
}

fn state(entries: Vec<(&str, SelfUiStateValue)>) -> GeneratedUiStateSnapshot {
    entries
        .into_iter()
        .map(|(key, value)| (SelfUiStateKey::new(key).expect("state key"), value))
        .collect()
}

fn foot_count_card(
    key: &str,
    state: GeneratedUiStateSnapshot,
) -> Result<GeneratedUiCard, impl std::fmt::Debug> {
    let tree = GeneratedLens::new(foot_count_root(key)).expect("generated lens");
    GeneratedUiCard::interactive(
        LensRenderId::new("stores-card").expect("card id"),
        tree,
        Vec::new(),
        state,
    )
}

fn foot_count_render() -> GeneratedUiRender {
    foot_count_card("picked", state(vec![("picked", number(12.0))]))
        .expect("a card whose interpolation reads a declared $state key")
        .render()
        .expect("render")
}

#[test]
fn interpolation_reading_a_declared_state_key_renders() {
    let render = foot_count_render();
    let wire = serde_json::to_value(&render).expect("serialize render");
    assert_eq!(
        wire["nodes"][0]["atom"]["props"]["spans"][0],
        json!({ "type": "interpolation", "value": { "key": "picked", "fallback": "12" } }),
        "the span keeps its key: the client reads $state[key]"
    );
    assert_eq!(
        wire["$state"]["picked"],
        json!({ "type": "number", "value": 12.0 })
    );
    serde_json::from_value::<GeneratedUiRender>(wire).expect("the render decodes again");
}

#[test]
fn interpolation_of_an_undeclared_state_key_is_refused() {
    assert!(
        foot_count_card("picked", GeneratedUiStateSnapshot::default()).is_err(),
        "a card whose text reads a $state key it never declared must not assemble"
    );
    assert!(
        foot_count_card("picked", state(vec![("total", number(14.0))])).is_err(),
        "the interpolation key must be the declared key itself"
    );
}

#[test]
fn interpolation_of_a_bool_state_value_is_refused() {
    let card = foot_count_card(
        "picked",
        state(vec![("picked", SelfUiStateValue::Bool(true))]),
    );
    assert!(card.is_err(), "a bool $state value has no single text form");
}

#[test]
fn interpolation_reading_text_or_token_state_assembles() {
    let as_text = foot_count_card(
        "picked",
        state(vec![("picked", SelfUiStateValue::Text(text("twelve")))]),
    );
    assert!(as_text.is_ok(), "a text value draws as itself");
    let as_token = serde_json::from_value::<SelfUiStateValue>(json!({
        "type": "token",
        "value": "reading-b"
    }))
    .expect("token state value");
    assert!(
        foot_count_card("picked", state(vec![("picked", as_token)])).is_ok(),
        "a token value draws as itself"
    );
}

#[test]
fn decoded_render_naming_an_undeclared_key_is_refused() {
    let mut wire = serde_json::to_value(foot_count_render()).expect("serialize render");
    wire["$state"] = json!({});
    assert!(
        serde_json::from_value::<GeneratedUiRender>(wire).is_err(),
        "a render whose text reads an undeclared $state key must not decode"
    );
}

#[test]
fn patch_that_moves_the_count_is_accepted() {
    let render = foot_count_render();
    let patch = vec![GeneratedUiStatePatch::Replace {
        path: "/$state/picked".to_string(),
        value: number(13.0),
    }];
    let next = apply_generated_ui_state_patch(&render.state, &render.state, &patch)
        .expect("replace a declared key");
    validate_generated_ui_state_bindings(&LensElementRef::collect_flat(&render.nodes), &next)
        .expect("the text follows the state");
    assert_eq!(
        next.get(&SelfUiStateKey::new("picked").expect("state key")),
        Some(&number(13.0))
    );
}

#[test]
fn patch_that_removes_the_interpolated_key_is_refused() {
    let render = foot_count_render();
    let patch = vec![GeneratedUiStatePatch::Remove {
        path: "/$state/picked".to_string(),
    }];
    let next = apply_generated_ui_state_patch(&render.state, &render.state, &patch)
        .expect("the patch rules alone admit a remove");
    assert!(
        validate_generated_ui_state_bindings(&LensElementRef::collect_flat(&render.nodes), &next)
            .is_err(),
        "the server refuses a patch that removes the key a text block reads"
    );
}
