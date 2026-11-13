//! GENUI-COND-TEMPLATE: an app component's prop may be a `$cond` over the closed
//! predicate algebra or a `$template`, exactly as canon names them (ARCH-0048
//! G5 #2, eiri-dec-0011, eiri-arch-0012). A predicate is `true` or `false`, a
//! `{"$state": "/<key>", "<op>": <literal>}` comparison with one of `eq`, `neq`,
//! `gt`, `gte`, `lt`, `lte`, a list (all of them), `$and` or `$or`, and nothing
//! else. A template draws text around at most one escaped read of a text,
//! number or token key. Every key either one reads is declared and stays
//! present, so a patch cannot remove it.
//!
//! The cards are built from the wire (`serde_json`), so this file compiles on
//! the PR's base, where every `$cond` and `$template` is refused.

use oneiron_lens_wire::lens::atom::{CollectionAtom, FiniteF64, LensAtom, LensNode, LensText};
use oneiron_lens_wire::lens::generated_ui::{
    GeneratedLens, GeneratedUiCard, GeneratedUiRender, GeneratedUiStatePatch,
    GeneratedUiStateSnapshot, GeneratedUiSurfaceCapabilities, LensElementRef, SelfUiStateValue,
    apply_generated_ui_state_patch, validate_generated_ui_state_bindings,
};
use oneiron_lens_wire::lens::wire_ids::{LensAtomId, LensRenderId, SelfUiStateKey};
use serde_json::{Value, json};

const CATALOG: &str = "stores";
const COMPONENT: &str = "badge";

fn text(value: &str) -> LensText {
    LensText::new(value).expect("lens text")
}

fn atom_id(value: &str) -> LensAtomId {
    LensAtomId::new(value).expect("atom id")
}

fn token(value: &str) -> SelfUiStateValue {
    serde_json::from_value(json!({ "type": "token", "value": value })).expect("token state value")
}

fn number(value: f64) -> SelfUiStateValue {
    SelfUiStateValue::Number(FiniteF64::new(value).expect("finite number"))
}

/// One key of each kind: a count, a reading switch, a name and a pick.
fn badge_state(name: &str, picked: bool) -> GeneratedUiStateSnapshot {
    [
        ("count", number(2.0)),
        ("reading", token("units")),
        ("name", SelfUiStateValue::Text(text(name))),
        ("picked", SelfUiStateValue::Bool(picked)),
    ]
    .into_iter()
    .map(|(key, value)| (SelfUiStateKey::new(key).expect("state key"), value))
    .collect()
}

fn badge_card(props: Value, state: GeneratedUiStateSnapshot) -> Option<GeneratedUiCard> {
    let atom = serde_json::from_value::<LensAtom>(json!({
        "kind": "component",
        "props": { "catalog": CATALOG, "name": COMPONENT, "props": props },
    }))
    .ok()?;
    let mut root = LensNode::new(
        atom_id("stores"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Stores"),
            rows: Vec::new(),
        }),
    );
    root.children = vec![LensNode::with_fallback_text(
        atom_id("badge"),
        atom,
        text("badge"),
    )];
    GeneratedUiCard::interactive(
        LensRenderId::new("stores-card").expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        Vec::new(),
        state,
    )
    .ok()
}

fn assembles(props: Value) -> bool {
    badge_card(props, badge_state("owen", true)).is_some()
}

fn surface(schema: Value, expressions: Option<Value>) -> GeneratedUiSurfaceCapabilities {
    let mut wire = json!({
        "catalog": CATALOG,
        "catalogVersion": "1.0.0",
        "primitives": ["sheet", "text_block"],
        "components": [{ "name": COMPONENT, "schema": schema }],
    });
    if let Some(expressions) = expressions {
        wire["expressions"] = expressions;
    }
    serde_json::from_value(wire).expect("surface decodes")
}

/// The badge as `surface` draws it: `component`, or `text_block` once lowered.
fn render(props: Value, state: GeneratedUiStateSnapshot, schema: Value) -> GeneratedUiRender {
    badge_card(props, state)
        .expect("the badge card assembles")
        .render_for_surface(&surface(schema, Some(json!({ "computed": ["count"] }))))
        .expect("render")
}

fn badge_wire(render: &GeneratedUiRender) -> Value {
    let wire = serde_json::to_value(render).expect("serialize render");
    wire["nodes"]
        .as_array()
        .expect("render nodes")
        .iter()
        .find(|node| node["id"] == "badge")
        .expect("badge in render")["atom"]
        .clone()
}

fn label_schema(label: &str) -> Value {
    json!({ "type": "object", "properties": { "label": { "const": label } } })
}

fn yes_or_no(predicate: Value) -> Value {
    json!({ "label": { "$cond": predicate, "$then": "yes", "$else": "no" } })
}

/// Whether `predicate` holds under [`badge_state`], read from the lowering's
/// schema check: the badge is kept only when its label resolves to "yes".
fn holds(predicate: Value) -> bool {
    let atom = badge_wire(&render(
        yes_or_no(predicate),
        badge_state("owen", true),
        label_schema("yes"),
    ));
    atom["kind"] == "component"
}

#[test]
fn cond_draws_the_branch_its_predicate_names() {
    let props = json!({
        "label": {
            "$cond": { "$state": "/picked", "eq": true },
            "$then": "Submit",
            "$else": "Choose first",
        },
    });
    let picked = render(
        props.clone(),
        badge_state("owen", true),
        label_schema("Submit"),
    );
    let atom = badge_wire(&picked);
    assert_eq!(atom["kind"], "component");
    assert_eq!(
        atom["props"]["props"], props,
        "the render carries the $cond: the client resolves it against $state"
    );
    let unpicked = render(props, badge_state("owen", false), label_schema("Submit"));
    assert_eq!(
        badge_wire(&unpicked)["kind"],
        "text_block",
        "the $else branch does not meet a schema that admits only the $then label"
    );
}

#[test]
fn predicate_algebra_is_canons_closed_set() {
    let count = |op: &str, literal: f64| json!({ "$state": "/count", op: literal });
    let reading = |op: &str, literal: &str| json!({ "$state": "/reading", op: literal });
    let cases = [
        (json!(true), true),
        (json!(false), false),
        (count("eq", 2.0), true),
        (count("neq", 2.0), false),
        (count("gt", 1.0), true),
        (count("gt", 2.0), false),
        (count("gte", 2.0), true),
        (count("lt", 2.0), false),
        (count("lte", 2.0), true),
        (reading("eq", "units"), true),
        (reading("neq", "units"), false),
        (json!({ "$state": "/name", "eq": "owen" }), true),
        (json!({ "$state": "/picked", "eq": true }), true),
        (json!({ "$state": "/picked", "neq": true }), false),
        (json!([count("gt", 1.0), reading("eq", "units")]), true),
        (json!([count("gt", 1.0), reading("eq", "revenue")]), false),
        (json!({ "$and": [true, count("lt", 3.0)] }), true),
        (json!({ "$or": [false, reading("eq", "revenue")] }), false),
        (json!({ "$or": [false, reading("eq", "units")] }), true),
        (json!({ "$or": [[true, false], { "$and": [true] }] }), true),
    ];
    for (predicate, expected) in cases {
        assert_eq!(holds(predicate.clone()), expected, "{predicate}");
    }
}

#[test]
fn predicates_outside_the_algebra_are_refused() {
    for predicate in [
        json!({ "not": { "$state": "/picked", "eq": true } }),
        json!({ "$not": { "$state": "/picked", "eq": true } }),
        json!({ "$state": "/count", "in": [1, 2] }),
        json!({ "$state": "/count", "eq": 1, "neq": 2 }),
        json!({ "$state": "/count" }),
        json!({ "$state": "/count", "eq": null }),
        json!({ "$state": "/count", "eq": { "$state": "/count" } }),
        json!({ "$state": "/reading", "gt": "a" }),
        json!({ "$state": "count", "eq": 2 }),
        json!([]),
        json!({ "$and": [] }),
        json!({ "$or": "picked" }),
        json!({ "$and": [true], "$or": [true] }),
        json!(1),
        json!("true"),
        json!(null),
    ] {
        assert!(
            !assembles(yes_or_no(predicate.clone())),
            "{predicate} is not of the closed predicate algebra"
        );
    }
    for cond in [
        json!({ "$cond": true, "$then": "yes" }),
        json!({ "$cond": true, "$else": "no" }),
        json!({ "$cond": true, "$then": "yes", "$else": "no", "$default": "maybe" }),
    ] {
        assert!(
            !assembles(json!({ "label": cond.clone() })),
            "{cond} is not a $cond"
        );
    }
}

#[test]
fn comparison_with_an_undeclared_key_or_another_kind_is_refused() {
    for predicate in [
        json!({ "$state": "/missing", "eq": 1 }),
        json!({ "$state": "/count", "eq": "2" }),
        json!({ "$state": "/reading", "eq": true }),
        json!({ "$state": "/reading", "gt": 1 }),
        json!({ "$state": "/picked", "lte": 1 }),
    ] {
        assert!(
            !assembles(yes_or_no(predicate.clone())),
            "{predicate} must read a declared key of its literal's kind"
        );
    }
}

#[test]
fn template_reads_one_declared_key() {
    let greeting = json!({ "label": { "$template": "Hello, ${/name}!" } });
    let owen = render(
        greeting.clone(),
        badge_state("owen", true),
        label_schema("Hello, owen!"),
    );
    assert_eq!(badge_wire(&owen)["kind"], "component");
    assert_eq!(
        badge_wire(&owen)["props"]["props"]["label"],
        json!({ "$template": "Hello, ${/name}!" })
    );
    let yuki = render(
        greeting,
        badge_state("yuki", true),
        label_schema("Hello, owen!"),
    );
    assert_eq!(
        badge_wire(&yuki)["kind"],
        "text_block",
        "the template resolves to the name it reads"
    );
    for (template, label) in [
        ("${/count} of 3 in", "2 of 3 in"),
        ("reading ${/reading}", "reading units"),
        ("no read at all", "no read at all"),
    ] {
        let rendered = render(
            json!({ "label": { "$template": template } }),
            badge_state("owen", true),
            label_schema(label),
        );
        assert_eq!(badge_wire(&rendered)["kind"], "component", "{template}");
    }
}

#[test]
fn templates_outside_the_one_read_rule_are_refused() {
    for template in [
        json!({ "$template": "${/name} reads ${/reading}" }),
        json!({ "$template": "${/picked}" }),
        json!({ "$template": "${name}" }),
        json!({ "$template": "${/missing}" }),
        json!({ "$template": "${/name" }),
        json!({ "$template": 3 }),
        json!({ "$template": "x", "fallback": "y" }),
    ] {
        assert!(
            !assembles(json!({ "label": template.clone() })),
            "{template} must not assemble"
        );
    }
}

#[test]
fn cond_and_template_nest_as_computed_arguments() {
    let picks = json!({
        "label": {
            "$computed": "count",
            "args": { "of": [
                { "$cond": { "$state": "/count", "gt": 1 }, "$then": true, "$else": false },
                { "$state": "/picked" },
            ] },
        },
    });
    assert!(assembles(picks), "a $cond of bools is a bool argument");
    let mixed = json!({
        "label": {
            "$computed": "count",
            "args": { "of": [{ "$cond": true, "$then": true, "$else": "no" }] },
        },
    });
    assert!(
        !assembles(mixed),
        "a $cond whose branches differ in kind is no count argument"
    );
    let summed = json!({
        "label": { "$computed": "sum", "args": { "of": [{ "$template": "${/count}" }] } },
    });
    assert!(!assembles(summed), "a template is text, not a number");
}

#[test]
fn patch_that_removes_a_key_a_predicate_or_template_reads_is_refused() {
    let props = json!({
        "label": { "$cond": { "$state": "/picked", "eq": true }, "$then": "yes", "$else": "no" },
        "title": { "$template": "Hello, ${/name}!" },
    });
    let drawn = render(
        props,
        badge_state("owen", true),
        json!({ "type": "object" }),
    );
    let elements = LensElementRef::collect_flat(&drawn.nodes);
    let renamed = apply_generated_ui_state_patch(
        &drawn.state,
        &drawn.state,
        &[GeneratedUiStatePatch::Replace {
            path: "/$state/name".to_string(),
            value: SelfUiStateValue::Text(text("yuki")),
        }],
    )
    .expect("replace a declared key");
    validate_generated_ui_state_bindings(&elements, &renamed)
        .expect("the template follows the new name");
    for key in ["picked", "name"] {
        let removed = apply_generated_ui_state_patch(
            &drawn.state,
            &drawn.state,
            &[GeneratedUiStatePatch::Remove {
                path: format!("/$state/{key}"),
            }],
        )
        .expect("the patch rules alone admit a remove");
        assert!(
            validate_generated_ui_state_bindings(&elements, &removed).is_err(),
            "the server refuses a patch that removes {key}, which the badge reads"
        );
    }
}

#[test]
fn cond_and_template_lower_on_a_surface_without_the_tier() {
    let card = badge_card(
        json!({
            "label": { "$cond": true, "$then": "yes", "$else": "no" },
            "title": { "$template": "Hello, ${/name}!" },
        }),
        badge_state("owen", true),
    )
    .expect("the badge card assembles");
    let lowered = card
        .render_for_surface(&surface(json!({}), None))
        .expect("render");
    assert_eq!(
        badge_wire(&lowered)["kind"],
        "text_block",
        "a component never sees an expression object"
    );
}
