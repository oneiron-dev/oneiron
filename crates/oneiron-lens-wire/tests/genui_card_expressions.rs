//! GENUI-COMPUTED: an app component's props may read the card's `$state`, either
//! directly with `{"$state": "/<key>"}` or through a `$computed` call of the
//! engine's fixed function set. The foot's count then follows the picks, and the
//! chart follows the reading switch, with no host re-send. A component never
//! sees an expression object: only a surface that declares the expression tier,
//! with every function the props call, keeps it, and the props it resolves
//! against `$state` must meet the component's schema. Every key an expression
//! reads is declared and stays present, so a patch cannot remove it.
//!
//! The surfaces that declare the tier are built from the wire (`serde_json`),
//! because the field is new: this file compiles on main, and its red run shows
//! the refusals.

use oneiron_lens_wire::lens::atom::{CollectionAtom, FiniteF64, LensAtom, LensNode, LensText};
use oneiron_lens_wire::lens::generated_ui::{
    GeneratedLens, GeneratedUiCard, GeneratedUiRender, GeneratedUiStatePatch,
    GeneratedUiStateSnapshot, GeneratedUiSurfaceCapabilities, LensElementRef, SelfUiStateValue,
    apply_generated_ui_state_patch, validate_generated_ui_state_bindings,
};
use oneiron_lens_wire::lens::wire_ids::{LensAtomId, LensRenderId, SelfUiStateKey};
use serde_json::{Value, json};

const CATALOG: &str = "stores";

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

fn state(entries: Vec<(&str, SelfUiStateValue)>) -> GeneratedUiStateSnapshot {
    entries
        .into_iter()
        .map(|(key, value)| (SelfUiStateKey::new(key).expect("state key"), value))
        .collect()
}

/// `$state` for a table of three stores, two of them picked, read as revenue.
fn stores_state() -> GeneratedUiStateSnapshot {
    state(vec![
        ("pick.r1", SelfUiStateValue::Bool(true)),
        ("pick.r2", SelfUiStateValue::Bool(false)),
        ("pick.r3", SelfUiStateValue::Bool(true)),
        ("reading", token("revenue")),
    ])
}

fn component_atom(name: &str, props: Value) -> Result<LensAtom, serde_json::Error> {
    serde_json::from_value(json!({
        "kind": "component",
        "props": { "catalog": CATALOG, "name": name, "props": props },
    }))
}

fn component(id: &str, name: &str, props: Value) -> LensNode {
    let atom = component_atom(name, props).expect("component atom decodes");
    LensNode::with_fallback_text(atom_id(id), atom, text(id))
}

/// The chart reads the reading switch's `$state` key and draws that series.
fn chart_props() -> Value {
    json!({
        "reading": { "$state": "/reading" },
        "readings": { "revenue": [3, 5, 8], "units": [1, 2, 4] },
    })
}

fn picks_count(keys: &[&str]) -> Value {
    let of = keys
        .iter()
        .map(|key| json!({ "$state": format!("/{key}") }))
        .collect::<Vec<_>>();
    json!({ "$computed": "count", "args": { "of": of } })
}

/// The foot's `12 of 14 in`, here `2 of 3 in`: the count follows the picks.
fn foot_props() -> Value {
    json!({
        "picked": picks_count(&["pick.r1", "pick.r2", "pick.r3"]),
        "total": 3,
    })
}

fn chart_schema() -> Value {
    json!({
        "type": "object",
        "required": ["reading", "readings"],
        "properties": { "reading": { "enum": ["revenue", "units"] } },
    })
}

fn foot_schema() -> Value {
    json!({
        "type": "object",
        "required": ["picked", "total"],
        "properties": { "picked": { "type": "integer", "minimum": 0, "maximum": 3 } },
    })
}

fn card(
    children: Vec<LensNode>,
    state: GeneratedUiStateSnapshot,
) -> Result<GeneratedUiCard, impl std::fmt::Debug> {
    let mut root = LensNode::new(
        atom_id("stores"),
        LensAtom::Sheet(CollectionAtom {
            title: text("Stores"),
            rows: Vec::new(),
        }),
    );
    root.children = children;
    GeneratedUiCard::interactive(
        LensRenderId::new("stores-card").expect("card id"),
        GeneratedLens::new(root).expect("generated lens"),
        Vec::new(),
        state,
    )
}

fn surface_wire(chart_schema: Value, foot_schema: Value) -> Value {
    json!({
        "catalog": CATALOG,
        "catalogVersion": "1.0.0",
        "primitives": ["sheet", "text_block"],
        "components": [
            { "name": "bar_chart", "schema": chart_schema },
            { "name": "list_foot", "schema": foot_schema },
        ],
    })
}

/// The stores app's surface, resolving the expression tier `expressions` names.
fn resolving_surface(expressions: Value) -> GeneratedUiSurfaceCapabilities {
    let mut wire = surface_wire(chart_schema(), foot_schema());
    wire["expressions"] = expressions;
    serde_json::from_value(wire).expect("a surface that declares the expression tier decodes")
}

/// A surface that resolves no expression and admits any props.
fn plain_surface() -> GeneratedUiSurfaceCapabilities {
    serde_json::from_value(surface_wire(json!({}), json!({}))).expect("plain surface decodes")
}

fn render_wire(render: &GeneratedUiRender) -> Value {
    serde_json::to_value(render).expect("serialize render")
}

fn node<'a>(wire: &'a Value, id: &str) -> &'a Value {
    wire["nodes"]
        .as_array()
        .expect("render nodes")
        .iter()
        .find(|node| node["id"] == id)
        .expect("node in render")
}

fn drawn_as(render: &GeneratedUiRender, id: &str) -> Value {
    node(&render_wire(render), id)["atom"]["kind"].clone()
}

#[test]
fn chart_prop_reading_the_switch_renders_on_a_surface_that_resolves_expressions() {
    let card = card(
        vec![component("chart", "bar_chart", chart_props())],
        stores_state(),
    )
    .expect("a chart whose prop reads a declared $state key assembles");
    let render = card
        .render_for_surface(&resolving_surface(json!({})))
        .expect("render for the stores app");
    let wire = render_wire(&render);
    let chart = node(&wire, "chart");
    assert_eq!(chart["atom"]["kind"], "component");
    assert_eq!(
        chart["atom"]["props"]["props"]["reading"],
        json!({ "$state": "/reading" }),
        "the render carries the expression: the client resolves it against $state"
    );
    serde_json::from_value::<GeneratedUiRender>(wire).expect("the decoded render proves it again");
}

#[test]
fn foot_count_follows_the_picks_through_computed_count() {
    let card = card(
        vec![component("foot", "list_foot", foot_props())],
        stores_state(),
    )
    .expect("a foot that counts the picks assembles");
    let render = card
        .render_for_surface(&resolving_surface(json!({ "computed": ["count"] })))
        .expect("render for the stores app");
    let wire = render_wire(&render);
    assert_eq!(node(&wire, "foot")["atom"]["kind"], "component");
    assert_eq!(
        node(&wire, "foot")["atom"]["props"]["props"]["picked"]["$computed"],
        "count"
    );
    let pick = vec![GeneratedUiStatePatch::Replace {
        path: "/$state/pick.r2".to_string(),
        value: SelfUiStateValue::Bool(true),
    }];
    let next = apply_generated_ui_state_patch(&render.state, &render.state, &pick)
        .expect("a pick is a declared bool");
    validate_generated_ui_state_bindings(&LensElementRef::collect_flat(&render.nodes), &next)
        .expect("the foot follows the pick with no host re-send");
}

#[test]
fn component_with_an_expression_lowers_on_a_surface_without_the_tier() {
    let card = card(
        vec![
            component("chart", "bar_chart", chart_props()),
            component("foot", "list_foot", foot_props()),
        ],
        stores_state(),
    )
    .expect("card");
    let render = card
        .render_for_surface(&plain_surface())
        .expect("render for a surface that resolves no expression");
    assert_eq!(
        drawn_as(&render, "chart"),
        "text_block",
        "a component never sees an expression object: it lowers to its fallbackText"
    );
    assert_eq!(drawn_as(&render, "foot"), "text_block");
}

#[test]
fn function_the_surface_did_not_register_lowers_the_component() {
    let card = card(
        vec![component("foot", "list_foot", foot_props())],
        stores_state(),
    )
    .expect("card");
    let without_count = card
        .render_for_surface(&resolving_surface(json!({ "computed": ["sum"] })))
        .expect("render");
    assert_eq!(
        drawn_as(&without_count, "foot"),
        "text_block",
        "the surface registered no count"
    );
    let with_count = card
        .render_for_surface(&resolving_surface(json!({ "computed": ["sum", "count"] })))
        .expect("render");
    assert_eq!(drawn_as(&with_count, "foot"), "component");
}

#[test]
fn resolved_props_must_meet_the_component_schema() {
    let surface = resolving_surface(json!({ "computed": ["count"] }));
    let off_schema = card(
        vec![component("chart", "bar_chart", chart_props())],
        state(vec![("reading", token("costs"))]),
    )
    .expect("card")
    .render_for_surface(&surface)
    .expect("render");
    assert_eq!(
        drawn_as(&off_schema, "chart"),
        "text_block",
        "a reading the chart's schema does not name lowers the chart"
    );
    let four_picks = card(
        vec![component(
            "foot",
            "list_foot",
            json!({
                "picked": picks_count(&["pick.r1", "pick.r2", "pick.r3", "pick.r4"]),
                "total": 3,
            }),
        )],
        state(vec![
            ("pick.r1", SelfUiStateValue::Bool(true)),
            ("pick.r2", SelfUiStateValue::Bool(true)),
            ("pick.r3", SelfUiStateValue::Bool(true)),
            ("pick.r4", SelfUiStateValue::Bool(true)),
        ]),
    )
    .expect("card")
    .render_for_surface(&surface)
    .expect("render");
    assert_eq!(
        drawn_as(&four_picks, "foot"),
        "text_block",
        "a count of 4 is past the foot's schema maximum of 3"
    );
}

#[test]
fn computed_sum_is_checked_against_the_schema_too() {
    let weights = |a: f64, b: f64| {
        card(
            vec![component(
                "foot",
                "list_foot",
                json!({
                    "picked": {
                        "$computed": "sum",
                        "args": { "of": [{ "$state": "/weight.a" }, { "$state": "/weight.b" }] },
                    },
                    "total": 3,
                }),
            )],
            state(vec![("weight.a", number(a)), ("weight.b", number(b))]),
        )
        .expect("card")
        .render_for_surface(&resolving_surface(json!({ "computed": ["sum"] })))
        .expect("render")
    };
    assert_eq!(drawn_as(&weights(1.0, 2.0), "foot"), "component");
    assert_eq!(
        drawn_as(&weights(2.0, 2.0), "foot"),
        "text_block",
        "a sum of 4 is past the foot's schema maximum of 3"
    );
}

#[test]
fn expression_reading_an_undeclared_key_is_refused() {
    assert!(
        card(
            vec![component("chart", "bar_chart", chart_props())],
            GeneratedUiStateSnapshot::default(),
        )
        .is_err(),
        "a chart that reads a $state key the card never declared must not assemble"
    );
    assert!(
        card(
            vec![component("foot", "list_foot", foot_props())],
            state(vec![
                ("pick.r1", SelfUiStateValue::Bool(true)),
                ("pick.r3", SelfUiStateValue::Bool(true)),
            ]),
        )
        .is_err(),
        "every key a $computed argument reads must be declared"
    );
}

#[test]
fn computed_argument_of_another_kind_is_refused() {
    let counts = |of: Value| {
        card(
            vec![component(
                "foot",
                "list_foot",
                json!({ "picked": { "$computed": "count", "args": { "of": of } }, "total": 3 }),
            )],
            stores_state(),
        )
    };
    assert!(
        counts(json!([{ "$state": "/pick.r1" }, true])).is_ok(),
        "count takes bools, literal or read"
    );
    assert!(
        counts(json!([{ "$state": "/reading" }])).is_err(),
        "a token is not a bool"
    );
    assert!(counts(json!([3])).is_err(), "a number is not a bool");
    assert!(
        counts(json!([[true]])).is_err(),
        "a list is not a plain value"
    );
}

#[test]
fn undeclared_expression_forms_are_refused_at_decode() {
    for props in [
        json!({ "x": { "$expr": "a + b" } }),
        json!({ "x": { "$bind": "/reading" } }),
        json!({ "x": { "$item": "day" } }),
        json!({ "x": { "$state": "reading" } }),
        json!({ "x": { "$state": "/reading", "default": "units" } }),
        json!({ "x": { "$computed": "format_date", "args": { "of": [] } } }),
        json!({ "x": { "$computed": "count" } }),
        json!({ "x": { "$computed": "count", "args": { "of": [], "by": "day" } } }),
        json!({ "$state": "/reading" }),
    ] {
        assert!(
            component_atom("bar_chart", props.clone()).is_err(),
            "{props} must not decode: a `$` key names one closed expression form"
        );
    }
}

#[test]
fn expressions_nest_at_most_eight_deep() {
    let nested = |depth: usize| {
        let mut value = json!({ "$state": "/weight.a" });
        for _ in 1..depth {
            value = json!({ "$computed": "sum", "args": { "of": [value] } });
        }
        card(
            vec![component(
                "foot",
                "list_foot",
                json!({ "picked": value, "total": 3 }),
            )],
            state(vec![("weight.a", number(1.0))]),
        )
    };
    assert!(nested(8).is_ok(), "eight levels assemble");
    assert!(nested(9).is_err(), "a ninth level is refused");
}

#[test]
fn patch_that_removes_a_key_a_prop_reads_is_refused() {
    let render = card(
        vec![component("chart", "bar_chart", chart_props())],
        stores_state(),
    )
    .expect("card")
    .render_for_surface(&resolving_surface(json!({})))
    .expect("render");
    let remove = vec![GeneratedUiStatePatch::Remove {
        path: "/$state/reading".to_string(),
    }];
    let next = apply_generated_ui_state_patch(&render.state, &render.state, &remove)
        .expect("the patch rules alone admit a remove");
    assert!(
        validate_generated_ui_state_bindings(&LensElementRef::collect_flat(&render.nodes), &next)
            .is_err(),
        "the server refuses a patch that removes the key the chart reads"
    );
}

#[test]
fn decoded_render_naming_an_undeclared_key_is_refused() {
    let render = card(
        vec![component("chart", "bar_chart", chart_props())],
        stores_state(),
    )
    .expect("card")
    .render_for_surface(&resolving_surface(json!({})))
    .expect("render");
    let mut wire = render_wire(&render);
    wire["$state"] = json!({ "pick.r1": { "type": "bool", "value": true } });
    assert!(
        serde_json::from_value::<GeneratedUiRender>(wire).is_err(),
        "a render whose chart reads an undeclared $state key must not decode"
    );
}

#[test]
fn props_without_expressions_keep_their_wire() {
    let props = json!({ "picked": 2, "total": 3, "note": { "kind": "plain" } });
    let render = card(
        vec![component("foot", "list_foot", props.clone())],
        GeneratedUiStateSnapshot::default(),
    )
    .expect("plain props need no $state")
    .render_for_surface(&plain_surface())
    .expect("render");
    let wire = render_wire(&render);
    assert_eq!(node(&wire, "foot")["atom"]["kind"], "component");
    assert_eq!(node(&wire, "foot")["atom"]["props"]["props"], props);
}
