//! Generated-UI render-protocol tests: cards, segments, prebuilt shorthand, and
//! tree construction.

use super::*;
use crate::Result;
use serde_json::json;

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
fn generated_lens_requires_fallback_text_per_node() {
    let missing = json!({
        "kit_version": LENS_ATOM_KIT_VERSION,
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
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
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
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
