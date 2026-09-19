//! Span-grain selection handles and quote triples (OF-248 steps 2-3).
//!
//! Atom-grain law lives in `selection_handles.rs`; this module covers only the
//! span grain: selecting a scalar range, resolving its Loro cursors at the pinned
//! revision, stale-revision fail-closed (including equal-length edits that keep
//! the scalar length), the span request shape fuzz, and the quote pointer triple
//! (`replyToMessageId + replyToRevisionId + replyToRange`, pointer never copy).

use super::*;
use crate::Result;
use crate::entity_id::EntityId;
use crate::lens::mediation::{LensQuoteTriple, LensSpanGrain, LensSpanSelectionRequest};
use crate::registry::ENTITY_TYPE_ASSET_TEXT;
use crate::temporal::TimeRange;
use crate::test_util::entity as test_entity_id;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serde_json::json;
use xxhash_rust::xxh32::xxh32;

const SPAN_TEXT: &str = "hello world";
const MULTILINGUAL_TEXT: &str = "\u{3042}\u{1f600}b\u{65e5}\u{672c}\u{8a9e}";

fn message_id(seed: u8) -> EntityId {
    test_entity_id(seed)
}

fn put_message(vault: &crate::Vault, id: &EntityId, content: &str) -> Result<()> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"span fixture author",
    )?;
    vault
        .memory(actor, crate::EdgeActorClass::Human)
        .witness(&crate::WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            occurred_at: 1,
            messages: vec![crate::WitnessMessage {
                id: Some(id.to_hex()),
                author: crate::WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: content.into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
    Ok(())
}

fn put_asset_text(vault: &crate::Vault, id: &EntityId, text: &str) -> Result<()> {
    vault.put_entity(
        id,
        ENTITY_TYPE_ASSET_TEXT,
        TimeRange { start: 1, end: 1 },
        1,
        text.as_bytes(),
    )
}

/// A frame holding one host-minted `visible-set` EntitySet row over a MESSAGE
/// carrying `content`, plus the entity id for quote assertions.
fn message_fixture(
    vault: &crate::Vault,
    seed: u8,
    content: &str,
) -> Result<(crate::claim::ScopedReadActorKey, LensRenderFrame, EntityId)> {
    let target_id = message_id(seed);
    put_message(vault, &target_id, content)?;
    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    frame.mint_backing_ref(
        &vault.scoped_read(viewer_key.clone()),
        handle("visible-set"),
        LensHandleRole::EntitySet,
        backing_target_for(vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;
    Ok((viewer_key, frame, target_id))
}

/// A frame holding one host-minted `visible-set` EntitySet row over an
/// ASSET_TEXT row. Asset text is mutable, so this is the staleness fixture: a
/// MESSAGE id is bound to its original body and can never move.
fn asset_fixture(
    vault: &crate::Vault,
    seed: u8,
    text: &str,
) -> Result<(crate::claim::ScopedReadActorKey, LensRenderFrame, EntityId)> {
    let target_id = message_id(seed);
    put_asset_text(vault, &target_id, text)?;
    let (viewer_key, mut frame) = viewer_frame("card-1")?;
    frame.mint_backing_ref(
        &vault.scoped_read(viewer_key.clone()),
        handle("visible-set"),
        LensHandleRole::EntitySet,
        backing_target_for(vault, &target_id, LensBackingTargetKind::Entity)?,
    )?;
    Ok((viewer_key, frame, target_id))
}

fn span_selection(
    card: &str,
    atom: &str,
    name: &str,
    start: u32,
    end: u32,
) -> LensSpanSelectionRequest {
    LensSpanSelectionRequest {
        card_id: render_id(card),
        atom_id: id(atom),
        handle: handle(name),
        start,
        end,
    }
}

fn span_render() -> Result<GeneratedUiRender> {
    selectable_render(
        "card-1",
        "people",
        vec![binding("visible-set", LensHandleRole::EntitySet)],
    )
}

#[test]
fn span_select_resolves_cursor_at_recorded_version() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = message_fixture(&vault, 30, SPAN_TEXT)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;

    let read_handle = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 1, 5),
    )?;
    let grain: &LensSpanGrain = read_handle
        .span()
        .expect("span-selected handles carry the grain");
    assert_eq!(grain.range(), (1, 5));
    assert_eq!(
        grain.revision().len(),
        64,
        "the pin is a blake3 hex revision"
    );
    assert!(
        grain
            .revision()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    );

    // The atom six-key wire plus exactly one grain key.
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
            "span",
            "targetKind"
        ]
    );
    let grain_value = encoded.get("span").expect("span grain rides the handle");
    let mut grain_keys = grain_value
        .as_object()
        .expect("span grain encodes as an object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    grain_keys.sort_unstable();
    assert_eq!(grain_keys, ["end", "revision", "start"]);
    assert!(
        !encoded.to_string().contains("ello"),
        "the handle carries the pin and the range, never the sliced text"
    );

    // Cursors resolve at the pinned revision, deterministically.
    let first = frame.resolve_span_cursors(&scoped_read, &render, &read_handle)?;
    assert_eq!(first.range, (1, 5));
    assert_eq!(first.revision, grain.revision());
    let second = frame.resolve_span_cursors(&scoped_read, &render, &read_handle)?;
    assert_eq!(
        first.cursors, second.cursors,
        "the derived doc is deterministic"
    );

    // The grain re-proves through the single resolution path.
    let resolved = frame.resolve_read_handle(&scoped_read, &render, &read_handle)?;
    assert_eq!(resolved.target().entity_id(), &message_id(30));

    // And the quote triple renders the pinned slice.
    let quote = frame.quote_from_span(&scoped_read, &render, &read_handle)?;
    assert_eq!(frame.resolve_quote(&scoped_read, &quote)?, "ello");
    Ok(())
}

#[test]
fn stale_span_version_fails_closed() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, target_id) = asset_fixture(&vault, 31, "version one text here")?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;
    let read_handle = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 0, 7),
    )?;
    assert!(
        frame
            .resolve_span_cursors(&scoped_read, &render, &read_handle)
            .is_ok()
    );

    // Mutable asset text moves: the pinned revision no longer names the body.
    put_asset_text(
        &vault,
        &target_id,
        "version two text here, longer than before",
    )?;
    assert!(
        frame
            .resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "a moved body fails the whole-handle comparison, span pin included"
    );
    assert!(
        frame
            .resolve_span_cursors(&scoped_read, &render, &read_handle)
            .is_err(),
        "no cursor resolves past a stale pin"
    );

    // A quote taken before the move names the missing revision and fails too.
    let quote = frame.quote_from_span(
        &vault.scoped_read(frame.principal().selected_read_key().clone()),
        &render,
        &read_handle,
    );
    assert!(
        quote.is_err(),
        "quoting a stale handle fails before any triple exists"
    );
    Ok(())
}

#[test]
fn stale_equal_length_text_change_fails_closed() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let before = "aaaa-bbbb";
    let (viewer_key, frame, target_id) = asset_fixture(&vault, 32, before)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;
    let read_handle = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 0, 9),
    )?;

    // Find a same-length mutation that ALSO collides the u8 short-ref hash, so the
    // short ref keeps resolving and only the full revision pin can catch the move.
    let old_hash = (xxh32(before.as_bytes(), 0) % 256) as u8;
    let mut after = None;
    for candidate in 0..100_000u32 {
        let text = format!("aaaa-{candidate:04}");
        if text.len() == before.len() && (xxh32(text.as_bytes(), 0) % 256) as u8 == old_hash {
            after = Some(text);
            break;
        }
    }
    let after = after.expect("a colliding same-length mutation exists within the u32 space");
    assert_ne!(after, before);
    put_asset_text(&vault, &target_id, &after)?;

    // The short ref below is freshly derived post-edit; it compares equal to the
    // handle's own short_ref exactly because the u8 hash collided, which the loop
    // guarantees. So the rejection that follows is the revision pin's doing.
    assert_eq!(
        read_handle.short_ref(),
        backing_target_for(&vault, &target_id, LensBackingTargetKind::Entity)?.short_ref(),
        "setup: the short ref still names the row after the edit"
    );
    assert!(
        frame
            .resolve_read_handle(&scoped_read, &render, &read_handle)
            .is_err(),
        "an equal-length edit pins a different revision and fails closed"
    );
    assert!(
        frame
            .resolve_span_cursors(&scoped_read, &render, &read_handle)
            .is_err(),
        "no cursor resolves past an equal-length move"
    );
    Ok(())
}

#[test]
fn span_request_shape_is_three_names_plus_scalar_offsets() {
    // Positive control: the honest shape is three names and two offsets.
    let honest = json!({
        "cardId": "card-1",
        "atomId": "people",
        "handle": "visible-set",
        "start": 1,
        "end": 5
    });
    let parsed: LensSpanSelectionRequest =
        serde_json::from_value(honest.clone()).expect("the honest span shape decodes");
    assert_eq!(parsed.card_id, render_id("card-1"));
    assert_eq!(parsed.start, 1);
    assert_eq!(parsed.end, 5);

    // The atom law carries over: no target, no text, no revision, no cursor.
    for forged in [
        json!({ "entityId": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" }),
        json!({ "body": "the note says ..." }),
        json!({ "revision": "ab".repeat(32) }),
        json!({ "cursor": "AAAA" }),
        json!({ "range": { "start": 1, "end": 5 } }),
        json!({ "quotedText": "ello" }),
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
            serde_json::from_value::<LensSpanSelectionRequest>(request).is_err(),
            "span selections must not carry {forged}"
        );
    }

    // All five fields are required.
    for absent in ["cardId", "atomId", "handle", "start", "end"] {
        let mut request = honest.clone();
        request
            .as_object_mut()
            .expect("request object")
            .remove(absent);
        assert!(
            serde_json::from_value::<LensSpanSelectionRequest>(request).is_err(),
            "a span selection without {absent} must not decode"
        );
    }
}

#[test]
fn span_runtime_shape_rejects_inversion_overflow_and_wrong_grain() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = message_fixture(&vault, 33, MULTILINGUAL_TEXT)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;
    let scalar_len = MULTILINGUAL_TEXT.chars().count() as u32;

    // Honest scalar ranges resolve, including the empty range and the full text.
    for (start, end) in [(0, 0), (0, scalar_len), (1, 2), (scalar_len, scalar_len)] {
        assert!(
            frame
                .select_span(
                    &scoped_read,
                    &render,
                    &span_selection("card-1", "people", "visible-set", start, end)
                )
                .is_ok(),
            "scalar range ({start}, {end}) over {scalar_len} scalars must resolve"
        );
    }
    // Inverted and out-of-range offsets fail closed.
    for (start, end, reason) in [
        (2, 1, "start past end is not a range"),
        (
            0,
            scalar_len + 1,
            "end past the scalar length is not addressable",
        ),
        (
            scalar_len + 1,
            scalar_len + 1,
            "start past the scalar length is not addressable",
        ),
        (u32::MAX, u32::MAX, "the ceiling is not a position"),
    ] {
        assert!(
            frame
                .select_span(
                    &scoped_read,
                    &render,
                    &span_selection("card-1", "people", "visible-set", start, end)
                )
                .is_err(),
            "{reason}"
        );
    }

    // Scalar semantics, not bytes and not UTF-16: the emoji is one scalar.
    let emoji = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 1, 2),
    )?;
    let quote = frame.quote_from_span(&scoped_read, &render, &emoji)?;
    assert_eq!(frame.resolve_quote(&scoped_read, &quote)?, "\u{1f600}");

    // The atom door and the span door stay separate grains.
    assert!(
        frame
            .select_span(
                &scoped_read,
                &render,
                &span_selection("card-1", "ghost", "visible-set", 0, 1)
            )
            .is_err(),
        "the span path still names an element of its render"
    );
    // A person row has no span text.
    let (_tmp2, vault2) = test_vault();
    let person_id = test_entity_id(34);
    put_person(&vault2, &person_id)?;
    let (viewer_key2, mut frame2) = viewer_frame("card-1")?;
    frame2.mint_backing_ref(
        &vault2.scoped_read(viewer_key2.clone()),
        handle("visible-set"),
        LensHandleRole::EntitySet,
        backing_target_for(&vault2, &person_id, LensBackingTargetKind::Entity)?,
    )?;
    assert!(
        frame2
            .select_span(
                &vault2.scoped_read(viewer_key2),
                &span_render()?,
                &span_selection("card-1", "people", "visible-set", 0, 1)
            )
            .is_err(),
        "spans reach message and asset text only"
    );
    Ok(())
}

#[test]
fn span_request_shape_fuzz() {
    let mut runner = TestRunner::new(Config::default());
    // The JSON shape half is pure: any field outside the five, or any missing one,
    // fails decode without touching the vault.
    runner
        .run(
            &(
                proptest::string::string_regex("[a-zA-Z][a-zA-Z0-9_]{0,16}").unwrap(),
                proptest::string::string_regex("[a-zA-Z0-9 :/._-]{0,32}").unwrap(),
            ),
            |(field, value)| {
                prop_assume!(
                    !["cardId", "atomId", "handle", "start", "end"].contains(&field.as_str())
                );
                let mut request = json!({
                    "cardId": "card-1",
                    "atomId": "people",
                    "handle": "visible-set",
                    "start": 1,
                    "end": 5
                });
                request
                    .as_object_mut()
                    .expect("request object")
                    .insert(field, json!(value));
                prop_assert!(serde_json::from_value::<LensSpanSelectionRequest>(request).is_err());
                Ok(())
            },
        )
        .expect("extra span selection fields never decode");

    // The runtime half shares one fixture vault: a range resolves iff it is
    // ordered and inside the scalar length. Every u32 offset is a scalar
    // boundary by construction, so inversion and overflow are the whole law.
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, _) = message_fixture(&vault, 35, MULTILINGUAL_TEXT).expect("fixture");
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render().expect("render");
    let scalar_len = MULTILINGUAL_TEXT.chars().count() as u64;
    runner
        .run(&(0..8u32, 0..8u32), |(start, end)| {
            let honest = start <= end && u64::from(end) <= scalar_len;
            let outcome = frame
                .select_span(
                    &scoped_read,
                    &render,
                    &span_selection("card-1", "people", "visible-set", start, end),
                )
                .is_ok();
            prop_assert_eq!(
                outcome,
                honest,
                "scalar range ({}, {}) over {} scalars",
                start,
                end,
                scalar_len
            );
            Ok(())
        })
        .expect("span ranges resolve exactly when ordered and in range");
}

#[test]
fn quote_triple_round_trips_as_pointer_never_copy() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, target_id) = message_fixture(&vault, 36, SPAN_TEXT)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;
    let read_handle = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 0, 5),
    )?;

    let quote = frame.quote_from_span(&scoped_read, &render, &read_handle)?;
    assert_eq!(quote.reply_to_message_id(), target_id.to_hex());
    assert_eq!(
        quote.reply_to_revision_id(),
        read_handle.span().expect("grain").revision()
    );
    assert_eq!(quote.reply_to_range(), (0, 5));

    // The wire triple is exactly the three pointer keys, camelCase, with the range
    // as {start, end} — and no text rides it.
    let encoded = serde_json::to_value(&quote).expect("quote encodes");
    let mut keys = encoded
        .as_object()
        .expect("quotes encode as objects")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["replyToMessageId", "replyToRange", "replyToRevisionId"]
    );
    let flat = encoded.to_string();
    assert!(flat.contains(&target_id.to_hex()));
    assert!(
        !flat.contains("hello"),
        "a quote stores the pointer, never a copy"
    );

    // The triple re-decodes (it is a client-presentable pointer) and re-proves.
    let decoded: LensQuoteTriple = serde_json::from_value(encoded).expect("quote decodes");
    assert_eq!(decoded, quote);
    assert_eq!(frame.resolve_quote(&scoped_read, &decoded)?, "hello");
    Ok(())
}

#[test]
fn quote_rejects_copies_missing_revisions_and_nonscalar_shapes() -> Result<()> {
    let (_tmp, vault) = test_vault();
    let (viewer_key, frame, target_id) = message_fixture(&vault, 37, MULTILINGUAL_TEXT)?;
    let scoped_read = vault.scoped_read(viewer_key);
    let render = span_render()?;
    let scalar_len = MULTILINGUAL_TEXT.chars().count() as u32;

    // A copied-text field is not part of the triple: unknown fields fail decode.
    let with_copy = json!({
        "replyToMessageId": target_id.to_hex(),
        "replyToRevisionId": "ab".repeat(32),
        "replyToRange": { "start": 0, "end": 1 },
        "quotedText": MULTILINGUAL_TEXT.chars().take(1).collect::<String>()
    });
    assert!(
        serde_json::from_value::<LensQuoteTriple>(with_copy).is_err(),
        "a quote carries no copied text"
    );
    for extra in [
        json!({ "replyToText": "x" }),
        json!({ "body": "x" }),
        json!({ "cursor": "AAAA" }),
    ] {
        let mut triple = json!({
            "replyToMessageId": target_id.to_hex(),
            "replyToRevisionId": "ab".repeat(32),
            "replyToRange": { "start": 0, "end": 1 }
        });
        for (key, value) in extra.as_object().expect("extra object") {
            triple
                .as_object_mut()
                .expect("triple object")
                .insert(key.clone(), value.clone());
        }
        assert!(
            serde_json::from_value::<LensQuoteTriple>(triple).is_err(),
            "the triple is three fields and nothing else: {extra}"
        );
    }

    // A well-shaped triple naming a revision that was never pinned fails closed.
    let missing_revision =
        LensQuoteTriple::from_parts_for_test(target_id.to_hex(), "ab".repeat(32), 0, 1);
    assert!(
        frame
            .resolve_quote(&scoped_read, &missing_revision)
            .is_err(),
        "a missing revision is not a quote"
    );

    // A triple naming no resolvable message fails closed.
    let ghost =
        LensQuoteTriple::from_parts_for_test(message_id(38).to_hex(), "ab".repeat(32), 0, 1);
    assert!(
        frame.resolve_quote(&scoped_read, &ghost).is_err(),
        "a quote over an unknown message resolves to nothing"
    );

    // Non-scalar shapes fail at use even with the right message and revision: take
    // the honest revision, then invert the range and run past the scalar length.
    let honest = frame.select_span(
        &scoped_read,
        &render,
        &span_selection("card-1", "people", "visible-set", 0, 1),
    )?;
    let revision = honest.span().expect("grain").revision().to_owned();
    for (start, end, reason) in [
        (1, 0, "an inverted range is not a quote"),
        (
            0,
            scalar_len + 1,
            "a range past the pinned text is not a quote",
        ),
        (
            scalar_len + 1,
            scalar_len + 1,
            "a start past the pinned text is not a quote",
        ),
    ] {
        let forged =
            LensQuoteTriple::from_parts_for_test(target_id.to_hex(), revision.clone(), start, end);
        assert!(
            frame.resolve_quote(&scoped_read, &forged).is_err(),
            "{reason}"
        );
    }

    // Quotes answer messages: an asset-text span handle is a span but not a quote.
    let (_tmp2, vault2) = test_vault();
    let (viewer_key2, frame2, _) = asset_fixture(&vault2, 39, "asset words here")?;
    let scoped2 = vault2.scoped_read(viewer_key2);
    let render2 = span_render()?;
    let asset_span = frame2.select_span(
        &scoped2,
        &render2,
        &span_selection("card-1", "people", "visible-set", 0, 5),
    )?;
    assert!(
        frame2
            .quote_from_span(&scoped2, &render2, &asset_span)
            .is_err(),
        "a quote answers a message, never asset text"
    );
    // And an atom handle with no grain is neither.
    let atom = frame2.select_atom(
        &scoped2,
        &render2,
        &selection("card-1", "people", "visible-set"),
    )?;
    assert!(atom.span().is_none());
    assert!(
        frame2.quote_from_span(&scoped2, &render2, &atom).is_err(),
        "quoting needs the span grain, never the atom grain"
    );
    Ok(())
}
