//! OF-329, hydrate's half (ONE-2331): a reader that declares no image input
//! hydrates an image ASSET and is served its ASSET_TEXT, with no routing of
//! its own.

use super::*;
use crate::registry::ENTITY_TYPE_ASSET_TEXT;

const PIXELS: &[u8] = b"\x89PNG\r\n\x1a\nstored pixels";

fn owner_vault() -> (tempfile::TempDir, crate::Vault, EntityId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    (dir, vault, owner)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).expect("encode");
    out
}

/// An ASSET holding image bytes with its media type and content hash.
fn image_asset(vault: &crate::Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("asset id");
    let body = encode(&Value::Map(vec![
        (Value::from("kind"), Value::from("image")),
        (Value::from("mime_type"), Value::from("image/png")),
        (
            Value::from("blake3"),
            Value::from(blake3::hash(PIXELS).to_hex().as_str()),
        ),
        (Value::from("bytes"), Value::Binary(PIXELS.to_vec())),
    ]));
    vault
        .put_entity(&id, ENTITY_TYPE_ASSET, test_time(5), 5, &body)
        .expect("put asset");
    id
}

/// An ASSET_TEXT derived from `asset`.
fn asset_text(vault: &crate::Vault, seed: u8, asset: &EntityId, text: &str) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("text id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_ASSET_TEXT,
            test_time(6),
            6,
            text.as_bytes(),
        )
        .expect("put text");
    vault
        .put_edge(&id, EdgeKind::DerivedFrom, asset, 1.0)
        .expect("derived edge");
    id
}

#[test]
fn text_only_reader_hydrates_an_image_asset_as_its_asset_text() {
    let (_dir, vault, owner) = owner_vault();
    let memory = facade_for(&vault, owner);
    let image = image_asset(&vault, 0xC2);
    let caption = asset_text(&vault, 0xC3, &image, "a red kite over a beach");

    let views = memory.hydrate(&[image.to_hex()]).expect("hydrate").value;
    assert_eq!(
        views[0].body,
        Some(serde_json::json!({
            "form": "asset_text",
            "asset_text_ref": caption.to_hex(),
            "text": "a red kite over a beach",
        }))
    );

    // A document ASSET keeps its own body: its text is served through retrieval.
    let document = EntityId::from_bytes([0xC4; 16]).expect("document id");
    let page = Value::Map(vec![(Value::from("text"), Value::from("the whole page"))]);
    let page = encode(&page);
    vault
        .put_entity(&document, ENTITY_TYPE_ASSET, test_time(5), 5, &page)
        .expect("put document");
    asset_text(&vault, 0xC5, &document, "one section");
    let views = memory.hydrate(&[document.to_hex()]).expect("hydrate").value;
    assert_eq!(
        views[0].body,
        Some(serde_json::json!({"text": "the whole page"}))
    );

    // An image with no ASSET_TEXT keeps the body it was hydrated with: its
    // fields name the image, and its bytes stay out.
    let bare = image_asset(&vault, 0xC6);
    let views = memory.hydrate(&[bare.to_hex()]).expect("hydrate").value;
    let body = views[0].body.as_ref().expect("stored body");
    assert_eq!(body["mime_type"], "image/png");
    assert_eq!(body["bytes"], serde_json::Value::Null);
    assert!(body.get("form").is_none(), "{body}");
}
