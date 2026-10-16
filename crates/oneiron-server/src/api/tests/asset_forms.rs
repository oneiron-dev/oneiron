//! OF-329's hydrate doors: a text-only agent that hydrates a
//! generated image, on `/v1` core hydrate and on MCP's `memory.hydrate`, is
//! served the image's ASSET_TEXT and never its bytes, with no routing of its
//! own. An image with no text it reads keeps the body it had: its fields, its
//! bytes nulled.

use super::*;

const PIXELS: &[u8] = b"\x89PNG\r\n\x1a\nserved pixels";
const CAPTION: &str = "a paper boat on a rain puddle";

/// A server holding one generated image the owner landed, and one image
/// ASSET with no text.
struct Assets {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    image: oneiron::memory::LandedImage,
    caption: String,
    bare: oneiron::EntityId,
}

impl Assets {
    fn new() -> Self {
        Self::on(auth_test_server(), CAPTION)
    }

    fn on((_dir, server): (tempfile::TempDir, Arc<SyncServer>), caption: &str) -> Self {
        let owner = server.vault.ensure_embedded_owner_actor().expect("owner");
        let image = server
            .vault
            .memory(owner, oneiron::EdgeActorClass::Human)
            .land_generated_image(
                &oneiron::llm::image::ImageResponse {
                    image: oneiron::llm::image::ImageBytes {
                        bytes: PIXELS.to_vec(),
                        media_type: "image/png".into(),
                    },
                    model: oneiron::ModelId::new("fake/image-1@1").expect("model id"),
                    metadata: std::collections::BTreeMap::new(),
                },
                caption,
                10,
            )
            .expect("land the generated image");
        let bare = seeded_test_entity_id(0x2331_0001);
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("kind"), rmpv::Value::from("image")),
                (
                    rmpv::Value::from("mime_type"),
                    rmpv::Value::from("image/png"),
                ),
                (
                    rmpv::Value::from("bytes"),
                    rmpv::Value::Binary(PIXELS.to_vec()),
                ),
            ]),
        )
        .expect("encode bare image");
        server
            .vault
            .put_entity(
                &bare,
                oneiron::registry::ENTITY_TYPE_ASSET,
                oneiron::TimeRange { start: 10, end: 10 },
                10,
                &body,
            )
            .expect("put bare image");
        Self {
            _dir,
            server,
            image,
            caption: caption.to_owned(),
            bare,
        }
    }

    /// A credential for an agent other than the owner that declared no image
    /// input.
    fn agent_bearer(&self) -> String {
        let agent = seeded_test_entity_id(0x2331_0002);
        self.server
            .vault
            .put_entity(
                &agent,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"agent",
            )
            .expect("seed agent");
        test_bearer(&format!(
            "scope=core:read;principal_ref={};actor_class=agent",
            agent.to_hex()
        ))
    }

    fn short_ref(&self, id: &oneiron::EntityId) -> String {
        let reference =
            oneiron::retrieval_depth::short_ref_or_hex(&self.server.vault, id).expect("short ref");
        assert!(reference.contains(':'), "{reference} has a short ref");
        reference
    }

    /// The text form a text-only reader is served for the generated image.
    fn text_form(&self) -> Value {
        json!({
            "form": "asset_text",
            "asset_text_ref": self.image.asset_text_ref,
            "text": self.caption,
        })
    }
}

/// Asserts `item` is the image's text form, with no field of the image body.
fn assert_text_form(item: &Value, assets: &Assets) {
    for (field, value) in assets.text_form().as_object().unwrap() {
        assert_eq!(&item[field], value, "{field}: {item}");
    }
    for field in ["bytes", "mime_type", "blake3"] {
        assert!(item.get(field).is_none(), "{field}: {item}");
    }
}

/// Asserts `fields` are the bare image's stored fields, its bytes nulled.
fn assert_stored_image(fields: &Value) {
    assert_eq!(fields["mime_type"], "image/png", "{fields}");
    assert_eq!(fields["bytes"], Value::Null, "{fields}");
    assert!(fields.get("form").is_none(), "{fields}");
}

/// OF-329 on `/v1`: an agent that declared no image input
/// hydrates the generated image's short ref, alone and in a batch, and is
/// served its ASSET_TEXT. On main the item was the image body with its bytes
/// nulled: `{kind, mime_type, blake3, byte_size, model, source, bytes: null}`.
#[tokio::test]
async fn a_text_only_agent_hydrates_a_generated_image_as_its_asset_text_on_v1() {
    let assets = Assets::new();
    let bearer = assets.agent_bearer();
    let asset = oneiron::EntityId::from_hex(&assets.image.asset_ref).expect("asset id");
    let (image, bare) = (assets.short_ref(&asset), assets.short_ref(&assets.bare));
    let call = |uri: &str, body: Value| {
        route_json(
            assets.server.clone(),
            core_request_with_authz("POST", uri, bearer.clone(), Some(&body)),
        )
    };

    let (status, single) = call("/v1/core/hydrate", json!({ "ref": image })).await;
    assert_eq!(status, StatusCode::OK, "{single}");
    assert_eq!(single["status"], "live", "{single}");
    assert_eq!(single["id"], assets.image.asset_ref, "{single}");
    assert_eq!(
        single["entity_type"],
        oneiron::registry::ENTITY_TYPE_ASSET,
        "{single}"
    );
    assert_text_form(&single["item"], &assets);

    let (status, batch) = call(
        "/v1/core/batch/shortId/hydrate",
        json!({ "refs": [image, bare] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{batch}");
    assert_eq!(batch["results"][0]["outcome"], "live", "{batch}");
    assert_text_form(&batch["results"][0]["result"]["item"], &assets);
    // An image with no text this reader reads keeps its stored body.
    assert_eq!(batch["results"][1]["outcome"], "live", "{batch}");
    assert_stored_image(&batch["results"][1]["result"]["item"]);

    let (status, stored) = call("/v1/core/hydrate", json!({ "ref": bare })).await;
    assert_eq!(status, StatusCode::OK, "{stored}");
    assert_stored_image(&stored["item"]);
}

/// OF-329 on MCP: a connector agent that declared no image input calls
/// `memory.hydrate` and `memory.hydrate_many` on the generated image and is
/// served its ASSET_TEXT. On main the item's body was the image body with its
/// bytes nulled.
#[tokio::test]
async fn a_text_only_mcp_agent_hydrates_a_generated_image_as_its_asset_text() {
    let assets = Assets::new();
    // The seeded manifest's agent ceiling names the first-party connector
    // actor; MCP resolves an agent connector only under one.
    let agent = oneiron::EntityId::from_bytes([0xE1; 16]).unwrap();
    let credential = "asset-forms-agent";
    register_mcp_actor(
        &assets.server,
        credential,
        agent,
        oneiron::EdgeActorClass::Agent,
    )
    .await;
    let asset = oneiron::EntityId::from_hex(&assets.image.asset_ref).expect("asset id");
    let (image, bare) = (assets.short_ref(&asset), assets.short_ref(&assets.bare));
    let call = |name: &'static str, request: Value| {
        let mut envelope = mcp_endpoint_envelope(agent, "memory_read");
        envelope["actor"]["actor_class"] = json!("agent");
        envelope["actor"]["gate_actor_class"] = json!("agent");
        route_json(
            assets.server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                name,
                name,
                mcp_merge_args(envelope, json!({ "arguments": { "request": request } })),
            ),
        )
    };

    let (_, single) = call("memory.hydrate", json!({ "ref": image })).await;
    assert!(single.get("error").is_none(), "{single}");
    let response = &single["result"]["structuredContent"]["output"]["response"];
    assert_eq!(response["status"], "live", "{single}");
    assert_eq!(response["item"]["id"], assets.image.asset_ref, "{single}");
    assert_eq!(response["item"]["body"], assets.text_form(), "{single}");

    let (_, batch) = call("memory.hydrate_many", json!({ "refs": [image, bare] })).await;
    assert!(batch.get("error").is_none(), "{batch}");
    let results = &batch["result"]["structuredContent"]["output"]["response"]["results"];
    assert_eq!(
        results[0]["result"]["item"]["body"],
        assets.text_form(),
        "{batch}"
    );
    // An image with no text this reader reads keeps its stored body.
    assert_eq!(results[1]["outcome"], "live", "{batch}");
    assert_stored_image(&results[1]["result"]["item"]["body"]);

    let (_, stored) = call("memory.hydrate", json!({ "ref": bare })).await;
    assert!(stored.get("error").is_none(), "{stored}");
    let response = &stored["result"]["structuredContent"]["output"]["response"];
    assert_stored_image(&response["item"]["body"]);
}

/// Sol on #1517: a batch's body budget bounds the text it serves too. An
/// image whose text is past what the batch may still decode keeps its id,
/// kind and time with the `bodyOmitted` marker, and the marker's ref hydrates
/// the text whole.
#[tokio::test]
async fn a_batch_omits_an_image_whose_text_is_past_its_body_budget() {
    let caption = ["a paper boat drifting down a long rain gutter"; 64].join(", ");
    let assets = Assets::on(
        test_server_with_config(SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            limits: crate::config::LimitsConfig {
                projection_body_bytes: 1024,
                ..Default::default()
            },
            ..Default::default()
        }),
        &caption,
    );
    let bearer = assets.agent_bearer();
    let asset = oneiron::EntityId::from_hex(&assets.image.asset_ref).expect("asset id");
    let image = assets.short_ref(&asset);
    let call = |uri: &str, body: Value| {
        route_json(
            assets.server.clone(),
            core_request_with_authz("POST", uri, bearer.clone(), Some(&body)),
        )
    };

    let (status, batch) = call("/v1/core/batch/shortId/hydrate", json!({ "refs": [image] })).await;
    assert_eq!(status, StatusCode::OK, "{batch}");
    assert_eq!(batch["results"][0]["outcome"], "live", "{batch}");
    let item = &batch["results"][0]["result"]["item"];
    assert_eq!(
        item["bodyOmitted"]["code"], "PROJECTION_BYTES_EXCEEDED",
        "{item}"
    );
    assert!(item.get("text").is_none(), "{item}");

    let marker = &item["bodyOmitted"]["ref"];
    let (status, whole) = call("/v1/core/hydrate", json!({ "ref": marker })).await;
    assert_eq!(status, StatusCode::OK, "{whole}");
    assert_text_form(&whole["item"], &assets);
}
