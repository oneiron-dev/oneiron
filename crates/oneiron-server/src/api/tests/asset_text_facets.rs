//! Facet rule C (arch-0022:139): a generated image's ASSET_TEXT is born under
//! its source ASSET's facet, in the commit that lands them, so a reader
//! limited to that facet reads the caption beside the image. The caption is
//! served only to a reader of every source ASSET: a later edge neither places
//! nor widens it, a lost source withdraws it, and a text written from images
//! under two facets is refused whole.

use super::*;
use oneiron::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};

const PIXELS: &[u8] = b"\x89PNG\r\n\x1a\nfaceted pixels";
const CAPTION: &str = "a heron over a frozen canal";
const PRIVATE: &str = "an otter the owner kept to itself";

/// A server whose vault default facet was `facet` when the owner landed one
/// generated image, and an agent other than the owner.
struct Faceted {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    owner: oneiron::EntityId,
    agent: oneiron::EntityId,
    facet: oneiron::EntityId,
    asset: oneiron::EntityId,
    text: oneiron::EntityId,
}

impl Faceted {
    fn new() -> Self {
        let (_dir, server) = auth_test_server();
        let owner = server.vault.ensure_embedded_owner_actor().expect("owner");
        let agent = seeded_test_entity_id(0x2701_0001);
        server
            .vault
            .put_entity(
                &agent,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"agent",
            )
            .expect("seed agent");
        let facet = seeded_test_entity_id(0x2701_0010);
        put_facet(&server, facet);
        make_default(&server, owner, facet);
        let landed = server
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
                CAPTION,
                10,
            )
            .expect("land the generated image");
        Self {
            _dir,
            server,
            owner,
            agent,
            facet,
            asset: oneiron::EntityId::from_hex(&landed.asset_ref).expect("asset id"),
            text: oneiron::EntityId::from_hex(&landed.asset_text_ref).expect("text id"),
        }
    }

    /// A read credential for the agent, narrowed further by `narrowing`.
    fn recipe(&self, narrowing: &str) -> String {
        test_bearer(&format!(
            "scope=core:read;principal_ref={};actor_class=agent;{narrowing}",
            self.agent.to_hex()
        ))
    }

    /// The agent limited to `facet`, reading ASSET and ASSET_TEXT rows.
    fn limited_to(&self, facet: oneiron::EntityId) -> String {
        self.recipe(&format!(
            "facets={};bands={ENTITY_TYPE_ASSET},{ENTITY_TYPE_ASSET_TEXT}",
            facet.to_hex()
        ))
    }

    fn short_ref(&self, id: &oneiron::EntityId) -> String {
        oneiron::retrieval_depth::short_ref_or_hex(&self.server.vault, id).expect("short ref")
    }

    /// `id`'s ref pinned at its current revision.
    fn pinned(&self, id: &oneiron::EntityId) -> String {
        let revision = self
            .server
            .vault
            .pin_entity_revision(id)
            .expect("pin revision");
        format!("{}@{}", self.short_ref(id), revision.to_hex())
    }

    /// An image ASSET born under the vault default facet as it stands.
    fn put_image(&self, seed: u128) -> oneiron::EntityId {
        let id = seeded_test_entity_id(seed);
        let body = rmp_serde::to_vec_named(&json!({ "kind": "image", "mime_type": "image/png" }))
            .expect("encode image");
        self.server
            .vault
            .put_entity(
                &id,
                ENTITY_TYPE_ASSET,
                oneiron::TimeRange { start: 10, end: 10 },
                10,
                &body,
            )
            .expect("put image");
        id
    }

    /// Settles the indexed revisions the query lane reads.
    fn index(&self) {
        self.server.vault.set_indexed_idle_delay_ms(0).unwrap();
        self.server
            .vault
            .refresh_staged_indexed_at_idle(u64::MAX)
            .unwrap();
    }

    async fn call(&self, bearer: &str, uri: &str, body: Value) -> (StatusCode, Value) {
        route_json(
            self.server.clone(),
            core_request_with_authz("POST", uri, bearer.to_owned(), Some(&body)),
        )
        .await
    }

    /// Whether `bearer` reads `id` live through `reference` on `/v1` core
    /// hydrate. A refused read discloses none of `words`.
    async fn reads(
        &self,
        bearer: &str,
        reference: &str,
        id: oneiron::EntityId,
        words: &str,
    ) -> bool {
        let (status, body) = self
            .call(bearer, "/v1/core/hydrate", json!({ "ref": reference }))
            .await;
        if status == StatusCode::OK && body["status"] == "live" {
            assert_eq!(body["id"], id.to_hex(), "{body}");
            return true;
        }
        assert!(!body.to_string().contains(words), "{body}");
        false
    }

    /// Whether `bearer` finds `id` on the `/v1` query lane by `word`.
    async fn finds(&self, bearer: &str, word: &str, id: oneiron::EntityId) -> bool {
        let (status, body) = self
            .call(
                bearer,
                "/v1/core/query",
                json!({ "query": word, "limit": 10 }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["items"].to_string().contains(&id.to_hex())
    }

    /// The caption `bearer` is served when it hydrates the image: its text
    /// form, or `None` where the image keeps its stored body, bytes nulled.
    async fn caption(&self, bearer: &str) -> Option<String> {
        let (status, body) = self
            .call(
                bearer,
                "/v1/core/hydrate",
                json!({ "ref": self.short_ref(&self.asset) }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "live", "{body}");
        let item = &body["item"];
        if item["form"] == "asset_text" {
            assert_eq!(item["asset_text_ref"], self.text.to_hex(), "{item}");
            assert!(item.get("bytes").is_none(), "{item}");
            return item["text"].as_str().map(str::to_owned);
        }
        assert_eq!(item["mime_type"], "image/png", "{item}");
        assert_eq!(item["bytes"], Value::Null, "{item}");
        None
    }
}

fn put_facet(server: &SyncServer, facet: oneiron::EntityId) {
    server
        .vault
        .put_entity(
            &facet,
            oneiron::registry::ENTITY_TYPE_FACET,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .expect("put facet");
}

fn make_default(server: &SyncServer, owner: oneiron::EntityId, facet: oneiron::EntityId) {
    server
        .vault
        .set_default_facet(
            facet,
            oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        )
        .expect("set the vault default facet");
}

/// A structural ASSET_TEXT `id` written from each of `sources`.
fn text_from(
    id: oneiron::EntityId,
    sources: &[oneiron::EntityId],
) -> oneiron::memory::StructuralPutInput {
    oneiron::memory::StructuralPutInput {
        id: Some(id.to_hex()),
        kind: "ASSET_TEXT".into(),
        body: json!({ "text": "two images side by side" }),
        text_fields: None,
        edges: Some(
            sources
                .iter()
                .map(|source| oneiron::memory::StructuralEdgeSpec {
                    edge_kind: "derived_from".into(),
                    target_ref: source.to_hex(),
                    weight: None,
                })
                .collect(),
        ),
        occurred_at: 20,
        learned_at: None,
    }
}

/// Rule C's check: the owner lands a generated image while facet F is the
/// vault default, and an agent limited to F reads its caption beside it. The
/// image's hydrate serves the text form, the caption's own ref reads it live
/// and at its pinned revision, and the query lane finds it. On main the
/// caption was born under no facet: the image fell back to its stored body,
/// bytes nulled, and the caption read as missing.
#[tokio::test]
async fn a_facet_limited_agent_reads_the_caption_born_under_its_image_facet() {
    let vault = Faceted::new();
    let bearer = vault.limited_to(vault.facet);
    assert_eq!(vault.caption(&bearer).await.as_deref(), Some(CAPTION));
    let text = vault.short_ref(&vault.text);
    assert!(vault.reads(&bearer, &text, vault.text, CAPTION).await);
    let pinned = vault.pinned(&vault.text);
    assert!(vault.reads(&bearer, &pinned, vault.text, CAPTION).await);
    vault.index();
    assert!(vault.finds(&bearer, "heron", vault.text).await);
}

/// Rule C places a text at birth only. A text the owner wrote unplaced and
/// later linked to the placed image by a `DerivedFrom` edge gains no facet by
/// it: a generic `FacetOf` onto it is refused as a stamp after birth, the
/// agent limited to F reads it as missing and finds it on no query, and the
/// image still serves its own caption. On main the stamp was refused as off
/// the `FacetOf` table (`InvalidFacetOfEdge`), and the image served none.
#[tokio::test]
async fn a_text_linked_to_a_placed_image_later_gains_no_facet() {
    let vault = Faceted::new();
    let bearer = vault.limited_to(vault.facet);
    let private = seeded_test_entity_id(0x2701_0020);
    vault
        .server
        .vault
        .batch()
        .put(
            &private,
            ENTITY_TYPE_ASSET_TEXT,
            oneiron::TimeRange { start: 20, end: 20 },
            20,
            PRIVATE.as_bytes(),
        )
        .text(&private, &[("text", PRIVATE)])
        .commit()
        .expect("put an unplaced text");
    vault
        .server
        .vault
        .put_edge(&private, oneiron::EdgeKind::DerivedFrom, &vault.asset, 1.0)
        .expect("link the text to the image");
    let refused = vault
        .server
        .vault
        .put_edge(&private, oneiron::EdgeKind::FacetOf, &vault.facet, 1.0)
        .expect_err("a text is placed only at birth");
    assert_eq!(
        refused.kind(),
        oneiron::ErrorKind::FacetStampImmutable,
        "{refused}"
    );
    let reference = vault.short_ref(&private);
    assert!(!vault.reads(&bearer, &reference, private, PRIVATE).await);
    vault.index();
    assert!(!vault.finds(&bearer, "otter", private).await);
    assert_eq!(vault.caption(&bearer).await.as_deref(), Some(CAPTION));
}

/// Rule C withdraws a caption with its source. Once the caption's
/// `DerivedFrom` edge is deleted, or its image is, the agent limited to F
/// reads the caption at neither its live ref nor the revision it pinned while
/// the caption stood, and finds it on no query; with the edge gone the image
/// serves no caption. On main the agent never read the caption.
#[tokio::test]
async fn a_caption_whose_source_is_lost_reads_as_missing() {
    for delete_image in [false, true] {
        let vault = Faceted::new();
        let bearer = vault.limited_to(vault.facet);
        let (live, pinned) = (vault.short_ref(&vault.text), vault.pinned(&vault.text));
        assert!(vault.reads(&bearer, &pinned, vault.text, CAPTION).await);
        if delete_image {
            assert!(
                vault
                    .server
                    .vault
                    .delete_entity(&vault.asset)
                    .expect("delete the image")
            );
        } else {
            assert!(
                vault
                    .server
                    .vault
                    .delete_edge(&vault.text, oneiron::EdgeKind::DerivedFrom, &vault.asset)
                    .expect("delete the caption's source edge")
            );
            assert_eq!(vault.caption(&bearer).await, None);
        }
        assert!(!vault.reads(&bearer, &live, vault.text, CAPTION).await);
        assert!(!vault.reads(&bearer, &pinned, vault.text, CAPTION).await);
        vault.index();
        assert!(!vault.finds(&bearer, "heron", vault.text).await);
    }
}

/// Rule C reads every source under the reader's own credential. An
/// ASSET-only credential is served the image's stored body and reads no
/// caption; an ASSET_TEXT-only one, and one bound to the caption's record
/// alone, read the caption as missing although each admits its row. On main
/// the agent reading both kinds read the caption as missing too.
#[tokio::test]
async fn a_caption_reads_only_beside_its_image_under_one_credential() {
    let vault = Faceted::new();
    let text = vault.short_ref(&vault.text);
    let facet = vault.facet.to_hex();
    let both = vault.limited_to(vault.facet);
    assert!(vault.reads(&both, &text, vault.text, CAPTION).await);
    let images = vault.recipe(&format!("facets={facet};bands={ENTITY_TYPE_ASSET}"));
    assert_eq!(vault.caption(&images).await, None);
    assert!(!vault.reads(&images, &text, vault.text, CAPTION).await);
    let texts = vault.recipe(&format!("facets={facet};bands={ENTITY_TYPE_ASSET_TEXT}"));
    assert!(!vault.reads(&texts, &text, vault.text, CAPTION).await);
    let record = vault.recipe(&format!(
        "facets={facet};bands={ENTITY_TYPE_ASSET},{ENTITY_TYPE_ASSET_TEXT};records={}",
        vault.text.to_hex()
    ));
    assert!(!vault.reads(&record, &text, vault.text, CAPTION).await);
}

/// Rule C's ruling (c): a text written structurally from images born under
/// two facets is refused, and none of it lands; one written from two images
/// under the same facet is born under it, and the agent limited to that
/// facet reads it. On main the first was written unplaced, and the second
/// read as missing.
#[tokio::test]
async fn a_text_from_images_in_two_facets_is_refused_whole() {
    let vault = Faceted::new();
    let elsewhere_facet = seeded_test_entity_id(0x2701_0030);
    put_facet(&vault.server, elsewhere_facet);
    make_default(&vault.server, vault.owner, elsewhere_facet);
    let elsewhere = vault.put_image(0x2701_0031);
    make_default(&vault.server, vault.owner, vault.facet);
    let beside = vault.put_image(0x2701_0032);
    let memory = vault
        .server
        .vault
        .memory(vault.owner, oneiron::EdgeActorClass::Human);

    let mixed = seeded_test_entity_id(0x2701_0033);
    let refused = memory
        .put_structural(&text_from(mixed, &[vault.asset, elsewhere]))
        .expect_err("sources in two facets");
    assert!(refused.message.contains("invalid claim body"), "{refused}");
    assert!(vault.server.vault.get(&mixed).unwrap().is_none());
    assert!(vault.server.vault.edges_out(&mixed).unwrap().is_empty());

    let same = seeded_test_entity_id(0x2701_0034);
    memory
        .put_structural(&text_from(same, &[vault.asset, beside]))
        .expect("sources in one facet");
    let bearer = vault.limited_to(vault.facet);
    assert!(
        vault
            .reads(&bearer, &vault.short_ref(&same), same, "side by side")
            .await
    );
}
