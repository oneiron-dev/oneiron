//! Asset generation and landing.
//! Entry: Memory::generate_image_asset.
//! Definitions: types stay in the parent; this module owns the listed impls and body functions.

use super::{
    AiMediaDoor, AiOperation, AssetConsumer, BODY_BLAKE3, BODY_MEDIA_TYPE, BudgetLease,
    ENTITY_TYPE_ASSET, EdgeKind, EntityId, ImageBytes, ImageCatalog, ImageIntent, ImageResponse,
    LandedImage, LlmCapability, MEMORY_CODE_MODEL_UNAVAILABLE, MediaPart, MediaRequest, Memory,
    MemoryError, MemoryResult, ModelId, TimeRange, Value, encode_rmpv, no_form,
};

impl Memory<'_> {
    /// Generates `intent` through `catalog` and lands the image the adapter
    /// returns ([`Self::land_generated_image`]). A generation draws what its
    /// instruction describes, so the instruction is the precomputed text.
    pub async fn generate_image_asset(
        &self,
        catalog: &ImageCatalog,
        intent: ImageIntent,
        lease: &BudgetLease,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        let description = intent.instruction.clone();
        let response = catalog.render(intent, None, lease).await.map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("image generation failed: {error}"),
                &[],
            )
        })?;
        self.land_generated_image(&response, &description, occurred_at)
    }

    /// Generates one image through the host's `ai.image` door, admitted,
    /// sent and settled under its run, and lands it
    /// ([`Self::land_generated_image`]). Each of `reference_assets` is read
    /// as an image through the bound actor's lane and sent, in order, as a
    /// reference: the call is then an edit, and an edit's instruction does
    /// not describe its result, so its caller's `description` is required.
    /// A generation without one is described by its instruction.
    pub async fn render_image_asset(
        &self,
        door: &dyn AiMediaDoor,
        mut request: MediaRequest,
        reference_assets: &[String],
        description: Option<&str>,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        if request.operation != AiOperation::Image {
            return Err(MemoryError::bad_request(
                "an image asset renders an image call",
            ));
        }
        let reader = AssetConsumer {
            capabilities: vec![LlmCapability::ImageInput],
            purpose: request.envelope.purpose.clone(),
        };
        for asset_ref in reference_assets {
            let image = self
                .resolve_asset(asset_ref, &reader, None)?
                .value
                .image
                .ok_or_else(|| no_form(asset_ref))?;
            request.references.push(MediaPart::Image {
                media_type: image.media_type,
                bytes: image.bytes,
            });
        }
        let description = match description {
            Some(description) => description.to_owned(),
            None if request.references.is_empty() => request.text(),
            None => {
                return Err(MemoryError::bad_request(
                    "an image edit lands with its caller's description of the result",
                ));
            }
        };
        let response = door.call(request).await.map_err(|error| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("image generation failed: {error}"),
                &[],
            )
        })?;
        let image = response.image().ok_or_else(|| {
            MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                "image generation returned no image".to_owned(),
                &[],
            )
        })?;
        let response = ImageResponse {
            image,
            model: response.model,
            metadata: std::collections::BTreeMap::new(),
        };
        self.land_generated_image(&response, &description, occurred_at)
    }

    /// Lands one generated image as the bound actor: the ASSET, its bytes
    /// as the blob it holds, and `description` as its ASSET_TEXT, derived
    /// from it and born under the image's facet, in one write. A text-only
    /// consumer is served that text, so an image with no description is
    /// refused rather than landed without one. An edit's instruction does
    /// not describe its result; its caller describes it.
    pub fn land_generated_image(
        &self,
        response: &ImageResponse,
        description: &str,
        occurred_at: u64,
    ) -> MemoryResult<LandedImage> {
        let description = description.trim();
        if description.is_empty()
            || response.image.bytes.is_empty()
            || !response.image.media_type.starts_with("image/")
        {
            return Err(MemoryError::bad_request(
                "a generated image lands with image bytes and a description",
            ));
        }
        let body = generated_asset_body(&response.image, &response.model)?;
        let (asset, text) = self.land_asset_body(
            None,
            &body,
            &response.image.bytes,
            Some(description),
            occurred_at,
        )?;
        Ok(LandedImage {
            asset_ref: asset.to_hex(),
            asset_text_ref: text.expect("a generated image lands with text").to_hex(),
        })
    }

    /// The shared actor-bound landing for generated and uploaded ASSETs.
    /// Create and erasure checks run in the same transaction as both rows,
    /// and `bytes`, whose hash `body` names, land in it after them as the
    /// blob the ASSET holds by reference (FIX 9949): an actor whose write is
    /// refused lands no bytes.
    pub(in crate::memory) fn land_asset_body(
        &self,
        asset: Option<EntityId>,
        body: &[u8],
        bytes: &[u8],
        description: Option<&str>,
        occurred_at: u64,
    ) -> MemoryResult<(EntityId, Option<EntityId>)> {
        let occurred = TimeRange {
            start: occurred_at,
            end: occurred_at,
        };
        let weight = EdgeKind::DerivedFrom.default_weight().unwrap_or(1.0);
        self.vault.ensure_text_index_trusted()?;
        let writer = self.write_actor();
        self.vault.try_with_write_txn_grouped(|wtxn| {
            crate::memory::verify_actor_binding_in_txn(
                self.vault,
                wtxn,
                self.actor,
                self.actor_class,
            )?;
            let mut content = crate::federation::ActorContentTxn::new(self.vault, wtxn, writer)?;
            let landed = self.land_asset_rows(
                &mut content,
                asset,
                body,
                description,
                (occurred, occurred_at, weight),
            )?;
            content.finish()?;
            super::blob::land_asset_blob_in_txn(
                self.vault,
                wtxn,
                &landed.0,
                bytes,
                occurred,
                occurred_at,
            )?;
            Ok(landed)
        })
    }

    /// The ASSET row and its ASSET_TEXT, as the actor `content` binds.
    fn land_asset_rows(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        asset: Option<EntityId>,
        body: &[u8],
        description: Option<&str>,
        (occurred, occurred_at, weight): (TimeRange, u64, f32),
    ) -> MemoryResult<(EntityId, Option<EntityId>)> {
        let asset = match asset {
            Some(asset) => asset,
            None => self.vault.store.clock.entity_id()?,
        };
        if self
            .vault
            .local_hard_delete_marker_exists_in_txn(content.read(), &asset)?
        {
            return Err(crate::memory::support::hard_deleted_refusal(&asset));
        }
        crate::memory::structural::ensure_structural_create_in_txn(
            self.vault,
            content.read(),
            &asset,
        )?;
        let text = description
            .map(|_| self.vault.store.clock.entity_id())
            .transpose()?;
        let mut batch =
            self.vault
                .batch_in()
                .put(&asset, ENTITY_TYPE_ASSET, occurred, occurred_at, body);
        if let (Some(text), Some(description)) = (text, description) {
            batch = batch
                .asset_text_birth(
                    &text,
                    occurred,
                    occurred_at,
                    description.as_bytes(),
                    &[(asset, weight)],
                )
                .text(&text, &[("text", description)]);
        }
        content.apply_batch(batch)?;
        Ok((asset, text))
    }
}

/// The ASSET body for generated bytes: the canon asset fields and the hash
/// that names the blob holding the bytes.
pub(crate) fn generated_asset_body(image: &ImageBytes, model: &ModelId) -> MemoryResult<Vec<u8>> {
    asset_body(
        crate::embed::InputKind::Image,
        &image.media_type,
        &image.bytes,
        "generated",
        Some(model.as_str()),
    )
}

/// The one ASSET metadata encoding (FIX 9949): kind, media type, the BLAKE3
/// hash and size of the bytes, source and model. The bytes themselves are
/// the blob the ASSET holds by that hash, never a field here; the resolver
/// and the media backfill read them through it (`blob`).
pub(in crate::memory) fn asset_body(
    kind: crate::embed::InputKind,
    mime_type: &str,
    bytes: &[u8],
    source: &str,
    model: Option<&str>,
) -> MemoryResult<Vec<u8>> {
    let kind = match kind {
        crate::embed::InputKind::Text => "text",
        crate::embed::InputKind::Image => "image",
        crate::embed::InputKind::Audio => "audio",
    };
    let mut fields = vec![
        (Value::from("kind"), Value::from(kind)),
        (Value::from(BODY_MEDIA_TYPE), Value::from(mime_type)),
        (
            Value::from(BODY_BLAKE3),
            Value::from(blake3::hash(bytes).to_hex().as_str()),
        ),
        (Value::from("byte_size"), Value::from(bytes.len() as u64)),
    ];
    if let Some(model) = model {
        fields.push((Value::from("model"), Value::from(model)));
    }
    fields.push((Value::from("source"), Value::from(source)));
    encode_rmpv(&Value::Map(fields))
}
