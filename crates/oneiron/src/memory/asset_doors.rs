//! Typed ASSET ingest and consumer-form reads (OF-370, OF-329).
use base64::Engine as _;

use super::asset_resolve::{AssetConsumer, asset_body};
use super::{Memory, MemoryError, MemoryResult, caps};
use crate::EntityId;
use crate::claim::ScopedReadResult;
use crate::store::embedding::InputKind;
use oneiron_model::llm::{CallPurpose, LlmCapability};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::asset_doors::{
    AssetIngestReceipt, AssetIngestRequest, AssetResolveRequest, AssetResolved,
};

impl Memory<'_> {
    pub fn ingest_asset(&self, input: &AssetIngestRequest) -> MemoryResult<AssetIngestReceipt> {
        let mime = input.mime_type.trim().to_ascii_lowercase();
        let kind = InputKind::for_media_type(&mime)
            .or_else(|| mime.starts_with("text/").then_some(InputKind::Text));
        if kind != Some(input.embedding_kind) {
            return Err(MemoryError::bad_request(
                "mime_type must match embedding_kind: text, image or audio",
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.bytes_b64)
            .map_err(|_| MemoryError::bad_request("bytes_b64 must be standard base64"))?;
        // Measured, never refused for its size (FIX 76): past
        // `blob_content_bytes` the row asks and the asset is stored whole.
        let _ = self.vault.measure_limit(
            crate::limit_ask::EngineLimit::BlobContentBytes,
            bytes.len() as u64,
        );
        if bytes.is_empty() {
            return Err(MemoryError::bad_request("an asset holds nonempty bytes"));
        }
        let text = match input.embedding_kind {
            InputKind::Text => Some(
                std::str::from_utf8(&bytes)
                    .map_err(|_| MemoryError::bad_request("a text asset holds UTF-8 bytes"))?,
            ),
            _ => input.text.as_deref(),
        };
        if text.is_some_and(|text| text.trim().is_empty()) {
            return Err(MemoryError::bad_request("an asset text form is nonempty"));
        }
        if input.embedding_kind == InputKind::Text
            && input
                .text
                .as_deref()
                .is_some_and(|supplied| Some(supplied) != text)
        {
            return Err(MemoryError::bad_request(
                "a text asset's text form is its UTF-8 content",
            ));
        }
        if let Some(text) = text {
            caps::check_payload_bytes("asset text", text.len())?;
        }
        let id = input
            .asset_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let body = asset_body(input.embedding_kind, &mime, &bytes, "uploaded", None)?;
        let (asset, text) = self.land_asset_body(id, &body, &bytes, text, input.occurred_at)?;
        Ok(AssetIngestReceipt {
            asset_ref: asset.to_hex(),
            asset_text_ref: text.map(|id| id.to_hex()),
            embedding_kind: input.embedding_kind,
            mime_type: mime,
            blake3: blake3::hash(&bytes).to_hex().to_string(),
            byte_size: bytes.len() as u64,
        })
    }

    pub fn resolve_asset_form(
        &self,
        input: &AssetResolveRequest,
    ) -> MemoryResult<ScopedReadResult<AssetResolved>> {
        let mut consumer = AssetConsumer::text_only(CallPurpose::AnswerGen);
        if input.image_input {
            consumer.capabilities.push(LlmCapability::ImageInput);
        }
        if input.audio_input {
            consumer.capabilities.push(LlmCapability::AudioInput);
        }
        let (served, receipt_refs) = self.serve_assets_with_receipts(
            std::slice::from_ref(&input.asset_ref),
            &consumer,
            None,
            input.room_bytes,
        )?;
        let ScopedReadResult { value, receipt } = served;
        let resolved = value
            .into_iter()
            .next()
            .ok_or_else(|| MemoryError::not_found("asset has no readable form"))?;
        let bytes = resolved
            .image
            .map(|image| (image.media_type, image.bytes))
            .or(resolved.audio);
        let (mime_type, bytes_b64) = match bytes {
            Some((mime, bytes)) => (
                Some(mime),
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            ),
            None => (None, None),
        };
        Ok(ScopedReadResult {
            value: AssetResolved {
                asset_ref: resolved.asset_ref,
                form: resolved.form,
                mime_type,
                bytes_b64,
                text: resolved.text,
                asset_text_ref: resolved.asset_text_ref,
                handle: resolved.handle,
                receipt_refs,
            },
            receipt,
        })
    }
}
