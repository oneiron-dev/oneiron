//! Typed ASSET ingest and consumer-form reads (OF-370, OF-329).
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::asset_resolve::{AssetConsumer, ServedAssetForm, asset_body};
use super::{Memory, MemoryError, MemoryResult, caps};
use crate::EntityId;
use crate::claim::ScopedReadResult;
use crate::embed::InputKind;
use crate::llm::{CallPurpose, LlmCapability};

/// Inline bytes become a real ASSET, not a BLOB_ARTIFACT. A supplied ref is
/// a fresh 32-hex id; omission mints one. Text is a caption or transcript for
/// media, and defaults to the UTF-8 content for a text asset.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetIngestRequest {
    #[serde(default)]
    pub asset_ref: Option<String>,
    pub embedding_kind: InputKind,
    pub mime_type: String,
    pub bytes_b64: String,
    #[serde(default)]
    pub text: Option<String>,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AssetIngestReceipt {
    pub asset_ref: String,
    pub asset_text_ref: Option<String>,
    pub embedding_kind: InputKind,
    pub mime_type: String,
    pub blake3: String,
    pub byte_size: u64,
}

/// Reader capabilities select the served form, never authority. All reads
/// use the caller's own credential and persist their served-form receipts.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssetResolveRequest {
    pub asset_ref: String,
    #[serde(default)]
    pub image_input: bool,
    #[serde(default)]
    pub audio_input: bool,
    #[serde(default)]
    pub room_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AssetResolved {
    pub asset_ref: String,
    pub form: ServedAssetForm,
    pub mime_type: Option<String>,
    /// Standard base64, only when the selected form includes bytes.
    pub bytes_b64: Option<String>,
    pub text: Option<String>,
    pub asset_text_ref: Option<String>,
    pub handle: Option<String>,
    pub receipt_refs: Vec<String>,
}

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
        if input.bytes_b64.len() > caps::MAX_BLOB_BASE64_LEN {
            return Err(MemoryError::bad_request(
                "asset bytes exceed the blob content bound",
            ));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&input.bytes_b64)
            .map_err(|_| MemoryError::bad_request("bytes_b64 must be standard base64"))?;
        caps::check_blob_bytes(bytes.len())?;
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
        let (asset, text) = self.land_asset_body(id, &body, text, input.occurred_at)?;
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
