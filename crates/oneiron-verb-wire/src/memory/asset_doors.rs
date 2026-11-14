//! Moved from `crates/oneiron/src/memory/asset_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::asset_resolve::types::ServedAssetForm;
use oneiron_store::embedding_vocabulary::InputKind;
use serde::Deserialize;
use serde::Serialize;

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
