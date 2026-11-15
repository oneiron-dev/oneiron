//! Moved from `crates/oneiron/src/lens/pack_export.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::share_travel::BornWith;
use oneiron_authority::share_travel::BornWithField;
use oneiron_authority::share_travel::TravelChoice;
use serde::Deserialize;
use serde::Serialize;

/// `vault.lenses.export_pack`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensPackExportRequest {
    /// The lens, as `vault.lenses.list` names it: 32 hex.
    pub lens_ref: String,
    /// The born-with text to send. Absent sends a lens pack's default, its
    /// intent prompt; `{"born_with": []}` sends none.
    #[serde(default)]
    pub travel: Option<TravelChoice>,
}

/// A portable lens pack file (`schema` [`LENS_PACK_SCHEMA`]). It names no
/// vault ref: what it carries is content, compared by hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackFile {
    pub schema: String,
    /// The pack the tree was compiled for, by name.
    pub pack_name: String,
    /// The content hash of the pack the tree was compiled against.
    pub pack_content_hash: String,
    /// blake3 hex of the frozen tree's canonical JSON, as `vault.lenses.list`
    /// names it.
    pub compiled_hash: String,
    /// The frozen generated-lens envelope (`kit_version`,
    /// `apps_contract_version`, `root`), exactly as the lens row holds it.
    pub compiled: serde_json::Value,
    /// The born-with text that travels with the pack, by field.
    pub born_with: BornWith,
}

/// `vault.lenses.export_pack`'s answer: the file and its local receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackExport {
    /// The pack file's bytes, a [`LensPackFile`] as JSON: the bytes the
    /// receipt's `content_hash` is of.
    pub pack_json: String,
    pub receipt: LensPackExportReceipt,
}

/// What left, for the sharer alone: the vault refs the file was made from
/// and its digest. It names; it grants nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackExportReceipt {
    /// The CODE kind=lens row the tree was read from, 32 hex.
    pub lens_ref: String,
    /// The `lens/intent` NOTE holding its authored prompt, 32 hex.
    pub prompt_ref: String,
    /// The slot's SKILL, 32 hex.
    pub skill_id: String,
    /// blake3 hex of `pack_json`'s bytes.
    pub content_hash: String,
    /// The born-with fields that left with the pack.
    pub travelled: Vec<BornWithField>,
}
