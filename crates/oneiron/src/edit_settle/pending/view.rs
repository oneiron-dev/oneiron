//! A waiting proposal as a review surface lists it.

use serde::{Deserialize, Serialize};

use super::{PendingBody, PendingRow, RawJson};
use crate::blob_artifact::hash_hex;
use crate::edit_roundtrip::EditManifest;
use crate::entity_id::EntityId;
use crate::provenance::made_by::MadeBy;

/// What kind of proposal is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingProposalKind {
    Edit,
    Output,
}

/// One proposal waiting beside its artifact, as a review surface lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PendingProposalView {
    pub artifact_id: EntityId,
    /// The artifact as a typed record ref (OF-063), built from its id with
    /// no read.
    pub artifact: crate::lens::RecordRef,
    pub proposal_ref: String,
    pub kind: PendingProposalKind,
    pub base_version: Option<u64>,
    /// BLAKE3 of the proposed bytes, hex.
    pub content_hash: String,
    pub byte_len: usize,
    pub retained_by: EntityId,
    /// `retained_by` as a typed record ref of the kind its row was when it
    /// retained the proposal (OF-063, FIX 9340); none when it had no row.
    pub retained_by_record: Option<crate::lens::RecordRef>,
    pub retained_at: u64,
    pub made_by: Option<MadeBy>,
    /// The deck's semantic diff line, the edit manifest's op count, or the
    /// organ's report.
    pub summary: RawJson,
}

impl PendingRow {
    pub(super) fn view(&self, artifact_id: EntityId) -> PendingProposalView {
        let summary = match &self.body {
            PendingBody::Edit {
                format, manifest, ..
            } => {
                let manifest = EditManifest::from_msgpack(manifest).ok();
                let ops = manifest.as_ref().map_or(0, |manifest| manifest.ops.len());
                let format_text = match format {
                    crate::edit_roundtrip::OfficeFormat::Xlsx => "\"xlsx\"",
                    crate::edit_roundtrip::OfficeFormat::Docx => "\"docx\"",
                    crate::edit_roundtrip::OfficeFormat::Pptx => "\"pptx\"",
                };
                let deck_text = manifest
                    .as_ref()
                    .and_then(|manifest| {
                        manifest.ops.iter().find_map(|op| match op {
                            crate::edit_roundtrip::EditOp::DeckTransaction { report, .. } => {
                                serde_json::from_str::<&serde_json::value::RawValue>(report)
                                    .ok()
                                    .map(|_| report.as_str())
                            }
                            _ => None,
                        })
                    })
                    .unwrap_or("null");
                let mut text = String::with_capacity(deck_text.len() + 64);
                text.push_str("{\"format\":");
                text.push_str(format_text);
                text.push_str(",\"ops\":");
                text.push_str(&ops.to_string());
                text.push_str(",\"deck\":");
                text.push_str(deck_text);
                text.push('}');
                // `deck_text` is a validated single JSON value or `null`,
                // `format_text` a quoted literal and `ops` a number, so the
                // checked build below always succeeds; the null fallback is
                // unreachable.
                RawJson(serde_json::value::RawValue::from_string(text).unwrap_or_default())
            }
            PendingBody::Output {
                name,
                media_type,
                report,
            } => {
                let name_json = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_owned());
                let media_json =
                    serde_json::to_string(media_type).unwrap_or_else(|_| "\"\"".to_owned());
                let mut text =
                    String::with_capacity(report.len() + name_json.len() + media_json.len() + 64);
                text.push_str("{\"name\":");
                text.push_str(&name_json);
                text.push_str(",\"media_type\":");
                text.push_str(&media_json);
                text.push_str(",\"report\":");
                text.push_str(report);
                text.push('}');
                // `name`/`media_type` are serializer-quoted strings and
                // `report` is stored report text validated at proposal time,
                // so the checked build below always succeeds; the null
                // fallback is unreachable.
                RawJson(serde_json::value::RawValue::from_string(text).unwrap_or_default())
            }
        };
        PendingProposalView {
            artifact_id,
            artifact: crate::lens::RecordRef::from_id(
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                &artifact_id,
                None,
            ),
            proposal_ref: self.proposal_ref.clone(),
            kind: match self.body {
                PendingBody::Edit { .. } => PendingProposalKind::Edit,
                PendingBody::Output { .. } => PendingProposalKind::Output,
            },
            base_version: self.base_version,
            content_hash: hash_hex(blake3::hash(&self.new_bytes).as_bytes()),
            byte_len: self.new_bytes.len(),
            retained_by: self.retained_by,
            retained_by_record: self
                .retained_by_kind
                .map(|kind| crate::lens::RecordRef::from_id(kind, &self.retained_by, None)),
            retained_at: self.retained_at,
            made_by: self.made_by.clone(),
            summary,
        }
    }
}
