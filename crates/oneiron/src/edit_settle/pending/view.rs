//! A waiting proposal as a review surface lists it.

use serde::{Deserialize, Serialize};

use super::{PendingBody, PendingRow};
use crate::blob_artifact::hash_hex;
use crate::edit_roundtrip::EditManifest;
use crate::entity_id::EntityId;
use crate::provenance::made_by::MadeBy;

#[doc(hidden)]
pub use oneiron_verb_wire::edit_settle::pending::view::PendingProposalKind;

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
    /// BLAKE3 of the proposed bytes, hex; empty for `NeedsStaging`, which
    /// has no proposed bytes.
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
    pub summary: serde_json::Value,
}

impl PendingRow {
    pub(super) fn view(&self, artifact_id: EntityId) -> PendingProposalView {
        let mut summary = match &self.body {
            PendingBody::SheetAnswers { bundle } => serde_json::json!({
                "format": "xlsx",
                "status": "needs_staging",
                "answers": bundle.answers.iter().filter(|answer| answer.value.is_some()).count(),
            }),
            PendingBody::Edit {
                format, manifest, ..
            } => {
                let manifest = EditManifest::from_msgpack(manifest).ok();
                serde_json::json!({
                    "format": format,
                    "ops": manifest.as_ref().map_or(0, |manifest| manifest.ops.len()),
                    "deck": manifest.as_ref().and_then(|manifest| {
                        manifest.ops.iter().find_map(|op| match op {
                            crate::edit_roundtrip::EditOp::DeckTransaction { report, .. } => {
                                serde_json::from_str::<serde_json::Value>(report).ok()
                            }
                            _ => None,
                        })
                    }),
                })
            }
            PendingBody::Output {
                name,
                media_type,
                report,
                ..
            } => serde_json::json!({
                "name": name,
                "media_type": media_type,
                "report": serde_json::from_str::<serde_json::Value>(report)
                    .unwrap_or(serde_json::Value::Null),
            }),
        };
        if let Some(next) = self.next_sheet_row {
            summary["next_sheet_row"] = serde_json::json!(next);
        }
        PendingProposalView {
            artifact_id,
            artifact: crate::lens::RecordRef::from_id(
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                &artifact_id,
                None,
            ),
            proposal_ref: self.proposal_ref.clone(),
            kind: match self.body {
                PendingBody::SheetAnswers { .. } => PendingProposalKind::NeedsStaging,
                PendingBody::Edit { .. } => PendingProposalKind::Edit,
                PendingBody::Output { .. } => PendingProposalKind::Output,
            },
            base_version: self.base_version,
            content_hash: if matches!(&self.body, PendingBody::SheetAnswers { .. }) {
                String::new()
            } else {
                // An output waiting in its body file is listed from its
                // descriptor, never read (FIX 20812).
                match &self.new_file {
                    Some(file) => hash_hex(&file.body.blake3),
                    None => hash_hex(blake3::hash(&self.new_bytes).as_bytes()),
                }
            },
            byte_len: usize::try_from(self.payload_len()).unwrap_or(usize::MAX),
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
