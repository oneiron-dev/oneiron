//! The ledger record a native output's Keep or Discard writes.

use super::{PendingBody, PendingRow};
use crate::edit_settle::records::{SettleConsent, SettleOutcomeKind, SettlementRecord};
use crate::write_envelope::WriteActor;

/// The ledger record of a native output's settle: `version` the version it
/// became, `replaced` the head that version replaced.
pub(super) fn output_record(
    row: &PendingRow,
    outcome: SettleOutcomeKind,
    (consent, actor): (&SettleConsent, WriteActor),
    settled_at: u64,
    (version, replaced): (
        Option<&crate::blob_artifact::BlobArtifactVersion>,
        Option<u64>,
    ),
) -> SettlementRecord {
    let report = match &row.body {
        PendingBody::Output { report, .. } => report.as_bytes(),
        PendingBody::Edit { manifest, .. } => manifest.as_slice(),
    };
    SettlementRecord {
        proposal_ref: row.proposal_ref.clone(),
        outcome,
        settled_at,
        actor_ref: Some(actor.entity_ref().to_hex()),
        brief_ref: consent.brief_ref().map(str::to_owned),
        before_version: version.and(replaced),
        version: version.map(|version| version.version),
        content_hash: version.map(|version| version.content_hash),
        manifest_ref: version.map(|_| *blake3::hash(report).as_bytes()),
        manifest_ops: 0,
        pptx_slide_creation_id_mints: Vec::new(),
        pptx_review_identities: Vec::new(),
        pptx_judgments: Vec::new(),
        docx_judgments: Vec::new(),
        anchors: Vec::new(),
        reason: None,
        sheet_answers: None,
        deck: None,
    }
}
