//! The pending proposal's typed result, without a JSON-tree record round trip.

use oneiron::edit_settle::{PendingProposalKind, PendingProposalView};

use super::{Lift, OneironError, WireJson, count, lift_record};

impl Lift<PendingProposalView> for crate::PendingProposalView {
    fn lift(value: PendingProposalView) -> Result<Self, OneironError> {
        // Consume the potentially deep report before any fallible metadata lift.
        let summary = WireJson::lift(value.summary)?;
        Ok(Self {
            artifact_id: value.artifact_id.to_hex(),
            artifact: record_ref(value.artifact),
            proposal_ref: value.proposal_ref,
            kind: match value.kind {
                PendingProposalKind::Edit => crate::PendingProposalKind::Edit,
                PendingProposalKind::Output => crate::PendingProposalKind::Output,
            },
            base_version: value.base_version,
            content_hash: value.content_hash,
            byte_len: count("byte_len", value.byte_len)?,
            retained_by: value.retained_by.to_hex(),
            retained_by_record: value.retained_by_record.map(record_ref),
            retained_at: value.retained_at,
            made_by: value
                .made_by
                .map(|made_by| lift_record("pending proposal made_by", &made_by))
                .transpose()?,
            summary,
        })
    }
}

fn record_ref(value: oneiron::lens::RecordRef) -> crate::RecordRef {
    crate::RecordRef {
        kind: value.kind,
        id: value.id,
        short_id: value.short_id,
        label: value.label,
    }
}
