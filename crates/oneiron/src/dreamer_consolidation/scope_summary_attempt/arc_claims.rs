//! The claims an Arc's call reads (FIX 7509 P8): for every subject the
//! Arc's TURNs name (their `mentions` and `about` edges), each current claim
//! head and each open conflict on it, read exactly through the Dreamer's own
//! scoped read, pinned and shown by call-local labels. No ranking and no
//! top-k: every one the Dreamer may read is shown. Facts and conflicts stay
//! on claims; the Arc only reads them, so a line the claims dispute can send
//! the model back to its turns.

use super::super::call_labels::{CallLabelMap, LabelKind, subject_label};
use super::super::resources::document_version;
use super::super::value_projection::rmpv_to_json;
use super::{ScopeSummaryEvidence, source_pin};
use crate::claim::{ClaimLifecycleStatus, PREDICATE_CONFLICT_OPEN, ScopedRead};
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::{EntityId, Vault};
use std::collections::BTreeSet;

/// The claims shown, as the call reads them, their ids, and each as an
/// entry an Arc composed in parts shows a range of (FIX 7509 PR3).
pub(super) struct ArcClaims {
    pub(super) text: String,
    pub(super) ids: Vec<EntityId>,
    pub(super) entries: Vec<ArcClaimEntry>,
}

/// One claim as shown: its `C` label and the words after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArcClaimEntry {
    pub(super) id: EntityId,
    pub(super) label: String,
    pub(super) body: String,
}

/// Every active claim on a subject `turns` name, read through `read` in
/// `txn`: pinned into `evidence`, readable to the call, labelled in
/// `labels`. A claim the Dreamer may not read is not shown.
pub(super) fn claims_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    turns: &[EntityId],
    labels: &mut CallLabelMap,
    evidence: &mut ScopeSummaryEvidence,
) -> Result<ArcClaims> {
    let mut subjects = Vec::new();
    let mut seen = BTreeSet::new();
    for turn in turns {
        for kind in [EdgeKind::Mentions, EdgeKind::About] {
            for subject in vault.filtered_edge_peers(txn, EdgeDirection::Out, turn, kind, None)? {
                if seen.insert(subject) {
                    subjects.push(subject);
                }
            }
        }
    }
    let mut candidates = Vec::new();
    let mut listed = BTreeSet::new();
    for subject in &subjects {
        for claim in vault.claims_for_subject_in_txn(txn, subject)? {
            if listed.insert(claim) {
                candidates.push(claim);
            }
        }
    }
    let rows = read.get_entities_parts_in_txn(txn, &candidates)?;
    let mut text = String::new();
    let mut ids = Vec::new();
    let mut entries = Vec::new();
    for (claim, row) in candidates.iter().zip(rows) {
        let Some((ENTITY_TYPE_CLAIM, _, body)) = &row else {
            continue;
        };
        let decoded = crate::claim::decode_claim_body(body, true)?;
        if decoded.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        evidence.readable.insert(document_version(*claim, body));
        evidence
            .source_versions
            .push(source_pin(vault, txn, *claim, row.as_ref())?);
        let label = labels.assign(LabelKind::Claim, *claim);
        let subject = subject_label(labels, &decoded.subject);
        let conflict = if decoded.predicate == PREDICATE_CONFLICT_OPEN {
            " open_conflict"
        } else {
            ""
        };
        let words = format!(
            "subject={subject} {} {} confidence={} approval={}{conflict}",
            decoded.predicate,
            rmpv_to_json(&decoded.value),
            decoded.confidence,
            decoded.approval.as_str(),
        );
        text.push_str(&format!("[{label}] {words}\n"));
        ids.push(*claim);
        entries.push(ArcClaimEntry {
            id: *claim,
            label: label.to_string(),
            body: words,
        });
    }
    Ok(ArcClaims { text, ids, entries })
}
