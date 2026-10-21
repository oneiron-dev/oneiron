//! An Arc's evidence (FIX 7509 P8, SUMMARY-SOURCE = A), read in one snapshot:
//! its sittings' summary lines, each with the call-local `T` labels of the
//! TURNs it cites (FIX 7506), never a SUMMARY id as a turn label; the TURNs
//! read again in place of a line that is not the Arc's whole; and the
//! current claims and open conflicts of the subjects its TURNs name
//! ([`super::arc_claims`]).
//!
//! Every TURN a line cites is read and pinned as any summary's source is,
//! with each MESSAGE it was read from; only those read in place of a line
//! are shown. Each sitting's summary is pinned beside them. A TURN the Arc
//! must read that its Dreamer may not is named, and the Arc stays owed.

use super::super::call_labels::{CallLabelMap, LabelKind};
use super::super::resources::document_version;
use super::super::turn_text::dreamer_read;
use super::{ScopeSummaryEvidence, scope_summary_evidence_in_txn, source_pin};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::error::Result;
use crate::scope_summary::ArcSources;
use crate::{EntityId, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// What one Arc call shows and how it names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ArcView {
    /// The call's labels: each TURN its lines cite `T`, each claim `C` and
    /// each claim's subject `P`.
    pub(super) labels: CallLabelMap,
    /// The sittings' lines as written, each with its `T` refs.
    pub(super) lines: String,
    /// The TURNs read again in place of a line, by label.
    pub(super) turns: String,
    /// The claims and open conflicts of the subjects the TURNs name.
    pub(super) claims: String,
    /// The TURNs whose words the call already shows.
    pub(super) opened: BTreeSet<EntityId>,
    /// Each claim shown, which the Arc depends on once it lands.
    pub(super) claim_ids: Vec<EntityId>,
    /// A TURN the Arc must read that its Dreamer could not.
    pub(super) unavailable: Option<EntityId>,
}

impl ScopeSummaryEvidence {
    /// The claims an Arc's call read (FIX 7509 P8); none for any other
    /// summary.
    pub(crate) fn arc_claims(&self) -> Vec<EntityId> {
        self.arc
            .as_ref()
            .map(|view| view.claim_ids.clone())
            .unwrap_or_default()
    }
}

/// The Arc's evidence in `txn`, as its plan's sources name it.
pub(crate) fn arc_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    arc: &ArcSources,
) -> Result<ScopeSummaryEvidence> {
    let mut evidence = scope_summary_evidence_in_txn(vault, txn, &arc.turns, true)?;
    let read: BTreeSet<String> = evidence
        .source_versions
        .iter()
        .filter(|pin| pin.entity_type.is_some())
        .map(|pin| pin.id.clone())
        .collect();
    let unavailable = arc
        .turns
        .iter()
        .find(|turn| !read.contains(&turn.to_hex()))
        .copied();
    let words: BTreeMap<EntityId, String> = evidence
        .turns
        .iter()
        .filter_map(|(turn, text)| text.text().map(|text| (*turn, text.to_owned())))
        .collect();
    // Each sitting's summary is pinned as read, and readable to the call.
    let dreamer = dreamer_read(vault)?;
    let lower: Vec<EntityId> = arc.lower.iter().map(|lower| lower.summary).collect();
    let rows = dreamer.get_entities_parts_in_txn(txn, &lower)?;
    for (summary, row) in lower.iter().zip(rows) {
        if let Some((_, _, body)) = &row {
            evidence.readable.insert(document_version(*summary, body));
        }
        evidence
            .source_versions
            .push(source_pin(vault, txn, *summary, row.as_ref())?);
    }
    let mut view = ArcView {
        unavailable,
        ..ArcView::default()
    };
    for (index, lower) in arc.lower.iter().enumerate() {
        view.lines.push_str(&format!("Sitting {}:\n", index + 1));
        for line in &lower.lines {
            let refs: Vec<String> = line
                .turns
                .iter()
                .map(|turn| view.labels.assign(LabelKind::Turn, *turn).to_string())
                .collect();
            if line.whole {
                view.lines
                    .push_str(&format!("- {} [{}]\n", line.words, refs.join(", ")));
                continue;
            }
            // A line not the Arc's whole is its TURNs, read again.
            for (turn, label) in line.turns.iter().zip(&refs) {
                if view.opened.insert(*turn)
                    && let Some(text) = words.get(turn)
                {
                    view.turns.push_str(&format!("[{label}] {text}\n"));
                }
            }
        }
    }
    let claims = super::arc_claims::claims_in_txn(
        vault,
        txn,
        &dreamer,
        &arc.turns,
        &mut view.labels,
        &mut evidence,
    )?;
    view.claims = claims.text;
    view.claim_ids = claims.ids;
    evidence.text = serde_json::to_string(&(&view.lines, &view.turns, &view.claims))
        .map_err(|_| invalid_consolidation("arc evidence encoding"))?;
    evidence.turns.clear();
    evidence.arc = Some(view);
    Ok(evidence)
}
