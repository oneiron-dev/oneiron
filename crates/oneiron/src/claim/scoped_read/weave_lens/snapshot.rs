//! A report's rows as one read showed them, against a later read of the
//! same report (FIX 7694). A loop decision the ledger gained after the
//! first read is a new event, not a change to any row that read showed: it
//! joins the next read and never holds back the rows the first read
//! showed. Every other row, and every loop row the first read showed, must
//! still read exactly as shown.
use std::collections::BTreeMap;

use super::{WeaveItem, WeaveReport};

/// Whether `fresh`, a later read of the report `snapshot` was read as,
/// still serves every row of `snapshot`: the same sections in order, each
/// section's other rows equal and in order, and each of its loop rows
/// exactly as `fresh` reads that decision now. A loop row only `fresh`
/// holds is left out of the comparison.
pub(crate) fn snapshot_still_served(snapshot: &WeaveReport, fresh: &WeaveReport) -> bool {
    snapshot.sections.len() == fresh.sections.len()
        && snapshot
            .sections
            .iter()
            .zip(&fresh.sections)
            .all(|(shown, now)| {
                let current: BTreeMap<[u8; 16], &WeaveItem> = now
                    .items
                    .iter()
                    .filter_map(|item| match item {
                        WeaveItem::LoopDecision { decision_id, .. } => {
                            Some((decision_id.as_bytes(), item))
                        }
                        _ => None,
                    })
                    .collect();
                shown.kind == now.kind
                    && shown
                        .items
                        .iter()
                        .filter(|item| !is_loop_row(item))
                        .eq(now.items.iter().filter(|item| !is_loop_row(item)))
                    && shown.items.iter().all(|item| match item {
                        WeaveItem::LoopDecision { decision_id, .. } => {
                            current.get(&decision_id.as_bytes()) == Some(&item)
                        }
                        _ => true,
                    })
            })
}

fn is_loop_row(item: &WeaveItem) -> bool {
    matches!(item, WeaveItem::LoopDecision { .. })
}
