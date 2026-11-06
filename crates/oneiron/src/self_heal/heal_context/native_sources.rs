//! Re-admit typed native witnesses in the heal reader's source snapshot.

use crate::Result;
use crate::claim::ScopedRead;
use crate::skill_optimize::{
    canonical_judge_label_in_txn, canonical_skill_edit_verdict_in_txn,
    canonical_skill_edit_verdicts_in_txn,
};
use crate::store::attempt_sources::{NativeReadSource, SkillEditVerdictSource};

pub(super) fn unavailable_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    source: &NativeReadSource,
) -> Result<Option<&'static str>> {
    match source {
        NativeReadSource::JudgeLabel { ask_id, .. } => {
            let Some(row) = canonical_judge_label_in_txn(lane.vault(), txn, ask_id)? else {
                return Ok(Some("source_missing"));
            };
            if row.source() != *source {
                return Ok(Some("source_changed"));
            }
            Ok((!lane.native_judge_label_admitted_in_txn(txn, &row)?).then_some("withheld"))
        }
        NativeReadSource::SkillEditVerdict { row: source } => {
            verdict_unavailable_in_txn(lane, txn, source)
        }
        NativeReadSource::SkillEditVerdictScan { prefix, rows } => {
            let (current, current_prefix) =
                canonical_skill_edit_verdicts_in_txn(lane.vault(), txn)?;
            if current_prefix != prefix.as_slice()
                || current.len() != rows.len()
                || current
                    .iter()
                    .zip(rows)
                    .any(|(row, source)| row.source() != *source)
            {
                return Ok(Some("source_changed"));
            }
            for row in &current {
                if !lane.native_skill_edit_verdict_admitted_in_txn(txn, row)? {
                    return Ok(Some("withheld"));
                }
            }
            Ok(None)
        }
    }
}

fn verdict_unavailable_in_txn(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    source: &SkillEditVerdictSource,
) -> Result<Option<&'static str>> {
    let Some(row) = canonical_skill_edit_verdict_in_txn(lane.vault(), txn, &source.id)? else {
        return Ok(Some("source_missing"));
    };
    if row.source() != *source {
        return Ok(Some("source_changed"));
    }
    Ok((!lane.native_skill_edit_verdict_admitted_in_txn(txn, &row)?).then_some("withheld"))
}
