//! Re-admit typed native witnesses in the heal reader's source snapshot.

use crate::Result;
use crate::claim::ScopedRead;
use crate::skill_attribution::{
    canonical_attribution_judgment_in_txn, canonical_attribution_judgments_in_txn,
    canonical_skill_edit_proposal_in_txn, canonical_skill_edit_proposals_in_txn,
};
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
        NativeReadSource::OutcomeRow { row: source } => {
            let Some(row) = crate::skill_reliability::canonical_outcome_dependency_in_txn(
                lane.vault(),
                txn,
                source,
            )?
            else {
                return Ok(Some("source_missing"));
            };
            if row.source() != *source {
                return Ok(Some("source_changed"));
            }
            Ok((!lane.native_outcome_dependency_admitted_in_txn(txn, &row)?).then_some("withheld"))
        }
        NativeReadSource::AttributedOutcomeScan {
            skill,
            prefixes,
            rows,
        } => {
            let (_, current) = crate::skill_reliability::canonical_attributed_outcomes_in_txn(
                lane.vault(),
                txn,
                skill,
            )?;
            if current.prefixes() != prefixes.as_slice() || current.sources() != *rows {
                return Ok(Some("source_changed"));
            }
            for row in current.rows() {
                if !lane.native_outcome_dependency_admitted_in_txn(txn, row)? {
                    return Ok(Some("withheld"));
                }
            }
            Ok(None)
        }
        NativeReadSource::RuleOutcome {
            skill,
            receipt,
            row: source,
        } => {
            let Some(row) = crate::skill_reliability::canonical_rule_outcome_in_txn(
                lane.vault(),
                txn,
                skill,
                receipt,
            )?
            else {
                return Ok(Some("source_missing"));
            };
            if row.source() != *source {
                return Ok(Some("source_changed"));
            }
            Ok(
                (!lane.native_rule_outcome_admitted_in_txn(txn, skill, &row)?)
                    .then_some("withheld"),
            )
        }
        NativeReadSource::RuleOutcomeScan {
            skill,
            prefix,
            rows,
        } => {
            let (current, current_prefix) =
                crate::skill_reliability::canonical_rule_outcomes_in_txn(lane.vault(), txn, skill)?;
            if current_prefix != *prefix
                || current.len() != rows.len()
                || current
                    .iter()
                    .zip(rows)
                    .any(|(row, source)| row.source() != *source)
            {
                return Ok(Some("source_changed"));
            }
            for row in &current {
                if !lane.native_rule_outcome_admitted_in_txn(txn, skill, row)? {
                    return Ok(Some("withheld"));
                }
            }
            Ok(None)
        }
        NativeReadSource::AttributionJudgment { row: source } => {
            let Some(row) =
                canonical_attribution_judgment_in_txn(lane.vault(), txn, source.sequence)?
            else {
                return Ok(Some("source_missing"));
            };
            if row.source() != *source {
                return Ok(Some("source_changed"));
            }
            Ok(
                (!lane.native_attribution_judgment_admitted_in_txn(txn, &row)?)
                    .then_some("withheld"),
            )
        }
        NativeReadSource::AttributionJudgmentScan { prefix, rows } => {
            let (current, current_prefix) =
                canonical_attribution_judgments_in_txn(lane.vault(), txn)?;
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
                if !lane.native_attribution_judgment_admitted_in_txn(txn, row)? {
                    return Ok(Some("withheld"));
                }
            }
            Ok(None)
        }
        NativeReadSource::SkillEditProposal { row: source } => {
            let Some(row) =
                canonical_skill_edit_proposal_in_txn(lane.vault(), txn, source.sequence)?
            else {
                return Ok(Some("source_missing"));
            };
            if row.source() != *source {
                return Ok(Some("source_changed"));
            }
            Ok(
                (!lane.native_skill_edit_proposal_admitted_in_txn(txn, &row)?)
                    .then_some("withheld"),
            )
        }
        NativeReadSource::SkillEditProposalScan { prefix, rows } => {
            let (current, current_prefix) =
                canonical_skill_edit_proposals_in_txn(lane.vault(), txn)?;
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
                if !lane.native_skill_edit_proposal_admitted_in_txn(txn, row)? {
                    return Ok(Some("withheld"));
                }
            }
            Ok(None)
        }
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
