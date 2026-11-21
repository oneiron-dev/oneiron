//! The rows one lent verdict read sends under.
//!
//! A native decision read sends on its route bound to the rows fixed code read its input
//! from (FIX 6998, FIX 11526), so the call's permit and its metered settlement name them.
//! The lent read does the same where those rows are known. A pack candidate that names
//! the recorded step candidates it is folded from was drawn from the rows those steps'
//! calls were read from, which each step's record keeps and the operand check joins
//! ([`OperandBound::sources`]). A candidate that names no step has no known rows, and a
//! read that rests on such a candidate sends unsourced, as a native read does over a
//! member whose rows are not known.
//!
//! Each set is built by the native constructor for its read, over the checked rows: a
//! correction read through [`correction_source_rows`] and a read over a conflict through
//! [`conflict_source_rows`]. Capture only: no read is refused, held or narrowed here.
//!
//! The set names every row the lent calls read, which is not always native's set. Native
//! asks each candidate before it folds candidates, so a lent operand folded from two steps
//! sends under both steps' rows where native sends under one step's. And a native
//! extraction call reads its whole chunk of TURNs, while a lent step may be given a part of
//! that chunk: its record then names fewer rows than the native call's, and so does a read
//! over its candidate.

use super::super::call_labels::CallLabelMap;
use super::super::executor::extraction::conflict_source_rows;
use super::super::executor::extraction::corrections::correction_source_rows;
use super::step_records::OperandBound;
use crate::entity_id::EntityId;

/// Holds whose recorded rows one checked read sends under.
pub(super) struct ReadSources {
    /// Holds each pack candidate's rows, by pack position: `None` where they are not
    /// known. Empty until the operand check's result is taken.
    candidates: Vec<Option<Vec<EntityId>>>,
    /// Holds, for a read over a conflict, the pack position of each row member with the
    /// member's unwritten claim id, in row order: `None` for a correction read.
    members: Option<Vec<(usize, EntityId)>>,
}

impl ReadSources {
    /// Starts the sources of a correction read, whose asked candidates the built read
    /// names.
    pub(super) fn over_correction() -> Self {
        Self {
            candidates: Vec::new(),
            members: None,
        }
    }

    /// Starts the sources of a read over a conflict: the pack `positions` of its row
    /// members, each with its derived id from the pack ordered `candidate_ids`.
    pub(super) fn over_conflict(positions: &[usize], candidate_ids: &[EntityId]) -> Self {
        let members = positions
            .iter()
            .filter_map(|position| {
                candidate_ids
                    .get(*position)
                    .map(|claim| (*position, *claim))
            })
            .collect();
        Self {
            candidates: Vec::new(),
            members: Some(members),
        }
    }

    /// Takes each pack candidate's rows as the shared operand check fixed them in
    /// `bounds`, by pack position.
    pub(super) fn with_candidates(mut self, bounds: &[OperandBound]) -> Self {
        self.candidates = bounds.iter().map(|bound| bound.sources.clone()).collect();
        self
    }

    /// The rows the read sends under, sorted and each once, or `None` when the rows of
    /// one candidate the read rests on are not known.
    ///
    /// A correction read rests on the candidates at `owners`, the pack positions that
    /// own its questions: it sends under their rows, the pack's `evidence` and the
    /// stored rows its `labels` name. A read over a conflict rests on every member: it
    /// sends under their rows, the pack's `evidence` and the stored rows its `labels`
    /// name, never a member's own unwritten claim id.
    ///
    /// The resolution final sends under its conflict's set. Native joins the final's
    /// set with each page's, and every page's set is that one: the same members and
    /// evidence, and labels that name only members and the prior heads, which the
    /// evidence lists.
    pub(super) fn rows(
        &self,
        owners: &[usize],
        evidence: &[EntityId],
        labels: &CallLabelMap,
    ) -> Option<Vec<EntityId>> {
        let label_rows: Vec<EntityId> = labels.rows().collect();
        let Some(members) = &self.members else {
            let known = |position: &usize| matches!(self.candidates.get(*position), Some(Some(_)));
            if !owners.iter().all(known) {
                return None;
            }
            let rows: Vec<&[EntityId]> = self
                .candidates
                .iter()
                .map(|rows| rows.as_deref().unwrap_or_default())
                .collect();
            return Some(correction_source_rows(&rows, owners, evidence, &label_rows));
        };
        let member_claims: Vec<EntityId> = members.iter().map(|(_, claim)| *claim).collect();
        let member_rows: Vec<Option<Vec<EntityId>>> = members
            .iter()
            .map(|(position, _)| self.candidates.get(*position).cloned().flatten())
            .collect();
        conflict_source_rows(&member_claims, &member_rows, evidence, &label_rows)
    }
}
