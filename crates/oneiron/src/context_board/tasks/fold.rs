//! TASKS under its actor's board layout: the live fold summary and the
//! section filter (BOARD-LAYOUT add-ons, owner 2026-11-03 20:29 and 20:31).
//!
//! Both read the admitted rows the projection renders from, never a
//! rendered line. The summary counts every admitted row, so a filter or a
//! window never hides a failure from the fold line.

use super::super::layout::{FoldSummary, SectionFilter};
use super::projection::{TaskBoardStatus, TaskIntentPresence, TasksSectionRows};
use super::render::label_preview;
use crate::EntityId;
use crate::context_board::task_kind::TaskKind;

/// The statuses a TASKS fold line counts, in line order.
const FOLD_STATUSES: [TaskBoardStatus; 5] = [
    TaskBoardStatus::Running,
    TaskBoardStatus::Scheduled,
    TaskBoardStatus::Queued,
    TaskBoardStatus::Done,
    TaskBoardStatus::Failed,
];

/// Characters of a task's label one fold-line mention shows.
const FOLD_MENTION_LABEL_CHARS: usize = 24;

/// Hex characters of a task's id one fold-line mention shows.
const FOLD_MENTION_ID_CHARS: usize = 8;

/// One short mention of a task on a fold line: its id's first characters
/// and the start of its label.
fn mention(intent: &TaskIntentPresence) -> String {
    let id: String = intent.id.chars().take(FOLD_MENTION_ID_CHARS).collect();
    match intent.label.as_deref().map(label_preview) {
        Some(label) if !label.is_empty() => {
            let mut short: String = label.chars().take(FOLD_MENTION_LABEL_CHARS).collect();
            if label.chars().count() > FOLD_MENTION_LABEL_CHARS {
                short.push('\u{2026}');
            }
            format!("{id} {short}")
        }
        _ => id,
    }
}

/// Whether `intent` asks `actor` for an answer: an open consult addressed
/// to it.
fn asks(intent: &TaskIntentPresence, actor: EntityId) -> bool {
    intent.kind == Some(TaskKind::Consult)
        && intent.who == Some(actor)
        && !matches!(
            intent.status,
            TaskBoardStatus::Done | TaskBoardStatus::Failed
        )
}

impl TasksSectionRows {
    /// The live summary a folded TASKS section shows, for `actor`'s board:
    /// every admitted row the section renders from (an acknowledged failure
    /// has left the board), its count by status, the failed rows by name,
    /// and the consults that ask `actor`.
    #[must_use]
    pub fn fold_summary(&self, actor: Option<EntityId>) -> FoldSummary {
        let intents: Vec<&TaskIntentPresence> = self
            .intents
            .iter()
            .filter(|intent| !intent.is_acked_failure())
            .collect();
        let mut summary = FoldSummary::total(intents.len() + self.bare_jobs.len());
        for status in FOLD_STATUSES {
            let count = intents
                .iter()
                .filter(|intent| intent.status == status)
                .count()
                + self
                    .bare_jobs
                    .iter()
                    .filter(|job| job.status == status)
                    .count();
            summary = if status == TaskBoardStatus::Failed {
                let failed = intents
                    .iter()
                    .filter(|intent| intent.status == status)
                    .map(|intent| mention(intent))
                    .collect();
                summary.count_rows(status.as_str(), count, failed)
            } else {
                summary.count(status.as_str(), count)
            };
        }
        if let Some(actor) = actor {
            let asking: Vec<String> = intents
                .iter()
                .filter(|intent| asks(intent, actor))
                .map(|intent| mention(intent))
                .collect();
            summary = summary.count_rows("asks you", asking.len(), asking);
        }
        summary
    }

    /// These rows narrowed by `filter`: its statuses, and its `who` through
    /// `who_matches`, which the host resolves against the typed assignee
    /// (`None` for a row with none, such as a bare system job). The source
    /// honesty bit stays as it was.
    #[must_use]
    pub fn filtered(
        &self,
        filter: &SectionFilter,
        who_matches: impl Fn(Option<EntityId>) -> bool,
    ) -> Self {
        let status_ok = |status: TaskBoardStatus| {
            filter.status.is_empty() || filter.status.iter().any(|named| named == status.as_str())
        };
        let who_on = filter.who.is_some();
        Self {
            intents: self
                .intents
                .iter()
                .filter(|intent| status_ok(intent.status))
                .filter(|intent| !who_on || who_matches(intent.who))
                .cloned()
                .collect(),
            bare_jobs: self
                .bare_jobs
                .iter()
                .filter(|job| status_ok(job.status))
                .filter(|_| !who_on || who_matches(None))
                .cloned()
                .collect(),
            source_exhausted: self.source_exhausted,
        }
    }
}
