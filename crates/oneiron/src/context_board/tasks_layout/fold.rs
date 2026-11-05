//! Whole-section TASKS folds from the same admitted, uncapped source.

use super::TasksLayoutSelection;
use crate::EntityId;
use crate::context_board::tasks::{fits_row, intent_row};
use crate::context_board::{
    BoardFrameError, BoardSection, HookPin, TaskBoardStatus, TaskIntentPresence, TasksSection,
    TasksSectionRows,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Structural attention refs in the one-line fold; the remaining count stays
/// explicit. This is presentation only, never a source scan or admission cap.
const TASKS_FOLD_ATTENTION_REFS: usize = 3;

/// No authored content is stored in the actor's fold baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskFoldMark {
    id: EntityId,
    intent: bool,
    digest: [u8; 32],
}

impl TasksLayoutSelection {
    /// Assembles the selected TASKS view after the ordinary projection and
    /// hook tagging. Unfolded selections return the original keep assembly.
    /// A fold's counts and baseline use the FULL already-admitted source,
    /// never its token or 100-row prefix. Nothing is fetched by id.
    pub fn board_section(
        &mut self,
        tasks: &TasksSection,
        source: &TasksSectionRows,
        lead: Vec<String>,
        pins: &[HookPin],
    ) -> Result<BoardSection, BoardFrameError> {
        if !self.folded {
            return tasks.board_section_keeping(lead, &self.keep);
        }
        let mut open = self.keep.clone();
        open.extend(pins.iter().flat_map(|pin| pin.refs.iter().copied()));
        open.sort_unstable();
        open.dedup();
        let context_rows = lead.len();
        let section = tasks.board_section_keeping(lead, &open)?;
        let mut fold = FoldSource::new(source);
        let baseline = if self.capture_baseline {
            if let Some(candidate) = &mut self.candidate {
                candidate.fold_baseline = Some(fold.marks.clone());
            }
            &fold.marks
        } else {
            &self.baseline
        };
        let previous: BTreeMap<_, _> = baseline
            .iter()
            .map(|mark| ((mark.intent, mark.id), mark.digest))
            .collect();
        let mut changed = Vec::new();
        let mut new = 0;
        for mark in &fold.marks {
            match previous.get(&(mark.intent, mark.id)) {
                Some(digest) if *digest != mark.digest => changed.push(mark.id),
                None => new += 1,
                _ => {}
            }
        }
        // Only CURRENT admitted ids contribute. Removed or withheld baseline
        // ids are never counted or surfaced on a narrower reader's board.
        let mut attention = std::mem::take(&mut fold.failed);
        attention.extend(changed.iter().copied());
        let mut unique = std::collections::BTreeSet::new();
        attention.retain(|id| unique.insert(*id));
        let shown = attention
            .iter()
            .take(TASKS_FOLD_ATTENTION_REFS)
            .map(EntityId::to_hex)
            .collect::<Vec<_>>();
        let omitted = attention.len().saturating_sub(shown.len());
        let attention = match (shown.is_empty(), omitted) {
            (true, _) => "none".to_owned(),
            (false, 0) => shown.join(","),
            (false, rest) => format!("{},+{rest}", shown.join(",")),
        };
        let scope = if source.source_exhausted {
            "exact"
        } else {
            "at_least"
        };
        let line = format!(
            "folded tasks={} jobs={} running={} scheduled={} queued={} done={} failed={} changed={} new_to_fold={} asking=unknown source={} context_rows={} attention={} open=POST:/v1/core/context-board/layout/tasks:{{folded:false}}",
            fold.intents,
            fold.jobs,
            fold.status[0],
            fold.status[1],
            fold.status[2],
            fold.status[3],
            fold.status[4],
            changed.len(),
            new,
            scope,
            context_rows,
            attention,
        );
        let summary = vec![line];
        let discovery = tasks
            .rows
            .iter()
            .filter(|row| section.pinned_rows().iter().any(|line| *line == row.line))
            .filter_map(fits_row)
            .collect();
        // Detail and fallback are identical, so final SHED can never grow a
        // folded view. Its actually rendered kept/hook floor stays open.
        Ok(BoardSection::new(
            "TASKS",
            section.pinned_rows().to_vec(),
            summary.clone(),
            summary,
            section.policy(),
        )?
        .with_discovery_rows(discovery))
    }
}

struct FoldSource {
    intents: usize,
    jobs: usize,
    status: [usize; 5],
    failed: Vec<EntityId>,
    marks: Vec<TaskFoldMark>,
}

impl FoldSource {
    fn new(source: &TasksSectionRows) -> Self {
        let mut fold = Self {
            intents: 0,
            jobs: source.bare_jobs.len(),
            status: [0; 5],
            failed: Vec::new(),
            marks: Vec::new(),
        };
        for intent in source
            .intents
            .iter()
            .filter(|intent| !intent.is_acked_failure())
        {
            fold.intents += 1;
            fold.jobs += intent.realizing_jobs.len();
            fold.count(intent.status);
            let Ok(id) = EntityId::from_hex(&intent.id) else {
                continue;
            };
            if intent.status == TaskBoardStatus::Failed {
                fold.failed.push(id);
            }
            fold.marks.push(TaskFoldMark {
                id,
                intent: true,
                digest: intent_digest(intent),
            });
        }
        for job in &source.bare_jobs {
            fold.count(job.status);
            let Ok(id) = EntityId::from_hex(&job.id) else {
                continue;
            };
            if job.status == TaskBoardStatus::Failed {
                fold.failed.push(id);
            }
            let mut hash = blake3::Hasher::new();
            job_digest(&mut hash, job);
            fold.marks.push(TaskFoldMark {
                id,
                intent: false,
                digest: *hash.finalize().as_bytes(),
            });
        }
        fold
    }

    fn count(&mut self, status: TaskBoardStatus) {
        let index = match status {
            TaskBoardStatus::Running => 0,
            TaskBoardStatus::Scheduled => 1,
            TaskBoardStatus::Queued => 2,
            TaskBoardStatus::Done => 3,
            TaskBoardStatus::Failed => 4,
        };
        self.status[index] += 1;
    }
}

fn leaf(hash: &mut blake3::Hasher, value: &[u8]) {
    hash.update(&(value.len() as u64).to_le_bytes());
    hash.update(value);
}

fn optional(hash: &mut blake3::Hasher, value: Option<&str>) {
    hash.update(&[u8::from(value.is_some())]);
    if let Some(value) = value {
        leaf(hash, value.as_bytes());
    }
}

fn job_digest(hash: &mut blake3::Hasher, job: &crate::context_board::JobPresence) {
    leaf(hash, job.id.as_bytes());
    leaf(hash, job.kind.as_bytes());
    leaf(hash, job.status.as_str().as_bytes());
    hash.update(&[u8::from(job.cancel_pathology.is_some())]);
    if let Some(pathology) = &job.cancel_pathology {
        leaf(hash, pathology.attempt_id.as_bytes());
        hash.update(&pathology.rejections.to_le_bytes());
        hash.update(&pathology.threshold.to_le_bytes());
        optional(hash, pathology.last_status.as_deref());
    }
}

fn intent_digest(intent: &TaskIntentPresence) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    let row = intent_row(intent);
    leaf(&mut hash, row.line.as_bytes());
    optional(&mut hash, intent.label.as_deref());
    optional(&mut hash, intent.kind.map(|kind| kind.as_str()));
    optional(&mut hash, intent.result_ref.as_deref());
    optional(&mut hash, intent.counter_task_ref.as_deref());
    hash.update(&[u8::from(intent.interrupted)]);
    match &intent.consult_result {
        Some(crate::context_board::consult_result::ConsultResultPresence::Answer {
            result_ref,
            evidence_ref_count,
        }) => {
            hash.update(&[1]);
            leaf(&mut hash, result_ref.as_bytes());
            hash.update(&(*evidence_ref_count as u64).to_le_bytes());
        }
        Some(crate::context_board::consult_result::ConsultResultPresence::Abstained {
            result_ref,
            reason_ref,
        }) => {
            hash.update(&[2]);
            leaf(&mut hash, result_ref.as_bytes());
            leaf(&mut hash, reason_ref.as_bytes());
        }
        None => {
            hash.update(&[0]);
        }
    }
    hash.update(&[u8::from(intent.who.is_some())]);
    if let Some(who) = intent.who {
        leaf(&mut hash, who.as_bytes());
    }
    hash.update(&(intent.realizing_jobs.len() as u64).to_le_bytes());
    for job in &intent.realizing_jobs {
        job_digest(&mut hash, job);
    }
    hash.update(&(intent.children.len() as u64).to_le_bytes());
    for (id, token) in &intent.children {
        leaf(&mut hash, id.as_bytes());
        leaf(&mut hash, token.as_bytes());
    }
    hash.update(&(intent.fits.len() as u64).to_le_bytes());
    for person in &intent.fits {
        leaf(&mut hash, person.as_bytes());
    }
    *hash.finalize().as_bytes()
}
