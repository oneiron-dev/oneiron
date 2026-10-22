//! Pure TASKS row rendering: intent rows, folded jobs, cause tokens, expansion detail.

use super::super::frame::MAX_BOARD_ROW_BYTES;
use super::super::{TASK_LABEL_MAX_BYTES, one_line_token};
use super::projection::{
    JobPresence, TaskBoardStatus, TaskIntentPresence, TaskRow, TasksSection,
    intent_cancel_pathology, ladder_board_projection,
};
use crate::outbound::ConnectorSendTaskOutcome;
use crate::task_verb::ConsultResultPresence;

/// Renders provided task presence into stable, collapsed rows — intent rows
/// first with realizing jobs folded under them, then bare system jobs as-is.
/// Acked failures have left the surface.
///
/// Compatibility door for callers that already hold a COMPLETE in-memory set;
/// a caller whose TASK scan was bounded must use
/// [`TasksSection::render_bounded`] so the footer can stay honest.
#[must_use]
pub fn render_tasks_section(
    intents: &[TaskIntentPresence],
    bare_jobs: &[JobPresence],
) -> TasksSection {
    TasksSection::render_bounded(intents, bare_jobs, true)
}

/// The failed lane of a rendered TASKS section. Acked failures were already
/// dropped at render time, so the lane is every surfaced failed row.
#[must_use]
pub fn failed_lane(section: &TasksSection) -> Vec<&TaskRow> {
    section
        .rows
        .iter()
        .filter(|row| row.status == TaskBoardStatus::Failed)
        .collect()
}

/// Unfolds one intent's realizing jobs under its row — the engine seam
/// behind `describe` on card `tasks.<id>`; the verb dispatch surface is ONE-1696.
/// Line order: the collapsed intent row first, then its realizing jobs in
/// presence order, indented one level.
#[must_use]
pub fn expand_task(intent: &TaskIntentPresence) -> Vec<String> {
    let mut lines = Vec::with_capacity(2 + intent.realizing_jobs.len());
    lines.push(intent_row(intent).line);
    lines.extend(
        intent
            .realizing_jobs
            .iter()
            .map(|job| format!("  {}", bare_job_row(job).line)),
    );
    if let Some(detail) = delegation_detail_line(intent) {
        lines.push(format!("  {detail}"));
    }
    lines
}

/// Typed refs only: an expanded consult says WHERE the result lives and what
/// SHAPE it has, never what it says.
fn delegation_detail_line(intent: &TaskIntentPresence) -> Option<String> {
    let mut tokens = Vec::new();
    if let Some(result_ref) = intent.result_ref.as_deref() {
        tokens.push(format!("result={}", single_token(result_ref)));
    }
    // The counter's own row renders independently; this only says WHERE the
    // successor is, so a reader never mistakes the immutable old row for it.
    if let Some(counter_task_ref) = intent.counter_task_ref.as_deref() {
        tokens.push(format!("counter={}", single_token(counter_task_ref)));
    }
    match &intent.consult_result {
        Some(ConsultResultPresence::Answer {
            evidence_ref_count, ..
        }) => {
            tokens.push("answer".to_owned());
            tokens.push(format!("evidence={evidence_ref_count}"));
        }
        Some(ConsultResultPresence::Abstained { reason_ref, .. }) => {
            tokens.push("abstained".to_owned());
            tokens.push(format!("reason={}", single_token(reason_ref)));
        }
        None => {}
    }
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

/// One structural token. `one_line_token` already keeps a value on one physical
/// line; collapsing the remaining whitespace also stops a handle or ref from
/// splitting into a second token that would read as board structure.
pub(super) fn single_token(value: &str) -> String {
    one_line_token(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
}

pub(crate) fn intent_row(intent: &TaskIntentPresence) -> TaskRow {
    let folded_job_count = intent.realizing_jobs.len();
    let mut tokens = vec![one_line_token(&intent.id)];
    if let Some(label) = intent.label.as_deref() {
        tokens.push(label_preview(label));
    }
    if let Some(who) = intent.who_label.as_deref().or(intent.assignee.as_deref()) {
        tokens.push(format!("who={}", single_token(who)));
    }
    tokens.push(intent.status.as_str().to_owned());
    tokens.extend(cause_tokens(intent));
    if folded_job_count > 0 {
        tokens.push(format!("jobs={folded_job_count}"));
    }
    let children_at = tokens.len();
    // ONE-1896: the refusal signal rides BESIDE the status, exactly like a
    // cause token — the row still says `running`, because the worker IS
    // running; what the owner learns is that it will not stop when asked.
    if let Some(pathology) = intent_cancel_pathology(intent) {
        tokens.push(pathology.token());
    }
    // FIX 3901: a comm widen ask reads as the widening it asks for. Its
    // answer is still the consult's own.
    if let Some(widening) = &intent.widening {
        tokens.push(widening.token());
    }
    // `fits:` is not here: it renders as the section's discovery rows, which
    // shed with discovery (FIX 9756).
    let others = tokens.iter().map(String::len).sum::<usize>() + tokens.len() - 1;
    if let Some(children) = children_token(&intent.children, others) {
        tokens.insert(children_at, children);
    }
    TaskRow::from_intent(intent, tokens.join(" "))
}

/// The `children=` token of a row whose other tokens take `others` bytes,
/// budgeted so the whole row stays inside [`MAX_BOARD_ROW_BYTES`] (FIX 9757).
/// A row whose children all fit renders them as it always did, in the order
/// they were attached. Past the ceiling the children go in attempt-id order,
/// as many as fit, and an additive `+N` counts the rest; a row too long even
/// for `children=+N` takes the section's count fallback.
fn children_token(children: &[(String, String)], others: usize) -> Option<String> {
    const KEY: &str = "children=";
    if children.is_empty() {
        return None;
    }
    let room = MAX_BOARD_ROW_BYTES.saturating_sub(others + 1);
    let all: Vec<String> = children
        .iter()
        .map(|(_, child)| single_token(child))
        .collect();
    let full = format!("{KEY}{}", all.join(","));
    if full.len() <= room {
        return Some(full);
    }
    let mut ordered: Vec<&(String, String)> = children.iter().collect();
    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    let mut shown: Vec<String> = Vec::new();
    let mut used = KEY.len();
    for (index, (_, child)) in ordered.iter().enumerate() {
        let token = single_token(child);
        let rest = ordered.len() - index - 1;
        let overflow = if rest == 0 {
            0
        } else {
            format!(",+{rest}").len()
        };
        let comma = usize::from(!shown.is_empty());
        if used + comma + token.len() + overflow > room {
            break;
        }
        used += comma + token.len();
        shown.push(token);
    }
    let omitted = ordered.len() - shown.len();
    if omitted > 0 {
        shown.push(format!("+{omitted}"));
    }
    Some(format!("{KEY}{}", shown.join(",")))
}

/// The discovery row naming who `fits:` `row`'s task (FIX 9756), apart from
/// its TASKS row so it sheds with discovery; `None` when no one does.
pub(crate) fn fits_row(row: &TaskRow) -> Option<String> {
    (!row.fits.is_empty()).then(|| {
        format!(
            "{} fits: {}",
            single_token(&row.id),
            row.fits
                .iter()
                .map(|person| single_token(person))
                .collect::<Vec<_>>()
                .join(",")
        )
    })
}

/// A task's label as its row shows it: on one line, and past
/// [`TASK_LABEL_MAX_BYTES`] cut at a character boundary and ended with an
/// ellipsis. Only the row is cut; the stored label stays whole, and the task's
/// id reads it in full.
pub(crate) fn label_preview(label: &str) -> String {
    const ELLIPSIS: char = '\u{2026}';
    let mut token = one_line_token(label);
    if token.len() > TASK_LABEL_MAX_BYTES {
        let mut end = TASK_LABEL_MAX_BYTES - ELLIPSIS.len_utf8();
        while !token.is_char_boundary(end) {
            end -= 1;
        }
        token.truncate(end);
        token.push(ELLIPSIS);
    }
    token
}

/// The cause tokens that ride BESIDE the status token, never inside it, and
/// only where they NARROW the axis.
///
/// A ladder outcome supersedes the raw ONE-1699 disposition here: it is the
/// finer vocabulary over the same terminal, so rendering both would duplicate
/// the cause. A token identical to the status is dropped for the same reason.
fn cause_tokens(intent: &TaskIntentPresence) -> Vec<String> {
    if intent.connector_outcome == Some(ConnectorSendTaskOutcome::Ambiguous) {
        return vec!["ambiguous".to_owned()];
    }
    if let Some(disposition) = intent.ladder_disposition {
        return ladder_board_projection(disposition)
            .tokens
            .into_iter()
            .filter(|token| *token != intent.status.as_str())
            .map(str::to_owned)
            .collect();
    }
    // A durably interrupted row is not terminal, so it has no disposition to
    // narrow with — the pause itself is the cause worth surfacing.
    if intent.interrupted {
        return vec!["interrupted".to_owned()];
    }
    // The failed lane folds rejected/failed/expired/abandoned/cancelled and
    // must stay distinguishable, while `done` has a single cause and
    // `running`/`queued`/`scheduled` are not terminal at all.
    match intent.terminal_disposition {
        Some(disposition)
            if intent.status == TaskBoardStatus::Failed
                && disposition.as_str() != intent.status.as_str() =>
        {
            vec![disposition.as_str().to_owned()]
        }
        _ => Vec::new(),
    }
}

pub(super) fn bare_job_row(job: &JobPresence) -> TaskRow {
    let mut line = format!(
        "{} {} {}",
        one_line_token(&job.id),
        one_line_token(&job.kind),
        job.status.as_str()
    );
    if let Some(pathology) = job.cancel_pathology.as_ref() {
        line.push(' ');
        line.push_str(&pathology.token());
    }
    TaskRow {
        id: job.id.clone(),
        line,
        status: job.status,
        is_intent: false,
        folded_job_count: 0,
        kind: None,
        assignee: None,
        terminal_disposition: None,
        connector_outcome: None,
        result_ref: None,
        ladder_disposition: None,
        counter_task_ref: None,
        cancel_pathology: job.cancel_pathology.clone(),
        widening: None,
        fits: Vec::new(),
    }
}
