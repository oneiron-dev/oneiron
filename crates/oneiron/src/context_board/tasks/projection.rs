//! Typed TASKS state: board status, intent and job presence, the ladder projection, and the overflow footer.

use super::authority_state::TaskRenderState;
use super::render::{bare_job_row, intent_row};
use crate::attempt_queue::run_tree_view::RunTreeNode;
use crate::consult_ladder::LadderTerminalDisposition;
use crate::context_board::consult_result::ConsultResultPresence;
use crate::context_board::task_kind::TaskKind;
use crate::failure_ladder::task_terminal::TaskTerminalDisposition;
use crate::outbound::{ConnectorSendTask, ConnectorSendTaskOutcome};
use crate::{EntityId, Result, Vault};

#[doc(hidden)]
use oneiron_records::context_board::tasks::projection::child_board_status;
#[doc(hidden)]
pub use oneiron_records::context_board::tasks::projection::{
    CancelRejectionPathology, TaskBoardStatus, TasksOverflow,
};
#[doc(hidden)]
pub(super) use oneiron_records::context_board::tasks::projection::{
    TASKS_RENDER_ROW_CAP, run_tree_board_status,
};

#[doc(hidden)]
pub use oneiron_verb_wire::context_board::tasks::projection::ConsultWidening;

/// One collapsed TASKS row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskRow {
    pub id: String,
    pub line: String,
    pub status: TaskBoardStatus,
    pub is_intent: bool,
    pub folded_job_count: usize,
    /// `None` is the landed standard-task default.
    pub kind: Option<TaskKind>,
    pub assignee: Option<String>,
    pub terminal_disposition: Option<TaskTerminalDisposition>,
    /// Synced connector result, separate from the board's five-state status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_outcome: Option<ConnectorSendTaskOutcome>,
    pub result_ref: Option<String>,
    /// ONE-1888 ladder outcome, when the row carries one. It NARROWS the
    /// ONE-1699 axis (approved vs overridden on `done`, rejected-with-counter
    /// on the failed lane) rather than replacing it.
    pub ladder_disposition: Option<LadderTerminalDisposition>,
    /// The counter TASK that replaced this one.
    pub counter_task_ref: Option<String>,
    /// ONE-1896: the realizing job that keeps refusing to stop, when one does.
    /// `None` is the ordinary case and leaves every existing row byte-identical.
    pub cancel_pathology: Option<CancelRejectionPathology>,
    /// FIX 3901: the widening a consult row asks for, when it is a comm
    /// widen ask; `None` on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub widening: Option<ConsultWidening>,
    /// FIX685: the hook-chosen due/deadline stamp, Unix seconds. Display
    /// only: it never changes status, sort, dispatch or expiry. `None`
    /// leaves every existing row byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<u64>,
    /// The persons who `fits:` this open, unassigned task, as the reader's
    /// board names them. They render as the section's discovery rows, apart
    /// from [`Self::line`], so they shed with discovery (FIX 9756).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fits: Vec<String>,
}

impl TaskRow {
    /// Collapses one intent into its row. Delegation columns ride along from
    /// the presence, so a caller never restates them.
    #[must_use]
    pub fn from_intent(intent: &TaskIntentPresence, line: String) -> Self {
        Self {
            id: intent.id.clone(),
            line,
            status: intent.status,
            is_intent: true,
            folded_job_count: intent.realizing_jobs.len(),
            kind: intent.kind,
            assignee: intent.who_label.clone().or_else(|| intent.assignee.clone()),
            terminal_disposition: intent.terminal_disposition,
            connector_outcome: intent.connector_outcome,
            result_ref: intent.result_ref.clone(),
            ladder_disposition: intent.ladder_disposition,
            counter_task_ref: intent.counter_task_ref.clone(),
            cancel_pathology: intent_cancel_pathology(intent),
            widening: intent.widening.clone(),
            due_at: intent.due_at,
            fits: intent.fits.clone(),
        }
    }
}

/// The refusal an owner must answer for, folded up from the intent's realizing
/// jobs: the WORST one, because the decision the signal exists for (wait, or
/// force) is made about the most stuck job, and a bounded row cannot carry N.
pub(super) fn intent_cancel_pathology(
    intent: &TaskIntentPresence,
) -> Option<CancelRejectionPathology> {
    intent
        .realizing_jobs
        .iter()
        .filter_map(|job| job.cancel_pathology.as_ref())
        .max_by_key(|pathology| pathology.rejections)
        .cloned()
}

/// The pinned board lane and cause tokens for one ladder outcome.
///
/// Crate-internal on purpose: consumers read the rendered row and
/// `TaskRow::ladder_disposition`, so the table has exactly one caller and the
/// shared `context_board` re-export chokepoint stays untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LadderBoardProjection {
    pub(crate) status: TaskBoardStatus,
    pub(crate) tokens: Vec<&'static str>,
}

/// Projects one ladder outcome onto the board's FIVE-value axis plus cause
/// tokens (ONE-1888).
///
/// The axis is unchanged and deliberately distinct from the A2A base states.
/// `Rejected` and `Failed` both land in the failed lane but keep distinct
/// cause tokens; `Countered` reads as the rejection it is; `Escalated` is not
/// terminal at all, so it stays on the queued lane and says so.
#[must_use]
pub(super) fn ladder_board_projection(
    disposition: LadderTerminalDisposition,
) -> LadderBoardProjection {
    let (status, tokens) = match disposition {
        LadderTerminalDisposition::Approved => (TaskBoardStatus::Done, vec!["approved"]),
        LadderTerminalDisposition::Overridden => (TaskBoardStatus::Done, vec!["overridden"]),
        LadderTerminalDisposition::Rejected => (TaskBoardStatus::Failed, vec!["rejected"]),
        LadderTerminalDisposition::Failed => (TaskBoardStatus::Failed, vec!["failed"]),
        LadderTerminalDisposition::Abandoned => (TaskBoardStatus::Failed, vec!["abandoned"]),
        // The OLD side of a counter: an immutable rejected row that names its
        // successor. The NEW counter TASK renders independently.
        LadderTerminalDisposition::Countered => {
            (TaskBoardStatus::Failed, vec!["rejected", "countered"])
        }
        // Non-terminal: the case is with its follow-on assignee.
        LadderTerminalDisposition::Escalated => {
            (TaskBoardStatus::Queued, vec!["interrupted", "escalated"])
        }
    };
    LadderBoardProjection { status, tokens }
}

/// Collapsed TASKS section.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TasksSection {
    pub rows: Vec<TaskRow>,
    /// Structural footer; never represented as a [`TaskRow`].
    pub overflow: Option<TasksOverflow>,
}

impl TasksSection {
    /// `TASKS_RENDER_ROW_CAP`, reachable outside this module.
    ///
    /// `context_board`'s re-export list is a shared chokepoint this ticket does
    /// not claim, and `mod tasks` is private — an associated const travels with
    /// the already re-exported type.
    pub const RENDER_ROW_CAP: usize = TASKS_RENDER_ROW_CAP;

    /// Renders presence into collapsed rows under the render cap, carrying the
    /// bounded scan's honesty bit into the footer.
    ///
    /// `source_exhausted` is `false` when the caller's TASK scan stopped at its
    /// own cap: the omitted-row count is then a lower bound, never a census.
    #[must_use]
    pub fn render_bounded(
        intents: &[TaskIntentPresence],
        bare_jobs: &[JobPresence],
        source_exhausted: bool,
    ) -> Self {
        Self::render_with_cap(intents, bare_jobs, source_exhausted, Self::RENDER_ROW_CAP)
    }

    /// Testable body: a board renders under its rows' owner count
    /// ([`TasksSectionRows::rows_shown`], [`Self::RENDER_ROW_CAP`] by default);
    /// tests inject a small cap so overflow behaviour is exercised without a
    /// 100-row fixture.
    pub(crate) fn render_with_cap(
        intents: &[TaskIntentPresence],
        bare_jobs: &[JobPresence],
        source_exhausted: bool,
        row_cap: usize,
    ) -> Self {
        let mut rows = Vec::with_capacity(intents.len() + bare_jobs.len());
        rows.extend(
            intents
                .iter()
                .filter(|intent| !intent.is_acked_failure())
                .map(intent_row),
        );
        rows.extend(bare_jobs.iter().map(bare_job_row));
        // The cap applies AFTER filtering and ordering, so the count names rows
        // that really would have rendered.
        let known_omitted_rows = rows.len().saturating_sub(row_cap);
        rows.truncate(row_cap);
        let overflow = (known_omitted_rows > 0 || !source_exhausted).then_some(TasksOverflow {
            known_omitted_rows,
            source_exhausted,
        });
        Self { rows, overflow }
    }
}

/// The rows a TASKS section renders from, before its render cap. A host whose
/// reader is narrower than the facade's actor keeps only the rows that reader
/// may see and renders those, so the cap and the overflow footer count
/// authorized rows alone and a withheld row moves no count (ARCH-0067 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TasksSectionRows {
    pub intents: Vec<TaskIntentPresence>,
    pub bare_jobs: Vec<JobPresence>,
    /// `false` when the TASK scan stopped at its own cap; see
    /// [`TasksSection::render_bounded`].
    pub source_exhausted: bool,
    /// The rows [`Self::render`] shows before its footer counts the rest: the
    /// owner's `context_board.tasks.rows_shown`, read with the rows, else
    /// [`TasksSection::RENDER_ROW_CAP`].
    pub rows_shown: usize,
}

impl TasksSectionRows {
    #[must_use]
    pub fn render(&self) -> TasksSection {
        TasksSection::render_with_cap(
            &self.intents,
            &self.bare_jobs,
            self.source_exhausted,
            self.rows_shown,
        )
    }

    /// PEOPLE (ARCH-0067): names each task's `who` as this reader's board
    /// names people, puts each live child on the task it realizes (a child
    /// whose task is not on the board rides as its own row), and lists who
    /// `fits:` each open, unassigned task: the persons who finished tasks of
    /// the same type, best measured fit first, then most often first.
    ///
    /// The fit (FIX 1161) is each person's (task-type, person) learning
    /// cell, fed by the runs the person drove
    /// ([`crate::skill_reliability::person_skill_fit`]), read at the open
    /// task's own stamp on the tree its project placed it in: the higher
    /// estimate first, then the more own runs. A person with no runs of
    /// this type reads the cell's borrowed prior (the person's parent type,
    /// else the shared prior), so persons on one prior keep the completion
    /// order. A row whose stamp that tree no longer holds, or whose fit read
    /// fails, ranks by completions alone, as before.
    ///
    /// Every child rides here. A host whose reader or destination is
    /// narrower than the actor uses [`Self::attach_people_admitted`].
    pub fn attach_people(
        &mut self,
        vault: &Vault,
        people: &crate::context_board::PeopleView<'_>,
        children: &[crate::context_board::ChildState],
    ) {
        let Ok(()) = self.attach_people_admitted(vault, people, children, |_| {
            Ok::<_, std::convert::Infallible>(true)
        });
    }

    /// [`Self::attach_people`], with each child whose task is not among
    /// these rows judged by `admit` first (FIX 9755): its backing TASK under
    /// the caller's read and destination ([`Self::task_admitted`]), or, with
    /// no backing TASK, the child itself. A child `admit` refuses never
    /// renders, so a TASK the caller's read or destination withheld does not
    /// come back through its child as a bare row. A child on a task among
    /// these rows rides that task, which already passed both.
    pub fn attach_people_admitted<E>(
        &mut self,
        vault: &Vault,
        people: &crate::context_board::PeopleView<'_>,
        children: &[crate::context_board::ChildState],
        mut admit: impl FnMut(&crate::context_board::ChildState) -> std::result::Result<bool, E>,
    ) -> std::result::Result<(), E> {
        for intent in &mut self.intents {
            intent.who_label = intent.who.map(|who| people.label(who));
        }
        for child in children {
            let task = child.task_ref.as_deref();
            match task.and_then(|task| self.intents.iter_mut().find(|intent| intent.id == task)) {
                Some(intent) => intent
                    .children
                    .push((child.attempt.clone(), child.token(people))),
                None => {
                    if admit(child)? {
                        self.bare_jobs.push(JobPresence {
                            id: child.attempt.clone(),
                            kind: format!("child {}", child.token(people)),
                            status: child_board_status(child.status),
                            cancel_pathology: None,
                        });
                    }
                }
            }
        }
        let fits = self.ranked_fits(vault, people);
        for (intent, fits) in self.intents.iter_mut().zip(fits) {
            intent.fits = fits;
        }
        Ok(())
    }

    /// Who `fits:` each open, unassigned row, as [`Self::attach_people`]
    /// ranks them; an empty list for every other row.
    fn ranked_fits(
        &self,
        vault: &Vault,
        people: &crate::context_board::PeopleView<'_>,
    ) -> Vec<Vec<String>> {
        let mut done: std::collections::BTreeMap<
            &str,
            std::collections::BTreeMap<crate::EntityId, usize>,
        > = std::collections::BTreeMap::new();
        for intent in &self.intents {
            if intent.status == TaskBoardStatus::Done
                && let (Some(type_ref), Some(who)) = (intent.type_ref.as_ref(), intent.who)
                && people.people.get(who).is_some()
            {
                *done
                    .entry(type_ref.node_id.as_str())
                    .or_default()
                    .entry(who)
                    .or_default() += 1;
            }
        }
        let fits_shown = crate::context_board::setting_keys::read_count(
            vault,
            &crate::context_board::setting_keys::TASKS_FITS_SHOWN,
        ) as usize;
        let mut fit_reads = PersonFitReads::new(vault);
        self.intents
            .iter()
            .map(|intent| {
                let open = matches!(
                    intent.status,
                    TaskBoardStatus::Queued | TaskBoardStatus::Scheduled
                );
                let Some((type_ref, past)) = intent
                    .type_ref
                    .as_ref()
                    .filter(|_| open && intent.who.is_none())
                    .and_then(|type_ref| Some((type_ref, done.get(type_ref.node_id.as_str())?)))
                else {
                    return Vec::new();
                };
                let measured = fit_reads.row(type_ref, intent.project_ref, past);
                let mut ranked: Vec<(EntityId, usize, Option<PersonFit>)> = past
                    .iter()
                    .map(|(who, finished)| {
                        let fit = measured.as_ref().and_then(|row| row.get(who).copied());
                        (*who, *finished, fit)
                    })
                    .collect();
                ranked.sort_by(|left, right| {
                    PersonFit::best_first(left.2.as_ref(), right.2.as_ref())
                        .then(right.1.cmp(&left.1))
                        .then(left.0.cmp(&right.0))
                });
                ranked
                    .into_iter()
                    .take(fits_shown)
                    .map(|(who, _, _)| people.label(who))
                    .collect()
            })
            .collect()
    }

    /// Whether `task` passes the reader and destination the TASKS rows pass
    /// (FIX 9755): toward `memory`'s destination off this device, a TASK a
    /// world keeps off that machine is withheld, as the board's TASK scan
    /// passes it over; then `read` judges it as the host's row cut does.
    /// A TASK that no longer exists withholds nothing, so its child keeps the
    /// bare row it had before.
    pub fn task_admitted(
        memory: &crate::memory::Memory<'_>,
        read: &crate::claim::ScopedRead<'_>,
        task: EntityId,
    ) -> Result<bool> {
        if !memory.vault().entity_exists(&task)? {
            return Ok(true);
        }
        let destination = memory.destination();
        if destination.is_off_device()
            && memory
                .vault()
                .off_device_readable_for(vec![task], destination)?
                .is_empty()
        {
            return Ok(false);
        }
        read.is_entity_readable(&task)
    }
}

/// One person's measured fit for an open task's type (FIX 1161): the
/// estimate of the person's (task-type, person) cell, and the runs of the
/// person's own it rests on (none when it reads a borrowed or shared prior).
#[derive(Debug, Clone, Copy)]
struct PersonFit {
    mean: f64,
    own_runs: f64,
}

impl PersonFit {
    fn of(read: &crate::learning::LearningRead) -> Self {
        Self {
            mean: read.estimate.mean(),
            own_runs: if read.own { read.estimate.runs } else { 0.0 },
        }
    }

    /// The `fits:` order: the higher estimate first, then the more own runs;
    /// a person with a fit before one without.
    fn best_first(left: Option<&Self>, right: Option<&Self>) -> std::cmp::Ordering {
        match (left, right) {
            (Some(left), Some(right)) => right
                .mean
                .total_cmp(&left.mean)
                .then(right.own_runs.total_cmp(&left.own_runs)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    }
}

/// The fit reads one `fits:` pass makes, each once: the type tree each
/// (project, tree version) placed its stamps in, and each (project, stamp)
/// row's person fits.
struct PersonFitReads<'v> {
    vault: &'v Vault,
    trees: std::collections::BTreeMap<(Option<EntityId>, u64), Option<crate::task_type::TypeTree>>,
    rows: std::collections::BTreeMap<
        (Option<EntityId>, crate::task_type::TaskTypeRef),
        Option<std::collections::BTreeMap<EntityId, PersonFit>>,
    >,
}

impl<'v> PersonFitReads<'v> {
    fn new(vault: &'v Vault) -> Self {
        Self {
            vault,
            trees: std::collections::BTreeMap::new(),
            rows: std::collections::BTreeMap::new(),
        }
    }

    /// Each of `past`'s persons' fit for a task stamped `type_ref` in
    /// `project`; `None` when the tree that placed the stamp no longer holds
    /// it, or a read fails, so the row ranks by completions alone.
    fn row(
        &mut self,
        type_ref: &crate::task_type::TaskTypeRef,
        project: Option<EntityId>,
        past: &std::collections::BTreeMap<EntityId, usize>,
    ) -> Option<std::collections::BTreeMap<EntityId, PersonFit>> {
        let key = (project, type_ref.clone());
        if let Some(row) = self.rows.get(&key) {
            return row.clone();
        }
        let row = self.read_row(type_ref, project, past);
        self.rows.insert(key, row.clone());
        row
    }

    fn read_row(
        &mut self,
        type_ref: &crate::task_type::TaskTypeRef,
        project: Option<EntityId>,
        past: &std::collections::BTreeMap<EntityId, usize>,
    ) -> Option<std::collections::BTreeMap<EntityId, PersonFit>> {
        let vault = self.vault;
        let tree = self
            .trees
            .entry((project, type_ref.tree_version))
            .or_insert_with(|| {
                crate::task_type::type_tree_at(vault, project, type_ref.tree_version)
                    .inspect_err(|error| {
                        tracing::warn!(%error, "a TASKS fits: type tree did not load");
                    })
                    .ok()
                    .flatten()
            })
            .as_ref()?;
        let query = crate::skill_reliability::SkillReliabilityQuery::on_tree(
            tree,
            project,
            crate::learning::TypeRef::from(type_ref),
            None,
        )
        .inspect_err(|error| tracing::warn!(%error, "a TASKS fits: query did not build"))
        .ok()
        .flatten()?;
        past.keys()
            .map(|person| {
                crate::skill_reliability::person_skill_fit(vault, person, &query)
                    .inspect_err(|error| {
                        tracing::warn!(%error, "a TASKS fits: person fit did not read");
                    })
                    .ok()
                    .map(|read| (*person, PersonFit::of(&read)))
            })
            .collect()
    }
}

/// One non-agent-dispatch JobQueue job projected for the board — a bare
/// system job row, or a realizing job folded under its owning intent row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobPresence {
    pub id: String,
    pub kind: String,
    pub status: TaskBoardStatus,
    /// ONE-1896: set only when this job has crossed the repeated-refusal
    /// threshold. Additive and `None` for every ordinary job.
    pub cancel_pathology: Option<CancelRejectionPathology>,
}

impl JobPresence {
    /// Projects one SURF-005 observed run-tree node onto the board axis.
    /// Row identity and normalized worker kind come from the observe surface.
    /// Returns `None` for agent-dispatch attempts, which belong to AGENTS.
    /// Returns `None` for cancelled rows: the axis has no token for withdrawn
    /// work, so it leaves the board.
    #[must_use]
    pub fn from_run_tree_node(node: &RunTreeNode) -> Option<JobPresence> {
        if node.worker_kind == crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE {
            return None;
        }

        Some(JobPresence {
            id: node.attempt_id.clone(),
            kind: node.worker_kind.clone(),
            status: run_tree_board_status(node.status)?,
            cancel_pathology: None,
        })
    }

    /// Attaches the owner-visible refusal signal read off the durable ATTEMPT
    /// row. Separate from [`Self::from_run_tree_node`] because the run tree
    /// carries lifecycle, not the cancel protocol's evidence.
    #[must_use]
    pub fn with_cancel_pathology(mut self, pathology: Option<CancelRejectionPathology>) -> Self {
        self.cancel_pathology = pathology;
        self
    }
}

/// Folds a task's realizing-job statuses into the owning task's board status
/// (ONE-1695 · 08b §3). Precedence is the L0-ruled working-document order:
/// Running > Failed > Scheduled > Queued > Done. Returns `None` for no jobs.
#[must_use]
pub fn fold_up_status(jobs: &[JobPresence]) -> Option<TaskBoardStatus> {
    jobs.iter()
        .map(|job| job.status)
        .max_by_key(|status| task_status_precedence_rank(*status))
}

pub(super) const fn task_status_precedence_rank(status: TaskBoardStatus) -> u8 {
    match status {
        TaskBoardStatus::Running => 5,
        TaskBoardStatus::Failed => 4,
        TaskBoardStatus::Scheduled => 3,
        TaskBoardStatus::Queued => 2,
        TaskBoardStatus::Done => 1,
    }
}

/// One intent TASK entity projected for the board (08b §3 two-layer /
/// one-surface: the intent row carries its realizing JobQueue jobs folded
/// under it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskIntentPresence {
    pub id: String,
    pub status: TaskBoardStatus,
    pub label: Option<String>,
    pub acked: bool,
    pub realizing_jobs: Vec<JobPresence>,
    /// Additive delegation projection (ONE-1699). `None` throughout is the
    /// landed standard-task default.
    pub kind: Option<TaskKind>,
    /// Resolved DISPLAY handle for the assignee; storage stays actor-addressed.
    pub assignee: Option<String>,
    pub terminal_disposition: Option<TaskTerminalDisposition>,
    pub connector_outcome: Option<ConnectorSendTaskOutcome>,
    pub result_ref: Option<String>,
    pub consult_result: Option<ConsultResultPresence>,
    /// ONE-1888 ladder projection. `None` throughout is the ONE-1699 default.
    pub ladder_disposition: Option<LadderTerminalDisposition>,
    /// The persisted TASK state is `Interrupted`: progress is durably paused.
    pub interrupted: bool,
    pub counter_task_ref: Option<String>,
    /// PEOPLE: the person or actor the task is assigned to, typed.
    pub who: Option<crate::EntityId>,
    /// The task's type stamp: `fits:` matches past work on its node and
    /// reads each person's measured fit at the stamp itself.
    pub type_ref: Option<crate::task_type::TaskTypeRef>,
    /// The project the task's brief names, whose type tree placed the stamp;
    /// `None` is the vault's.
    pub project_ref: Option<crate::EntityId>,
    /// `who` as this reader's board names the person; set by
    /// [`TasksSectionRows::attach_people`].
    pub who_label: Option<String>,
    /// Persons who did this type of task before, best measured fit first, as
    /// this reader's board names them.
    pub fits: Vec<String>,
    /// Live children realizing this task: each one's attempt id and its
    /// `<agent>:<status>[:lead]` token, in the order they were attached.
    pub children: Vec<(String, String)>,
    /// FIX 3901: the widening this consult asks for, when it is a comm widen
    /// ask.
    pub widening: Option<ConsultWidening>,
    /// FIX685: the hook-chosen due/deadline stamp, Unix seconds. Display
    /// only: it never changes status, sort, dispatch or expiry.
    pub due_at: Option<u64>,
}

impl TaskIntentPresence {
    /// The pre-delegation construction surface, unchanged. Additive projection
    /// fields start absent and are set by the projector that knows them.
    #[must_use]
    pub fn new(
        id: String,
        status: TaskBoardStatus,
        label: Option<String>,
        acked: bool,
        realizing_jobs: Vec<JobPresence>,
    ) -> Self {
        Self {
            id,
            status,
            label,
            acked,
            realizing_jobs,
            kind: None,
            assignee: None,
            terminal_disposition: None,
            connector_outcome: None,
            result_ref: None,
            consult_result: None,
            ladder_disposition: None,
            interrupted: false,
            counter_task_ref: None,
            who: None,
            type_ref: None,
            project_ref: None,
            who_label: None,
            fits: Vec::new(),
            children: Vec::new(),
            widening: None,
            due_at: None,
        }
    }

    /// Projects the connector-send TASK read (the one realized TASK subkind
    /// today). Board status arrives from the observe projection — the
    /// job→task fold-up derivation is ONE-1695 — and `acked` starts false
    /// because ack state is only written by the ONE-1696 verb surface.
    #[must_use]
    pub fn from_connector_send_task(
        task: &ConnectorSendTask,
        status: TaskBoardStatus,
        realizing_jobs: Vec<JobPresence>,
    ) -> TaskIntentPresence {
        Self::from_connector_send_task_with_ack(task, status, realizing_jobs, false)
    }

    /// Projects a connector-send TASK with the persisted render-tier ack bit.
    #[must_use]
    pub(crate) fn from_connector_send_task_with_ack(
        task: &ConnectorSendTask,
        status: TaskBoardStatus,
        realizing_jobs: Vec<JobPresence>,
        acked: bool,
    ) -> TaskIntentPresence {
        let status = match task.outcome {
            Some(ConnectorSendTaskOutcome::Delivered) => TaskBoardStatus::Done,
            Some(
                ConnectorSendTaskOutcome::Failed
                | ConnectorSendTaskOutcome::Ambiguous
                | ConnectorSendTaskOutcome::OwnerDeclinedResend,
            ) => TaskBoardStatus::Failed,
            None => status,
        };
        let mut presence = Self::new(
            task.task_ref.to_hex(),
            status,
            Some(task.intent.verb.clone()),
            acked,
            realizing_jobs,
        );
        presence.connector_outcome = task.outcome;
        presence
    }

    /// Failed rows stay surfaced until acked (08b §3); an acked failure has
    /// left the board surface.
    #[must_use]
    pub fn is_acked_failure(&self) -> bool {
        self.status == TaskBoardStatus::Failed && self.acked
    }

    /// Reads both render-tier state bits for one TASK through a caller-owned
    /// read transaction, so assembling one board page costs ONE render-state
    /// transaction instead of two per TASK.
    ///
    /// Both bits come from the TASK's own replicated authority facts, so a
    /// cancellation or acknowledgement made on one device renders the same way
    /// on every other one — no node-local `vault_meta` bit decides what a peer
    /// sees. Cancellation is read INDEPENDENTLY of the owner proof: a cancel
    /// that really happened hides the row whether or not the task also carries
    /// an Owner fact.
    ///
    /// The FOLD stays STRICT and the board CALL SITES degrade. A companion
    /// fact set that will not read — an owner fork, a malformed fact body, a
    /// fact re-pointed at a subject it does not name — returns `Err` here, and
    /// `Vault::task_authority_state` keeps failing closed on it so the cancel /
    /// force-cancel doors refuse that task. The board never asks who the owner
    /// is, so its readers map that same `Err` to a per-row outcome instead:
    /// `task_verb::presence_scan` skips the poisoned row inside the page loop
    /// (P2 F8 — one bad row must never abort `describe`, and these rows
    /// replicate), and the by-id door answers `Ok(None)`. The degrade is a
    /// SKIP, never a render with false bits, because a row whose facts cannot
    /// be read may really be cancelled.
    ///
    /// Hung off the presence type rather than standing as a free function
    /// because `context_board`'s re-export list is a shared chokepoint this
    /// ticket does not claim; an associated item travels with the type that is
    /// already re-exported.
    pub(crate) fn render_state_in(
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<TaskRenderState> {
        let facts = vault.task_authority_facts_in(rtxn, task_ref)?;
        // An acknowledgement answers the settlement that stood when it was
        // made (FIX 3694): a TASK a continuation put back on its lane, live
        // again or settled since, is not acknowledged by it. Both clocks are
        // recorded seconds; an ack in its failure's own second still counts.
        let acked = match facts.acked_at {
            Some(acked_at) => crate::task_verb::task_settled_at_in(vault, rtxn, task_ref)?
                .is_some_and(|settled| settled <= acked_at),
            None => false,
        };
        Ok(TaskRenderState {
            acked,
            cancelled: facts.cancelled,
        })
    }
}
