//! A TASK's bound library program, pinned per try (CUA E4; DESIGN-2 §2,
//! owner C1 = A).
//!
//! A TASK binds one filed program by its handle and string arguments
//! ([`super::WorkflowBinding`]) and never holds its steps. A try's first
//! lease resolves the handle, in the claim's own transaction, and pins what
//! it found in one row keyed by the try: the live record and the arguments,
//! or why there is none, with the brief stamp and the done-means the try
//! was leased under. A later lease never reads the TASK again, so a revised
//! brief binds only later tries. Pinning never fails a claim: a read it
//! cannot make pins nothing, and a library it cannot read is pinned as the
//! cause.
//!
//! The try's host reads the pin under its lease
//! ([`task_workflow_binding`]), runs the program strict before any planner
//! call, and records once what came of it
//! ([`record_task_workflow_outcome`]): a receipt NOTE holding the whole
//! report, and the outcome on the pin. A recorded outcome is never written
//! again. Before the program can act, its start goes on the pin under the
//! lease ([`mark_task_workflow_started`], FIX 8104), so an entry after a
//! death mid-run hands off as interrupted instead of running it again. A
//! hard erase of the TASK removes its tries' pins.

use std::collections::{BTreeMap, BTreeSet};

use oneiron_browser::{
    BatchStopCause, ExpectInput, ExpectOutput, LibraryRunOutput, SecretArg, SubgoalStatus,
};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::browser_library::{
    WorkflowResolution, resolve_workflow_in_txn, secret_param_names_in_txn,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::ActorContentTxn;
use crate::note::{NoteActor, NoteBody, NoteKind, encode_note_body};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;

use super::brief::{BriefStamp, DoneMeans};
use super::highway::attempt_hex;
use super::highway_runner::{runner_actor_in, runner_refusal, runner_task_in};
use super::highway_types::{
    HostBinding, TaskWorkflowHandoff, TaskWorkflowOutcome, TaskWorkflowStatus,
};
use super::verb_kind::TaskAssignee;
use super::wire_decode::task_verb_body_in;

/// Each bound try's pin. Key: id16 (attempt).
const ATTEMPTS: SideTable<[u8; 16], AttemptRow, Named> =
    SideTable::new(&side_table::TASK_BROWSER_WORKFLOW_ATTEMPT);

/// Domain of a try's receipt NOTE id.
const RECEIPT_NOTE_DOMAIN: &[u8] = b"oneiron.tasks.browser_workflow.receipt.v1";
/// A try's receipt is a research NOTE, as a workflow run's report is.
const RECEIPT_NOTE_KIND: &str = "research";
/// What a masked secret value reads as in a receipt, as the browser's
/// own displays mask one (`oneiron_browser` secret_fields::SECRET_MARK).
const SECRET_MARK: &str = "[secret]";

/// One bound try's pin: its TASK, the brief it was leased under, the record
/// the TASK's handle named, the program that resolved to, the done-means it
/// runs against, what came of it, and when its lease pinned it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptRow {
    task_ref: EntityId,
    brief: BriefStamp,
    requested: EntityId,
    pin: TaskWorkflowPin,
    goal: DoneMeans,
    outcome: TaskWorkflowOutcome,
    pinned_at: u64,
}

/// The program a try's first lease pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowPin {
    /// The live program the handle led to, and the TASK's arguments for it.
    Active {
        record: EntityId,
        args: BTreeMap<String, String>,
        /// Secret slots' arguments in typed form, as bound (FIX 8348).
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        secret_args: BTreeMap<String, SecretArg>,
        /// The program's secret parameter names at pin time: their values
        /// are masked in the try's receipt (FIX 8348).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        secret_names: Vec<String>,
    },
    /// No program to run, and why.
    Unavailable { cause: TaskWorkflowUnavailable },
}

/// Why a try's first lease pinned no program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowUnavailable {
    /// The handle's lineage ends at `id`, retired for `reason` with no
    /// successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under the handle.
    Missing,
    /// The library did not read; `detail` is its error.
    Unreadable { detail: String },
}

/// One bound try's pin, as its host reads it under its lease. Read-only.
#[derive(Debug, Clone)]
pub struct TaskWorkflowAttempt {
    attempt: AttemptId,
    row: AttemptRow,
}

impl TaskWorkflowAttempt {
    /// The try.
    #[must_use]
    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// The TASK the try realizes.
    #[must_use]
    pub fn task_ref(&self) -> EntityId {
        self.row.task_ref
    }

    /// The brief version the try was leased under.
    #[must_use]
    pub fn brief(&self) -> BriefStamp {
        self.row.brief
    }

    /// The record the TASK's handle named.
    #[must_use]
    pub fn requested(&self) -> EntityId {
        self.row.requested
    }

    /// What the try's first lease pinned.
    #[must_use]
    pub fn pin(&self) -> &TaskWorkflowPin {
        &self.row.pin
    }

    /// The done-means the try was leased under.
    #[must_use]
    pub fn goal(&self) -> &DoneMeans {
        &self.row.goal
    }

    /// What came of the try's strict run; [`TaskWorkflowOutcome::Pending`]
    /// until its host records it.
    #[must_use]
    pub fn outcome(&self) -> &TaskWorkflowOutcome {
        &self.row.outcome
    }

    /// The pinned program and the TASK's arguments, while it pinned one.
    #[must_use]
    pub fn active(&self) -> Option<(EntityId, &BTreeMap<String, String>)> {
        match &self.row.pin {
            TaskWorkflowPin::Active { record, args, .. } => Some((*record, args)),
            TaskWorkflowPin::Unavailable { .. } => None,
        }
    }

    /// The pinned program's typed secret arguments, while it pinned one.
    #[must_use]
    pub fn active_secret_args(&self) -> Option<&BTreeMap<String, SecretArg>> {
        match &self.row.pin {
            TaskWorkflowPin::Active { secret_args, .. } => Some(secret_args),
            TaskWorkflowPin::Unavailable { .. } => None,
        }
    }

    /// Whether the pinned done-means is the TASK's browser checks alone
    /// (Engine C1): at least one check, and no criterion.
    #[must_use]
    pub fn typed_goal(&self) -> bool {
        let goal = &self.row.goal;
        !goal.browser_checks.is_empty()
            && goal.criteria.yes_if_all.is_empty()
            && goal.criteria.no_if_any.is_empty()
    }
}

/// Pins a bound TASK's program for `record`, its freshly leased try, in the
/// claim's own transaction: on the try's first lease only, for a TASK on a
/// runner lane an agent definition is assigned to and whose brief binds a
/// program, and only while no pin is there. It never fails the claim: a
/// read it cannot make is logged and pins nothing, and a library it cannot
/// read is pinned as the cause. Only the pin's own write returns its error.
pub(super) fn pin_first_lease_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    // A later lease never reads the TASK again.
    if record.attempt_count != 1 {
        return Ok(());
    }
    let row = match pin_row_in(vault, txn, record) {
        Ok(Some(row)) => row,
        Ok(None) => return Ok(()),
        Err(error) => {
            tracing::warn!(%error, attempt = ?record.id, "a bound try's TASK did not read at its first lease; it pins no program");
            return Ok(());
        }
    };
    ATTEMPTS.put(vault, txn, record.id.as_bytes(), &row)
}

/// The pin `record`'s first lease owes, read in `txn`: `None` when it owes
/// none, or one is there already.
fn pin_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<AttemptRow>> {
    if ATTEMPTS.contains(&vault.store, txn, record.id.as_bytes())? {
        return Ok(None);
    }
    let Some(task_ref) = runner_task_in(vault, txn, record).map_err(runner_refusal)? else {
        return Ok(None);
    };
    let Some(body) = task_verb_body_in(vault, txn, task_ref)? else {
        return Ok(None);
    };
    if !matches!(body.assignee, Some(TaskAssignee::AgentDef { .. })) {
        return Ok(None);
    }
    let Some(stored) = body.brief else {
        return Ok(None);
    };
    let Some(binding) = &stored.brief.context.workflow else {
        return Ok(None);
    };
    let Some(requested) = binding.record() else {
        // Bind refuses such a handle, so none reaches a TASK it binds.
        tracing::warn!(attempt = ?record.id, "a bound TASK's workflow handle does not parse; its try pins no program");
        return Ok(None);
    };
    let pin = match resolve_workflow_in_txn(vault, txn, &requested) {
        Ok(WorkflowResolution::Active { id }) => TaskWorkflowPin::Active {
            record: id,
            args: binding.args.clone(),
            secret_args: binding.secret_args.clone(),
            secret_names: secret_param_names_in_txn(vault, txn, id)?,
        },
        Ok(WorkflowResolution::Retired { id, reason }) => TaskWorkflowPin::Unavailable {
            cause: TaskWorkflowUnavailable::Retired { id, reason },
        },
        Ok(WorkflowResolution::Missing) => TaskWorkflowPin::Unavailable {
            cause: TaskWorkflowUnavailable::Missing,
        },
        Err(error) => TaskWorkflowPin::Unavailable {
            cause: TaskWorkflowUnavailable::Unreadable {
                detail: error.to_string(),
            },
        },
    };
    Ok(Some(AttemptRow {
        task_ref,
        brief: stored.stamp(),
        requested,
        pin,
        goal: stored.brief.success.clone(),
        outcome: TaskWorkflowOutcome::Pending,
        pinned_at: record.claimed_at.unwrap_or(record.updated_at),
    }))
}

/// The pin of the try `binding` leases, read in the caller's `txn`: the
/// try's own row only, never the live TASK or the library. `None` when the
/// try is unbound.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] once the lease no longer holds,
/// [`Error::InvariantViolation`] for a pin that names another TASK than its
/// try's, storage errors, and a pin that does not read.
pub fn task_workflow_binding_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    binding: &HostBinding,
) -> Result<Option<TaskWorkflowAttempt>> {
    let record = binding
        .leased_record_in_txn(vault, txn)?
        .ok_or(Error::InvalidClaimBody("the run's lease no longer holds"))?;
    let Some(row) = pinned_row_in(vault, txn, &record)? else {
        return Ok(None);
    };
    Ok(Some(TaskWorkflowAttempt {
        attempt: record.id,
        row,
    }))
}

/// [`task_workflow_binding_in_txn`] in a snapshot of its own, for a host
/// that holds no read: never call it while this thread holds one.
///
/// # Errors
///
/// As [`task_workflow_binding_in_txn`].
pub fn task_workflow_binding(
    vault: &Vault,
    binding: &HostBinding,
) -> Result<Option<TaskWorkflowAttempt>> {
    let txn = vault.store.env.read_txn()?;
    task_workflow_binding_in_txn(vault, &txn, binding)
}

/// The TASK the try `binding` leases realizes, with its brief's done-means
/// (CUA E8b): what the run's browser span is checked against when the run
/// ends, for the Coach's solved-run evidence. `None` when the try realizes
/// no TASK, or its TASK carries no brief.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] once the lease no longer holds, and storage
/// errors.
pub fn task_run_done_means(
    vault: &Vault,
    binding: &HostBinding,
) -> Result<Option<(EntityId, DoneMeans)>> {
    let txn = vault.store.env.read_txn()?;
    let record = binding
        .leased_record_in_txn(vault, &txn)?
        .ok_or(Error::InvalidClaimBody("the run's lease no longer holds"))?;
    let Some(task_ref) = runner_task_in(vault, &txn, &record).map_err(runner_refusal)? else {
        return Ok(None);
    };
    let Some(body) = task_verb_body_in(vault, &txn, task_ref)? else {
        return Ok(None);
    };
    Ok(body.brief.map(|stored| (task_ref, stored.brief.success)))
}

/// `record`'s pin, checked against the TASK the try realizes.
fn pinned_row_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> Result<Option<AttemptRow>> {
    let Some(row) = ATTEMPTS.get(&vault.store, txn, record.id.as_bytes())? else {
        return Ok(None);
    };
    if record.task_ref.as_deref() != Some(row.task_ref.to_hex().as_str()) {
        return Err(Error::InvariantViolation(
            "a bound try's pin names another TASK",
        ));
    }
    Ok(Some(row))
}

/// What a bound try's host found when it ran the pinned program, for
/// [`record_task_workflow_outcome`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskWorkflowReport {
    /// The strict program ran to its end, and `checks` are the TASK's
    /// browser checks as the host read them on the page it left, in the
    /// pinned done-means' order.
    Ran {
        output: LibraryRunOutput,
        checks: Vec<TaskWorkflowCheck>,
    },
    /// The strict program handed off before its end, for `stop_cause`;
    /// `output` is its run, `None` when the call never ran.
    Program {
        stop_cause: BatchStopCause,
        output: Option<LibraryRunOutput>,
    },
    /// The pin names no program, so nothing ran.
    Unavailable,
    /// The program was started at an earlier entry and its end was never
    /// recorded (FIX 8104): whether it acted on the page is unknown.
    Interrupted,
}

/// One TASK browser check, and what the page showed for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskWorkflowCheck {
    pub expect: ExpectInput,
    pub observed: ExpectOutput,
}

/// Records, once, what came of the try `binding` leases, in one writer under
/// its lease: a receipt NOTE holding the whole report, authored by the try's
/// agent, then the outcome on its pin, which is returned. The outcome is
/// read from the report here: a program that met its postcondition with
/// every pinned check met is Done; a missed check hands off as
/// [`TaskWorkflowHandoff::GoalUnmet`]; a program that stopped short hands
/// off as [`TaskWorkflowHandoff::Program`]; a pin with no program hands off
/// for its cause; a started program whose end was never recorded hands off
/// as [`TaskWorkflowHandoff::Interrupted`]. An outcome already recorded is
/// returned as it stands, and nothing is written.
///
/// # Errors
///
/// A lapsed lease, a try with no pin, a report its pin does not admit (a run
/// on a pin with no program or of another program, checks that are not the
/// pinned ones, no run on a pin with a program, an interruption of a program
/// never started), a receipt the try's agent may not write, and storage
/// errors.
pub fn record_task_workflow_outcome(
    vault: &Vault,
    binding: &HostBinding,
    report: TaskWorkflowReport,
    now: u64,
) -> Result<TaskWorkflowOutcome> {
    vault.with_write_txn_grouped(|wtxn| {
        let record = binding
            .leased_record_in_txn(vault, wtxn)?
            .ok_or(Error::InvalidClaimBody("the run's lease no longer holds"))?;
        let Some(mut row) = pinned_row_in(vault, wtxn, &record)? else {
            return Err(Error::InvalidConfig(
                "the try binds no library program".to_owned(),
            ));
        };
        if !matches!(
            row.outcome,
            TaskWorkflowOutcome::Pending | TaskWorkflowOutcome::Started { .. }
        ) {
            return Ok(row.outcome);
        }
        let note = receipt_note_id(record.id)?;
        let outcome = settled_outcome(&row, &report, note)?;
        let actor = runner_actor_in(vault, wtxn, &record)?
            .ok_or(Error::InvariantViolation("a bound try names no actor"))?;
        if vault.get_entity_type_in_txn(wtxn, &note)?.is_none() {
            let author = actor.entity_ref();
            let body = encode_note_body(&NoteBody {
                kind: NoteKind::parse(RECEIPT_NOTE_KIND).ok_or(Error::InvariantViolation(
                    "the research NOTE kind is not shipped",
                ))?,
                author_ref: NoteActor::Actor(author),
                markdown: receipt_markdown(&record, &row, &outcome, &report)?,
                source_revision_ref: *note.as_bytes(),
            })?;
            let batch = vault
                .batch_in()
                .put_authored_note(
                    &note,
                    &author,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .edge(&note, EdgeKind::AuthoredBy, &author, 1.0)
                .edge(&note, EdgeKind::About, &row.task_ref, 1.0);
            let mut content = ActorContentTxn::new(vault, wtxn, actor)?;
            content.apply_batch(batch)?;
            content.finish()?;
        }
        row.outcome = outcome.clone();
        ATTEMPTS.put(vault, wtxn, record.id.as_bytes(), &row)?;
        Ok(outcome)
    })
}

/// Marks, once, that the try `binding` leases is about to run its pinned
/// program (FIX 8104): one writer under its lease turns a Pending pin to
/// [`TaskWorkflowOutcome::Started`] at `now`, before the program can act.
/// `None` when it marked it; else the outcome the pin already holds, and
/// nothing is written. An entry that later finds it Started records
/// [`TaskWorkflowReport::Interrupted`]; the mark says nothing about what the
/// program did.
///
/// # Errors
///
/// A lapsed lease, a try with no pin, and storage errors.
pub fn mark_task_workflow_started(
    vault: &Vault,
    binding: &HostBinding,
    now: u64,
) -> Result<Option<TaskWorkflowOutcome>> {
    vault.with_write_txn_grouped(|wtxn| {
        let record = binding
            .leased_record_in_txn(vault, wtxn)?
            .ok_or(Error::InvalidClaimBody("the run's lease no longer holds"))?;
        let Some(mut row) = pinned_row_in(vault, wtxn, &record)? else {
            return Err(Error::InvalidConfig(
                "the try binds no library program".to_owned(),
            ));
        };
        if row.outcome != TaskWorkflowOutcome::Pending {
            return Ok(Some(row.outcome));
        }
        row.outcome = TaskWorkflowOutcome::Started { at: now };
        ATTEMPTS.put(vault, wtxn, record.id.as_bytes(), &row)?;
        Ok(None)
    })
}

/// A try's receipt NOTE id, derived from the try alone, so every pass
/// names the same entity.
fn receipt_note_id(attempt: AttemptId) -> Result<EntityId> {
    EntityId::derive(RECEIPT_NOTE_DOMAIN, &[attempt.as_bytes().as_slice()])
}

/// The outcome `report` comes to for `row`'s pin, with its receipt `note`.
fn settled_outcome(
    row: &AttemptRow,
    report: &TaskWorkflowReport,
    note: EntityId,
) -> Result<TaskWorkflowOutcome> {
    let handoff = |cause| TaskWorkflowOutcome::Handoff {
        cause,
        receipt_ref: note,
    };
    match (&row.pin, report) {
        // Only a program whose start is on the pin was interrupted.
        (_, TaskWorkflowReport::Interrupted) => match row.outcome {
            TaskWorkflowOutcome::Started { .. } => Ok(handoff(TaskWorkflowHandoff::Interrupted)),
            _ => refused("reported an interruption of a program it never started"),
        },
        (TaskWorkflowPin::Unavailable { cause }, TaskWorkflowReport::Unavailable) => {
            Ok(handoff(match cause {
                TaskWorkflowUnavailable::Retired { id, reason } => TaskWorkflowHandoff::Retired {
                    id: *id,
                    reason: reason.clone(),
                },
                TaskWorkflowUnavailable::Missing => {
                    TaskWorkflowHandoff::Missing { id: row.requested }
                }
                TaskWorkflowUnavailable::Unreadable { .. } => {
                    TaskWorkflowHandoff::Unreadable { id: row.requested }
                }
            }))
        }
        (TaskWorkflowPin::Unavailable { .. }, _) => refused("ran a program its pin does not name"),
        (TaskWorkflowPin::Active { .. }, TaskWorkflowReport::Unavailable) => {
            refused("ran nothing, and its pin names a program")
        }
        (
            TaskWorkflowPin::Active { record, .. },
            TaskWorkflowReport::Program { stop_cause, output },
        ) => {
            if output.as_ref().is_some_and(|output| !runs(output, *record)) {
                return refused("ran another program than its pin's");
            }
            Ok(handoff(TaskWorkflowHandoff::Program {
                stop_cause: stop_cause.clone(),
            }))
        }
        (TaskWorkflowPin::Active { record, .. }, TaskWorkflowReport::Ran { output, checks }) => {
            if !runs(output, *record) {
                return refused("ran another program than its pin's");
            }
            if output.status != SubgoalStatus::Done || !output.unmet.is_empty() {
                return Ok(handoff(TaskWorkflowHandoff::Program {
                    stop_cause: stop_cause_of(output),
                }));
            }
            let pinned = &row.goal.browser_checks;
            if checks.len() != pinned.len()
                || checks
                    .iter()
                    .zip(pinned)
                    .any(|(check, expect)| check.expect != *expect)
            {
                return refused("read other checks than its pinned done-means'");
            }
            if checks.iter().all(|check| check.observed.met) {
                Ok(TaskWorkflowOutcome::Done { receipt_ref: note })
            } else {
                Ok(handoff(TaskWorkflowHandoff::GoalUnmet))
            }
        }
    }
}

/// A report its pin does not admit, refused for `what` it did.
fn refused(what: &str) -> Result<TaskWorkflowOutcome> {
    Err(Error::InvalidConfig(format!("a bound try's report {what}")))
}

/// Why `output`'s run stopped short, as its batch states it, else its
/// failed step's receipt; a run that states neither is `library_run_unstated`,
/// as the preflight reads one.
fn stop_cause_of(output: &LibraryRunOutput) -> BatchStopCause {
    output
        .batch
        .stop_cause
        .clone()
        .or_else(|| {
            output
                .batch
                .failed_receipt
                .as_ref()
                .map(|receipt| receipt.stop_cause.clone())
        })
        .unwrap_or_else(|| BatchStopCause::Browser {
            code: "library_run_unstated".to_owned(),
        })
}

/// Whether `output` is a run of the program `record`.
fn runs(output: &LibraryRunOutput, record: EntityId) -> bool {
    EntityId::from_hex(&output.workflow).is_ok_and(|ran| ran == record)
}

/// The whole of what a receipt NOTE holds, as JSON.
#[derive(Serialize)]
struct Receipt<'a> {
    attempt: String,
    task: EntityId,
    requested: EntityId,
    brief: BriefStamp,
    pin: &'a TaskWorkflowPin,
    outcome: &'a TaskWorkflowOutcome,
    /// The TASK checks that did not hold, each with what the page showed.
    missed: Vec<&'a TaskWorkflowCheck>,
    report: &'a TaskWorkflowReport,
}

/// `pin` as its receipt holds it (FIX 8348): secret values masked,
/// names kept. A typed secret's text and a plain argument under a
/// secret parameter's name read [`SECRET_MARK`]; a handle is a custody
/// reference, not a value, and stays. The pin row itself keeps its
/// values: only the receipt's rendering is masked.
fn redacted_pin(pin: &TaskWorkflowPin) -> TaskWorkflowPin {
    let mut pin = pin.clone();
    if let TaskWorkflowPin::Active {
        args,
        secret_args,
        secret_names,
        ..
    } = &mut pin
    {
        for (name, value) in args.iter_mut() {
            if secret_names.contains(name) {
                *value = SECRET_MARK.to_owned();
            }
        }
        for value in secret_args.values_mut() {
            if let SecretArg::Text(text) = value {
                *text = SECRET_MARK.to_owned();
            }
        }
    }
    pin
}

/// The receipt NOTE's text: what the try ran and what came of it, then the
/// whole report as JSON, unclipped.
fn receipt_markdown(
    record: &AttemptRecord,
    row: &AttemptRow,
    outcome: &TaskWorkflowOutcome,
    report: &TaskWorkflowReport,
) -> Result<String> {
    let missed: Vec<&TaskWorkflowCheck> = match report {
        TaskWorkflowReport::Ran { checks, .. } => {
            checks.iter().filter(|check| !check.observed.met).collect()
        }
        TaskWorkflowReport::Program { .. }
        | TaskWorkflowReport::Unavailable
        | TaskWorkflowReport::Interrupted => Vec::new(),
    };
    let mut lines = vec![
        "# Library program receipt".to_owned(),
        String::new(),
        format!("- task: {}", row.task_ref.to_hex()),
        format!("- try: {}", attempt_hex(record.id)),
        format!("- workflow: workflow:{}", row.requested.to_hex()),
    ];
    match &row.pin {
        TaskWorkflowPin::Active { record, .. } => {
            lines.push(format!("- pinned: {}", record.to_hex()));
        }
        TaskWorkflowPin::Unavailable {
            cause: TaskWorkflowUnavailable::Unreadable { detail },
        } => lines.push(format!(
            "- pinned: none; the library did not read: {detail}"
        )),
        TaskWorkflowPin::Unavailable { .. } => lines.push("- pinned: none".to_owned()),
    }
    lines.push(match outcome {
        TaskWorkflowOutcome::Pending => "- outcome: pending".to_owned(),
        TaskWorkflowOutcome::Started { .. } => "- outcome: started".to_owned(),
        TaskWorkflowOutcome::Done { .. } => "- outcome: done".to_owned(),
        TaskWorkflowOutcome::Handoff { cause, .. } => {
            format!("- outcome: handoff, {}", cause.code())
        }
    });
    if !missed.is_empty() {
        lines.push(format!("- missed checks: {}", missed.len()));
    }
    // FIX 8104: an interrupted run's effects are unknown, never claimed.
    if let (TaskWorkflowReport::Interrupted, TaskWorkflowOutcome::Started { at }) =
        (report, &row.outcome)
    {
        lines.push(format!(
            "- browser effects: unknown. The strict program was started at {at} and its end was never recorded, so this receipt cannot say what it did or did not do on the page."
        ));
    }
    let pin = redacted_pin(&row.pin);
    let evidence = Receipt {
        attempt: attempt_hex(record.id),
        task: row.task_ref,
        requested: row.requested,
        brief: row.brief,
        pin: &pin,
        outcome,
        missed,
        report,
    };
    let json = serde_json::to_string_pretty(&evidence)
        .map_err(|_| Error::InvariantViolation("a library program receipt does not encode"))?;
    lines.push(String::new());
    lines.push("```json".to_owned());
    lines.push(json);
    lines.push("```".to_owned());
    Ok(lines.join("\n"))
}

/// The status of a TASK's bound try, read in `txn`: the try `attempt`
/// names, else `task_ref`'s newest pinned try. `None` when no pin answers.
pub(super) fn workflow_status_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    attempt: Option<AttemptId>,
) -> Result<Option<TaskWorkflowStatus>> {
    let found = match attempt {
        Some(attempt) => ATTEMPTS
            .get(&vault.store, txn, attempt.as_bytes())?
            .filter(|row| row.task_ref == task_ref)
            .map(|row| (*attempt.as_bytes(), row)),
        None => ATTEMPTS
            .scan(&vault.store, txn)?
            .into_iter()
            .filter(|(_, row)| row.task_ref == task_ref)
            .max_by_key(|(key, row)| (row.pinned_at, *key)),
    };
    Ok(found.map(|(key, row)| TaskWorkflowStatus {
        attempt_ref: crate::entity_id::bytes_to_hex_lower(&key),
        requested: row.requested,
        resolved: match row.pin {
            TaskWorkflowPin::Active { record, .. } => Some(record),
            TaskWorkflowPin::Unavailable { .. } => None,
        },
        brief: row.brief,
        outcome: row.outcome,
    }))
}

/// Drops the pins of every try of a TASK among `erased`, an archived try's
/// included, in the hard erase's transaction: their arguments and goal are
/// the TASK's. A pin that does not read goes too: no reader can use it, it
/// may hold an erased TASK's arguments, and the erase still lands.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_task_workflows_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    if erased.is_empty() {
        return Ok(());
    }
    let mut dropped = Vec::new();
    for row in ATTEMPTS.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) else {
            continue;
        };
        match ATTEMPTS.decode_value(&value) {
            Ok(row) if !erased.contains(&row.task_ref) => {}
            _ => dropped.push(key),
        }
    }
    for key in dropped {
        ATTEMPTS.delete(store, txn, &key)?;
    }
    Ok(())
}
