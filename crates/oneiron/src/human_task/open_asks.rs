//! The asks still open with one person (FIX 5908), read from the TASKs
//! themselves. This replica's follow-up cursors only say how far its nudging
//! got: a TASK it holds no cursor for is still an open ask.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult, verify_actor_binding};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
use crate::scan_check::{EngineScan, ScanCount};

use super::model::HumanFollowupStage;
use super::storage::followup_record_in_txn;

/// The family an [`OpenHumanAsk`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenHumanAskKind {
    /// A TASK assigned to the person.
    Task,
    /// The person's member TASK of a `tasks.ask` that has not settled.
    Ask,
}

impl OpenHumanAskKind {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Ask => "tasks.ask",
        }
    }
}

/// The families [`open_asks_for`] reads: TASK-borne asks only.
pub const OPEN_HUMAN_ASK_FAMILIES: &[OpenHumanAskKind] =
    &[OpenHumanAskKind::Task, OpenHumanAskKind::Ask];

/// A family of ask a person can hold that no TASK carries, so
/// [`open_asks_for`] does not read it (FIX 7208).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncoveredHumanAskFamily {
    /// A decision waiting in the person's inbox.
    InboxDecision,
    /// A proposal waiting on the person's say.
    ConsentProposal,
    /// An ask the owner owes an answer to.
    OwnerAnswer,
}

impl UncoveredHumanAskFamily {
    /// Stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InboxDecision => "inbox_decision",
            Self::ConsentProposal => "consent_proposal",
            Self::OwnerAnswer => "owner_answer",
        }
    }
}

/// The families [`open_asks_for`] does not read.
pub const UNCOVERED_HUMAN_ASK_FAMILIES: &[UncoveredHumanAskFamily] = &[
    UncoveredHumanAskFamily::InboxDecision,
    UncoveredHumanAskFamily::ConsentProposal,
    UncoveredHumanAskFamily::OwnerAnswer,
];

/// Where this replica's follow-up of one open ask got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAskFollowup {
    /// The stage this replica's follow-up cursor for the TASK holds.
    Cursor(HumanFollowupStage),
    /// This replica holds no follow-up cursor for the TASK: one synced in
    /// and never rebuilt here, say.
    Untracked,
}

impl OpenAskFollowup {
    /// Stable token: the cursor's stage token, or `untracked`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cursor(stage) => stage.as_str(),
            Self::Untracked => "untracked",
        }
    }
}

/// One ask still open with a person (FIX 5908).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenHumanAsk {
    pub kind: OpenHumanAskKind,
    /// The TASK that waits on the person.
    pub reference: EntityId,
    /// The person it waits on.
    pub addressee: EntityId,
    /// Where this replica's follow-up of it got to. The TASK's own live
    /// facts, never this, say that it is open.
    pub state: OpenAskFollowup,
}

/// What [`open_asks_for`] read of one person's open asks, and how far that
/// read reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenHumanAsks {
    /// The open asks, in task order.
    pub asks: Vec<OpenHumanAsk>,
    /// The families read ([`OPEN_HUMAN_ASK_FAMILIES`]).
    pub families: &'static [OpenHumanAskKind],
    /// The families of ask a person can hold that are not read here
    /// ([`UNCOVERED_HUMAN_ASK_FAMILIES`]): no TASK carries them.
    pub not_read: &'static [UncoveredHumanAskFamily],
    /// Whether `families` is every family of ask a person can hold: `false`
    /// while `not_read` names any.
    pub complete: bool,
    /// TASK rows that did not read: neither listed nor taken as closed. A
    /// row whose body does not read is counted whoever it is assigned to.
    pub unreadable: usize,
}

/// The asks still open with `person`, as `memory`'s own caller reads them
/// (FIX 5908): each TASK assigned to the person whose live facts still hold
/// it open, a `tasks.ask` member TASK while its ask has not settled. Every
/// TASK row is read, with no cap on how many, whether or not this replica
/// holds a follow-up cursor for it (FIX 7208); past its threshold row the
/// walk raises its check and reads on (FIX 7212). It reads under the
/// caller's own handle, never as the person: off this device a TASK a
/// device-local world keeps reads as no ask, and so does an ask whose
/// question, context, class or member rows such a world keeps (FIX 7209); a
/// handle bound to a read credential lists only the TASKs it reads. A row
/// that does not read is counted, never dropped unsaid. Only TASK-borne asks
/// are read ([`OpenHumanAsks::not_read`]).
///
/// # Errors
/// An actor binding that does not verify, or a storage error outside any
/// one row.
pub fn open_asks_for(memory: &Memory<'_>, person: EntityId) -> MemoryResult<OpenHumanAsks> {
    let vault = memory.vault();
    verify_actor_binding(vault, memory.actor(), memory.actor_class())?;
    let mut asks = Vec::new();
    let mut unreadable = 0_usize;
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let kept = crate::settings::device_local_worlds_for(vault, &txn, memory.destination())?;
    let mut count = ScanCount::start(
        &vault.store,
        &txn,
        EngineScan::OpenAskTaskRows,
        person.as_bytes(),
    )?;
    for row in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_TASK, None)?
    {
        count.row();
        let Ok(task_ref) = row else {
            unreadable += 1;
            continue;
        };
        match crate::task_verb::task_human_assignee_in(vault, &txn, task_ref) {
            Ok(Some(assignee)) if assignee == person => {}
            Ok(_) => continue,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        }
        memory.produced_from([task_ref]);
        match open_ask_in(memory, &txn, &kept, task_ref, person) {
            Ok(Some(ask)) => asks.push(ask),
            Ok(None) => {}
            Err(_) => unreadable += 1,
        }
    }
    drop(txn);
    count.finish(vault);
    let refs: Vec<EntityId> = asks.iter().map(|ask| ask.reference).collect();
    if !refs.is_empty()
        && let Some(readable) = memory.credential_readable_ids(&refs)?
    {
        asks.retain(|ask| readable.contains(&ask.reference));
    }
    Ok(OpenHumanAsks {
        asks,
        families: OPEN_HUMAN_ASK_FAMILIES,
        not_read: UNCOVERED_HUMAN_ASK_FAMILIES,
        complete: UNCOVERED_HUMAN_ASK_FAMILIES.is_empty(),
        unreadable,
    })
}

/// The ask `task` is, in `txn`, while it is still open with `person`: its
/// live TASK holds it open and assigned to them, no device-local world in
/// `kept` keeps it and, for a `tasks.ask` member, none keeps a row its ask
/// answers from. `None`: settled, gone, someone else's, or kept from the
/// caller's destination.
fn open_ask_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    kept: &BTreeSet<EntityId>,
    task: EntityId,
    person: EntityId,
) -> Result<Option<OpenHumanAsk>> {
    let vault = memory.vault();
    match crate::task_verb::open_thread_task_holder_in(
        vault,
        txn,
        task,
        crate::gate::TaskHolderFallback::AssigneeOnly,
    ) {
        Ok(Some(holder)) if holder == person => {}
        // An erased TASK holds nothing open.
        Ok(_) | Err(Error::EntityNotFound) => return Ok(None),
        Err(error) => return Err(error),
    }
    if crate::settings::device_local_keeps_among(&vault.store, txn, kept, &task)? {
        return Ok(None);
    }
    let kind = if crate::task_verb::ask_notice_at_in(vault, txn, task, 0)?.is_some() {
        // FIX 7209: the ask's own rows take the cut its member TASK takes.
        if crate::task_verb::ask_rows_kept_in(memory, txn, kept, task)? {
            return Ok(None);
        }
        OpenHumanAskKind::Ask
    } else {
        OpenHumanAskKind::Task
    };
    let state = followup_record_in_txn(vault, txn, task)?
        .map_or(OpenAskFollowup::Untracked, |record| {
            OpenAskFollowup::Cursor(record.stage)
        });
    Ok(Some(OpenHumanAsk {
        kind,
        reference: task,
        addressee: person,
        state,
    }))
}
