//! Vault storage for the tracker mirror: replicated fields, local OCC and CAS links.
use super::TaskExecutionState;
use super::wire_decode::{task_body_has_typed_subkind, task_verb_body_in};
use super::wire_encode::encode_task_verb_body;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::linear_sync::*;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const REVISIONS: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::LINEAR_TASK_REVISION);
const DIRTY: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::LINEAR_TASK_DIRTY);
/// Value: the task revision it stamps (u64be), the writer id16 and its actor class byte.
const WRITER: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::LINEAR_TASK_WRITER);
const ISSUE_REVERSE: SideTable<String, EntityId, Raw> =
    SideTable::new(&side_table::LINEAR_ISSUE_REVERSE);
const PULL_CURSOR: SideTable<(), String, Raw> = SideTable::new(&side_table::LINEAR_PULL_CURSOR);

fn revision(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<u64> {
    Ok(REVISIONS.get(store, txn, &id)?.unwrap_or(0))
}
pub(crate) fn task_revision_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<u64> {
    revision(store, txn, id)
}

/// A raw/replayed TASK put clears this mark at the generic batch door. Only
/// the verified typed facade may restamp it after the same write transaction.
pub(crate) fn note_task_writer_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
) -> Result<()> {
    let rev = revision(store, txn, task)?;
    let mut value = Vec::with_capacity(25);
    value.extend_from_slice(&rev.to_be_bytes());
    value.extend_from_slice(actor.as_bytes());
    value.push(class as u8);
    WRITER.put(store, txn, &task, &value)?;
    Ok(())
}

fn writer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<Option<LinearWriteActor>> {
    let Some(raw) = WRITER.get(store, txn, &task)? else {
        return Ok(None);
    };
    if raw.len() != 25 {
        return Err(Error::CorruptedIndex("linear task writer"));
    }
    let stamped_rev = u64::from_be_bytes(
        raw[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("linear task writer revision"))?,
    );
    if stamped_rev != revision(store, txn, task)? {
        return Ok(None);
    }
    let id = EntityId::from_bytes(
        raw[8..24]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("linear task writer id"))?,
    )?;
    let class = EdgeActorClass::try_from_u8(raw[24])
        .ok_or(Error::CorruptedIndex("linear task writer class"))?;
    Ok(Some(LinearWriteActor {
        actor_ref: id,
        actor_class: class as u8,
    }))
}

pub(crate) fn note_task_write(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &[u8],
) -> Result<()> {
    if !task_body_has_typed_subkind(body)? {
        return Ok(());
    }
    let revision = revision(store, txn, id)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("task revision"))?;
    REVISIONS.put(store, txn, &id, &revision)?;
    DIRTY.put(store, txn, &id, &revision)?;
    WRITER.delete(store, txn, &id)?;
    Ok(())
}
fn issue_key(issue: &LinearIssueRef) -> String {
    // issue ids are globally scoped; identifiers and teams may change.
    issue.issue_id.clone()
}
fn read_link(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<Option<TaskIssueLink>> {
    LINEAR_LINKS.get(&vault.store, txn, &task)
}

/// One locked view for the external Linear effect door. No provider bytes.
pub(crate) struct LinearEffectState {
    pub revision: u64,
    pub dirty_revision: Option<u64>,
    pub link: Option<TaskIssueLink>,
    pub writer: Option<LinearWriteActor>,
    /// The outbound snapshot as of this transaction.
    pub snapshot: TaskMirrorSnapshot,
}

pub(crate) fn linear_effect_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> LinearSyncResult<LinearEffectState> {
    let dirty_revision = DIRTY.get(&vault.store, txn, &task)?;
    Ok(LinearEffectState {
        revision: revision(&vault.store, txn, task)?,
        dirty_revision,
        link: read_link(vault, txn, task)?,
        writer: writer_in_txn(&vault.store, txn, task)?,
        snapshot: VaultLinearTaskStore::new(vault).snapshot(txn, task)?,
    })
}

pub struct VaultLinearTaskStore<'v> {
    vault: &'v Vault,
}
impl<'v> VaultLinearTaskStore<'v> {
    /// Trusted engine-side storage. Hosts bind authenticated source/egress
    /// adapters outside this port; no provider credentials enter the vault.
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }
    /// Writer of the current dirty revision; raw/replayed writes have none.
    pub fn dirty_writer(&self, task: EntityId) -> LinearSyncResult<Option<LinearWriteActor>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(writer_in_txn(&self.vault.store, &txn, task)?)
    }
    fn snapshot(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
    ) -> LinearSyncResult<TaskMirrorSnapshot> {
        let body = task_verb_body_in(self.vault, txn, task)?.ok_or(Error::EntityNotFound)?;
        let link = read_link(self.vault, txn, task)?;
        let mut fields = body.mirror_fields.clone().unwrap_or(MirroredTaskFields {
            title: String::new(),
            description: None,
            priority: None,
            assignee_ref: body.assignee.and_then(|a| match a {
                super::TaskAssignee::Peer { actor_ref }
                | super::TaskAssignee::Human { actor_ref } => Some(actor_ref.to_hex()),
                super::TaskAssignee::AgentDef { agent_def_ref } => Some(agent_def_ref.to_hex()),
                _ => None,
            }),
            status: "queued".to_owned(),
        });
        fields.title = body.label.clone().unwrap_or_default();
        // Execution facts win over the last imported tracker token. Inbound
        // status remains a mirror field; it never authors Working or Terminal.
        fields.status = match body.state.as_ref() {
            Some(TaskExecutionState::Working { .. }) => "working".to_owned(),
            Some(TaskExecutionState::Interrupted { .. }) => "interrupted".to_owned(),
            Some(TaskExecutionState::Blocked { .. }) => "blocked".to_owned(),
            Some(TaskExecutionState::Terminal(record)) => record.disposition.as_str().to_owned(),
            None | Some(TaskExecutionState::Queued) => fields.status,
        };
        Ok(TaskMirrorSnapshot {
            task_ref: task,
            issue: link.as_ref().map(|l| l.issue.clone()),
            revision: revision(&self.vault.store, txn, task)?,
            last_pushed_at_ms: link
                .as_ref()
                .filter(|l| l.last_direction == LinearSyncDirection::TaskToIssue)
                .map(|l| l.issue_updated_at_ms),
            last_pulled_updated_at_ms: link.as_ref().map(|l| l.issue_updated_at_ms),
            fields,
        })
    }

    /// Durable outbox populated at the TASK storage door, including raw/replay
    /// writes. A worker pushes these through LinearSyncAdapter, then acks the
    /// exact revision. Newer writes cannot be lost under an old acknowledgement.
    pub fn dirty_tasks(&self) -> Result<Vec<(EntityId, u64)>> {
        let txn = self.vault.store.env.read_txn()?;
        DIRTY.scan(&self.vault.store, &txn)
    }
    pub fn acknowledge_push(&self, task: EntityId, expected_revision: u64) -> Result<bool> {
        self.vault.with_write_txn_grouped(|txn| {
            if DIRTY.get(&self.vault.store, txn, &task)? == Some(expected_revision) {
                return DIRTY.delete(&self.vault.store, txn, &task);
            }
            Ok(false)
        })
    }
    /// Whether a pass holds `task`'s push (OF-427 C6): the TASK is opted out
    /// of the mirror, or a mapping edit linked it and no tracker event has
    /// witnessed the issue since, so no remote precondition exists for a
    /// conditional update. Its dirty revision waits.
    fn holds_push(&self, task: EntityId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        Ok(mirror_opted_out_in(self.vault, &txn, task)?
            || read_link(self.vault, &txn, task)?
                .is_some_and(|link| link.remote_field_hashes.is_empty()))
    }
}
impl LinearTaskStore for VaultLinearTaskStore<'_> {
    fn task_snapshot(&self, task: EntityId) -> LinearSyncResult<TaskMirrorSnapshot> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.snapshot(&txn, task)
    }
    fn apply_issue_fields(
        &mut self,
        task: EntityId,
        expected_revision: u64,
        fields: &MirroredTaskFields,
        now: u64,
    ) -> LinearSyncResult<TaskMirrorSnapshot> {
        self.vault.try_with_write_txn_grouped(|txn| {
            let current = self.snapshot(txn, task)?;
            if current.revision != expected_revision {
                return Err(LinearSyncError::Conflict {
                    expected_revision,
                    found: current.revision,
                });
            }
            let prior_writer = writer_in_txn(&self.vault.store, txn, task)?;
            let locally_dirty = read_link(self.vault, txn, task)?
                .is_some_and(|link| current.fields.field_hashes() != link.base_field_hashes);
            let mut body =
                task_verb_body_in(self.vault, txn, task)?.ok_or(Error::EntityNotFound)?;
            // Imported status is tracker state, never a forged completion/result.
            // Preserve execution spec, terminal register, and every engine field.
            body.label = Some(fields.title.clone());
            body.mirror_fields = Some(fields.clone());
            self.vault
                .batch_in()
                .put_internal(
                    &task,
                    crate::registry::ENTITY_TYPE_TASK,
                    crate::TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &encode_task_verb_body(body),
                )
                .apply(txn)?;
            // An inbound disjoint-field merge may carry an unsent LOCAL edit.
            // The generic batch write clears writer provenance, so copy only
            // an already-verified current writer to the merged revision. An
            // unattributed raw/replayed write cannot gain one here.
            if locally_dirty && let Some(writer) = prior_writer {
                let class = EdgeActorClass::try_from_u8(writer.actor_class)
                    .ok_or(Error::CorruptedIndex("linear task writer class"))?;
                note_task_writer_in_txn(&self.vault.store, txn, task, writer.actor_ref, class)?;
            }
            self.snapshot(txn, task)
        })
    }
    fn link(&self, task: EntityId) -> LinearSyncResult<Option<TaskIssueLink>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(read_link(self.vault, &txn, task)?)
    }
    fn link_for_issue(&self, issue: &LinearIssueRef) -> LinearSyncResult<Option<TaskIssueLink>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let Some(task) = ISSUE_REVERSE.get(&self.vault.store, &txn, &issue_key(issue))? else {
            return Ok(None);
        };
        Ok(read_link(self.vault, &txn, task)?)
    }
    fn put_link(&mut self, expected: Option<u64>, link: &TaskIssueLink) -> LinearSyncResult<()> {
        self.vault.try_with_write_txn_grouped(|txn| {
            self.snapshot(txn, link.task_ref)?;
            let old = read_link(self.vault, txn, link.task_ref)?;
            let found = old.as_ref().map(|row| row.link_revision);
            if found != expected {
                return Err(LinearSyncError::LinkConflict { expected, found });
            }
            let next = expected.map_or(Ok(0), |r| {
                r.checked_add(1)
                    .ok_or(Error::ArithmeticOverflow("linear link revision"))
            })?;
            if link.link_revision != next || link.issue.issue_id.trim().is_empty() {
                return Err(Error::InvalidConfig(
                    "invalid linear link revision or issue".to_owned(),
                )
                .into());
            }
            let reverse = issue_key(&link.issue);
            if ISSUE_REVERSE
                .get(&self.vault.store, txn, &reverse)?
                .is_some_and(|task| task != link.task_ref)
            {
                return Err(LinearSyncError::LinkConflict { expected, found });
            }
            if let Some(old) = old
                && old.issue.issue_id != link.issue.issue_id
            {
                ISSUE_REVERSE.delete(&self.vault.store, txn, &issue_key(&old.issue))?;
            }
            LINEAR_LINKS.put(self.vault, txn, &link.task_ref, link)?;
            ISSUE_REVERSE.put(&self.vault.store, txn, &reverse, &link.task_ref)?;
            Ok(())
        })
    }
}

impl<I: LinearChangeSource, O: LinearEgress> LinearSyncAdapter<VaultLinearTaskStore<'_>, I, O> {
    /// Scheduled host entry: reconcile every available inbound page BEFORE
    /// publishing any dirty TASK snapshot. A rejected outbound item retains
    /// its revision without starving later items or the pull cursor.
    ///
    /// # Errors
    ///
    /// The pull's error; else, when a push failed, that failure, or every
    /// push failure as [`LinearSyncError::PushFailed`] when more than one did
    /// (FIX 6837), a held push's [`LinearSyncError::Held`] naming its press;
    /// else [`LinearSyncError::Waiting`] when a push waits for its Rate
    /// window.
    pub fn synchronize(
        &mut self,
        now: u64,
        max_pull_pages_per_pass: usize,
    ) -> LinearSyncResult<(Vec<LinearMirrorReceipt>, LinearPullReceipt)> {
        let pulled = self.pull_pass(now, max_pull_pages_per_pass)?;
        let mut pushed = Vec::new();
        let mut failures = PassFailures::default();
        for (task, revision) in self.tasks().dirty_tasks()? {
            if let Some(receipt) = self.push_dirty(task, revision, now, &mut failures) {
                pushed.push(receipt);
            }
        }
        if let Some(error) = failures.into_error() {
            return Err(error);
        }
        Ok((pushed, pulled))
    }

    /// A caller's own push of the one TASK `task` (FIX 8788, FIX 9382), as a
    /// pass sends it: every available inbound page is reconciled first, then
    /// `task` is pushed when it owes the mirror its dirty revision and no
    /// held push skips it, with the row and acknowledgement a pass keeps.
    /// `None` when it owes nothing or its push is held. Its egress decides
    /// how long a full Rate window is waited for.
    ///
    /// # Errors
    ///
    /// As [`Self::synchronize`].
    pub fn push_dirty_task(
        &mut self,
        task: EntityId,
        now: u64,
        max_pull_pages_per_pass: usize,
    ) -> LinearSyncResult<(Option<LinearMirrorReceipt>, LinearPullReceipt)> {
        let pulled = self.pull_pass(now, max_pull_pages_per_pass)?;
        let revision = {
            let vault = self.tasks().vault;
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            DIRTY.get(&vault.store, &txn, &task)?
        };
        let Some(revision) = revision else {
            return Ok((None, pulled));
        };
        let mut failures = PassFailures::default();
        let receipt = self.push_dirty(task, revision, now, &mut failures);
        if let Some(error) = failures.into_error() {
            return Err(error);
        }
        Ok((receipt, pulled))
    }

    /// Every available inbound page, its cursor durable after each.
    fn pull_pass(
        &mut self,
        now: u64,
        max_pull_pages_per_pass: usize,
    ) -> LinearSyncResult<LinearPullReceipt> {
        if !(1..=1024).contains(&max_pull_pages_per_pass) {
            return Err(
                Error::InvalidConfig("linear pull page policy is out of bounds".into()).into(),
            );
        }
        let mut cursor = {
            let txn = self
                .tasks()
                .vault
                .store
                .env
                .read_txn()
                .map_err(Error::from)?;
            PULL_CURSOR.get(&self.tasks().vault.store, &txn, &())?
        };
        let mut pulled = LinearPullReceipt {
            applied: 0,
            skipped_echo: 0,
            conflicts: Vec::new(),
            new_cursor: cursor.clone(),
            pulled_at: now,
        };
        // A malicious or broken source cannot keep the pass inside pagination
        // forever. The cursor of each completed page is durable before reading
        // the next; no outbound write occurs until a terminal page is reached.
        let mut seen = std::collections::BTreeSet::new();
        let mut caught_up = false;
        for _ in 0..max_pull_pages_per_pass {
            let page = self.pull_page(cursor.as_deref(), now)?;
            pulled.applied += page.applied;
            pulled.skipped_echo += page.skipped_echo;
            pulled.conflicts.extend(page.conflicts);
            let Some(next) = page.new_cursor else {
                caught_up = true;
                break;
            };
            if cursor.as_deref() == Some(next.as_str()) || !seen.insert(next.clone()) {
                return Err(
                    Error::InvalidConfig("linear source repeated its cursor".into()).into(),
                );
            }
            self.tasks().vault.with_write_txn_grouped(|txn| {
                PULL_CURSOR.put(&self.tasks().vault.store, txn, &(), &next)?;
                Ok(())
            })?;
            cursor = Some(next);
            pulled.new_cursor = cursor.clone();
        }
        if !caught_up {
            return Err(Error::InvalidConfig("linear source page bound exceeded".into()).into());
        }
        Ok(pulled)
    }

    /// One dirty TASK's push at `revision`, as a pass sends it: a held push
    /// is skipped, a sent push keeps its row, and the revision is
    /// acknowledged unless the push met a conflict. Each failure goes to
    /// `failures` under `task` (FIX 6837), a push the Gate holds for a press
    /// as the door's [`LinearSyncError::Held`] with its digest.
    fn push_dirty(
        &mut self,
        task: EntityId,
        revision: u64,
        now: u64,
        failures: &mut PassFailures,
    ) -> Option<LinearMirrorReceipt> {
        match self.tasks().holds_push(task) {
            Ok(false) => {}
            Ok(true) => return None,
            Err(error) => {
                failures.note(task, error.into());
                return None;
            }
        }
        // Evidence for the push's row only; the effect door re-proves it.
        let writer = self.tasks().dirty_writer(task).ok().flatten();
        match self.push_task(task, now) {
            Ok(receipt) => {
                // Each push this pass sent keeps its row (OF-427 C9).
                if matches!(
                    receipt.status,
                    LinearMirrorStatus::Linked | LinearMirrorStatus::Applied
                ) && let Err(error) = record_outbound(self.tasks().vault, &receipt, writer)
                {
                    failures.note(task, error.into());
                }
                if receipt.status != LinearMirrorStatus::Conflict
                    && let Err(error) = self.tasks().acknowledge_push(task, revision)
                {
                    failures.note(task, error.into());
                }
                Some(receipt)
            }
            Err(error) => {
                failures.note(task, error);
                None
            }
        }
    }
}

/// A mirror pass's push failures, one per TASK in push order (FIX 6837). A
/// push that waits for its Rate window (FIX 8788) keeps its dirty revision
/// and yields to every real failure.
#[derive(Default)]
struct PassFailures {
    waiting: Option<LinearSyncError>,
    failed: Vec<LinearPushFailure>,
}

impl PassFailures {
    fn note(&mut self, task: EntityId, error: LinearSyncError) {
        if matches!(error, LinearSyncError::Waiting(_)) {
            self.waiting.get_or_insert(error);
        } else {
            self.failed.push(LinearPushFailure { task, error });
        }
    }

    /// The pass's error: its one failure itself, every failure as
    /// [`LinearSyncError::PushFailed`] when more than one push failed, else
    /// its first wait; `None` when every push went or was held back.
    fn into_error(mut self) -> Option<LinearSyncError> {
        match self.failed.len() {
            0 => self.waiting,
            1 => self.failed.pop().map(|failure| failure.error),
            _ => Some(LinearSyncError::PushFailed(self.failed)),
        }
    }
}

pub(crate) fn forget_task_mirror(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    DIRTY.delete(store, txn, &id)?;
    WRITER.delete(store, txn, &id)?;
    forget_mirror_control_in(store, txn, id)?;
    if let Some(link) = LINEAR_LINKS.get(store, txn, &id)? {
        ISSUE_REVERSE.delete(store, txn, &issue_key(&link.issue))?;
        LINEAR_LINKS.delete(store, txn, &id)?;
    }
    Ok(())
}

/// The TASK `issue_id` is linked to, if any.
pub(crate) fn linear_issue_task_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    issue_id: &str,
) -> Result<Option<EntityId>> {
    ISSUE_REVERSE.get(&vault.store, txn, &issue_id.to_owned())
}

/// Writes a mapping edit's link and its reverse (OF-427 C6). The caller
/// checked in `txn` that neither the TASK nor the issue is linked.
pub(crate) fn put_mirror_link_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    link: &TaskIssueLink,
) -> Result<()> {
    LINEAR_LINKS.put(vault, txn, &link.task_ref, link)?;
    ISSUE_REVERSE.put(&vault.store, txn, &issue_key(&link.issue), &link.task_ref)?;
    Ok(())
}

/// Removes `task`'s link and its reverse (OF-427 C6). The TASK, the issue
/// and the mirror's history stay.
pub(crate) fn drop_mirror_link_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
) -> Result<()> {
    if let Some(link) = LINEAR_LINKS.get(&vault.store, txn, &task)? {
        ISSUE_REVERSE.delete(&vault.store, txn, &issue_key(&link.issue))?;
        LINEAR_LINKS.delete(&vault.store, txn, &task)?;
    }
    Ok(())
}

/// Queues `task`'s current revision for the next pass as written by
/// `actor`, the owner who asked to mirror it (OF-427 C6): with no link, the
/// pass creates a fresh issue through the admitted-effect door.
pub(crate) fn mark_mirror_dirty_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
) -> Result<()> {
    let current = revision(&vault.store, txn, task)?;
    DIRTY.put(&vault.store, txn, &task, &current)?;
    note_task_writer_in_txn(&vault.store, txn, task, actor, class)
}
