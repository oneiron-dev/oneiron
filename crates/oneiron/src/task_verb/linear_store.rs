//! Vault storage for the tracker mirror: replicated fields, local OCC and CAS links.
use super::wire_decode::{task_body_has_typed_subkind, task_verb_body_in};
use super::wire_encode::encode_task_verb_body;
use crate::error::{Error, Result};
use crate::linear_sync::*;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

const REVISIONS: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::LINEAR_TASK_REVISION);
const DIRTY: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::LINEAR_TASK_DIRTY);
const ISSUE_REVERSE: SideTable<String, EntityId, Raw> =
    SideTable::new(&side_table::LINEAR_ISSUE_REVERSE);
const PULL_CURSOR: SideTable<(), String, Raw> = SideTable::new(&side_table::LINEAR_PULL_CURSOR);

fn revision(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<u64> {
    Ok(REVISIONS.get(store, txn, &id)?.unwrap_or(0))
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

pub struct VaultLinearTaskStore<'v> {
    vault: &'v Vault,
}
impl<'v> VaultLinearTaskStore<'v> {
    /// Trusted engine-side storage. Hosts bind authenticated source/egress
    /// adapters outside this port; no provider credentials enter the vault.
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
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
        if let Some(terminal) = body.terminal() {
            fields.status = terminal.disposition.as_str().to_owned();
        }
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
        self.vault.with_write_txn(|txn| {
            if DIRTY.get(&self.vault.store, txn, &task)? == Some(expected_revision) {
                return DIRTY.delete(&self.vault.store, txn, &task);
            }
            Ok(false)
        })
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
        self.vault.try_with_write_txn(|txn| {
            let current = self.snapshot(txn, task)?;
            if current.revision != expected_revision {
                return Err(LinearSyncError::Conflict {
                    expected_revision,
                    found: current.revision,
                });
            }
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
        self.vault.try_with_write_txn(|txn| {
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
            LINEAR_LINKS.put(&self.vault.store, txn, &link.task_ref, link)?;
            ISSUE_REVERSE.put(&self.vault.store, txn, &reverse, &link.task_ref)?;
            Ok(())
        })
    }
}

impl<I: LinearChangeSource, O: LinearEgress> LinearSyncAdapter<VaultLinearTaskStore<'_>, I, O> {
    /// Scheduled host entry: drain TASK writes then consume one source page.
    /// Errors retain dirty revisions/cursor for retry. The injected egress is
    /// still the authenticated OF-327 rail, never a credential in core.
    pub fn synchronize(
        &mut self,
        now: u64,
    ) -> LinearSyncResult<(Vec<LinearMirrorReceipt>, LinearPullReceipt)> {
        let mut pushed = Vec::new();
        for (task, revision) in self.tasks().dirty_tasks()? {
            let receipt = self.push_task(task, now)?;
            if receipt.status != LinearMirrorStatus::Conflict {
                self.tasks().acknowledge_push(task, revision)?;
            }
            pushed.push(receipt);
        }
        let cursor = {
            let txn = self
                .tasks()
                .vault
                .store
                .env
                .read_txn()
                .map_err(Error::from)?;
            PULL_CURSOR.get(&self.tasks().vault.store, &txn, &())?
        };
        let pulled = self.pull_page(cursor.as_deref(), now)?;
        if let Some(cursor) = &pulled.new_cursor {
            self.tasks().vault.with_write_txn(|txn| {
                PULL_CURSOR.put(&self.tasks().vault.store, txn, &(), cursor)?;
                Ok(())
            })?;
        }
        Ok((pushed, pulled))
    }
}

pub(crate) fn forget_task_mirror(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    DIRTY.delete(store, txn, &id)?;
    if let Some(link) = LINEAR_LINKS.get(store, txn, &id)? {
        ISSUE_REVERSE.delete(store, txn, &issue_key(&link.issue))?;
        LINEAR_LINKS.delete(store, txn, &id)?;
    }
    Ok(())
}
