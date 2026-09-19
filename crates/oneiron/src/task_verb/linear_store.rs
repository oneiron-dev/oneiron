//! Vault storage for the tracker mirror: replicated fields, local OCC and CAS links.
use super::wire_decode::{task_body_has_typed_subkind, task_verb_body_in};
use super::wire_encode::encode_task_verb_body;
use crate::error::{Error, Result};
use crate::linear_sync::*;
use crate::store::Store;
use crate::{EntityId, Vault};

const REVISION: &[u8] = b"linear.task_revision.v1/";
const DIRTY: &[u8] = b"linear.task_dirty.v1/";
const ISSUE: &[u8] = b"linear.issue.v1/";
fn key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}
fn revision(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<u64> {
    store
        .vault_meta
        .get(txn, &key(REVISION, id))?
        .map_or(Ok(0), |raw| {
            Ok(u64::from_be_bytes(
                raw.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("task revision"))?,
            ))
        })
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
    store
        .vault_meta
        .put(txn, &key(REVISION, id), &revision.to_be_bytes())?;
    store
        .vault_meta
        .put(txn, &key(DIRTY, id), &revision.to_be_bytes())?;
    Ok(())
}
fn issue_key(issue: &LinearIssueRef) -> Vec<u8> {
    // issue ids are globally scoped; identifiers and teams may change.
    [ISSUE, issue.issue_id.as_bytes()].concat()
}
fn read_link(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<Option<TaskIssueLink>> {
    vault
        .store
        .vault_meta
        .get(txn, &linear_sync_link_key(task))?
        .map(|raw| serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("linear link")))
        .transpose()
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
        self.vault
            .store
            .vault_meta
            .prefix_iter(&txn, DIRTY)?
            .map(|row| {
                let (key, raw) = row?;
                Ok((
                    EntityId::from_bytes(
                        key[DIRTY.len()..]
                            .try_into()
                            .map_err(|_| Error::CorruptedIndex("linear outbox id"))?,
                    )?,
                    u64::from_be_bytes(
                        raw.as_ref()
                            .try_into()
                            .map_err(|_| Error::CorruptedIndex("linear outbox revision"))?,
                    ),
                ))
            })
            .collect()
    }
    pub fn acknowledge_push(&self, task: EntityId, expected_revision: u64) -> Result<bool> {
        self.vault.with_write_txn(|txn| {
            let key = key(DIRTY, task);
            if self
                .vault
                .store
                .vault_meta
                .get(txn, &key)?
                .is_some_and(|raw| raw.as_ref() == expected_revision.to_be_bytes())
            {
                return Ok(self.vault.store.vault_meta.delete(txn, &key)?);
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
        let Some(raw) = self.vault.store.vault_meta.get(&txn, &issue_key(issue))? else {
            return Ok(None);
        };
        let task = EntityId::from_bytes(
            raw.as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("linear reverse link"))?,
        )?;
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
            if self
                .vault
                .store
                .vault_meta
                .get(txn, &reverse)?
                .is_some_and(|raw| raw.as_ref() != link.task_ref.as_bytes())
            {
                return Err(LinearSyncError::LinkConflict { expected, found });
            }
            if let Some(old) = old
                && old.issue.issue_id != link.issue.issue_id
            {
                self.vault
                    .store
                    .vault_meta
                    .delete(txn, &issue_key(&old.issue))?;
            }
            let raw = serde_json::to_vec(link)
                .map_err(|_| Error::InvariantViolation("linear link encoding"))?;
            self.vault
                .store
                .vault_meta
                .put(txn, &linear_sync_link_key(link.task_ref), &raw)?;
            self.vault
                .store
                .vault_meta
                .put(txn, &reverse, link.task_ref.as_bytes())?;
            Ok(())
        })
    }
}

const PULL_CURSOR: &[u8] = b"linear.pull_cursor.v1";
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
            self.tasks()
                .vault
                .store
                .vault_meta
                .get(&txn, PULL_CURSOR)?
                .map(|raw| {
                    String::from_utf8(raw.to_vec())
                        .map_err(|_| Error::CorruptedIndex("linear pull cursor"))
                })
                .transpose()?
        };
        let pulled = self.pull_page(cursor.as_deref(), now)?;
        if let Some(cursor) = &pulled.new_cursor {
            self.tasks().vault.with_write_txn(|txn| {
                self.tasks()
                    .vault
                    .store
                    .vault_meta
                    .put(txn, PULL_CURSOR, cursor.as_bytes())?;
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
    store.vault_meta.delete(txn, &key(DIRTY, id))?;
    let link_key = linear_sync_link_key(id);
    if let Some(raw) = store.vault_meta.get(txn, &link_key)? {
        let link: TaskIssueLink =
            serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("linear link"))?;
        store.vault_meta.delete(txn, &issue_key(&link.issue))?;
        store.vault_meta.delete(txn, &link_key)?;
    }
    Ok(())
}
