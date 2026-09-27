//! Vault storage for the tracker mirror: replicated fields, local OCC and CAS links.
use super::wire_decode::{task_body_has_typed_subkind, task_verb_body_in};
use super::wire_encode::encode_task_verb_body;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::linear_sync::*;
use crate::store::Store;
use crate::{EntityId, Vault};

const REVISION: &[u8] = b"linear.task_revision.v1/";
const DIRTY: &[u8] = b"linear.task_dirty.v1/";
const WRITER: &[u8] = b"linear.task_writer.v1/";
const ISSUE: &[u8] = b"linear.issue.v1/";
const CREATE_INTENT: &[u8] = b"linear.create_intent.v1/";
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
    store.vault_meta.put(txn, &key(WRITER, task), &value)?;
    Ok(())
}

fn writer_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<Option<LinearWriteActor>> {
    let Some(raw) = store.vault_meta.get(txn, &key(WRITER, task))? else {
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
    store
        .vault_meta
        .put(txn, &key(REVISION, id), &revision.to_be_bytes())?;
    store
        .vault_meta
        .put(txn, &key(DIRTY, id), &revision.to_be_bytes())?;
    store.vault_meta.delete(txn, &key(WRITER, id))?;
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

/// One locked view for the external Linear effect door. No provider bytes.
pub(crate) struct LinearEffectState {
    pub revision: u64,
    pub dirty_revision: Option<u64>,
    pub link: Option<TaskIssueLink>,
    pub create_intent: Option<LinearCreateIntent>,
    pub writer: Option<LinearWriteActor>,
}

pub(crate) fn linear_effect_state_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
) -> Result<LinearEffectState> {
    let dirty_revision = vault
        .store
        .vault_meta
        .get(txn, &key(DIRTY, task))?
        .map(|raw| {
            raw.as_ref()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::CorruptedIndex("linear dirty revision"))
        })
        .transpose()?;
    let create_intent = vault
        .store
        .vault_meta
        .get(txn, &key(CREATE_INTENT, task))?
        .map(|raw| {
            serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("linear create intent"))
        })
        .transpose()?;
    Ok(LinearEffectState {
        revision: revision(&vault.store, txn, task)?,
        dirty_revision,
        link: read_link(vault, txn, task)?,
        create_intent,
        writer: writer_in_txn(&vault.store, txn, task)?,
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

    /// Frozen first-create intent, retained through lost responses and removed
    /// in the same transaction that creates the link.
    pub fn create_intent_for(
        &self,
        task: EntityId,
    ) -> LinearSyncResult<Option<LinearCreateIntent>> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        self.vault
            .store
            .vault_meta
            .get(&txn, &key(CREATE_INTENT, task))?
            .map(|raw| {
                serde_json::from_slice(&raw)
                    .map_err(|_| Error::CorruptedIndex("linear create intent").into())
            })
            .transpose()
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
                return self.vault.store.vault_meta.delete(txn, &key);
            }
            Ok(false)
        })
    }
}
impl LinearTaskStore for VaultLinearTaskStore<'_> {
    fn create_intent(
        &mut self,
        draft: &LinearCreateIntent,
    ) -> LinearSyncResult<LinearCreateIntent> {
        self.vault.try_with_write_txn(|txn| {
            self.snapshot(txn, draft.task_ref)?;
            if let Some(link) = read_link(self.vault, txn, draft.task_ref)? {
                return Err(LinearSyncError::LinkConflict {
                    expected: None,
                    found: Some(link.link_revision),
                });
            }
            let key = key(CREATE_INTENT, draft.task_ref);
            if let Some(raw) = self.vault.store.vault_meta.get(txn, &key)? {
                let stored: LinearCreateIntent = serde_json::from_slice(&raw)
                    .map_err(|_| Error::CorruptedIndex("linear create intent"))?;
                if stored.task_ref != draft.task_ref
                    || stored.operation_id == [0; 32]
                    || stored.writer.is_none()
                {
                    return Err(Error::CorruptedIndex("linear create intent identity").into());
                }
                return Ok(stored);
            }
            let writer = writer_in_txn(&self.vault.store, txn, draft.task_ref)?
                .ok_or(LinearSyncError::AuthorizationDenied)?;
            let created = LinearCreateIntent {
                writer: Some(writer),
                ..draft.clone()
            };
            let raw = serde_json::to_vec(&created)
                .map_err(|_| Error::InvariantViolation("linear create intent encoding"))?;
            self.vault.store.vault_meta.put(txn, &key, &raw)?;
            Ok(created)
        })
    }

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
            if expected.is_none() {
                self.vault
                    .store
                    .vault_meta
                    .delete(txn, &key(CREATE_INTENT, link.task_ref))?;
            }
            Ok(())
        })
    }
}

const PULL_CURSOR: &[u8] = b"linear.pull_cursor.v1";
impl<I: LinearChangeSource, O: LinearEgress> LinearSyncAdapter<VaultLinearTaskStore<'_>, I, O> {
    /// Scheduled host entry: pull one source page before draining TASK writes.
    /// A pending page defers outbound writes, so the remote conflict barrier
    /// is caught up before a dirty TASK can overwrite tracker fields.
    /// Errors retain dirty revisions/cursor for retry. The injected egress is
    /// still the authenticated OF-327 rail, never a credential in core.
    pub fn synchronize(
        &mut self,
        now: u64,
    ) -> LinearSyncResult<(Vec<LinearMirrorReceipt>, LinearPullReceipt)> {
        // Pull first. Pushing a dirty TASK before observing a remote edit
        // would overwrite the tracker field before the conflict barrier has a
        // chance to see it. A pending source page defers outbound writes;
        // even a final nonempty page still carries a durable checkpoint.
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
        let mut pulled = self.pull_page(cursor.as_deref(), now)?;
        if pulled.has_more && pulled.new_cursor.is_none() {
            return Err(LinearSyncError::Store(Error::InvariantViolation(
                "linear page continuation without checkpoint",
            )));
        }
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
        if pulled.has_more {
            return Ok((Vec::new(), pulled));
        }
        let mut pushed = Vec::new();
        for (task, revision) in self.tasks().dirty_tasks()? {
            match self.push_task(task, now) {
                Ok(receipt) => {
                    let created_snapshot_matches = if receipt.status == LinearMirrorStatus::Linked {
                        let link = self
                            .tasks()
                            .link(task)?
                            .ok_or(Error::InvariantViolation("linked Linear TASK missing link"))?;
                        self.tasks().task_snapshot(task)?.fields.field_hashes()
                            == link.base_field_hashes
                    } else {
                        true
                    };
                    if receipt.status != LinearMirrorStatus::Conflict && created_snapshot_matches {
                        self.tasks().acknowledge_push(task, revision)?;
                    }
                    pushed.push(receipt);
                }
                Err(
                    LinearSyncError::AssigneeUnmapped
                    | LinearSyncError::CreateConflict
                    | LinearSyncError::AuthorizationDenied,
                ) => {
                    // One unmirrorable TASK cannot hold every later dirty row.
                    // Keep this exact revision in the durable outbox for repair.
                    pulled.refused_outbound.push(task);
                }
                Err(error) => return Err(error),
            }
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
    store.vault_meta.delete(txn, &key(WRITER, id))?;
    store.vault_meta.delete(txn, &key(CREATE_INTENT, id))?;
    let link_key = linear_sync_link_key(id);
    if let Some(raw) = store.vault_meta.get(txn, &link_key)? {
        let link: TaskIssueLink =
            serde_json::from_slice(&raw).map_err(|_| Error::CorruptedIndex("linear link"))?;
        store.vault_meta.delete(txn, &issue_key(&link.issue))?;
        store.vault_meta.delete(txn, &link_key)?;
    }
    Ok(())
}
