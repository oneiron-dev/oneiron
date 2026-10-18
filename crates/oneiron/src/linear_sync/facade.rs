//! The TASK ↔ issue mirror doors (OF-427 C6, C7).
//!
//! The two reads need the TASK readable by the caller, as the facade's
//! readable-ref admission already checked at the door, and return only refs
//! the caller's read scope passes. A mapping edit needs the caller's Owner
//! standing on the TASK through L02's rule, never a body field, compares the
//! TASK's mapping revision and answers a replay of its intent key from the
//! row it recorded. A link carries no common base, so every field that
//! differs at the next inbound event is a conflict, never a silent winner.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_OFF_RECORD_SESSION_DOOR, Memory, MemoryError,
    MemoryResult,
};
use crate::registry::ENTITY_TYPE_TASK;

use super::facade_types::{
    LINEAR_PROVENANCE_PAGE_DEFAULT, LINEAR_PROVENANCE_PAGE_MAX, LinearLinkView, LinearMappingEdit,
    LinearMappingEditReceipt, LinearMappingOp, LinearMappingRequest, LinearMappingView,
    LinearProvenanceEntry, LinearProvenancePage, LinearProvenanceRequest,
};
use super::mirror_event::{
    EventCursor, EventDirection, EventKey, LinearMirrorEvent, control_in, event_in, mapping_key,
    put_control_in, put_event_in, request_digest, task_events_in,
};
use super::model::{LinearIssueRef, LinearSyncDirection, LinearSyncError, TaskIssueLink};

/// A cursor's width: the row's time, then its key.
const CURSOR_BYTES: usize = 8 + 33;

fn mirror_error(error: LinearSyncError) -> MemoryError {
    match error {
        LinearSyncError::Store(error) => MemoryError::from(error),
        other => MemoryError::new(MEMORY_CODE_INVALID_STATE, other.to_string(), &[]),
    }
}

fn refusal(message: &str, suggestion: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[suggestion])
}

fn cursor_hex((at, key): EventCursor) -> String {
    let mut bytes = Vec::with_capacity(CURSOR_BYTES);
    bytes.extend_from_slice(&at.to_be_bytes());
    bytes.extend_from_slice(&key);
    bytes_to_hex_lower(&bytes)
}

fn parse_cursor(text: &str) -> MemoryResult<EventCursor> {
    let invalid = || MemoryError::bad_request("cursor is not a provenance page cursor");
    if text.len() != CURSOR_BYTES * 2 || !text.is_ascii() {
        return Err(invalid());
    }
    let mut bytes = [0; CURSOR_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(|_| invalid())?;
    }
    let mut at = [0; 8];
    at.copy_from_slice(&bytes[..8]);
    let mut key: EventKey = [0; 33];
    key.copy_from_slice(&bytes[8..]);
    Ok((u64::from_be_bytes(at), key))
}

fn link_view(link: TaskIssueLink) -> LinearLinkView {
    LinearLinkView {
        issue: link.issue,
        link_revision: link.link_revision,
        task_revision: link.task_revision,
        issue_updated_at_ms: link.issue_updated_at_ms,
        unresolved_conflicts: link.unresolved_conflicts,
    }
}

/// The artifact a provider-event payload ref names (`blob:<hex>@<version>`).
fn payload_artifact(payload_ref: &str) -> Option<EntityId> {
    let (artifact, _) = payload_ref.strip_prefix("blob:")?.split_once('@')?;
    EntityId::from_hex(artifact).ok()
}

/// The vault rows one event row names by ref.
fn named_rows(row: &LinearMirrorEvent) -> impl Iterator<Item = EntityId> {
    row.writer_actor
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .into_iter()
        .chain(row.payload_ref.as_deref().and_then(payload_artifact))
}

/// `row` without the refs `readable` does not hold.
fn withhold(row: &mut LinearMirrorEvent, readable: &BTreeSet<EntityId>) {
    let unread = |id: Option<EntityId>| id.is_some_and(|id| !readable.contains(&id));
    if unread(
        row.writer_actor
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok()),
    ) {
        row.writer_actor = None;
        row.writer_class = None;
    }
    if unread(row.payload_ref.as_deref().and_then(payload_artifact)) {
        row.payload_ref = None;
    }
}

/// A mapping edit's link of `task` to `issue`. It has no common base and no
/// remote witness: every field that differs at the next inbound event is a
/// conflict (both sides read as moved), and the scheduler holds the TASK's
/// pushes until that event.
fn unbased_link(task: EntityId, issue: LinearIssueRef, revision: u64, now: u64) -> TaskIssueLink {
    TaskIssueLink {
        task_ref: task,
        issue,
        task_revision: revision,
        issue_updated_at_ms: 0,
        seen_event_digests: BTreeSet::new(),
        last_operation_id: [0; 32],
        last_direction: LinearSyncDirection::IssueToTask,
        base_field_hashes: BTreeMap::new(),
        remote_field_hashes: BTreeMap::new(),
        unresolved_conflicts: Vec::new(),
        link_revision: 0,
        updated_at: now,
    }
}

/// The receipt a replayed intent key answers; another edit under it refuses.
fn replayed_edit(row: &LinearMirrorEvent, digest: &str) -> MemoryResult<LinearMappingEditReceipt> {
    if row.body_digest.as_deref() != Some(digest) {
        return Err(MemoryError::bad_request_with(
            "this intent key already names another mapping edit",
            &["Re-issue the same edit, or use a new intent key."],
        ));
    }
    let mut receipt: LinearMappingEditReceipt = row
        .receipt
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .ok_or(Error::CorruptedIndex("linear mapping edit receipt"))?;
    receipt.replayed = true;
    Ok(receipt)
}

impl Memory<'_> {
    /// The TASK `task_ref` names, when this handle's credential reads it.
    fn mirror_task(&self, task_ref: &str) -> MemoryResult<EntityId> {
        let task = EntityId::from_hex(task_ref)?;
        if self
            .credential_readable_ids(&[task])?
            .is_some_and(|readable| readable.is_empty())
        {
            return Err(MemoryError::from(Error::EntityNotFound));
        }
        Ok(task)
    }

    /// `vault.tasks.linear.mapping`: one TASK's link, watermarks, unresolved
    /// conflicts, opt-out, mapping and dirty revisions, and its newest event
    /// rows (OF-427 C7).
    pub fn linear_mapping(&self, input: &LinearMappingRequest) -> MemoryResult<LinearMappingView> {
        let task = self.mirror_task(&input.task_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let state = crate::task_verb::linear_effect_state_in_txn(vault, &txn, task)
            .map_err(mirror_error)?;
        let control = control_in(vault, &txn, task)?;
        let (events, _) = task_events_in(
            vault,
            &txn,
            task,
            None,
            LINEAR_PROVENANCE_PAGE_DEFAULT as usize,
        )?;
        drop(txn);
        self.produced_from([task]);
        Ok(LinearMappingView {
            task_ref: task.to_hex(),
            task_revision: state.revision,
            link: state.link.map(link_view),
            opted_out: control.opted_out,
            mapping_revision: control.mapping_revision,
            dirty_revision: state.dirty_revision,
            newest_event_refs: events
                .iter()
                .map(|(key, _)| bytes_to_hex_lower(key))
                .collect(),
        })
    }

    /// `vault.tasks.linear.provenance`: one TASK's stored mirror events,
    /// newest first, one cursor page at a time (OF-427 C7). A writer or a
    /// payload the caller does not read is left out of its row.
    pub fn linear_provenance(
        &self,
        input: &LinearProvenanceRequest,
    ) -> MemoryResult<LinearProvenancePage> {
        let task = self.mirror_task(&input.task_ref)?;
        let limit = input.limit.unwrap_or(LINEAR_PROVENANCE_PAGE_DEFAULT);
        if limit == 0 || limit > LINEAR_PROVENANCE_PAGE_MAX {
            return Err(MemoryError::bad_request(format!(
                "limit must be 1 to {LINEAR_PROVENANCE_PAGE_MAX}"
            )));
        }
        let after = input.cursor.as_deref().map(parse_cursor).transpose()?;
        let vault = self.vault();
        let (rows, next) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            if vault.get_entity_type_in_txn(&txn, &task)? != Some(ENTITY_TYPE_TASK) {
                return Err(MemoryError::from(Error::EntityNotFound));
            }
            task_events_in(vault, &txn, task, after, limit as usize)?
        };
        let named: Vec<EntityId> = rows.iter().flat_map(|(_, row)| named_rows(row)).collect();
        let readable = self.credential_readable_ids(&named)?;
        let events: Vec<LinearProvenanceEntry> = rows
            .into_iter()
            .map(|(key, mut event)| {
                if let Some(readable) = &readable {
                    withhold(&mut event, readable);
                }
                LinearProvenanceEntry {
                    event_ref: bytes_to_hex_lower(&key),
                    event,
                }
            })
            .collect();
        self.produced_from(
            std::iter::once(task).chain(events.iter().flat_map(|entry| named_rows(&entry.event))),
        );
        Ok(LinearProvenancePage {
            task_ref: task.to_hex(),
            events,
            next_cursor: next.map(cursor_hex),
        })
    }

    /// `vault.tasks.linear.mapping.edit`: one link, unlink or mirror of one
    /// TASK by its owner, at the mapping revision the caller read (OF-427
    /// C6). `team_id` is the host's configured tracker team a link names;
    /// with none a link refuses.
    pub fn linear_mapping_edit(
        &self,
        input: &LinearMappingEdit,
        team_id: Option<&str>,
    ) -> MemoryResult<LinearMappingEditReceipt> {
        let task = self.mirror_task(&input.task_ref)?;
        if input.intent_key.trim().is_empty() {
            return Err(MemoryError::bad_request("intent_key must not be blank"));
        }
        if self.keeps_no_record() {
            return Err(MemoryError::new(
                MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
                "a mirror mapping edit is recorded, so an off-record session makes none",
                &["Edit the mapping outside the off-record session."],
            ));
        }
        let op = serde_json::to_vec(&input.op)
            .map_err(|_| MemoryError::bad_request("the mapping edit does not encode"))?;
        let digest = request_digest(&[task.as_bytes(), &op]);
        let key = mapping_key(task, &input.intent_key);
        let vault = self.vault();
        let now = vault.now_recorded_at();
        self.with_verified_actor_write_txn(|wtxn| {
            if let Some(row) = event_in(vault, wtxn, &key)? {
                return replayed_edit(&row, &digest);
            }
            crate::task_verb::prove_task_owner_in(self, wtxn, task)?;
            let mut control = control_in(vault, wtxn, task)?;
            if control.mapping_revision != input.expected_mapping_revision {
                return Err(refusal(
                    "the TASK's mirror mapping moved",
                    "Read the mapping again and edit at its current revision.",
                ));
            }
            let (issue, opted_out) = self.mapping_op_in(wtxn, task, &input.op, team_id, now)?;
            control.opted_out = opted_out;
            control.mapping_revision = control
                .mapping_revision
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("linear mapping revision"))?;
            let receipt = LinearMappingEditReceipt {
                task_ref: task.to_hex(),
                op: input.op.as_str().to_owned(),
                mapping_revision: control.mapping_revision,
                opted_out,
                issue,
                event_ref: bytes_to_hex_lower(&key),
                replayed: false,
                at: now,
            };
            let json = serde_json::to_string(&receipt)
                .map_err(|_| Error::InvariantViolation("linear mapping receipt encoding"))?;
            control.last_intent_key = Some(input.intent_key.clone());
            control.last_receipt = Some(json.clone());
            control.by = Some(self.actor().to_hex());
            control.at = now;
            put_control_in(vault, wtxn, task, &control)?;
            let mut row =
                LinearMirrorEvent::blank(EventDirection::MappingEdit, input.op.as_str(), now);
            row.task_ref = Some(task.to_hex());
            row.issue.clone_from(&receipt.issue);
            row.body_digest = Some(digest.clone());
            row.written_by(self.actor(), self.actor_class());
            row.receipt = Some(json);
            put_event_in(vault, wtxn, &key, &row)?;
            Ok(receipt)
        })
    }

    /// Runs one mapping op on `task` in `wtxn`: the issue it linked or
    /// unlinked, and whether the TASK is opted out after it.
    fn mapping_op_in(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task: EntityId,
        op: &LinearMappingOp,
        team_id: Option<&str>,
        now: u64,
    ) -> MemoryResult<(Option<LinearIssueRef>, bool)> {
        let vault = self.vault();
        let state = crate::task_verb::linear_effect_state_in_txn(vault, wtxn, task)
            .map_err(mirror_error)?;
        let linked = || {
            refusal(
                "the TASK is already linked to an issue",
                "Unlink the TASK first.",
            )
        };
        match op {
            LinearMappingOp::Link {
                issue_id,
                identifier,
            } => {
                let team = team_id
                    .filter(|team| !team.trim().is_empty())
                    .ok_or_else(|| {
                        refusal(
                            "this host configures no Linear tracker team",
                            "Configure the Linear tracker mapping on the host.",
                        )
                    })?;
                if issue_id.trim().is_empty() || identifier.trim().is_empty() {
                    return Err(MemoryError::bad_request(
                        "issue_id and identifier must not be blank",
                    ));
                }
                if state.link.is_some() {
                    return Err(linked());
                }
                if crate::task_verb::linear_issue_task_in(vault, wtxn, issue_id)?.is_some() {
                    return Err(refusal(
                        "the issue is already linked to another TASK",
                        "Unlink that TASK first.",
                    ));
                }
                let issue = LinearIssueRef {
                    issue_id: issue_id.clone(),
                    team_id: team.to_owned(),
                    identifier: identifier.clone(),
                };
                let link = unbased_link(task, issue.clone(), state.revision, now);
                crate::task_verb::put_mirror_link_in(vault, wtxn, &link)?;
                Ok((Some(issue), false))
            }
            LinearMappingOp::Unlink => {
                let link = state.link.ok_or_else(|| {
                    refusal(
                        "the TASK is not linked to an issue",
                        "Link it, or mirror it to create a fresh issue.",
                    )
                })?;
                crate::task_verb::drop_mirror_link_in(vault, wtxn, task)?;
                Ok((Some(link.issue), true))
            }
            LinearMappingOp::Mirror => {
                if state.link.is_some() {
                    return Err(linked());
                }
                crate::task_verb::mark_mirror_dirty_in(
                    vault,
                    wtxn,
                    task,
                    self.actor(),
                    self.actor_class(),
                )?;
                Ok((None, false))
            }
        }
    }
}
