//! Issue-tracker mirror adapter: one TASK ↔ one Linear issue, bidirectional,
//! conflict-surfacing (ONE-1905, CSTDY-05).
//!
//! The engine stays generic; only this module knows an issue tracker exists.
//! It follows the OF-201-class registry shape (a typed adapter registration
//! plus normalized change records) but deliberately does NOT implement
//! [`crate::ingest::IngestSource`]: an issue event is a mirror delta against a
//! durable link, not transcript ingest, and normalizing it into turns would
//! put tracker rows on the memory path.
//!
//! The load-bearing rules:
//!
//! * **one durable link, two watermarks, per-field bases** — [`TaskIssueLink`]
//!   pins the TASK revision, the Linear `updated_at`, and the per-field hash of
//!   the LAST-SYNCHRONIZED value. Two coarse watermarks cannot attribute a
//!   change to a side; the base hashes can, which is what makes per-field
//!   conflict detection decidable from the stored snapshot alone.
//! * **echo cannot bounce** — applying EITHER direction advances BOTH
//!   watermarks and stamps the stable operation id, so our own write coming
//!   back as an inbound event is a [`LinearMirrorStatus::Noop`], and an inbound
//!   apply does not re-push. Outbound idempotency is keyed by
//!   `(task_ref, task_revision, operation_kind)`; inbound by
//!   `(issue_id, issue_updated_at_ms, event_id)`.
//! * **deterministic field ownership** — identity, `blocked_by`, run-result
//!   refs and readiness are ENGINE-AUTHORITATIVE and never mirror inbound;
//!   title / description / priority / assignee / status are bidirectional and
//!   apply only when exactly one side moved. Same-field concurrent edits become
//!   a durable [`LinearMirrorReceipt`] with status
//!   [`LinearMirrorStatus::Conflict`] that mutates NEITHER side — there is no
//!   silent last-write-wins anywhere in this module.
//! * **no credential in core** — no token, provider client, or HTTP lives
//!   here. [`LinearEgress`] is the host boundary that crosses the existing
//!   outbound door, so every test in this crate runs on fakes with no Linear
//!   workspace in sight.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

/// Wire version of the mirror link rows and receipts.
pub const LINEAR_SYNC_SCHEMA_VERSION: u8 = 1;

/// Durable key prefix of the TASK ↔ issue link row.
pub const LINEAR_SYNC_LINK_KEY_PREFIX: &[u8] = b"linear_sync:link:v1:";

/// Domain separator for [`linear_operation_id`]; pinned, because operation ids
/// are compared across processes and replicas to suppress duplicate writes.
pub const LINEAR_SYNC_OPERATION_DOMAIN: &[u8] = b"oneiron:linear-sync-op:v1";

/// Stable adapter id in the registry shape.
pub const LINEAR_SYNC_ADAPTER_ID: &str = "linear";

/// Bidirectional field: issue title.
pub const LINEAR_FIELD_TITLE: &str = "title";
/// Bidirectional field: issue description / TASK body.
pub const LINEAR_FIELD_DESCRIPTION: &str = "description";
/// Bidirectional field: issue priority.
pub const LINEAR_FIELD_PRIORITY: &str = "priority";
/// Bidirectional field: assignee reference.
pub const LINEAR_FIELD_ASSIGNEE_REF: &str = "assignee_ref";
/// Bidirectional field: workflow status.
pub const LINEAR_FIELD_STATUS: &str = "status";

/// Every bidirectional field, in stable (sorted) order.
pub const LINEAR_MIRRORED_FIELDS: [&str; 5] = [
    LINEAR_FIELD_ASSIGNEE_REF,
    LINEAR_FIELD_DESCRIPTION,
    LINEAR_FIELD_PRIORITY,
    LINEAR_FIELD_STATUS,
    LINEAR_FIELD_TITLE,
];

/// Engine-authoritative facts that never take an inbound value: the mirror
/// projects them outward and refuses to read them back.
pub const LINEAR_ENGINE_AUTHORITATIVE_FIELDS: [&str; 4] =
    ["blocked_by", "identity", "readiness", "run_result_refs"];

const LINEAR_SYNC_FIELD_DOMAIN: &[u8] = b"oneiron:linear-sync-field:v1";

const ERR_UNLINKED_ISSUE: &str = "linear_sync: issue change has no durable TASK link";

/// Which way one mirror operation moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearSyncDirection {
    /// Engine → tracker.
    TaskToIssue,
    /// Tracker → engine.
    IssueToTask,
}

impl LinearSyncDirection {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TaskToIssue => "task_to_issue",
            Self::IssueToTask => "issue_to_task",
        }
    }
}

/// Outcome of one mirror operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinearMirrorStatus {
    /// A new issue was created and linked to the TASK.
    Linked,
    /// Field values were written to the other side.
    Applied,
    /// Nothing to do: unchanged, already applied, or our own echo.
    Noop,
    /// Same-field concurrent edit; NEITHER side was mutated.
    Conflict,
}

impl LinearMirrorStatus {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Applied => "applied",
            Self::Noop => "noop",
            Self::Conflict => "conflict",
        }
    }
}

/// The tracker-side identity of a mirrored issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearIssueRef {
    /// Opaque tracker id; the join key of the link row.
    pub issue_id: String,
    /// Owning team id.
    pub team_id: String,
    /// Human-facing identifier (e.g. `ENG-123`).
    pub identifier: String,
}

/// The durable one-to-one link between a TASK and an issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskIssueLink {
    /// The mirrored TASK entity.
    pub task_ref: EntityId,
    /// The mirrored issue.
    pub issue: LinearIssueRef,
    /// Watermark: the TASK revision this link last synchronized.
    pub task_revision: u64,
    /// Watermark: the tracker `updated_at` this link last synchronized.
    pub issue_updated_at_ms: u64,
    /// Operation id of the write that produced this state.
    pub last_operation_id: [u8; 32],
    /// Direction of the write that produced this state.
    pub last_direction: LinearSyncDirection,
    /// Per-field hashes of the LAST-SYNCHRONIZED value of every bidirectional
    /// field (the common base). This is what makes per-field conflict
    /// detection decidable: a side changed a field iff its current value hash
    /// differs from the base hash. Same field changed on both sides ⇒ conflict
    /// (surface, don't overwrite); disjoint fields ⇒ merge. Without the base,
    /// two coarse watermarks cannot attribute changes. Updated atomically with
    /// every successful push/pull.
    pub base_field_hashes: BTreeMap<String, [u8; 32]>,
    /// Wall-clock stamp of the last link write.
    pub updated_at: u64,
}

/// The bidirectional field set, in the engine's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredTaskFields {
    /// Short title.
    pub title: String,
    /// Long-form body.
    pub description: Option<String>,
    /// Tracker priority scale, passed through untyped.
    pub priority: Option<u8>,
    /// Assignee reference, rendered by the host.
    pub assignee_ref: Option<String>,
    /// Workflow status token.
    pub status: String,
}

impl MirroredTaskFields {
    /// The rendered value of one bidirectional field, or `None` when the field
    /// is unset or unknown.
    #[must_use]
    pub fn field_value(&self, field: &str) -> Option<String> {
        match field {
            LINEAR_FIELD_TITLE => Some(self.title.clone()),
            LINEAR_FIELD_DESCRIPTION => self.description.clone(),
            LINEAR_FIELD_PRIORITY => self.priority.map(|priority| priority.to_string()),
            LINEAR_FIELD_ASSIGNEE_REF => self.assignee_ref.clone(),
            LINEAR_FIELD_STATUS => Some(self.status.clone()),
            _ => None,
        }
    }

    /// Per-field hashes of the CURRENT values, in the shape
    /// [`TaskIssueLink::base_field_hashes`] stores.
    #[must_use]
    pub fn field_hashes(&self) -> BTreeMap<String, [u8; 32]> {
        LINEAR_MIRRORED_FIELDS
            .iter()
            .map(|field| {
                let value = self.field_value(field);
                ((*field).to_owned(), field_hash(value.as_deref()))
            })
            .collect()
    }
}

/// One normalized inbound change record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearIssueChange {
    /// Tracker event id; third component of the inbound idempotency key.
    pub event_id: String,
    /// The issue the change belongs to.
    pub issue: LinearIssueRef,
    /// Tracker `updated_at` in epoch milliseconds.
    pub updated_at_ms: u64,
    /// Issue-side values after the change.
    pub fields: MirroredTaskFields,
}

/// Result alias for the mirror adapter.
pub type LinearSyncResult<T> = Result<T, LinearSyncError>;

/// Result alias used by [`crate::wave_orchestration`]; the same error domain,
/// kept for readability at the call site.
pub type WaveResult<T> = Result<T, LinearSyncError>;

/// Failure domain shared by the mirror adapter and wave orchestration.
#[derive(Debug, thiserror::Error)]
pub enum LinearSyncError {
    /// Host transport (HTTP / GraphQL) failure; retryable.
    #[error("linear transport failure: {0}")]
    Transport(String),
    /// Optimistic-concurrency miss: the TASK moved under the operation.
    #[error("linear mirror revision conflict: expected {expected_revision}, found {found}")]
    Conflict {
        /// Revision the operation was built against.
        expected_revision: u64,
        /// Revision the store actually holds.
        found: u64,
    },
    /// Engine storage or invariant failure.
    #[error(transparent)]
    Store(#[from] crate::error::Error),
}

/// One page of normalized inbound changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearChangePage {
    /// Changes in ascending `updated_at_ms` order.
    pub changes: Vec<LinearIssueChange>,
    /// Cursor for the next page; `None` means caught up.
    pub next_cursor: Option<String>,
}

/// What one pull pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearPullReceipt {
    /// Changes that mutated TASK fields.
    pub applied: usize,
    /// Changes the pass deliberately did not apply: our own echoes, replays
    /// already behind the watermark, and issues this vault does not mirror.
    pub skipped_echo: usize,
    /// Durable conflict receipts minted by this pass; each mutated neither
    /// side and needs a human (or a later one-sided edit) to resolve.
    pub conflicts: Vec<LinearMirrorReceipt>,
    /// Cursor to resume from; `None` means caught up.
    pub new_cursor: Option<String>,
    /// Wall-clock stamp of the pass.
    pub pulled_at: u64,
}

/// The mirror-state read.
///
/// Carries the stored watermarks, so "changed since the watermark" — the echo
/// suppression and conflict rules — is decidable from the snapshot plus the
/// link alone, with no extra tracker round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMirrorSnapshot {
    /// The TASK entity.
    pub task_ref: EntityId,
    /// The linked issue, when the TASK is already mirrored.
    pub issue: Option<LinearIssueRef>,
    /// Local optimistic-concurrency revision.
    pub revision: u64,
    /// Echo watermark: our most recent outbound write.
    pub last_pushed_at_ms: Option<u64>,
    /// Pull watermark from the tracker's `updated_at`.
    pub last_pulled_updated_at_ms: Option<u64>,
    /// Current bidirectional field values.
    pub fields: MirroredTaskFields,
}

/// Cursor-paged source of normalized inbound changes.
pub trait LinearChangeSource {
    /// Returns the page that starts at `cursor`.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the page cannot be fetched.
    fn changes_since(&mut self, cursor: Option<&str>) -> LinearSyncResult<LinearChangePage>;
}

/// The host/outbound-door boundary for tracker writes.
///
/// Implementations live OUTSIDE the engine and carry the credential; core
/// stores no token and holds no provider client. Both calls are keyed by an
/// engine-computed `operation_id`, so a retried call is a duplicate the host
/// can collapse.
pub trait LinearEgress {
    /// Creates the tracker issue that mirrors `task_ref`.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the create cannot be performed.
    fn create_issue(
        &mut self,
        operation_id: [u8; 32],
        task_ref: EntityId,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange>;

    /// Updates an already-linked tracker issue.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the update cannot be performed.
    fn update_issue(
        &mut self,
        operation_id: [u8; 32],
        issue: &LinearIssueRef,
        fields: &MirroredTaskFields,
    ) -> LinearSyncResult<LinearIssueChange>;
}

/// Engine-side storage the mirror reads and writes.
pub trait LinearTaskStore {
    /// Current mirror state of one TASK.
    ///
    /// # Errors
    ///
    /// Returns a store error when the TASK cannot be read.
    fn task_snapshot(&self, task_ref: EntityId) -> LinearSyncResult<TaskMirrorSnapshot>;

    /// Applies inbound field values under optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`LinearSyncError::Conflict`] when `expected_revision` is
    /// stale, or a store error when the write fails.
    fn apply_issue_fields(
        &mut self,
        task_ref: EntityId,
        expected_revision: u64,
        fields: &MirroredTaskFields,
        now: u64,
    ) -> LinearSyncResult<TaskMirrorSnapshot>;

    /// The link row of one TASK, if it is mirrored.
    ///
    /// # Errors
    ///
    /// Returns a store error when the link cannot be read.
    fn link(&self, task_ref: EntityId) -> LinearSyncResult<Option<TaskIssueLink>>;

    /// The link row of one issue — the reverse of [`LinearTaskStore::link`],
    /// which is how an inbound change finds its TASK.
    ///
    /// # Errors
    ///
    /// Returns a store error when the link cannot be read.
    fn link_for_issue(&self, issue: &LinearIssueRef) -> LinearSyncResult<Option<TaskIssueLink>>;

    /// Writes the link row.
    ///
    /// # Errors
    ///
    /// Returns a store error when the link cannot be written.
    fn put_link(&mut self, link: &TaskIssueLink) -> LinearSyncResult<()>;
}

/// One field both sides edited since the common base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearFieldConflict {
    /// The bidirectional field name.
    pub field: String,
    /// Engine-side value that was NOT overwritten.
    pub task_value: Option<String>,
    /// Tracker-side value that was NOT applied.
    pub issue_value: Option<String>,
}

/// The durable record of one mirror operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearMirrorReceipt {
    /// What happened.
    pub status: LinearMirrorStatus,
    /// Which way the operation moved.
    pub direction: LinearSyncDirection,
    /// Stable operation id; the idempotency handle on both sides.
    pub operation_id: [u8; 32],
    /// The mirrored TASK.
    pub task_ref: EntityId,
    /// The mirrored issue.
    pub issue: LinearIssueRef,
    /// Fields left untouched because both sides moved them.
    pub conflicts: Vec<LinearFieldConflict>,
    /// Wall-clock stamp of the operation.
    pub mirrored_at: u64,
}

/// Typed adapter registration in the OF-201 registry shape.
///
/// Deliberately NOT an [`crate::ingest::IngestSource`] registration: it
/// declares field ownership for a mirror, not a normalizer for transcript
/// ingest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinearSyncRegistration {
    /// Stable adapter id.
    pub adapter_id: &'static str,
    /// Wire version of the adapter's records.
    pub schema_version: u8,
    /// Fields that mirror in both directions.
    pub mirrored_fields: &'static [&'static str],
    /// Fields the engine owns outright.
    pub engine_authoritative_fields: &'static [&'static str],
}

/// The single registration this adapter publishes.
pub const LINEAR_SYNC_REGISTRATION: LinearSyncRegistration = LinearSyncRegistration {
    adapter_id: LINEAR_SYNC_ADAPTER_ID,
    schema_version: LINEAR_SYNC_SCHEMA_VERSION,
    mirrored_fields: &LINEAR_MIRRORED_FIELDS,
    engine_authoritative_fields: &LINEAR_ENGINE_AUTHORITATIVE_FIELDS,
};

/// The durable storage key of one TASK ↔ issue link row.
#[must_use]
pub fn linear_sync_link_key(task_ref: EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(LINEAR_SYNC_LINK_KEY_PREFIX.len() + 16);
    key.extend_from_slice(LINEAR_SYNC_LINK_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

/// The stable, domain-separated idempotency handle of one mirror operation.
///
/// Outbound callers pass `issue_updated_at_ms: None`, so the id is exactly the
/// `(task_ref, task_revision, operation_kind)` key — `issue_id: None` is a
/// create, `Some` is an update — and a retry of the same logical push
/// recomputes the same id. Inbound callers pass both, giving the
/// `(issue_id, issue_updated_at_ms)` key of the event being applied.
#[must_use]
pub fn linear_operation_id(
    direction: LinearSyncDirection,
    task_ref: EntityId,
    task_revision: u64,
    issue_id: Option<&str>,
    issue_updated_at_ms: Option<u64>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_OPERATION_DOMAIN);
    hasher.update(&[LINEAR_SYNC_SCHEMA_VERSION]);
    update_field(&mut hasher, Some(direction.as_str()));
    hasher.update(task_ref.as_bytes());
    hasher.update(&task_revision.to_le_bytes());
    update_field(&mut hasher, issue_id);
    match issue_updated_at_ms {
        Some(updated_at_ms) => {
            hasher.update(&[1]);
            hasher.update(&updated_at_ms.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Mirrors one TASK against one tracker issue.
#[derive(Debug)]
pub struct LinearSyncAdapter<T, I, O> {
    tasks: T,
    inbound: I,
    outbound: O,
}

impl<T, I, O> LinearSyncAdapter<T, I, O> {
    /// Wraps the three injected ports.
    pub const fn new(tasks: T, inbound: I, outbound: O) -> Self {
        Self {
            tasks,
            inbound,
            outbound,
        }
    }

    /// Borrows the task store.
    pub const fn tasks(&self) -> &T {
        &self.tasks
    }

    /// Mutably borrows the task store.
    pub fn tasks_mut(&mut self) -> &mut T {
        &mut self.tasks
    }

    /// Unwraps the three ports.
    pub fn into_parts(self) -> (T, I, O) {
        (self.tasks, self.inbound, self.outbound)
    }
}

impl<T: LinearTaskStore, I: LinearChangeSource, O: LinearEgress> LinearSyncAdapter<T, I, O> {
    /// Mirrors the current TASK state outward.
    ///
    /// Creates and links the issue on first push; afterwards pushes only when
    /// the TASK actually moved past the link's revision watermark. A repeated
    /// push of an already-mirrored revision recomputes the same operation id
    /// and returns [`LinearMirrorStatus::Noop`] without touching the tracker.
    ///
    /// # Errors
    ///
    /// Returns the store's or egress's error.
    pub fn push_task(
        &mut self,
        task_ref: EntityId,
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        let snapshot = self.tasks.task_snapshot(task_ref)?;
        let existing = self.tasks.link(task_ref)?;
        match existing {
            None => self.create_linked_issue(&snapshot, now),
            Some(link) => self.push_linked_issue(&snapshot, link, now),
        }
    }

    /// Pulls one page of inbound changes and applies what is applicable.
    ///
    /// # Errors
    ///
    /// Returns the change source's, store's, or egress's error.
    pub fn pull_page(
        &mut self,
        cursor: Option<&str>,
        now: u64,
    ) -> LinearSyncResult<LinearPullReceipt> {
        let page = self.inbound.changes_since(cursor)?;
        let mut applied = 0;
        let mut skipped_echo = 0;
        let mut conflicts = Vec::new();
        for change in page.changes {
            if self.tasks.link_for_issue(&change.issue)?.is_none() {
                skipped_echo += 1;
                continue;
            }
            let receipt = self.apply_issue_change(change, now)?;
            match receipt.status {
                LinearMirrorStatus::Applied => applied += 1,
                LinearMirrorStatus::Conflict => conflicts.push(receipt),
                LinearMirrorStatus::Linked | LinearMirrorStatus::Noop => skipped_echo += 1,
            }
        }
        Ok(LinearPullReceipt {
            applied,
            skipped_echo,
            conflicts,
            new_cursor: page.next_cursor,
            pulled_at: now,
        })
    }

    /// Applies one inbound change to its linked TASK.
    ///
    /// Suppresses echoes and replays by watermark and operation id, merges
    /// disjoint-field edits, and refuses same-field concurrent edits with a
    /// conflict receipt that mutates neither side.
    ///
    /// # Errors
    ///
    /// Returns an invariant violation when the issue has no durable link, or
    /// the store's error (including [`LinearSyncError::Conflict`] when the
    /// TASK moved under the apply).
    pub fn apply_issue_change(
        &mut self,
        change: LinearIssueChange,
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        let link = self
            .tasks
            .link_for_issue(&change.issue)?
            .ok_or_else(|| store_invariant(ERR_UNLINKED_ISSUE))?;
        let snapshot = self.tasks.task_snapshot(link.task_ref)?;
        let operation_id = linear_operation_id(
            LinearSyncDirection::IssueToTask,
            link.task_ref,
            snapshot.revision,
            Some(&change.issue.issue_id),
            Some(change.updated_at_ms),
        );
        if inbound_already_seen(&link, &snapshot, &change, operation_id) {
            return Ok(mirror_receipt(
                LinearMirrorStatus::Noop,
                LinearSyncDirection::IssueToTask,
                operation_id,
                link.task_ref,
                change.issue,
                Vec::new(),
                now,
            ));
        }

        let decision = decide_fields(&link.base_field_hashes, &snapshot.fields, &change.fields);
        if !decision.conflicts.is_empty() {
            return Ok(mirror_receipt(
                LinearMirrorStatus::Conflict,
                LinearSyncDirection::IssueToTask,
                operation_id,
                link.task_ref,
                change.issue,
                decision.conflicts,
                now,
            ));
        }
        if !decision.issue_changed {
            return self.absorb_inbound_echo(link, &change, operation_id, now);
        }

        let merged = merge_fields(&snapshot.fields, &change.fields, &decision.issue_wins);
        let applied = self
            .tasks
            .apply_issue_fields(link.task_ref, snapshot.revision, &merged, now)?;
        let updated = TaskIssueLink {
            task_ref: link.task_ref,
            issue: change.issue.clone(),
            task_revision: applied.revision,
            issue_updated_at_ms: change.updated_at_ms.max(link.issue_updated_at_ms),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::IssueToTask,
            base_field_hashes: merged.field_hashes(),
            updated_at: now,
        };
        self.tasks.put_link(&updated)?;
        Ok(mirror_receipt(
            LinearMirrorStatus::Applied,
            LinearSyncDirection::IssueToTask,
            operation_id,
            link.task_ref,
            change.issue,
            Vec::new(),
            now,
        ))
    }

    fn create_linked_issue(
        &mut self,
        snapshot: &TaskMirrorSnapshot,
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        let operation_id = linear_operation_id(
            LinearSyncDirection::TaskToIssue,
            snapshot.task_ref,
            snapshot.revision,
            None,
            None,
        );
        let created = self
            .outbound
            .create_issue(operation_id, snapshot.task_ref, &snapshot.fields)?;
        let link = TaskIssueLink {
            task_ref: snapshot.task_ref,
            issue: created.issue.clone(),
            task_revision: snapshot.revision,
            issue_updated_at_ms: created.updated_at_ms,
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::TaskToIssue,
            base_field_hashes: created.fields.field_hashes(),
            updated_at: now,
        };
        self.tasks.put_link(&link)?;
        Ok(mirror_receipt(
            LinearMirrorStatus::Linked,
            LinearSyncDirection::TaskToIssue,
            operation_id,
            snapshot.task_ref,
            created.issue,
            Vec::new(),
            now,
        ))
    }

    fn push_linked_issue(
        &mut self,
        snapshot: &TaskMirrorSnapshot,
        link: TaskIssueLink,
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        let operation_id = linear_operation_id(
            LinearSyncDirection::TaskToIssue,
            snapshot.task_ref,
            snapshot.revision,
            Some(&link.issue.issue_id),
            None,
        );
        let unchanged = snapshot.fields.field_hashes() == link.base_field_hashes;
        let already_pushed = snapshot.revision <= link.task_revision;
        let repeat_operation = operation_id == link.last_operation_id;
        if unchanged || already_pushed || repeat_operation {
            return Ok(mirror_receipt(
                LinearMirrorStatus::Noop,
                LinearSyncDirection::TaskToIssue,
                operation_id,
                snapshot.task_ref,
                link.issue,
                Vec::new(),
                now,
            ));
        }

        let pushed = self
            .outbound
            .update_issue(operation_id, &link.issue, &snapshot.fields)?;
        let updated = TaskIssueLink {
            task_ref: snapshot.task_ref,
            issue: pushed.issue.clone(),
            task_revision: snapshot.revision,
            issue_updated_at_ms: pushed.updated_at_ms.max(link.issue_updated_at_ms),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::TaskToIssue,
            base_field_hashes: pushed.fields.field_hashes(),
            updated_at: now,
        };
        self.tasks.put_link(&updated)?;
        Ok(mirror_receipt(
            LinearMirrorStatus::Applied,
            LinearSyncDirection::TaskToIssue,
            operation_id,
            snapshot.task_ref,
            pushed.issue,
            Vec::new(),
            now,
        ))
    }

    /// Advances the issue watermark for a change that carries no issue-side
    /// movement, so the same echo cannot come back a second time. No TASK
    /// field is touched.
    fn absorb_inbound_echo(
        &mut self,
        link: TaskIssueLink,
        change: &LinearIssueChange,
        operation_id: [u8; 32],
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        let task_ref = link.task_ref;
        let advanced = TaskIssueLink {
            issue_updated_at_ms: change.updated_at_ms.max(link.issue_updated_at_ms),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::IssueToTask,
            updated_at: now,
            ..link
        };
        self.tasks.put_link(&advanced)?;
        Ok(mirror_receipt(
            LinearMirrorStatus::Noop,
            LinearSyncDirection::IssueToTask,
            operation_id,
            task_ref,
            change.issue.clone(),
            Vec::new(),
            now,
        ))
    }
}

/// Per-field verdict of one inbound change against the stored base.
#[derive(Debug, Default)]
struct FieldDecision {
    conflicts: Vec<LinearFieldConflict>,
    issue_wins: BTreeSet<&'static str>,
    issue_changed: bool,
}

fn store_invariant(message: &'static str) -> LinearSyncError {
    LinearSyncError::Store(crate::error::Error::InvariantViolation(message))
}

fn mirror_receipt(
    status: LinearMirrorStatus,
    direction: LinearSyncDirection,
    operation_id: [u8; 32],
    task_ref: EntityId,
    issue: LinearIssueRef,
    conflicts: Vec<LinearFieldConflict>,
    now: u64,
) -> LinearMirrorReceipt {
    LinearMirrorReceipt {
        status,
        direction,
        operation_id,
        task_ref,
        issue,
        conflicts,
        mirrored_at: now,
    }
}

/// Whether an inbound change is behind a watermark or repeats the last applied
/// operation — the `(issue_id, issue_updated_at_ms, event_id)` replay guard.
fn inbound_already_seen(
    link: &TaskIssueLink,
    snapshot: &TaskMirrorSnapshot,
    change: &LinearIssueChange,
    operation_id: [u8; 32],
) -> bool {
    let behind_link = change.updated_at_ms <= link.issue_updated_at_ms;
    let behind_store = snapshot
        .last_pulled_updated_at_ms
        .is_some_and(|watermark| change.updated_at_ms <= watermark);
    behind_link || behind_store || operation_id == link.last_operation_id
}

/// Attributes every bidirectional field change to a side, using the stored
/// base hashes. Both sides moved the same field to different values ⇒
/// conflict; only the issue moved ⇒ the issue value wins; only the task moved
/// (or neither) ⇒ the task value stands.
fn decide_fields(
    base: &BTreeMap<String, [u8; 32]>,
    task: &MirroredTaskFields,
    issue: &MirroredTaskFields,
) -> FieldDecision {
    let mut decision = FieldDecision::default();
    for field in LINEAR_MIRRORED_FIELDS {
        let task_value = task.field_value(field);
        let issue_value = issue.field_value(field);
        let task_hash = field_hash(task_value.as_deref());
        let issue_hash = field_hash(issue_value.as_deref());
        let base_hash = base.get(field).copied();
        let task_changed = base_hash != Some(task_hash);
        let issue_changed = base_hash != Some(issue_hash);
        if task_changed && issue_changed && task_hash != issue_hash {
            decision.conflicts.push(LinearFieldConflict {
                field: field.to_owned(),
                task_value,
                issue_value,
            });
            continue;
        }
        if issue_changed && issue_hash != task_hash {
            decision.issue_wins.insert(field);
            decision.issue_changed = true;
        }
    }
    decision
}

/// Builds the merged field set: issue values for the fields the issue owns in
/// this change, task values everywhere else.
fn merge_fields(
    task: &MirroredTaskFields,
    issue: &MirroredTaskFields,
    issue_wins: &BTreeSet<&'static str>,
) -> MirroredTaskFields {
    MirroredTaskFields {
        title: if issue_wins.contains(LINEAR_FIELD_TITLE) {
            issue.title.clone()
        } else {
            task.title.clone()
        },
        description: if issue_wins.contains(LINEAR_FIELD_DESCRIPTION) {
            issue.description.clone()
        } else {
            task.description.clone()
        },
        priority: if issue_wins.contains(LINEAR_FIELD_PRIORITY) {
            issue.priority
        } else {
            task.priority
        },
        assignee_ref: if issue_wins.contains(LINEAR_FIELD_ASSIGNEE_REF) {
            issue.assignee_ref.clone()
        } else {
            task.assignee_ref.clone()
        },
        status: if issue_wins.contains(LINEAR_FIELD_STATUS) {
            issue.status.clone()
        } else {
            task.status.clone()
        },
    }
}

/// Domain-separated, length-prefixed hash of one field value; `None` and the
/// empty string hash differently.
fn field_hash(value: Option<&str>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_FIELD_DOMAIN);
    update_field(&mut hasher, value);
    *hasher.finalize().as_bytes()
}

/// Absorbs one optional string into a hasher with a presence byte and a length
/// prefix, so concatenations cannot collide.
fn update_field(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(text) => {
            hasher.update(&[1]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

#[cfg(test)]
mod tests;
