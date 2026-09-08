//! Link/issue/mirror domain types, port traits, result aliases, conflict and receipt types.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::codec::{field_hash, linear_event_digest};

/// Wire version of the mirror link rows and receipts.
///
/// v2 made two correctness facts durable that v1 kept nowhere: the inbound
/// event history and the unresolved-conflict barrier. v3 (ONE-1959) fixes the
/// shape of both: the history becomes a NON-EVICTING digest set (a 32-entry
/// ring forgets identities that are still redeliverable) and every row carries
/// a [`TaskIssueLink::link_revision`] compare-and-set token. An older row read
/// as a v3 row would present an empty history and revision zero — that is, it
/// would silently re-open the replay and the clobber — so the row namespace
/// moves with the version and the version stays hashed into every operation id.
pub const LINEAR_SYNC_SCHEMA_VERSION: u8 = 3;

/// Durable key prefix of the TASK ↔ issue link row. Versioned with
/// [`LINEAR_SYNC_SCHEMA_VERSION`], so a row written under the older shape can
/// never be read back as the newer one.
pub const LINEAR_SYNC_LINK_KEY_PREFIX: &[u8] = b"linear_sync:link:v3:";

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

pub(super) const LINEAR_SYNC_FIELD_DOMAIN: &[u8] = b"oneiron:linear-sync-field:v1";

/// Domain separator for [`linear_event_digest`]; pinned, because the digests
/// are durable link state compared across processes and replicas.
pub(super) const LINEAR_SYNC_EVENT_DOMAIN: &[u8] = b"oneiron:linear-sync-event:v1";

pub(super) const ERR_UNLINKED_ISSUE: &str = "linear_sync: issue change has no durable TASK link";

pub(super) const ERR_BLANK_EVENT_ID: &str =
    "linear_sync: issue change carries a blank tracker event id";

pub(super) const ERR_LINK_REVISION_OVERFLOW: &str = "linear_sync link revision";

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
    /// Same-field concurrent edit: every conflicting field was left untouched
    /// on BOTH sides and pinned in the link. The same change's non-conflicting
    /// issue-owned fields, if any, still applied — the refusal is per field.
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
    /// Watermark: the TASK revision this link last observed.
    ///
    /// Progress only. It is NOT proof that the local values reached the
    /// tracker: an inbound apply advances the revision while a disjoint local
    /// edit is still pending outbound, so gating a push on
    /// `revision <= task_revision` would drop exactly the edit the push exists
    /// to deliver. A STRICTLY older snapshot is stale, however: publishing it
    /// after the link observed a newer resolution would undo that resolution.
    /// `base_field_hashes` remains the sound "the tracker already has this"
    /// test at an equal or newer revision.
    pub task_revision: u64,
    /// Watermark: the tracker `updated_at` this link last synchronized. Prunes
    /// only what is STRICTLY older; an equal `updated_at` is a different event,
    /// separated by `seen_event_digests`.
    pub issue_updated_at_ms: u64,
    /// [`linear_event_digest`] of every inbound tracker event this link has
    /// already processed — applied, absorbed as an echo, or refused as a
    /// conflict.
    ///
    /// The `updated_at` watermark is not an inbound identity on its own. A
    /// tracker may emit two distinct events carrying the SAME `updated_at`
    /// (a watermark collapses the second and loses a real change) and may
    /// redeliver ONE event with a LATER `updated_at` (a watermark waves it
    /// through and then drags itself forward past events never seen). The
    /// digest set is the durable half of the `(issue_id, issue_updated_at_ms,
    /// event_id)` key.
    ///
    /// A SET, never a ring. Membership here is a permanent fact — "this exact
    /// event has been accounted for" — and a bounded history that evicts the
    /// oldest entries is a promise to forget it: the tracker may redeliver an
    /// old event after any number of newer ones, with any `updated_at` it
    /// likes, and an evicted identity makes that redelivery a second apply
    /// (ONE-1959). Digests, not raw ids, because 32 bytes per event is the
    /// cheapest exact identity that also binds the issue it belongs to.
    ///
    /// Conflicting events ARE recorded, because they are no longer inert: the
    /// same event still applies its non-conflicting fields, and applying them
    /// twice is exactly the double-write the history exists to stop. The
    /// refusal survives in `unresolved_conflicts` instead, which is durable and
    /// re-surfaces on every replay and every push.
    pub seen_event_digests: BTreeSet<[u8; 32]>,
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
    ///
    /// The base is the value the TRACKER is known to hold. After an inbound
    /// merge that is the event's own field set — never the merged local
    /// snapshot, which contains pending edits the tracker has never seen and
    /// would falsely certify as already pushed.
    ///
    /// A CONFLICTING field is the one exception, and for the same reason: the
    /// two sides never agreed on it, so there is no new common base to record.
    /// Its base stays where it was, which is what keeps both sides reading as
    /// "moved since the base" and lets every later event re-derive the conflict
    /// from the stored row alone. Adopting the tracker's value here would erase
    /// the divergence, let the next unrelated event clear the barrier, and hand
    /// the following push the overwrite the pull refused (ONE-1959).
    pub base_field_hashes: BTreeMap<String, [u8; 32]>,
    /// Same-field concurrent edits this link refused to resolve, pinned with
    /// both sides' values.
    ///
    /// Durable, because the refusal has to survive the call boundary. The
    /// inbound apply declines to overwrite the newer tracker value, but the
    /// next outbound push carries the FULL local snapshot and would overwrite
    /// it anyway — silent last-write-wins through the back door. While a field
    /// still holds the value that conflicted,
    /// [`LinearSyncAdapter::push_task`] re-surfaces the conflict instead of
    /// calling the egress.
    ///
    /// Resolution stays evidence-based and needs no new API: a later explicit
    /// edit that moves the field OFF the value that conflicted — to the
    /// tracker's value or to a deliberate third one — lifts the barrier for
    /// that field, and any later inbound event re-derives the whole set from
    /// the base, so a conflict the tracker has since reverted clears itself.
    ///
    /// Re-derived, never accumulated: an inbound event rewrites this set from
    /// the base comparison it just performed, so a settled conflict does not
    /// linger. A settled conflict cannot be RESURRECTED either, which needs two
    /// separate guarantees — `seen_event_digests` stops the resolved event's
    /// own redelivery, `task_revision` rejects a pre-resolution full TASK
    /// snapshot, and `link_revision` stops an older in-flight operation from
    /// writing its stale barrier over the resolution.
    pub unresolved_conflicts: Vec<LinearFieldConflict>,
    /// Monotonic compare-and-set token. A newly created row starts at zero;
    /// every replacement increments it.
    ///
    /// Every [`LinearTaskStore::put_link`] states the revision its operation
    /// READ, and the store applies the write only if the row still holds it.
    /// Without that, the barrier — which is metadata, not a TASK field, and so
    /// has no revision of its own to ride on — is an unconditional overwrite:
    /// an operation that read the pre-resolution row and wrote afterwards would
    /// silently reinstate a conflict a human had already settled (ONE-1959).
    pub link_revision: u64,
    /// Wall-clock stamp of the last link write.
    pub updated_at: u64,
}

impl TaskIssueLink {
    /// Whether this link has already processed the tracker event `event_id`.
    ///
    /// Exact and permanent: the answer never changes back to `false` as newer
    /// events arrive, which is the whole point of a non-evicting digest set.
    #[must_use]
    pub fn has_seen_event(&self, event_id: &str) -> bool {
        self.seen_event_digests
            .contains(&linear_event_digest(&self.issue.issue_id, event_id))
    }

    /// The link revision the NEXT durable write of this row must carry.
    pub(super) fn next_revision(&self) -> LinearSyncResult<u64> {
        self.link_revision.checked_add(1).ok_or_else(|| {
            LinearSyncError::Store(crate::error::Error::ArithmeticOverflow(
                ERR_LINK_REVISION_OVERFLOW,
            ))
        })
    }
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
    /// Tracker event id; third component of the inbound idempotency key, and
    /// the only component that separates two events sharing an `updated_at` or
    /// recognizes one event redelivered under a new one.
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
    /// Compare-and-set miss on the durable link row: another operation wrote
    /// the link between this operation's read and its write, so this write
    /// carries stale state — a stale conflict barrier, most dangerously — and
    /// the store refused it rather than let it clobber the newer row.
    ///
    /// `None` means "no link row"; an expected `None` is a first-link create.
    #[error("linear link revision conflict: expected {expected:?}, found {found:?}")]
    LinkConflict {
        /// Link revision the operation read, or `None` when it read no link.
        expected: Option<u64>,
        /// Link revision the store actually holds, or `None` when unlinked.
        found: Option<u64>,
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
    /// Changes that mutated TASK fields with no conflicting field at all.
    pub applied: usize,
    /// Changes the pass deliberately did not apply: our own echoes, replays
    /// already recognized by identity or behind the watermark, and issues this
    /// vault does not mirror.
    pub skipped_echo: usize,
    /// Durable conflict receipts minted by this pass; each left every
    /// conflicting field untouched on both sides and needs a human (or a later
    /// one-sided edit) to resolve. A change counted here may still have applied
    /// its NON-conflicting issue-owned fields — the refusal is per field — so
    /// this is a count of changes, not of untouched TASKs.
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

    /// Writes the link row under compare-and-set.
    ///
    /// `expected_link_revision` is the [`TaskIssueLink::link_revision`] the
    /// operation READ — `None` when it read no link and is creating one.
    /// Implementations MUST perform the comparison atomically with the write
    /// and MUST refuse it with [`LinearSyncError::LinkConflict`] when the
    /// stored row's revision (or its absence) differs. A read followed by an
    /// unconditional write in the caller is NOT an implementation of this
    /// contract: the whole window this guards is the one between them.
    ///
    /// The link is metadata, not a TASK field, so it rides on no other
    /// optimistic-concurrency check. Its conflict barrier is durable refusal
    /// state, and an unconditional overwrite lets an older in-flight operation
    /// reinstate a conflict that has already been resolved (ONE-1959).
    ///
    /// # Errors
    ///
    /// Returns [`LinearSyncError::LinkConflict`] when the stored link moved
    /// under the operation, or a store error when the write fails.
    fn put_link(
        &mut self,
        expected_link_revision: Option<u64>,
        link: &TaskIssueLink,
    ) -> LinearSyncResult<()>;
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

/// Per-field verdict of one inbound change against the stored base.
#[derive(Debug, Default)]
pub(super) struct FieldDecision {
    pub(super) conflicts: Vec<LinearFieldConflict>,
    pub(super) issue_wins: BTreeSet<&'static str>,
    pub(super) issue_changed: bool,
}
