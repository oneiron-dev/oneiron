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
//!   conflict detection decidable from the stored snapshot alone. The base is
//!   always the value the TRACKER is known to hold, never the value we merely
//!   wrote locally: a disjoint merge that keeps a local edit the tracker has
//!   not seen must not claim that edit as base, or the edit is silently dropped
//!   instead of pushed (ONE-1959).
//! * **echo cannot bounce, and identity never expires** — applying EITHER
//!   direction advances BOTH watermarks, stamps the stable operation id, and
//!   records the tracker event's DURABLE digest, so our own write coming back
//!   as an inbound event is a [`LinearMirrorStatus::Noop`], and an inbound
//!   apply does not re-push. Outbound idempotency is keyed by
//!   `(task_ref, task_revision, operation_kind)`; inbound by
//!   `(issue_id, issue_updated_at_ms, event_id)` — with the event id
//!   load-bearing, because a timestamp alone collapses two distinct events that
//!   share an `updated_at` and lets one redelivered event with a rewritten
//!   `updated_at` walk straight past the watermark. The processed-event set is
//!   a SET, not a ring: a bounded history forgets old identities, and a
//!   forgotten identity is a redelivery that applies twice (ONE-1959). A blank
//!   `event_id` carries no identity at all and is refused up front, before any
//!   lookup, dedupe or write.
//! * **deterministic field ownership** — identity, `blocked_by`, run-result
//!   refs and readiness are ENGINE-AUTHORITATIVE and never mirror inbound;
//!   title / description / priority / assignee / status are bidirectional and
//!   apply only when exactly one side moved. Same-field concurrent edits become
//!   a durable [`LinearMirrorReceipt`] with status
//!   [`LinearMirrorStatus::Conflict`] that mutates NEITHER SIDE OF THE
//!   CONFLICTING FIELD — there is no silent last-write-wins anywhere in this
//!   module. The unresolved fields are PINNED IN THE LINK, because the refusal
//!   has to survive the call boundary: the next outbound push carries the full
//!   local snapshot and would otherwise launder the conflict into exactly the
//!   overwrite the pull refused. The conflict is per FIELD, so the same event's
//!   non-conflicting issue-owned fields still apply exactly once, and the base
//!   of a conflicting field deliberately does NOT move: the divergence is what
//!   later events re-derive the conflict from.
//! * **link writes are compare-and-set** — the barrier is durable state, so
//!   writing it unconditionally lets an older in-flight operation clobber a
//!   newer resolution and resurrect a conflict that was already settled.
//!   [`LinearTaskStore::put_link`] therefore takes the [`TaskIssueLink`]
//!   revision the operation READ and the store itself refuses the write when
//!   the row has moved ([`LinearSyncError::LinkConflict`]). The atomic check
//!   belongs to the store; a read-then-write in adapter code is not one.
//! * **no credential in core** — no token, provider client, or HTTP lives
//!   here. [`LinearEgress`] is the host boundary that crosses the existing
//!   outbound door, so every test in this crate runs on fakes with no Linear
//!   workspace in sight.
//!
//! One seam this module cannot close alone: an inbound apply writes the TASK
//! through [`LinearTaskStore::apply_issue_fields`] and the link through
//! [`LinearTaskStore::put_link`], two guarded writes that no port here can
//! wrap in one transaction. Both are compare-and-set, so neither can overwrite
//! newer state; a link write that loses its CAS surfaces the error with the
//! event NOT recorded, which is the safe direction — the retry re-derives the
//! decision from the stored base rather than assuming it landed.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

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

const LINEAR_SYNC_FIELD_DOMAIN: &[u8] = b"oneiron:linear-sync-field:v1";

/// Domain separator for [`linear_event_digest`]; pinned, because the digests
/// are durable link state compared across processes and replicas.
const LINEAR_SYNC_EVENT_DOMAIN: &[u8] = b"oneiron:linear-sync-event:v1";

const ERR_UNLINKED_ISSUE: &str = "linear_sync: issue change has no durable TASK link";

const ERR_BLANK_EVENT_ID: &str = "linear_sync: issue change carries a blank tracker event id";

const ERR_LINK_REVISION_OVERFLOW: &str = "linear_sync link revision";

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
    fn next_revision(&self) -> LinearSyncResult<u64> {
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
/// Outbound callers pass `issue_updated_at_ms: None` and `event_id: None`, so
/// the id is exactly the `(task_ref, task_revision, operation_kind)` key —
/// `issue_id: None` is a create, `Some` is an update — and a retry of the same
/// logical push recomputes the same id. Inbound callers pass all three, giving
/// the full `(issue_id, issue_updated_at_ms, event_id)` key of the event being
/// applied.
///
/// The event id is load-bearing, not decoration: without it two DISTINCT
/// tracker events that share an `updated_at` mint the SAME id and the second is
/// discarded as a duplicate of the first. With it, a retry of ONE event against
/// an unchanged TASK revision still recomputes its own id, so retry idempotency
/// survives.
#[must_use]
pub fn linear_operation_id(
    direction: LinearSyncDirection,
    task_ref: EntityId,
    task_revision: u64,
    issue_id: Option<&str>,
    issue_updated_at_ms: Option<u64>,
    event_id: Option<&str>,
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
    update_field(&mut hasher, event_id);
    *hasher.finalize().as_bytes()
}

/// The durable identity of one inbound tracker event, as stored in
/// [`TaskIssueLink::seen_event_digests`].
///
/// Binds the issue, so an event id a tracker only makes unique per issue cannot
/// mask a different issue's event. Deliberately free of `updated_at`: a
/// redelivery of ONE event with a rewritten timestamp is the SAME event, and a
/// digest that moved with the clock would fail to say so.
#[must_use]
pub fn linear_event_digest(issue_id: &str, event_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINEAR_SYNC_EVENT_DOMAIN);
    hasher.update(&[LINEAR_SYNC_SCHEMA_VERSION]);
    update_field(&mut hasher, Some(issue_id));
    update_field(&mut hasher, Some(event_id));
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
    /// the TASK fields actually differ from the base the tracker is known to
    /// hold. A repeated push of an unchanged snapshot recomputes the same
    /// operation id and returns [`LinearMirrorStatus::Noop`] without touching
    /// the tracker. A snapshot older than the link's observed TASK revision is
    /// also a no-op, so a split read cannot republish pre-resolution fields.
    ///
    /// A field left unresolved by an earlier same-field concurrent edit is a
    /// durable barrier: the push returns [`LinearMirrorStatus::Conflict`] and
    /// calls no egress, because this payload is the whole local snapshot and
    /// would overwrite the newer tracker value the pull refused to touch.
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
    /// Returns an invariant violation when a change carries a blank tracker
    /// event id, or the change source's, store's, or egress's error.
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
            // Before the link lookup, not after: an unidentifiable event is
            // rejected by the page it arrived in, and never reaches a store
            // read it could be silently classified by.
            ensure_event_identity(&change)?;
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
    /// Suppresses echoes and replays by durable event identity, watermark and
    /// operation id, merges disjoint-field edits, and refuses same-field
    /// concurrent edits with a conflict receipt that leaves every conflicting
    /// field untouched on both sides and pins a durable barrier against the
    /// next push. A change that conflicts on SOME fields still applies its
    /// remaining issue-owned fields, exactly once: those fields are not in
    /// dispute, and withholding them only means the next event re-applies them
    /// against a base that has meanwhile moved.
    ///
    /// # Errors
    ///
    /// Returns an invariant violation when the change carries a blank event id
    /// or the issue has no durable link, or the store's error (including
    /// [`LinearSyncError::Conflict`] when the TASK moved under the apply and
    /// [`LinearSyncError::LinkConflict`] when the link row did).
    pub fn apply_issue_change(
        &mut self,
        change: LinearIssueChange,
        now: u64,
    ) -> LinearSyncResult<LinearMirrorReceipt> {
        // Validate before the first store access: a blank id has no durable
        // dedupe identity and must mutate nothing.
        ensure_event_identity(&change)?;
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
            Some(&change.event_id),
        );
        if inbound_already_seen(&link, &snapshot, &change, operation_id) {
            return Ok(inbound_replay_receipt(
                &link,
                &snapshot,
                change,
                operation_id,
                now,
            ));
        }

        let expected_link_revision = link.link_revision;
        let next_link_revision = link.next_revision()?;
        let decision = decide_fields(&link.base_field_hashes, &snapshot.fields, &change.fields);
        // `merge_fields` takes the issue value only for the fields the issue
        // OWNS in this change, and a conflicting field is never one of them, so
        // the conflicting task values are carried through untouched even when
        // this same event applies its safe fields.
        let task_revision = if decision.issue_changed {
            let merged = merge_fields(&snapshot.fields, &change.fields, &decision.issue_wins);
            self.tasks
                .apply_issue_fields(link.task_ref, snapshot.revision, &merged, now)?
                .revision
        } else {
            // Observed progress; equality can still contain a pending edit.
            snapshot.revision
        };
        let updated = TaskIssueLink {
            task_ref: link.task_ref,
            issue: change.issue.clone(),
            task_revision,
            issue_updated_at_ms: change.updated_at_ms.max(link.issue_updated_at_ms),
            // The event is consumed whatever its verdict — applied, absorbed,
            // or refused on some field. A refused event is NOT inert: it just
            // applied its safe fields, and a redelivery that is not recognized
            // applies them a second time. The refusal survives in
            // `unresolved_conflicts`, which every replay and every push reads.
            seen_event_digests: remember_event(
                link.seen_event_digests,
                &change.issue.issue_id,
                &change.event_id,
            ),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::IssueToTask,
            // The base is what the TRACKER holds after this event, NOT what we
            // just wrote locally. A field only the task moved is still pending
            // outbound: the tracker's value for it is the last agreed value, so
            // it stays the base. Storing `merged` here would certify the local
            // edit as already mirrored and the next push would find nothing to
            // send — the edit would be lost, not merged (ONE-1959). A
            // conflicting field keeps its OLD base, because the two sides never
            // agreed on a new one.
            base_field_hashes: rebased_fields(
                &link.base_field_hashes,
                &change.fields,
                &decision.conflicts,
            ),
            // Re-derived from the base this event was just attributed against,
            // so a conflict the tracker has since reverted clears itself and a
            // conflict still live stays pinned.
            unresolved_conflicts: decision.conflicts.clone(),
            link_revision: next_link_revision,
            updated_at: now,
        };
        // Compare-and-set against the row this operation READ. An older
        // operation that read the pre-resolution link loses here instead of
        // reinstating a settled conflict.
        self.tasks
            .put_link(Some(expected_link_revision), &updated)?;
        let status = decision.status();
        Ok(mirror_receipt(
            status,
            LinearSyncDirection::IssueToTask,
            operation_id,
            updated.task_ref,
            change.issue,
            decision.conflicts,
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
            None,
        );
        let created =
            self.outbound
                .create_issue(operation_id, snapshot.task_ref, &snapshot.fields)?;
        let link = TaskIssueLink {
            task_ref: snapshot.task_ref,
            issue: created.issue.clone(),
            task_revision: snapshot.revision,
            issue_updated_at_ms: created.updated_at_ms,
            // Our own create is the first event this issue will ever emit, so
            // seeding the history is what stops it bouncing back inbound.
            seen_event_digests: remember_event(
                BTreeSet::new(),
                &created.issue.issue_id,
                &created.event_id,
            ),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::TaskToIssue,
            base_field_hashes: created.fields.field_hashes(),
            unresolved_conflicts: Vec::new(),
            link_revision: 0,
            updated_at: now,
        };
        // `None`: this operation read no link, so the create loses the race
        // against any link row that appeared meanwhile rather than replacing it.
        self.tasks.put_link(None, &link)?;
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
            None,
        );
        // The durable conflict barrier is checked FIRST and reported, never
        // rounded down to a no-op: this push carries the full local snapshot,
        // so sending it would overwrite the newer tracker value the inbound
        // apply deliberately refused — a last-write-wins the module promises
        // nowhere to do (ONE-1959).
        let blocked = blocking_conflicts(&link, &snapshot.fields);
        if !blocked.is_empty() {
            return Ok(mirror_receipt(
                LinearMirrorStatus::Conflict,
                LinearSyncDirection::TaskToIssue,
                operation_id,
                snapshot.task_ref,
                link.issue,
                blocked,
                now,
            ));
        }

        // A strictly older snapshot cannot be authoritative over a link that
        // already observed a newer TASK revision. This catches the split-read
        // ordering where a push captured the pre-resolution task, then read the
        // post-resolution link; publishing that full stale snapshot would undo
        // the resolution before the link CAS could reject anything. Equality is
        // not a gate because an inbound merge can retain a pending local edit.
        let stale_snapshot = snapshot.revision < link.task_revision;
        // Base hashes decide whether current fields are already on the tracker.
        let unchanged = snapshot.fields.field_hashes() == link.base_field_hashes;
        let repeat_operation = operation_id == link.last_operation_id;
        if stale_snapshot || unchanged || repeat_operation {
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

        let expected_link_revision = link.link_revision;
        let next_link_revision = link.next_revision()?;
        let pushed = self
            .outbound
            .update_issue(operation_id, &link.issue, &snapshot.fields)?;
        let updated = TaskIssueLink {
            task_ref: snapshot.task_ref,
            issue: pushed.issue.clone(),
            task_revision: snapshot.revision,
            issue_updated_at_ms: pushed.updated_at_ms.max(link.issue_updated_at_ms),
            // Our own write; remembering its event id is what keeps it from
            // coming back inbound as somebody else's change.
            seen_event_digests: remember_event(
                link.seen_event_digests,
                &pushed.issue.issue_id,
                &pushed.event_id,
            ),
            last_operation_id: operation_id,
            last_direction: LinearSyncDirection::TaskToIssue,
            base_field_hashes: pushed.fields.field_hashes(),
            // Reached only with an empty barrier, and this push republished
            // every bidirectional field, so nothing is left unresolved.
            unresolved_conflicts: Vec::new(),
            link_revision: next_link_revision,
            updated_at: now,
        };
        // The resolution is only durable if it wins the row: an inbound
        // operation that read the pre-push link must not land its barrier on
        // top of what this push just agreed with the tracker.
        self.tasks
            .put_link(Some(expected_link_revision), &updated)?;
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
}

/// Per-field verdict of one inbound change against the stored base.
#[derive(Debug, Default)]
struct FieldDecision {
    conflicts: Vec<LinearFieldConflict>,
    issue_wins: BTreeSet<&'static str>,
    issue_changed: bool,
}

impl FieldDecision {
    fn status(&self) -> LinearMirrorStatus {
        if !self.conflicts.is_empty() {
            LinearMirrorStatus::Conflict
        } else if self.issue_changed {
            LinearMirrorStatus::Applied
        } else {
            LinearMirrorStatus::Noop
        }
    }
}

fn store_invariant(message: &'static str) -> LinearSyncError {
    LinearSyncError::Store(crate::error::Error::InvariantViolation(message))
}

/// Refuses an inbound change whose tracker event id is empty or whitespace.
///
/// Identity is the load-bearing half of the inbound key: it is what recognizes
/// a redelivery, what the durable history stores, and what a conflicting event
/// is recorded under. A blank id supplies none of it — every blank event is
/// "the same event" as every other, so honoring one would either swallow real
/// changes as replays or apply one change repeatedly, depending only on
/// delivery order. The check runs before the link lookup, so a malformed event
/// cannot reach a store read, a watermark, a barrier or a TASK write.
fn ensure_event_identity(change: &LinearIssueChange) -> LinearSyncResult<()> {
    if change.event_id.trim().is_empty() {
        return Err(store_invariant(ERR_BLANK_EVENT_ID));
    }
    Ok(())
}

/// Reports an already-processed inbound event without mutating either row.
///
/// A replay still reports any barrier the link currently holds. Thus a
/// redelivered conflict re-surfaces while unresolved, but the same stale event
/// reports a no-op after resolution instead of restoring its old barrier.
fn inbound_replay_receipt(
    link: &TaskIssueLink,
    snapshot: &TaskMirrorSnapshot,
    change: LinearIssueChange,
    operation_id: [u8; 32],
    now: u64,
) -> LinearMirrorReceipt {
    let conflicts = blocking_conflicts(link, &snapshot.fields);
    let status = if conflicts.is_empty() {
        LinearMirrorStatus::Noop
    } else {
        LinearMirrorStatus::Conflict
    };
    mirror_receipt(
        status,
        LinearSyncDirection::IssueToTask,
        operation_id,
        link.task_ref,
        change.issue,
        conflicts,
        now,
    )
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

/// Whether an inbound change was already processed, or is behind a watermark,
/// or repeats the last applied operation — the full
/// `(issue_id, issue_updated_at_ms, event_id)` replay guard.
///
/// Event identity is checked first and independently of the clock, because the
/// clock cannot decide either direction on its own:
///
/// * a redelivery of ONE event with a rewritten (later) `updated_at` is not
///   behind any watermark, so only the recorded identity can recognize it — and
///   re-applying it would also drag the watermark forward past events that were
///   never seen;
/// * two DISTINCT events may share an `updated_at`, so the watermark comparison
///   must be STRICTLY less-than. An equal stamp is a different event until the
///   digest history says otherwise, and collapsing it would silently drop a
///   change.
///
/// The identity half never expires, which is what makes this guard survive
/// resolution: a stale event minted before a conflict was settled is recognized
/// no matter how many events have landed since, so it cannot re-open the
/// conflict or overwrite the agreed value (ONE-1959).
fn inbound_already_seen(
    link: &TaskIssueLink,
    snapshot: &TaskMirrorSnapshot,
    change: &LinearIssueChange,
    operation_id: [u8; 32],
) -> bool {
    let replayed_event = link.has_seen_event(&change.event_id);
    let behind_link = change.updated_at_ms < link.issue_updated_at_ms;
    let behind_store = snapshot
        .last_pulled_updated_at_ms
        .is_some_and(|watermark| change.updated_at_ms < watermark);
    replayed_event || behind_link || behind_store || operation_id == link.last_operation_id
}

/// Records one tracker event in the link's durable inbound history. Idempotent,
/// and never evicting: the set only grows, because forgetting an identity is
/// indistinguishable from never having seen it.
///
/// A blank id is silently not recorded rather than stored as an entry that
/// matches nothing meaningful; inbound events carrying one are refused outright
/// by [`ensure_event_identity`], so the only source of one is an egress reply
/// that failed to name the event it wrote.
fn remember_event(
    mut history: BTreeSet<[u8; 32]>,
    issue_id: &str,
    event_id: &str,
) -> BTreeSet<[u8; 32]> {
    if event_id.trim().is_empty() {
        return history;
    }
    history.insert(linear_event_digest(issue_id, event_id));
    history
}

/// The unresolved conflicts that still block an outbound push: a field whose
/// engine-side value is STILL the value that conflicted, so pushing the local
/// snapshot would overwrite the newer tracker value with it.
///
/// A field whose value has since moved is no longer blocking. That move is the
/// deliberate, evidence-based resolution — the operator either adopted the
/// tracker's value or chose a third one — and it needs no API of its own.
fn blocking_conflicts(
    link: &TaskIssueLink,
    task_fields: &MirroredTaskFields,
) -> Vec<LinearFieldConflict> {
    link.unresolved_conflicts
        .iter()
        .filter(|conflict| task_fields.field_value(&conflict.field) == conflict.task_value)
        .cloned()
        .collect()
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

/// The base after one inbound event: the tracker's post-event value for every
/// field, EXCEPT that a conflicting field keeps the base it already had.
///
/// A base is a value both sides are known to have agreed on. A conflicting
/// field has no such value — that is what the conflict means — so adopting the
/// tracker's side of the disagreement would quietly declare it settled in the
/// tracker's favor: the next unrelated event would see the field as changed by
/// the task alone, drop the barrier, and let the following push overwrite the
/// tracker. Holding the old base keeps BOTH sides reading as moved, so the
/// conflict re-derives itself from the row until one side actually moves
/// (ONE-1959).
fn rebased_fields(
    previous: &BTreeMap<String, [u8; 32]>,
    issue: &MirroredTaskFields,
    conflicts: &[LinearFieldConflict],
) -> BTreeMap<String, [u8; 32]> {
    let mut base = issue.field_hashes();
    for conflict in conflicts {
        match previous.get(&conflict.field) {
            Some(hash) => base.insert(conflict.field.clone(), *hash),
            // No prior base is the strongest form of "not agreed": every side
            // reads as changed, so the conflict cannot lapse.
            None => base.remove(&conflict.field),
        };
    }
    base
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
