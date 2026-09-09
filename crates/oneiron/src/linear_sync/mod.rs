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

mod codec;
mod engine;
mod model;

pub use self::codec::{linear_event_digest, linear_operation_id, linear_sync_link_key};
pub use self::engine::LinearSyncAdapter;
pub use self::model::{
    LINEAR_ENGINE_AUTHORITATIVE_FIELDS, LINEAR_FIELD_ASSIGNEE_REF, LINEAR_FIELD_DESCRIPTION,
    LINEAR_FIELD_PRIORITY, LINEAR_FIELD_STATUS, LINEAR_FIELD_TITLE, LINEAR_MIRRORED_FIELDS,
    LINEAR_SYNC_ADAPTER_ID, LINEAR_SYNC_LINK_KEY_PREFIX, LINEAR_SYNC_OPERATION_DOMAIN,
    LINEAR_SYNC_REGISTRATION, LINEAR_SYNC_SCHEMA_VERSION, LinearChangePage, LinearChangeSource,
    LinearEgress, LinearFieldConflict, LinearIssueChange, LinearIssueRef, LinearMirrorReceipt,
    LinearMirrorStatus, LinearPullReceipt, LinearSyncDirection, LinearSyncError,
    LinearSyncRegistration, LinearSyncResult, LinearTaskStore, MirroredTaskFields, TaskIssueLink,
    TaskMirrorSnapshot, WaveResult,
};

#[cfg(test)]
mod tests;

// The flat linear_sync.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every linear-sync-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use std::collections::BTreeMap;
