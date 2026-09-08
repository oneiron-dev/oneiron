//! LinearSyncAdapter push/pull/apply verbs with replay, conflict, and receipt logic.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::codec::{field_hash, linear_event_digest, linear_operation_id};
use super::model::{
    ERR_BLANK_EVENT_ID, ERR_UNLINKED_ISSUE, FieldDecision, LINEAR_FIELD_ASSIGNEE_REF,
    LINEAR_FIELD_DESCRIPTION, LINEAR_FIELD_PRIORITY, LINEAR_FIELD_STATUS, LINEAR_FIELD_TITLE,
    LINEAR_MIRRORED_FIELDS, LinearChangeSource, LinearEgress, LinearFieldConflict,
    LinearIssueChange, LinearIssueRef, LinearMirrorReceipt, LinearMirrorStatus, LinearPullReceipt,
    LinearSyncDirection, LinearSyncError, LinearSyncResult, LinearTaskStore, MirroredTaskFields,
    TaskIssueLink, TaskMirrorSnapshot,
};

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

    pub(super) fn push_linked_issue(
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
pub(super) fn inbound_already_seen(
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
