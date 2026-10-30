//! The vault-owned wake of the origin mirror pushes (FIX 6866 part 2; CALLS
//! "FIX 6866 full-auto trigger" and "FIX 6866 full-auto newest green per
//! ref").
//!
//! A full-auto mirror is due at once on every non-import published-ref move
//! and on every green landing, with no delay floor
//! ([`super::mirror_auto::ORIGIN_MIRROR_FULL_AUTO_MIN_DELAY_SECS`]). The
//! places that move them (a publication's finish, a published slot restored
//! or retired, a successful journaled GitWire ref effect, the merge queue's
//! green advance) call [`Vault::note_origin_ref_moved`] or
//! [`Vault::wake_origin_mirrors`] after their write committed. The wake is a
//! signal, never the queue: the pass it starts reads the published refs and
//! the green evidence as they stand, and each mirror's tick repairs a wake
//! that was missed. Wakes that come together coalesce into one pass; a wake
//! that comes while a pass runs is kept and starts the next pass after it.
//! Nothing here can fail, so no local effect ever fails for a wake.
//!
//! The cell also keeps, per full-auto mirror, the fingerprint of the
//! published refs and green pointer its last settled run saw, so a pass
//! over an unchanged repository reads no green evidence. In memory only: a
//! restarted host reads everything once.
//!
//! The same vault-owned cell carries the merge queue drain's own wake (FIX
//! 7306): a committed queue write, check request, check result, conflict
//! handoff or received push wakes that drain alone, never another attempt
//! commit, and its lifecycle tick repairs a wake that was missed.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::mirror::ORIGIN_MIRROR_IMPORTED_PREFIX;
use super::publication::{OriginPublicationRecord, OriginPublicationStatus};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::git_wire::{GIT_WIRE_KEEP_REF_PREFIX, GitRefPublication};

/// The wake cell one vault handle owns.
#[derive(Debug, Default)]
pub(crate) struct OriginMirrorWake {
    notify: tokio::sync::Notify,
    deferred: AtomicBool,
    seen: Mutex<HashMap<EntityId, String>>,
    /// The merge queue drain's wake (FIX 7306).
    merge_queue: tokio::sync::Notify,
}

impl Vault {
    /// What the host waits on beside its lifecycle tick: a pass over the
    /// full-auto mirrors and open plans starts when it fires.
    pub fn origin_mirror_wake(&self) -> &tokio::sync::Notify {
        &self.origin_mirror_wake.notify
    }

    /// Wakes the mirror pushes now.
    pub fn wake_origin_mirrors(&self) {
        self.origin_mirror_wake.notify.notify_one();
    }

    /// What the host's merge queue drain waits on beside its lifecycle tick:
    /// a pass starts when a write the drain reads committed (FIX 7306).
    pub fn merge_queue_wake(&self) -> &tokio::sync::Notify {
        &self.origin_mirror_wake.merge_queue
    }

    /// Wakes the merge queue drain now, after a write it reads committed.
    pub(crate) fn wake_merge_queue(&self) {
        self.origin_mirror_wake.merge_queue.notify_one();
    }

    /// Keeps a wake for the pass that runs now to hand on when it ends.
    pub fn defer_origin_mirror_wake(&self) {
        self.origin_mirror_wake
            .deferred
            .store(true, Ordering::Release);
    }

    /// Takes the kept wake: `true` when there was one.
    pub fn take_origin_mirror_wake(&self) -> bool {
        self.origin_mirror_wake
            .deferred
            .swap(false, Ordering::AcqRel)
    }

    /// A published ref moved: wakes the mirror pushes, unless it is an
    /// imported ref, which never goes back out, or a keep-ref.
    pub(crate) fn note_origin_ref_moved(&self, ref_name: &str) {
        if !ref_name.starts_with(ORIGIN_MIRROR_IMPORTED_PREFIX)
            && !ref_name.starts_with(GIT_WIRE_KEEP_REF_PREFIX)
        {
            self.wake_origin_mirrors();
        }
    }

    /// A publication reached its terminal state: a published one moved its
    /// ref, and a received push the merge queue drain takes in is
    /// Published now (FIX 7306).
    pub(crate) fn note_origin_publication_finished(&self, record: &OriginPublicationRecord) {
        if record.status == OriginPublicationStatus::Published {
            self.note_origin_ref_moved(record.ref_name.as_str());
            self.wake_merge_queue();
        }
    }

    /// A journaled GitWire ref effect landed: each ref it moved.
    pub(crate) fn note_git_refs_moved(&self, publications: &[GitRefPublication]) {
        for publication in publications {
            self.note_origin_ref_moved(publication.name().as_str());
        }
    }

    /// Whether a full-auto mirror's last settled run saw `fingerprint`.
    pub(super) fn full_auto_seen(&self, repo_id: EntityId, fingerprint: &str) -> bool {
        self.origin_mirror_wake
            .seen
            .lock()
            .is_ok_and(|seen| seen.get(&repo_id).is_some_and(|kept| kept == fingerprint))
    }

    /// Keeps what a full-auto mirror's settled run saw, or forgets it.
    pub(super) fn keep_full_auto_seen(&self, repo_id: EntityId, fingerprint: Option<String>) {
        if let Ok(mut seen) = self.origin_mirror_wake.seen.lock() {
            match fingerprint {
                Some(fingerprint) => seen.insert(repo_id, fingerprint),
                None => seen.remove(&repo_id),
            };
        }
    }
}
