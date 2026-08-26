use crate::entity_id::EntityId;
use crate::store::GateDecisionId;

#[cfg(test)]
use crate::error::{Error, Result};

/// ONE-1149 race-test rendezvous seam. The deterministic raced-delete harness
/// must order the deleter's lock-free `read_entity_header` read_txn (which does
/// NOT take the single LMDB write lock) BEFORE the eraser's commit, so the
/// headerful gate is forced to win the header read and the partial-residue leg
/// is exercised every run instead of nondeterministically diverting to the
/// headerless path. The only way to inject that ordering across the spawned
/// production call is a `#[cfg(test)]` signal emitted from inside
/// `delete_entity_with_reason` once the header is proven `Some`. It compiles
/// out of production entirely (the `#[cfg(not(test))]` shim is a no-op),
/// mirroring the established sweep-side fault-injection seam idiom.
#[cfg(test)]
static AFTER_HEADER_READ: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);

/// Installs the one-shot rendezvous sender consumed by
/// [`signal_after_header_read`]. Called by the raced-delete harness before it
/// releases the deleter; the matching receiver `recv()`s on the eraser side
/// just before its commit.
#[cfg(test)]
pub(crate) fn install_after_header_read_signal(tx: std::sync::mpsc::SyncSender<()>) {
    *AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned") = Some(tx);
}

/// Fires the rendezvous signal exactly once if a sender is installed, then
/// clears it so unrelated headerful deletes in the same serial run never block
/// on a stale rendezvous. A no-op when no harness installed a sender.
#[cfg(test)]
pub(super) fn signal_after_header_read() {
    let sender = AFTER_HEADER_READ
        .lock()
        .expect("AFTER_HEADER_READ poisoned")
        .take();
    if let Some(sender) = sender {
        // The rendezvous (`sync_channel(0)`) blocks here until the eraser
        // `recv()`s; that recv is positioned immediately before its commit, so
        // the deleter's header read is provably ordered before the erase.
        let _ = sender.send(());
    }
}

/// Production no-op shim for the race-test rendezvous seam: compiles out the
/// signal entirely in non-test builds.
#[cfg(not(test))]
#[inline(always)]
pub(super) fn signal_after_header_read() {}

#[cfg(all(test, feature = "sync"))]
thread_local! {
    static FAIL_AFTER_TOMBSTONE_BEFORE_PURGE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_LIVE_TOMBSTONE_PERSIST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms a one-shot crash surrogate after TXN1 has durably persisted the CRDT
/// tombstone and request-keyed authority recovery sidecar, but before any
/// local scrub/purge.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_after_tombstone_before_purge() {
    FAIL_AFTER_TOMBSTONE_BEFORE_PURGE.with(|armed| armed.set(true));
}

/// Arms a one-shot TXN1 failure after the live Loro tombstone commits but
/// before its snapshot/update persistence transaction begins.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn arm_fail_live_tombstone_persist() {
    FAIL_LIVE_TOMBSTONE_PERSIST.with(|armed| armed.set(true));
}

#[cfg(all(test, feature = "sync"))]
pub(super) fn maybe_fail_live_tombstone_persist() -> Result<()> {
    if FAIL_LIVE_TOMBSTONE_PERSIST.replace(false) {
        return Err(Error::InvariantViolation(
            "test failure persisting committed live deletion tombstone",
        ));
    }
    Ok(())
}

// Both call sites live inside the `sync`-only `write_crdt_tombstone`, so the
// shim is only ever named on a `sync` build; the sibling
// `maybe_fail_after_tombstone_before_purge` has cfg-independent call sites and
// keeps the wider `not(all(test, sync))` cfg. Compiling this one on sync-off
// builds too made it plain dead code that failed `clippy -D warnings`.
#[cfg(all(not(test), feature = "sync"))]
#[inline(always)]
pub(super) fn maybe_fail_live_tombstone_persist() {}

#[cfg(all(test, feature = "sync"))]
pub(super) fn maybe_fail_after_tombstone_before_purge() -> Result<()> {
    #[cfg(all(test, feature = "sync"))]
    if FAIL_AFTER_TOMBSTONE_BEFORE_PURGE.replace(false) {
        return Err(Error::InvariantViolation(
            "test crash after deletion TXN1 before purge",
        ));
    }
    Ok(())
}

#[cfg(not(all(test, feature = "sync")))]
#[inline(always)]
pub(super) fn maybe_fail_after_tombstone_before_purge() {}

#[cfg(all(test, not(feature = "sync")))]
thread_local! {
    static FAIL_FIRST_TXN_PENDING_TOMBSTONE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms a one-shot crash surrogate INSIDE the non-publishing soft-erase txn,
/// after its `pt:` pending-tombstone marker is staged and before the commit.
///
/// It exists to prove ATOMICITY, which is the whole of fix-leg 9: the scrub and
/// the replayable propagation intent are one transaction, so a failure at the
/// marker write must take the scrub down with it. Armed only on a build without
/// `sync`, because that is the build whose `write_crdt_tombstone` publishes
/// nothing and therefore reaches this site.
#[cfg(all(test, not(feature = "sync")))]
pub(crate) fn arm_fail_first_txn_pending_tombstone() {
    FAIL_FIRST_TXN_PENDING_TOMBSTONE.with(|armed| armed.set(true));
}

#[cfg(all(test, not(feature = "sync")))]
pub(super) fn maybe_fail_first_txn_pending_tombstone() -> Result<()> {
    if FAIL_FIRST_TXN_PENDING_TOMBSTONE.replace(false) {
        return Err(Error::InvariantViolation(
            "test failure writing the first-transaction pending-tombstone marker",
        ));
    }
    Ok(())
}

#[cfg(not(all(test, not(feature = "sync"))))]
#[inline(always)]
pub(super) fn maybe_fail_first_txn_pending_tombstone() {}

/// The points on the delete path at which a test harness may park the deleter
/// and commit a `RevokeActor`, so the authority race is driven deterministically
/// instead of hoped for.
///
/// The three steps bracket the linearization point, which is what makes them
/// worth naming: one strictly BEFORE the publish commit (refusal expected,
/// nothing published) and two strictly AFTER it (completion expected, because a
/// revocation ordered after the publish commit does not reach back — fix-leg 7's
/// ruling). Constructed on every build; only the parking machinery is test-only.
///
/// "After the publish" is a misnomer on a build with no CRDT: there
/// `write_crdt_tombstone` publishes nothing, so [`Self::AfterTombstonePublish`]
/// marks the window between the facade's entry fold and the FIRST destructive
/// transaction — exactly where fix-leg 8's conditional re-fold has to bite. The
/// parking machinery is therefore compiled on every test build, not just `sync`
/// ones; the two remaining fire points are already cfg-independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteRendezvous {
    /// After the gate recovery sidecar is durably staged, BEFORE the publish txn
    /// opens — the interval fix-5 left unguarded, in which a `RevokeActor` used
    /// to land unseen while the tombstone still reached peers.
    ///
    /// Fired only from the `sync` tombstone writer; a build without CRDTs has no
    /// publication to bracket (its `write_crdt_tombstone` is a no-op).
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    BeforeTombstonePublish,
    /// The publish txn has COMMITTED. Next comes the first post-publication
    /// destructive step: the soft-erase for gdpr/policy, the purge otherwise.
    AfterTombstonePublish,
    /// After any post-publication soft-erase committed, BEFORE the purge txn
    /// opens — the second post-publication window, reached only on the arms that
    /// have a soft-erase phase.
    BeforeHardPurge,
}

/// The channels + identity of one installed rendezvous.
///
/// TWO phase, and it has to be: the harness cannot pre-stage the revocation in
/// a held write txn the way the fix-5 rendezvous does, because the steps around
/// these seams take the write lock themselves and the deleter would block before
/// ever arriving. So the deleter announces on `arrived` holding NO write lock,
/// the harness commits the revocation, and only then does `resume` release it.
/// Both are `sync_channel(0)`.
///
/// Keyed by `(step, target)`, not by step alone. `cargo test` runs the suite as
/// parallel threads of ONE process against a single static, and several
/// unrelated tests delete entities concurrently — a step-only match let a
/// stranger's delete fire the harness's `arrived` channel, so the harness
/// committed its revocation while its OWN deleter was still short of the seam.
/// Matching the target entity makes each rendezvous belong to exactly the delete
/// that installed it.
///
/// The `arrived` half carries the staged [`GateDecisionId`] when the arm has
/// one: a refused publish returns no request id to the caller, so the harness
/// could not otherwise name the sidecar it must prove absent. `None` on the soft
/// arm, which ledgers its decision in the shell-scrub txn and stages no sidecar.
///
/// Compiles out of every non-test build via the no-op shim, exactly like
/// [`signal_after_header_read`].
#[cfg(test)]
type DeleteRendezvousChannels = (
    DeleteRendezvous,
    EntityId,
    std::sync::mpsc::SyncSender<Option<GateDecisionId>>,
    std::sync::mpsc::Receiver<()>,
);

#[cfg(test)]
static DELETE_RENDEZVOUS: std::sync::Mutex<Option<DeleteRendezvousChannels>> =
    std::sync::Mutex::new(None);

/// Installs the one-shot rendezvous consumed by [`signal_delete_rendezvous`]
/// when a delete of `target` reaches `step`. Any other step, or any other
/// entity, passes straight through.
#[cfg(test)]
pub(crate) fn install_delete_rendezvous(
    step: DeleteRendezvous,
    target: EntityId,
    arrived: std::sync::mpsc::SyncSender<Option<GateDecisionId>>,
    resume: std::sync::mpsc::Receiver<()>,
) {
    *DELETE_RENDEZVOUS
        .lock()
        .expect("DELETE_RENDEZVOUS poisoned") = Some((step, target, arrived, resume));
}

/// Parks the deleter once if a rendezvous is installed for THIS step and THIS
/// entity, then clears it so later deletes never block on a stale rendezvous.
/// The mutex guard is released before the blocking `recv` — holding it across
/// the park would deadlock every other delete that reaches a seam.
#[cfg(test)]
pub(super) fn signal_delete_rendezvous(
    step: DeleteRendezvous,
    id: &EntityId,
    decision_id: Option<GateDecisionId>,
) {
    let mut installed = DELETE_RENDEZVOUS
        .lock()
        .expect("DELETE_RENDEZVOUS poisoned");
    if installed
        .as_ref()
        .is_none_or(|(at_step, target, _, _)| *at_step != step || target != id)
    {
        return;
    }
    let (_, _, arrived, resume) = installed.take().expect("checked installed above");
    drop(installed);
    let _ = arrived.send(decision_id);
    let _ = resume.recv();
}

#[cfg(not(test))]
#[inline(always)]
pub(super) fn signal_delete_rendezvous(
    _step: DeleteRendezvous,
    _id: &EntityId,
    _decision_id: Option<GateDecisionId>,
) {
}
