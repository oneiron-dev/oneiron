use crate::Vault;
use crate::entity_id::EntityId;
use crate::store::GateDecisionId;

#[cfg(test)]
use crate::error::{Error, Result};

// ONE-1149 race-test rendezvous seam. The deterministic raced-delete harness
// must order the deleter's lock-free `read_entity_header` read_txn (which does
// NOT take the single LMDB write lock) BEFORE the eraser's commit, so the
// headerful gate is forced to win the header read and the partial-residue leg
// is exercised every run instead of nondeterministically diverting to the
// headerless path. The only way to inject that ordering across the spawned
// production call is a `#[cfg(test)]` signal emitted from inside
// `delete_entity_with_reason` once the header is proven `Some`. It compiles
// out of production entirely (the `#[cfg(not(test))]` shim is a no-op),
// mirroring the established sweep-side fault-injection seam idiom.
//
// The slot belongs to the VAULT being deleted from
// (`crate::store::TestHooks::install_after_header_read_signal`), not to the
// process and not to the deleter thread. A process-global slot let a sibling
// test overwrite the sender (dropping it, so the eraser's `recv()` failed with
// `RecvError`) or consume it with an unrelated headerful delete; a per-vault
// slot is unreachable from every test that opened a different vault, which is
// every other test.

/// Fires this vault's post-header-read rendezvous signal, if one is armed.
///
/// Compiles out of every non-test build via the no-op shim below.
#[cfg(test)]
pub(super) fn signal_after_header_read(vault: &Vault) {
    vault.test_hooks().signal_after_header_read();
}

/// Production no-op shim for the race-test rendezvous seam: compiles out the
/// signal entirely in non-test builds.
#[cfg(not(test))]
#[inline(always)]
pub(super) fn signal_after_header_read(_vault: &Vault) {}

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
/// Keyed by `(step, target)`, not by step alone. One vault serves many deletes
/// — a test's own control delete, a warmup, the second park the raced-purge
/// harness installs while its deleter is still held at the first — and a
/// step-only match let any of them fire the harness's `arrived` channel, so the
/// harness committed its revocation while its OWN deleter was still short of the
/// seam. Matching the target entity makes each rendezvous belong to exactly the
/// delete that installed it.
///
/// The `arrived` half carries the staged [`GateDecisionId`] when the arm has
/// one: a refused publish returns no request id to the caller, so the harness
/// could not otherwise name the sidecar it must prove absent. `None` on the soft
/// arm, which ledgers its decision in the shell-scrub txn and stages no sidecar.
///
/// The slot itself is a field on the vault's
/// [`crate::store::TestHooks`]; it compiles out of every non-test build, and the
/// firing side goes through the no-op shim below exactly like
/// [`signal_after_header_read`].
#[cfg(test)]
pub(crate) type DeleteRendezvousChannels = (
    DeleteRendezvous,
    EntityId,
    std::sync::mpsc::SyncSender<Option<GateDecisionId>>,
    std::sync::mpsc::Receiver<()>,
);

/// Parks this vault's deleter if a rendezvous is installed for `step` and `id`.
#[cfg(test)]
pub(super) fn signal_delete_rendezvous(
    vault: &Vault,
    step: DeleteRendezvous,
    id: &EntityId,
    decision_id: Option<GateDecisionId>,
) {
    vault
        .test_hooks()
        .signal_delete_rendezvous(step, id, decision_id);
}

#[cfg(not(test))]
#[inline(always)]
pub(super) fn signal_delete_rendezvous(
    _vault: &Vault,
    _step: DeleteRendezvous,
    _id: &EntityId,
    _decision_id: Option<GateDecisionId>,
) {
}
