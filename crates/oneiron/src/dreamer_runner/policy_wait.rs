//! The policy waits of executor-error parks: an ExecutorError park whose refusal an owner policy write clears,
//! and the requeue that write gives it (FIX 23347 part 2; Engine ruling 06:28, 13 Nov).
//!
//! Two refusals an executor reaches wait on owner policy, not on a consent with an identity: a claim source the
//! source-trust ceiling does not trust for Auto (`SourceNotTrustedForAuto`), and a family write the gate would not
//! answer Auto (`FamilyRequiresAutoGrant`). Such a try parks as ExecutorError, as every refusal of an owner act
//! does, with its notice raised and the owner's release open. In the park's own write it is also indexed here
//! under its kind and the lease generation it parked at.
//!
//! The owner's policy-manifest write that changes what clears that kind (the `source_trust` section for the
//! first; the approval sections for the second) requeues the indexed parks of that kind in its own write: each
//! park resumes once as the same try, its notices are resolved, and its entry goes. That is the matching signal for
//! a policy wait: targeted by kind, once per owner act, never a timed or blind retry (constraint C5). A try the
//! change did not clear meets the same refusal on its next run and parks again, indexed at its new generation, so
//! the next such act retries it once more. Every other executor-error park, and every park written before this
//! index, stays owner-released (part 1).

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::{ErrorKind, Result};
use crate::side_table::{self, Named, SideTable};

use super::{
    DreamerParkCause, DreamerParkedAttemptRecord, DreamerRunnerStore, PARKED, ParkResumer,
};

/// Executor-error parks by (kind byte, attempt), each holding the try's lease generation at its park.
const POLICY_WAITS: SideTable<([u8; 1], AttemptId), u32, Named> =
    SideTable::new(&side_table::DREAMER_POLICY_WAITS);

/// The owner policy an executor-error park waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PolicyWaitKind {
    /// A claim source the source-trust ceiling does not trust for Auto: a change of the manifest's
    /// `source_trust` section clears it.
    SourceTrust,
    /// A family write the gate would not answer Auto: a change of the sections the gate reads for an Auto
    /// answer (the actor ceilings, delegated grants, rules, defaults and source trust) clears it.
    AutoGrant,
}

impl PolicyWaitKind {
    /// Every kind, in key order.
    pub(crate) const ALL: [Self; 2] = [Self::SourceTrust, Self::AutoGrant];

    /// The kind's key byte in the index.
    const fn key_byte(self) -> u8 {
        match self {
            Self::SourceTrust => 1,
            Self::AutoGrant => 2,
        }
    }

    /// The policy wait of an executor error of `kind`, when an owner policy write clears it.
    pub(crate) const fn of_error_kind(kind: ErrorKind) -> Option<Self> {
        match kind {
            ErrorKind::SourceNotTrustedForAuto => Some(Self::SourceTrust),
            ErrorKind::FamilyRequiresAutoGrant => Some(Self::AutoGrant),
            _ => None,
        }
    }
}

/// Indexes `attempt`'s executor-error park under `kind`, at the try's lease generation read in this write: the
/// write that parks it.
pub(crate) fn index_policy_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    kind: PolicyWaitKind,
    attempt: AttemptId,
) -> Result<()> {
    let Some(row) = AttemptQueue::new(vault).get_in_write_txn(wtxn, attempt)? else {
        return Ok(());
    };
    POLICY_WAITS.put(
        &vault.store,
        wtxn,
        &([kind.key_byte()], attempt),
        &row.attempt_count,
    )
}

/// Drops `record`'s policy-wait entries, in the writer that clears or replaces its park.
pub(crate) fn unindex_policy_wait_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) -> Result<()> {
    for kind in PolicyWaitKind::ALL {
        POLICY_WAITS.delete(&vault.store, wtxn, &([kind.key_byte()], record.attempt_id))?;
    }
    Ok(())
}

/// Requeues every executor-error park indexed under one of `kinds`, once, in the caller's write: the owner's
/// policy write that clears those kinds. Each park resumes as the same try under its own park owner and its
/// notices are resolved. Every entry read goes, so a later act retries only a try that parked again. An entry
/// with no park, a park that is no longer an untyped ExecutorError park the resume table admits, or a lease that
/// moved on is stale: it goes and nothing moves. Returns the tries it requeued.
pub(crate) fn requeue_policy_waits_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    kinds: &[PolicyWaitKind],
) -> Result<Vec<AttemptId>> {
    let store = DreamerRunnerStore::new(vault);
    let queue = AttemptQueue::new(vault);
    let now = vault.store.clock.now_recorded_at();
    let mut requeued = Vec::new();
    for kind in kinds {
        let key_byte = [kind.key_byte()];
        // Materialize the scan before writing: each requeue deletes its entry.
        for ((_, attempt), lease_generation) in
            POLICY_WAITS.scan_from(&vault.store, wtxn, &key_byte)?
        {
            POLICY_WAITS.delete(&vault.store, wtxn, &(key_byte, attempt))?;
            let Some(park) = PARKED.get(&vault.store, &*wtxn, &attempt)? else {
                continue;
            };
            if park.cause != DreamerParkCause::ExecutorError
                || !park.resumable_by(ParkResumer::PolicyChange)
            {
                continue;
            }
            let fresh = queue
                .get_in_txn(wtxn, attempt)?
                .is_some_and(|row| row.state.is_running() && row.attempt_count == lease_generation);
            if !fresh {
                continue;
            }
            if store
                .resume_parked_in_txn(wtxn, attempt, &park.park_owner, now)?
                .is_none()
            {
                continue;
            }
            super::park_release::resolve_notices_in_txn(vault, wtxn, &park, lease_generation)?;
            tracing::info!(
                attempt = ?attempt,
                kind = ?kind,
                "an owner policy write requeued an executor-error park it clears"
            );
            requeued.push(attempt);
        }
    }
    if !requeued.is_empty() {
        // The deadline lane arms the requeued tries once the owner's write commits.
        crate::batch::queue_proactivity_change(vault, wtxn);
    }
    Ok(requeued)
}
