//! The stored workload (pass 33, 5.1): one `JOB_WORKLOAD` row per pin, keyed by
//! the pin's digest. The pin is written once; an approval and a revoke change
//! the row after it.
use serde::{Deserialize, Serialize};

use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::WorkloadPin;

pub(super) const JOB_WORKLOADS: SideTable<[u8; 32], JobWorkload, Named> =
    SideTable::new(&side_table::JOB_WORKLOAD);

/// One pinned workload: the exact thing allowed to run, who pinned it, and
/// its approval or revoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobWorkload {
    /// [`WorkloadPin::digest`] of `pin`: the row's key, lower hex.
    pub digest: String,
    pub pin: WorkloadPin,
    /// The owner or agent who pinned it; `None` after their erase.
    pub pinned_by: Option<EntityId>,
    /// The Grant an agent pinned it under; `None` for the owner's own pin.
    /// With no starters named, only this Grant may start it.
    pub pinned_under: Option<EntityId>,
    pub pinned_at_ms: u64,
    pub approval: Option<WorkloadApproval>,
    pub revoked: Option<WorkloadRevocation>,
}

/// The yes for one pinned workload: the owner's (card EN-1 A, each exact
/// workload).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadApproval {
    pub by: WorkloadApprovedBy,
    /// The machines it may run on; never empty.
    pub machines: Vec<EntityId>,
    /// The Grants that may start it; empty means the Grant it was pinned
    /// under only (the owner may start any approved workload).
    pub starters: Vec<EntityId>,
    pub expires_at_ms: u64,
    pub at_ms: u64,
}

/// Who approved a workload, and so how the start gate judges the approval.
/// Pass 34's check-in of an agent's pin (R2's follow-up, with R7) adds its
/// own variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkloadApprovedBy {
    /// The vault owner under their own proof; `None` after their erase.
    Owner { owner: Option<EntityId> },
}

/// The revoke of a workload: no later start, and the issuer stops its
/// running jobs (EN-4 A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRevocation {
    /// The owner who revoked it; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
}

/// The 32 key bytes of a workload digest: 64 lower-hex characters.
pub(super) fn digest_key(digest: &str) -> Option<[u8; 32]> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut key = [0u8; 32];
    for (index, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(key)
}

impl Vault {
    /// The workload pinned under `digest`, if any.
    pub fn job_workload(&self, digest: &str) -> crate::Result<Option<JobWorkload>> {
        let txn = self.store.env.read_txn()?;
        self.job_workload_in_txn(&txn, digest)
    }

    /// The workload pinned under `digest`, read in `txn`.
    pub fn job_workload_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        digest: &str,
    ) -> crate::Result<Option<JobWorkload>> {
        let Some(key) = digest_key(digest) else {
            return Ok(None);
        };
        JOB_WORKLOADS.get(&self.store, txn, &key)
    }

    /// Every pinned workload, newest pin first.
    pub fn job_workloads(&self) -> crate::Result<Vec<JobWorkload>> {
        let txn = self.store.env.read_txn()?;
        self.job_workloads_in_txn(&txn)
    }

    /// Every pinned workload, newest pin first, read in `txn`.
    pub fn job_workloads_in_txn(&self, txn: &heed::RoTxn<'_>) -> crate::Result<Vec<JobWorkload>> {
        let mut rows: Vec<JobWorkload> = JOB_WORKLOADS
            .scan(&self.store, txn)?
            .into_iter()
            .map(|(_, row)| row)
            .collect();
        rows.sort_by(|a, b| {
            b.pinned_at_ms
                .cmp(&a.pinned_at_ms)
                .then_with(|| a.digest.cmp(&b.digest))
        });
        Ok(rows)
    }
}

/// Takes the erased actor out of every workload: their name leaves the pins
/// they made, the approvals they gave and the revokes they made (the side
/// table's actor scrub). The workloads and their approvals stay: they are the
/// owner's settings, not the actor's data.
pub(crate) fn erase_workload_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (key, mut row) in JOB_WORKLOADS.scan(&vault.store, wtxn)? {
        let mut changed = false;
        if row.pinned_by == Some(*actor) {
            row.pinned_by = None;
            changed = true;
        }
        if let Some(approval) = row.approval.as_mut() {
            let WorkloadApprovedBy::Owner { owner: approver } = &mut approval.by;
            if *approver == Some(*actor) {
                *approver = None;
                changed = true;
            }
        }
        if let Some(revoked) = row.revoked.as_mut()
            && revoked.by == Some(*actor)
        {
            revoked.by = None;
            changed = true;
        }
        if changed {
            JOB_WORKLOADS.put(&vault.store, wtxn, &key, &row)?;
        }
    }
    Ok(())
}
