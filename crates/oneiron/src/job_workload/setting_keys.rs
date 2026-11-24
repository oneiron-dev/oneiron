//! The pinned workloads' Setting key (pass 33 row R2; the lead's POLICY AS SETTINGS, 25 Nov
//! 00:04): who approves and revokes a pinned workload. Its default is card EN-1 A as a value,
//! not as code: the vault owner approves each exact workload.

use crate::Vault;
use crate::error::Result;
use crate::setting::Kind;

/// Off: only the vault owner approves and revokes a pinned workload.
fn owner_approves_alone() -> bool {
    false
}

crate::setting::setting_keys! {
    /// Let an agent approve and revoke pinned workloads under its own Grant. Off by default
    /// (card EN-1 A): only the vault owner approves a workload, with presence at Important, and
    /// only the owner revokes one. On, an agent whose own live Grant names
    /// vault.jobs.workloads.approve or vault.jobs.workloads.revoke does that act too, but never
    /// approves a workload pinned under its own Grant and never names its own Grant as a
    /// starter. The start gate admits an agent's approval only while this is on and the agent
    /// still holds a live Grant naming vault.jobs.workloads.approve. On is the looser value, so
    /// only the owner turns it on; an agent's change waits on the owner's answer.
    pub(crate) JOB_WORKLOADS_AGENT_MAY_APPROVE: bool = "jobs.workloads.agent_may_approve" {
        kind: Kind::new(owner_approves_alone)
            .strictest(owner_approves_alone)
            .lower(),
    };
}

/// Whether an agent may approve and revoke pinned workloads, read in `txn` at the vault scope.
///
/// # Errors
///
/// Storage errors.
pub(super) fn agent_may_approve_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(JOB_WORKLOADS_AGENT_MAY_APPROVE
        .read_in_txn(vault, txn, &[], None)?
        .value)
}
