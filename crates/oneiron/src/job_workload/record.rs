//! The stored workload (pass 33, 5.1): one `JOB_WORKLOAD` row per pin, keyed by
//! the pin's digest. The pin is written once; an approval and a revoke change
//! the row after it.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::setting::{SettingScope, SettingSource};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

use super::WorkloadPin;
use super::screen::PinScreen;
use super::setting_keys::PinCheckInMode;

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
    /// The project the pin named: it picks the `compute.pin` grants that may
    /// cover the pin, and the start gate's live re-read names it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<EntityId>,
    /// How the pin checked in (pass 34, 6.5): its act, mode and outcome.
    /// `None` on a row pinned before the check-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<WorkloadCheckIn>,
}

/// How one pin checked in (pass 34, 6.5): who made it is the row's
/// `pinned_by` and `pinned_under`; this is the rest. A successful admission
/// is recorded here, since check-in's own receipts cover only the pending
/// transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadCheckIn {
    /// The act class the host read from the pin: `reversible_work`, or
    /// `outbound_send` for a pin with the host's network.
    pub act: String,
    /// Why the host read that class.
    pub act_reasons: Vec<String>,
    /// The mode the pin checked in under, and the row that decided it;
    /// `None` for the owner's own pin, which goes on his own proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PinCheckInMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode_source: Option<SettingSource>,
    /// The digest (hex) of the `compute.pin` grant that covered the pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covering_grant: Option<String>,
    pub outcome: PinCheckInOutcome,
    /// The screen, when it ran: for a reversible pin it decided; for a
    /// network pin it is the ask's recommendation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screen: Option<PinScreen>,
    pub at_ms: u64,
}

/// Where a pin's check-in stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PinCheckInOutcome {
    /// The pin went, and may start until `until_ms`
    /// (`jobs.workloads.approval_days` after it went).
    Went {
        basis: PinGoBasis,
        /// The pending check-in an approval of which was spent (hex).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        check_in: Option<String>,
        until_ms: u64,
    },
    /// The pin waits on the pending check-in `check_in` (hex); the call
    /// that names it once it is approved lets the pin go.
    Waits { check_in: String, reason: String },
}

/// Why a pin went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PinGoBasis {
    /// Mode `full-access`.
    NeverAsk,
    /// Rung 0: a `compute.pin` grant covers it.
    StandingRow,
    /// Rung 1: the screen was sure.
    Sure,
    /// The owner's own pin, on his own proof.
    OwnProof,
    /// A holder up the ladder approved its pending check-in.
    Answered,
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
/// A pin the check-in let go needs no approval ([`WorkloadCheckIn`]).
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

/// Whether `source`, the row that decided a pin's mode, sits at `actor`'s
/// own scope.
fn source_names_actor(source: &SettingSource, actor: &EntityId) -> bool {
    match source {
        SettingSource::Pin(scope)
        | SettingSource::Row(scope)
        | SettingSource::Carried(scope)
        | SettingSource::Seeded(scope)
        | SettingSource::Unreadable(scope) => *scope == SettingScope::Agent(*actor),
        SettingSource::Fit(_) | SettingSource::Met | SettingSource::Default => false,
    }
}

/// Takes the erased actor out of every workload: their name leaves the pins
/// they made, the approvals they gave, the revokes they made and the mode
/// rows their pins recorded (the side table's actor scrub). The workloads and their approvals stay: they are the
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
        // The mode's source names an agent when that agent's own row decided.
        if let Some(check_in) = row.check_in.as_mut()
            && check_in
                .mode_source
                .as_ref()
                .is_some_and(|source| source_names_actor(source, actor))
        {
            check_in.mode_source = None;
            changed = true;
        }
        if changed {
            JOB_WORKLOADS.put(&vault.store, wtxn, &key, &row)?;
        }
    }
    Ok(())
}
