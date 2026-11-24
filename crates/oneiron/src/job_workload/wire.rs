//! The `vault.jobs.workloads.*` verbs' inputs and answers: plain fields the
//! SDK spells (ids and digests in hex), converted at the door to and from the
//! stored workload.
use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::WorkloadPin;
use super::doors::WorkloadError;
use super::record::{JobWorkload, WorkloadApprovedBy};

/// `vault.jobs.workloads.pin`: the exact workload to pin. Pinning approves
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPinRequest {
    pub pin: WorkloadPin,
}

/// `vault.jobs.workloads.approve`: the owner's yes for one pinned workload,
/// on the machines it may run on, for the Grants that may start it, until
/// `expires_at_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadApproveRequest {
    /// The workload digest (64 hex).
    pub workload: String,
    /// The MACHINE ids (hex) it may run on; never empty.
    pub machines: Vec<String>,
    /// The Grant ids (hex) that may start it; empty means the Grant it was
    /// pinned under only.
    #[serde(default)]
    pub starters: Vec<String>,
    pub expires_at_ms: u64,
}

/// `vault.jobs.workloads.revoke`, `vault.jobs.workloads.get`: one workload by
/// its digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRef {
    /// The workload digest (64 hex).
    pub workload: String,
}

/// `vault.jobs.workloads.list`: every workload the caller may read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadListRequest {}

/// Where a workload stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadStanding {
    /// Pinned, not approved.
    Pinned,
    /// Approved and not expired.
    Approved,
    /// Approved, and the approval has expired.
    Expired,
    /// Revoked by the owner.
    Revoked,
}

/// The owner's approval of a workload, as the SDK spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadApprovalView {
    /// The owner who approved it (hex); `None` after their erase.
    pub owner: Option<String>,
    pub machines: Vec<String>,
    pub starters: Vec<String>,
    pub expires_at_ms: u64,
    pub at_ms: u64,
}

/// One workload as the verbs answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadView {
    pub digest: String,
    pub pin: WorkloadPin,
    pub standing: WorkloadStanding,
    /// Who pinned it (hex); `None` after their erase.
    pub pinned_by: Option<String>,
    /// The Grant an agent pinned it under (hex); `None` for the owner's pin.
    pub pinned_under: Option<String>,
    pub pinned_at_ms: u64,
    pub approval: Option<WorkloadApprovalView>,
    pub revoked_at_ms: Option<u64>,
}

impl WorkloadView {
    /// The view of `row` at `now_ms`.
    #[must_use]
    pub fn of(row: &JobWorkload, now_ms: u64) -> Self {
        let standing = match (&row.revoked, &row.approval) {
            (Some(_), _) => WorkloadStanding::Revoked,
            (None, None) => WorkloadStanding::Pinned,
            (None, Some(approval)) if approval.expires_at_ms <= now_ms => WorkloadStanding::Expired,
            (None, Some(_)) => WorkloadStanding::Approved,
        };
        Self {
            digest: row.digest.clone(),
            pin: row.pin.clone(),
            standing,
            pinned_by: row.pinned_by.map(|id| id.to_hex()),
            pinned_under: row.pinned_under.map(|id| id.to_hex()),
            pinned_at_ms: row.pinned_at_ms,
            approval: row.approval.as_ref().map(|approval| {
                let WorkloadApprovedBy::Owner { owner } = &approval.by;
                WorkloadApprovalView {
                    owner: owner.map(|id| id.to_hex()),
                    machines: approval.machines.iter().map(EntityId::to_hex).collect(),
                    starters: approval.starters.iter().map(EntityId::to_hex).collect(),
                    expires_at_ms: approval.expires_at_ms,
                    at_ms: approval.at_ms,
                }
            }),
            revoked_at_ms: row.revoked.as_ref().map(|revoked| revoked.at_ms),
        }
    }
}

/// The answer of a door that may leave a workload as it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadChange {
    /// False when the call repeated what already stood.
    pub changed: bool,
    pub workload: WorkloadView,
}

/// `vault.jobs.workloads.list`'s answer, newest pin first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadList {
    pub workloads: Vec<WorkloadView>,
}

/// The ids in `hex`, each parsed, or a bad request naming `field`.
pub(super) fn parse_ids(
    field: &'static str,
    hex: &[String],
) -> Result<Vec<EntityId>, WorkloadError> {
    hex.iter()
        .map(|id| EntityId::from_hex(id).map_err(|_| WorkloadError::BadId { field }))
        .collect()
}
