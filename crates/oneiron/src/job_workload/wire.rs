//! The `vault.jobs.workloads.*` verbs' inputs and answers: plain fields the
//! SDK spells (ids and digests in hex), converted at the door to and from the
//! stored workload.
use serde::{Deserialize, Serialize};

use crate::EntityId;

use super::WorkloadPin;
use super::doors::WorkloadError;
use super::record::{JobWorkload, PinCheckInOutcome, WorkloadApprovedBy, WorkloadCheckIn};

/// `vault.jobs.workloads.pin`: the exact workload to pin. The pin checks in
/// (pass 34, 6.5): it goes, or it waits on a check-in the call answers
/// `CHECK_IN_PENDING` naming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadPinRequest {
    pub pin: WorkloadPin,
    /// The project the pin works for (an id in hex): it picks the agent's
    /// `compute.pin` grants that may cover the pin. Not part of the pin's
    /// digest; a pin that names none is never covered by a grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// The pin's approved check-in (32 hex): the call that names it lets the
    /// pin go and spends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in_ref: Option<String>,
}

/// `vault.jobs.workloads.approve`: the yes for one pinned workload, on the
/// machines it may run on, for the Grants that may start it, until
/// `expires_at_ms`: the owner's act.
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
    /// Pinned, with neither a check-in nor an approval.
    Pinned,
    /// Its check-in waits for the ladder.
    Waiting,
    /// Its check-in let it go, and it may start until the record's
    /// `until_ms`.
    Cleared,
    /// Approved and not expired.
    Approved,
    /// Approved or let go, and that has expired.
    Expired,
    /// Revoked.
    Revoked,
}

/// The approval of a workload, as the SDK spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkloadApprovalView {
    /// The owner who approved it (hex); `None` after the owner's erase.
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
    /// The project the pin named (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// How the pin checked in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<WorkloadCheckIn>,
}

impl WorkloadView {
    /// The view of `row` at `now_ms`.
    #[must_use]
    pub fn of(row: &JobWorkload, now_ms: u64) -> Self {
        let outcome = row.check_in.as_ref().map(|check_in| &check_in.outcome);
        let standing = match (&row.revoked, &row.approval, outcome) {
            (Some(_), _, _) => WorkloadStanding::Revoked,
            (None, Some(approval), _) if approval.expires_at_ms <= now_ms => {
                WorkloadStanding::Expired
            }
            (None, Some(_), _) => WorkloadStanding::Approved,
            (None, None, Some(PinCheckInOutcome::Went { until_ms, .. })) if *until_ms <= now_ms => {
                WorkloadStanding::Expired
            }
            (None, None, Some(PinCheckInOutcome::Went { .. })) => WorkloadStanding::Cleared,
            (None, None, Some(PinCheckInOutcome::Waits { .. })) => WorkloadStanding::Waiting,
            (None, None, None) => WorkloadStanding::Pinned,
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
            project: row.project.map(|id| id.to_hex()),
            check_in: row.check_in.clone(),
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
