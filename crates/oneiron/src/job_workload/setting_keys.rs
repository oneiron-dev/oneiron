//! The pinned workloads' Setting keys (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5; the lead's POLICY AS SETTINGS): how an agent's pin checks in,
//! and how long a pin the check-in let go may start.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::check_in::{ActClass, CheckInMode};
use crate::error::{Error, Result};
use crate::setting::{ChainOrder, Kind, ScopeKind, SettingScope, SettingSource, SettingValue};
use crate::{EntityId, Vault};

/// How an agent's pin checks in: the three modes of check-in, with their wire
/// tokens (`CheckInMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PinCheckInMode {
    /// Every pin waits for the ladder, even inside a `compute.pin` grant.
    #[serde(rename = "manual")]
    Manual,
    /// A pin inside a `compute.pin` grant goes; a reversible pin outside one
    /// goes when the screen is sure; a network pin outside one asks.
    #[serde(rename = "auto")]
    Auto,
    /// Every pin the agent's Grant may make goes, with a record.
    #[serde(rename = "full-access")]
    FullAccess,
}

impl PinCheckInMode {
    /// The check-in mode it is.
    #[must_use]
    pub const fn check_in_mode(self) -> CheckInMode {
        match self {
            Self::Manual => CheckInMode::AlwaysAsk,
            Self::Auto => CheckInMode::AskWhenUnsure,
            Self::FullAccess => CheckInMode::NeverAsk,
        }
    }
}

impl ChainOrder for PinCheckInMode {
    const STRICTEST_FIRST: &'static [Self] = &[Self::Manual, Self::Auto, Self::FullAccess];
}

impl SettingValue for PinCheckInMode {
    const CLOSED: bool = true;
}

/// How many days a pin the check-in let go may start: 1 to 365.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct ApprovalDays(pub u64);

impl SettingValue for ApprovalDays {
    const CLOSED: bool = true;

    fn check(self) -> Result<Self> {
        if (1..=365).contains(&self.0) {
            Ok(self)
        } else {
            Err(Error::InvalidConfig(
                "a pin's approval lasts from 1 to 365 days".into(),
            ))
        }
    }
}

const fn auto() -> PinCheckInMode {
    PinCheckInMode::Auto
}

const fn manual() -> PinCheckInMode {
    PinCheckInMode::Manual
}

const fn fourteen_days() -> ApprovalDays {
    ApprovalDays(14)
}

const fn one_day() -> ApprovalDays {
    ApprovalDays(1)
}

crate::setting::setting_keys! {
    /// How an agent's new pin of a workload checks in (pass 34, 6.5): manual, auto (the
    /// default) or full-access. In manual every pin waits for the ladder, even inside a
    /// compute.pin standing grant, and the owner answers it. In auto a pin a compute.pin grant
    /// covers goes and nobody is asked; outside one, a pin with no network goes when the screen
    /// is sure and waits otherwise, and a network pin always waits. In full-access every pin the
    /// agent's Grant may make goes, with a record. A row at an agent and the vault's row meet:
    /// the stricter wins. Loosening is the owner's; a holder's loosening waits on his answer.
    pub(crate) JOB_WORKLOADS_CHECK_IN_MODE: PinCheckInMode = "jobs.workloads.check_in_mode" {
        kind: Kind::new(auto).strictest(manual).chain(),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
        act: ActClass::GrantWiden,
    };
    /// How many days a pin the check-in let go may start (pass 34, 6.5): 14 unless the owner
    /// sets it, from 1 to 365. The owner's own approval of an exact pin names its own expiry.
    pub(crate) JOB_WORKLOADS_APPROVAL_DAYS: ApprovalDays = "jobs.workloads.approval_days" {
        kind: Kind::new(fourteen_days).strictest(one_day).lower(),
        act: ActClass::GrantWiden,
    };
}

/// The mode in force for `agent`'s pins, read in `txn`, and the row that
/// decided it: its own row and the vault's meet, and the stricter wins.
///
/// # Errors
///
/// Storage errors.
pub(super) fn check_in_mode_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<(PinCheckInMode, SettingSource)> {
    let resolved =
        JOB_WORKLOADS_CHECK_IN_MODE.read_in_txn(vault, txn, &[SettingScope::Agent(agent)], None)?;
    Ok((resolved.value, resolved.source))
}

/// How long a pin the check-in let go may start, in milliseconds, read in
/// `txn`.
///
/// # Errors
///
/// Storage errors.
pub(super) fn approval_window_ms_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<u64> {
    let days = JOB_WORKLOADS_APPROVAL_DAYS
        .read_in_txn(vault, txn, &[], None)?
        .value
        .0;
    Ok(days.saturating_mul(86_400_000))
}
