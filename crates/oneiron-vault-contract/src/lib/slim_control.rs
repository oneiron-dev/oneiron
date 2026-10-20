//! The supervisor's SLIM recovery surface (FIX 5186): what a vault reports of
//! its residency and its live outbound wait
//! ([`CtlRequest::SlimStatus`](crate::CtlRequest::SlimStatus)), and the
//! logical return to FULL after a pressure episode
//! ([`CtlRequest::Unslim`](crate::CtlRequest::Unslim)).
//!
//! It rides v3 with a build floor and no version move. A vault built before
//! it answers either request as unknown (`Ok { ok: false }`) and ignores a
//! `wait_id` on `Shed`, shedding unguarded, and its `Ping` carries no
//! `slim_recovery_revision`. A supervisor reads a missing revision as no
//! extension, and sends a guarded `Shed` only once a `Ping` from that same
//! vault process reports [`SLIM_RECOVERY_REVISION`]. Pressure and recovery
//! thresholds are the supervisor's: nothing here carries one.

use serde::{Deserialize, Serialize};

/// The revision of this surface a vault built with it reports on `Ping`
/// (`slim_recovery_revision`).
pub const SLIM_RECOVERY_REVISION: u32 = 1;

/// The blocker kind a `Shed` carrying a `wait_id` refuses with when the step
/// the vault would shed has no live wait under that id any more: the wait
/// ended or another took its place. Nothing was dropped; read a fresh
/// [`SlimStatusWire`] before asking again.
pub const WAIT_OBSERVATION_CHANGED: &str = "wait_observation_changed";

/// A vault process's live residency. `Reaped` is process absence, so it has
/// no spelling here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlimResidency {
    Full,
    Slim,
}

/// The one live outbound wait, a model call or an effect send, that a `Shed`
/// would park the vault on now. `wait_id` is opaque and names this wait in
/// this vault process only: check it with the vault's name and PID. No
/// payload, prompt, credential or step identity crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibleWaitWire {
    pub wait_id: u64,
    /// How long it has waited, in whole seconds of the vault's monotonic
    /// clock.
    pub waited_secs: u64,
}

/// The answer to [`CtlRequest::SlimStatus`](crate::CtlRequest::SlimStatus):
/// one atomic read that changes no residency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlimStatusWire {
    pub residency: SlimResidency,
    /// `null` is a known "no eligible live wait" in this valid reply only.
    /// It is required on the wire: a reply without it is no status. A vault
    /// whose journal does not read answers `Ok { ok: false }`, never `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub eligible_wait: Option<EligibleWaitWire>,
}

/// Whether an [`CtlRequest::Unslim`](crate::CtlRequest::Unslim) ended a SLIM
/// episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnslimStatus {
    /// The vault was SLIM and is logically FULL again.
    Resumed,
    /// The vault was already FULL.
    AlreadyFull,
}

/// The answer to [`CtlRequest::Unslim`](crate::CtlRequest::Unslim). Logical
/// FULL only: the vault rebuilds nothing eagerly, schedules no wake, writes
/// no journal row and leaves every in-flight outbound call as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnslimWire {
    pub status: UnslimStatus,
    /// The residency this call left: always [`SlimResidency::Full`].
    pub residency: SlimResidency,
}
