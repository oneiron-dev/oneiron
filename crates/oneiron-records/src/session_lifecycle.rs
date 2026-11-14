//! Moved from `crates/oneiron/src/session_lifecycle.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::session_lifecycle::speakers::SessionParticipant;
pub use crate::session_lifecycle::speakers::SessionSpeakers;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One sitting's identity. Hosts bind it from their actor and machine context;
/// it confers no write authority and cannot shape a Dreamer pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SessionKey {
    pub actor: EntityId,
    pub machine: EntityId,
}

impl SessionKey {
    fn pointer(self) -> (EntityId, EntityId) {
        (self.actor, self.machine)
    }
}

/// Why a session ended. `Explicit` is the app's own end hint; `IdleFloor`
/// is the driver's inactivity backstop; `LifetimeCeiling` is the hard
/// wall-clock cap that closes a session regardless of activity hints
/// (H-S4: forged typing hints reset `last_activity` forever, so the floor
/// alone is defeatable — the ceiling is not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    Explicit,
    IdleFloor,
    LifetimeCeiling,
}

/// The three timestamps retained for one driver-authored session hint.
///
/// `claimed_ms` is producer provenance and is never rewritten, even when the
/// driver rejects it for derivation. `arrival_ms` is the channel stamp, and
/// `effective_ms` is the driver's monotone, bounded decisional time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHintTimestamp {
    pub claimed_ms: Option<u64>,
    pub arrival_ms: u64,
    pub effective_ms: u64,
}

/// A loss-aware rollup of adjacent activity hints. The endpoints retain the
/// complete timestamp provenance; `count` records how many hints the period
/// represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionActivityPeriod {
    pub first: SessionHintTimestamp,
    pub last: SessionHintTimestamp,
    pub count: u64,
}

/// Durable lifecycle clock fields for one SESSION entity. The legacy entity
/// clock fields remain unix SECONDS; hint provenance is stored in unix
/// MILLISECONDS so source data is never rounded away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLifecycleRecord {
    pub version: u8,
    pub key: SessionKey,
    /// Stamped by the app-open hint — not by the first turn.
    pub started_at: u64,
    /// Bumped by turn-witness or an activity hint; never rewinds.
    pub last_activity: u64,
    /// Set exactly once, by explicit-end, idle floor, or lifetime ceiling.
    pub ended_at: Option<u64>,
    pub end_reason: Option<SessionEndReason>,
    /// Effective timestamp of the minting app-open hint.
    #[serde(default)]
    pub started_effective_ms: u64,
    /// Monotone floor used to derive the next hint's effective timestamp.
    #[serde(default)]
    pub last_effective_ms: u64,
    /// Every app-open point applied to this sitting, including the mint.
    #[serde(default)]
    pub app_open_hints: Vec<SessionHintTimestamp>,
    /// Activity hints retained as endpoint-and-count periods.
    #[serde(default)]
    pub activity_periods: Vec<SessionActivityPeriod>,
    /// The explicit-end point, when this sitting ended explicitly.
    #[serde(default)]
    pub explicit_end_hint: Option<SessionHintTimestamp>,
    /// Why a `host.session.close` hook would have kept the sitting open,
    /// when one tried: no hook keeps a sitting open, so it closed anyway.
    #[serde(default)]
    pub close_hook_stop: Option<String>,
    /// Who spoke in the sitting (FIX 2015): its answering agents and its
    /// participants with their names as bound. Empty on a sitting recorded
    /// before them.
    #[serde(default)]
    pub speakers: SessionSpeakers,
    /// The summary attempt this sitting's close queued (FIX 7509), which
    /// writes its summary from the turns it retained. `None` while it is
    /// open, and on a sitting that closed with none queued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_attempt: Option<[u8; 16]>,
}
pub mod speakers;
