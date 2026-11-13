//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/silence.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// The activity `silent` judged one leased attempt's quiet by (OF-568 L5),
/// each part the newest of its kind since the attempt's claim. A card holds
/// its newest finding's; none of it is evidence, so it never reopens a
/// settled card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthSilenceActivity {
    /// Its own newest call: a receipt that names it at its current lease
    /// generation, in Unix seconds.
    pub own_call_at: Option<u64>,
    /// Its own newest model step at that generation: the step replay
    /// capsule's capture time, in Unix seconds.
    pub own_step_at: Option<u64>,
    /// Its actor's newest call that names no attempt, even when older than
    /// the dial. It cannot be attributed, so it counts for every leased
    /// attempt of the actor.
    pub actor_only_at: Option<u64>,
    /// The runtime's last streamed output frame for this lease, in Unix
    /// seconds, while this vault runs it. In memory only: a restart, or the
    /// end of its last run's binding, drops it.
    pub stream_at: Option<u64>,
    /// The runtime's last finished tool call for this lease (answered,
    /// refused or failed), in Unix seconds; in memory only, as `stream_at`.
    pub tool_finished_at: Option<u64>,
    /// Its actor's newest call that names another attempt, or another
    /// generation of this one: counter-evidence only.
    pub other_session: Option<HealthOtherSession>,
}

/// Another session of the same agent that made a call since the attempt's
/// claim (OF-568 L5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthOtherSession {
    /// The attempt the call's receipt names.
    pub attempt: EntityId,
    /// The lease generation the receipt names.
    pub generation: u32,
    /// When the call was recorded, in Unix seconds.
    pub at: u64,
}
