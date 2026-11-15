//! Moved from `crates/oneiron/src/dreamer_runner/free_time/policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::ActSurface;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::dreamer_runner::free_time::policy::FreeTimeCadence;
pub use oneiron_verb_wire::dreamer_runner::free_time::policy::FreeTimeSchedule;
pub use oneiron_verb_wire::dreamer_runner::free_time::policy::FreeTimeSplit;
use serde::Deserialize;
use serde::Serialize;

/// One agent's free-time policy as the engine keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicy {
    /// The agent definition it is for.
    pub agent: EntityId,
    /// 1 for the first set; each set takes the revision it replaces.
    pub revision: u64,
    pub total_units: u64,
    pub schedule: FreeTimeSchedule,
    pub pinned_split: Option<FreeTimeSplit>,
    pub cap_shown_at_ms: u64,
    /// The owner, as this vault revalidated them in the write; `None` for an
    /// agent's set (`set_by_agent`), and once that owner was erased (FIX
    /// 8875). A holder's schedule move keeps the setter of the set it moves.
    /// Audit only; no rule reads it.
    pub set_by: Option<EntityId>,
    /// The agent whose act set it: within its live Grant (FIX 5660), with
    /// its signed record naming the Grant; `None` for the owner's own set,
    /// and once that agent was erased. A holder's schedule move keeps the
    /// agent of the set it moves; the move's record is the engine-control
    /// receipt (FABLE-6918-2). A home move judges it with `set_grant`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_agent: Option<EntityId>,
    /// The Grant the agent's set acted under (FIX 11608): a home move lands
    /// the row only while that Grant names `free_time_policy_set` at
    /// `set_at`. `None` for the owner's own set, for rows set before grants
    /// were stamped, and once that agent was erased. A holder's schedule
    /// move keeps the Grant of the set it moves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_grant: Option<EntityId>,
    /// Vault clock seconds of the owner's or the agent's set; a holder's
    /// schedule move keeps it, and its own time is in the record's act and
    /// in its receipt. No cycle opens at a boundary before this.
    pub set_at: u64,
    /// After a holder's schedule move (FABLE-6918-1), vault clock seconds:
    /// the boundary the schedule in force before the move would have opened
    /// its next cycle at. No cycle opens at a boundary before it, so a move
    /// delays the next cycle and never brings it forward, and no move opens
    /// a second cycle, with a second whole allowance, in one period. Each
    /// move only raises it; `None` for the owner's or an agent's set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_not_before: Option<u64>,
    /// Where the owner said so; `None` also once the linked machine it was
    /// said on was erased. Audit only; no rule reads it.
    pub surface: Option<ActSurface>,
    /// BLAKE3 over the policy it replaced, as JSON (`null` for none).
    pub prior: [u8; 32],
}
