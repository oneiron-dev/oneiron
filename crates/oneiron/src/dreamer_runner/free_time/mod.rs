//! An agent's free time (FIX 4453, ARCH-0005b #free-time). It comes in two
//! kinds: "for your human" (`autonomy.for_human`), where the agent thinks
//! how to help its human and what it suggests lands as a proposal, and "own
//! time" (`autonomy.own_time`), its own reading, fun and rest.
//!
//! The owner sets the total budget and the cycle's clock (`policy`). Each
//! cycle opens at its owner-set boundary on the elected home, under one root
//! spend scope holding that total (`cycle`), and queues one item of each
//! kind (`items`): the resident's free time for its human, and its own
//! dreaming as its own time. Each item ends in one receipt by label, and the
//! floor reads those receipts alone (`receipt`). Beyond the floor the agent
//! owes nothing: an own-time item may be rest with no output, unspent budget
//! is no failure, and nothing here scores, limits or nudges its own time.
//! The owner reads the policy, the cycles and each cycle's sheet (`doors`):
//! the agent's short note and the spending records, never its diary.
//!
//! No policy, no cycle (`FREE_TIME_WHEN_UNSET`): a resident without one
//! keeps its nightly dreaming exactly as before.
//!
//! Every row here is this node's own, under the vault's elected home: the
//! cycle opens where its items run. An actor's erase takes its rows in all
//! five families (`erase`, FIX 5664). A home move carries all five, with
//! each cycle's spend tree, from the old home to the new one (`handoff`,
//! FIX 5661); with no carried state the new home opens its cycles as before.
//! A restore over a live vault keeps the tries those bindings name as the
//! live vault holds them, as it keeps the bindings (`restore`, FIX 6577).

mod actor_content;
mod cycle;
mod doors;
mod erase;
#[cfg(feature = "sync")]
mod handoff;
mod items;
mod policy;
mod receipt;
#[cfg(feature = "sync")]
mod restore;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::llm::CallPurpose;
use crate::side_table::{self, Named, SideTable};

pub use self::cycle::{
    FreeTimeCycle, FreeTimeCycleState, FreeTimeItemRef, FreeTimeNote, FreeTimeOwnTimeChoice,
};
pub use self::doors::{
    FreeTimeCycleRequest, FreeTimeCycleSummary, FreeTimeCycleView, FreeTimeCyclesPage,
    FreeTimeCyclesRequest, FreeTimeItemReceiptView, FreeTimeItemView, FreeTimeLabelSpend,
    FreeTimeNoteView, FreeTimePolicyRequest, FreeTimePolicyRow, FreeTimePolicySetRequest,
    FreeTimePolicyState, FreeTimePolicyView, FreeTimeSpendView, free_time_cycle_as_owner,
    free_time_cycles_as_owner, free_time_policy_as_owner, free_time_policy_set_as_owner,
};
pub(crate) use self::erase::erase_free_time_actor_in_txn;
#[cfg(feature = "sync")]
pub(crate) use self::handoff::{
    FreeTimeClockRows, FreeTimeCycleRows, FreeTimeItemRows, FreeTimePolicyRows,
    FreeTimeReceiptRows, free_time_root_scopes_in_txn,
};
#[cfg(feature = "sync")]
pub(crate) use self::items::free_time_items_fenced_in_txn;
pub(crate) use self::items::{
    FreeTimeForHumanContext, FreeTimeForHumanReply, FreeTimeItemRun, charge_free_time_item_in_txn,
    end_free_time_item_in_txn, free_time_item_input, free_time_item_to_run,
    free_time_item_waits_unstarted, free_time_line, land_free_time_for_human,
    record_own_time_landed_in_txn,
};
pub use self::items::{FreeTimeItemBinding, is_free_time_try};
pub(crate) use self::policy::free_time_owns_reflection_in_txn;
pub use self::policy::{
    FREE_TIME_WHEN_UNSET, FreeTimeCadence, FreeTimePolicy, FreeTimePolicyInput, FreeTimeSchedule,
    FreeTimeSplit, UnsetFreeTimePolicy,
};
pub use self::receipt::{
    FreeTimeCycleSheet, FreeTimeFloor, FreeTimeItemOutcome, FreeTimeItemReceipt, free_time_floor,
};
#[cfg(feature = "sync")]
pub(crate) use self::restore::free_time_attempt_restore_keys;

/// The owner's policy per agent definition, with the witness of its sets and
/// clears.
const POLICY: SideTable<EntityId, policy::FreeTimePolicyRecord, Named> =
    SideTable::new(&side_table::DREAMER_FREE_TIME_POLICY);
/// The last boundary this node opened a cycle at, per agent.
const CLOCK: SideTable<EntityId, FreeTimeClock, Named> =
    SideTable::new(&side_table::DREAMER_FREE_TIME_CLOCK);
/// Each cycle, by agent and boundary, so an agent's cycles read in time order.
const CYCLE: SideTable<(EntityId, u64), cycle::FreeTimeCycle, Named> =
    SideTable::new(&side_table::DREAMER_FREE_TIME_CYCLE);
/// Each item attempt's binding, by the attempt its cycle queued.
const ITEM: SideTable<AttemptId, items::FreeTimeItemBinding, Named> =
    SideTable::new(&side_table::DREAMER_FREE_TIME_ITEM);
/// Each item's terminal receipt, by agent, cycle and item.
const RECEIPT: SideTable<(EntityId, EntityId, EntityId), receipt::FreeTimeItemReceipt, Named> =
    SideTable::new(&side_table::DREAMER_FREE_TIME_RECEIPT);

/// A retry lineage of more tries than this is logged once per binding lookup
/// that walks it (`items`, FIX 7057) and once per restore (`restore`, FIX
/// 7006). It is walked whole all the same: this bounds nothing.
const LONG_RETRY_LINEAGE: usize = 64;

/// The two kinds of an agent's free time, by the label its calls carry.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeKind {
    /// `autonomy.for_human`: it thinks how to help its human, and what it
    /// suggests lands as a proposal.
    ForHuman,
    /// `autonomy.own_time`: its own reading, fun and rest. Nothing scores it.
    OwnTime,
}

impl FreeTimeKind {
    /// The purpose label every call of this kind carries.
    #[must_use]
    pub fn purpose(self) -> CallPurpose {
        match self {
            Self::ForHuman => CallPurpose::AutonomyForHuman,
            Self::OwnTime => CallPurpose::AutonomyOwnTime,
        }
    }

    /// The byte an item's id is derived with.
    const fn code(self) -> u8 {
        match self {
            Self::ForHuman => 1,
            Self::OwnTime => 2,
        }
    }
}

/// The last owner-set boundary this node opened (or passed) a cycle at for
/// one agent, and the boundary of the cycle still open. Live: a restore
/// never moves it back, so no image re-opens a cycle it already spent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FreeTimeClock {
    last_boundary: u64,
    open: Option<u64>,
}
