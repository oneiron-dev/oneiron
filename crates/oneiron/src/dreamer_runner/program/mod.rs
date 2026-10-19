//! Turn-woken programs (DOOR-141, FIX 4382).
//!
//! An actor arms a pinned callable SKILL entry for its own future turns
//! (`arm`). Each turn it lands records the wake it owes in that turn's own
//! commit (`wake`), sealing the actor's authority as witnesses. A drain
//! admits each wake in one writer (`admit`): the checks against the live
//! vault, a Gate receipt, and one Dreamer program attempt, the root of its
//! run tree, stamped as the waking actor (`authority`). The program runs
//! under that actor's authority and Grant only: never the operator root,
//! never a Dreamer stamp standing in for the actor. Its own lease is the
//! program kind's (`lease`).
//!
//! PR1 stops at admission: an admitted attempt is parked until the program
//! runtime lands (PR2). Nothing here runs or completes it.

mod admit;
mod arm;
mod authority;
mod lease;
mod types;
mod wake;

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};

pub(crate) use self::arm::{
    arm_turn_program_in_txn, disarm_turn_program_in_txn, erase_turn_program_actor_in_txn,
};
pub(crate) use self::authority::{
    TurnProgramAuthority, require_program_actor_in_txn, stamp_program_attempt,
};
pub use self::types::{
    ArmTurnProgram, DisarmTurnProgram, LandedTurnRef, ProgramRecipePin,
    TurnProgramAdmissionOutcome, TurnProgramAdmissionReceipt, TurnProgramDrain,
    TurnProgramRegistration,
};
pub(crate) use self::wake::{
    drain_turn_program_wakes, record_turn_program_wakes_in_txn, turn_programs_armed_in_txn,
};

use self::types::{
    TurnProgramAdmissionRecord, TurnProgramArming, TurnProgramAttemptStamp, TurnProgramWake,
};

/// One armed program, keyed by its actor, then its registration.
const ARM: SideTable<(EntityId, EntityId), TurnProgramArming, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ARM);
/// One admission, keyed by its dedupe identity.
const ADMISSION: SideTable<[u8; 32], TurnProgramAdmissionRecord, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ADMISSION);
/// The waking actor one program attempt runs as, keyed by attempt.
const ATTEMPT: SideTable<AttemptId, TurnProgramAttemptStamp, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_ATTEMPT);
/// One owed wake, keyed by the turn, then the registration it woke.
const WAKE: SideTable<(EntityId, EntityId), TurnProgramWake, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_WAKE);

/// Who parks an admitted program until its runtime resumes it.
const PARK_OWNER: &str = "dreamer.turn_program";
/// Why: the attempt is admitted and has not run.
const PARK_REASON: &str = "admitted; the turn program runtime lands with DOOR-141 PR2";
