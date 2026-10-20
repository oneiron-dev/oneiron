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
//! PR2 runs it: the Dreamer's program runtime (`dreamer_wake::program`)
//! binds each attempt to its live authority and its code run (`run`), runs
//! the pinned entry there, and settles each effect into its step. PR3b
//! resumes it: a run cut before it settled re-enters its pinned entry as the
//! same try, each settled call answered from its checkpoint, and a run the
//! runtime holds resumes once its hold's condition is met (`resume`).
//!
//! PR3a reads it (`read`): what a turn's wakes admitted, where a program's
//! run stands and a settled step's exact result, each for the program's
//! waking actor or the verified owner, on the caller's own read lane; PR3b
//! adds the checkpoint its restarter resumes from.

mod admit;
mod arm;
mod authority;
mod bodies;
mod lease;
mod read;
mod resume;
mod run;
mod types;
mod wake;

use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::side_table::{self, Named, SideTable};

pub(crate) use self::arm::{
    arm_turn_program_in_txn, disarm_turn_program_in_txn, erase_turn_program_actor_in_txn,
    turn_program_erase_details,
};
pub(crate) use self::authority::{
    TurnProgramAuthority, TurnProgramBinding, TurnProgramBound, apply_program_started_in_txn,
    program_milestone_envelope, require_program_actor_in_txn, stamp_program_attempt,
};
pub(crate) use self::bodies::{
    program_run_actor_in_txn, program_step_carriage, program_step_owners,
};
pub use self::read::{
    ProgramAdmissionOutcomeView, ProgramCheckpointCallView, ProgramCheckpointHeadView,
    ProgramCheckpointRequest, ProgramCheckpointView, ProgramCheckpointWaitView,
    ProgramFrontierView, ProgramHeldView, ProgramQueueView, ProgramResultAvailability,
    ProgramRunLifecycle, ProgramRunRequest, ProgramRunStateView, ProgramRunView,
    ProgramStepIssueView, ProgramStepState, ProgramStepView, ProgramTryView,
    SettledProgramStepRequest, SettledProgramStepView, TurnProgramAdmissionItem,
    TurnProgramAdmissionRequest, TurnProgramAdmissionView, program_checkpoint, program_run,
    settled_program_step, turn_program_admission,
};
pub(crate) use self::resume::ProgramHold;
pub(crate) use self::run::{
    ProgramWrite, TurnProgramEntered, bind_program_write_in_txn, join_program_checkpoint_in_txn,
    note_program_write_uncertain, settle_program_outbound_in_txn, settle_program_write_in_txn,
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

/// Who parks a program attempt the program runtime holds.
pub(crate) const PROGRAM_PARK_OWNER: &str = "dreamer.turn_program";
/// The park DOOR-141 PR1 left on each admitted attempt, exactly: the runtime
/// resumes these (`lease`), and no other park.
const PR1_PARK_REASON: &str = "admitted; the turn program runtime lands with DOOR-141 PR2";
