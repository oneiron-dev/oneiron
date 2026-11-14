//! The wire shapes of a turn program's reads (DOOR-141 PR3a). Ids are
//! lowercase hex: 32 characters for an entity, attempt or step, 64 for a
//! digest. Times are the vault's recording clock, in seconds. A field the
//! caller's own lane does not read is absent and named in `withheld`.

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::program::read::views::{
    OwedWakeHoldView, ProgramAdmissionOutcomeView, ProgramCheckpointCallView,
    ProgramCheckpointConsentView, ProgramCheckpointHeadView, ProgramCheckpointRequest,
    ProgramCheckpointView, ProgramCheckpointWaitView, ProgramFrontierView, ProgramHeldView,
    ProgramQueueView, ProgramResultAvailability, ProgramRunLifecycle, ProgramRunRequest,
    ProgramRunStateView, ProgramRunView, ProgramStepIssueView, ProgramStepState, ProgramStepView,
    ProgramTryView, SettledProgramStepRequest, SettledProgramStepView, TurnProgramAdmissionItem,
    TurnProgramAdmissionRequest, TurnProgramAdmissionView, TurnProgramOwedWakeItem,
};
