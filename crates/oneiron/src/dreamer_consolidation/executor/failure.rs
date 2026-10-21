//! How a partition attempt's failed step parks with what it spent (FIX
//! 414). A plain park settles only the run line's meter, which a partition
//! attempt never registers: the attempt's own tally (the terminal steps it
//! already charged, a conflict pack's among them) and a refused call's paid
//! usage would be refunded as if never spent. Every such park carries them.

use super::super::step_charge::StepChargeTally;
use crate::dreamer_runner::DreamerParkCause;
use crate::dreamer_wake::DreamerAttemptExecution;
use crate::llm::DurableStepError;

/// The park a partition attempt's step `error` ends it in, carrying
/// `charges` with any paid usage `error` holds added first. A deadline or
/// finalize stop checkpoints, as before; a refused paid reply (a conflict
/// read `conflict_failed` kept the open marker of among them) asks again
/// after its retry delay, as a refused extraction does (FIX 7272); any other
/// parks as [`DreamerParkCause::of_step`] says. Reasons are as before.
pub(super) fn park_partition_failure_with_spend(
    error: DurableStepError,
    charges: &mut StepChargeTally,
) -> DreamerAttemptExecution {
    match &error {
        DurableStepError::DeadlineHardCut => return charges.checkpoint(),
        DurableStepError::FinalizeRefused => {
            return charges.park_for("wake pass finalize window", DreamerParkCause::Checkpoint);
        }
        DurableStepError::SpentSchemaValidation { usage, .. }
        | DurableStepError::SpentFinalizeRefused { usage }
        | DurableStepError::SpentLlm { usage, .. } => charges.record_usage(usage),
        _ => {}
    }
    let cause = if matches!(error, DurableStepError::SpentSchemaValidation { .. }) {
        DreamerParkCause::Retry
    } else {
        DreamerParkCause::of_step(&error)
    };
    charges.park_for(&error.to_string(), cause)
}
