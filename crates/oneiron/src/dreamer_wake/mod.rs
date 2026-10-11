//! Dreamer wake-pass driver (ONE-1288, DREAM-001 residual).
//!
//! One wake pass = one bounded work cycle on one node (a Dreamer wake-pass,
//! never a process wake). The driver composes the LANDED primitives only —
//! atomic admission (`admit_next_consolidation`), reserve-then-spend budget
//! settlement, park rows, milestones-as-claims, and the ephemeral progress
//! lane — and adds the LOOP: admit → execute → settle/complete or park,
//! until a stop condition. The engine owns no timer or cron: hosts call
//! [`request_wake`] to ENQUEUE and [`DreamerWakeDriver::run_wake_pass`] to
//! RUN the pass — two separate host calls. Idle = nothing runs.
mod deadline;
mod driver;
mod grain;
mod legibility;
mod policy;
mod projector;
mod recipe;
mod scheduling;
mod settlement;
mod sieve;
mod types;

pub use self::deadline::*;
pub use self::driver::*;
pub use self::grain::*;
pub use self::legibility::*;
pub use self::policy::*;
pub use self::recipe::*;
pub use self::scheduling::*;
pub use self::types::*;
pub use self::projector::ProjectorPolicy;
pub use self::sieve::{
    RuleClass, SievePass, SievePolicy, SieveRung, SieveSpan, SpanBand, SpanKind, SpanOrigin,
};
pub(crate) use self::projector::apply_in_txn as apply_projection_in_txn;
pub(crate) use self::sieve::owe_read_in_txn as owe_sieve_read_in_txn;

/// The erase hook, in the erasing transaction before the graph is torn down:
/// an erased TURN leaves the sieve and the projection, and a TURN whose
/// MESSAGE is erased leaves them too and is owed a new read of the words it
/// keeps.
pub(crate) fn erase_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &crate::EntityId,
) -> crate::Result<()> {
    use crate::ports::EntityStoreRead;
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    let Some(row) = vault.store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    let turns = match row.entity_type {
        ENTITY_TYPE_TURN => vec![*id],
        ENTITY_TYPE_MESSAGE => vault.filtered_edge_peers(
            txn,
            crate::ports::EdgeDirection::Out,
            id,
            crate::edge::EdgeKind::PartOf,
            Some(ENTITY_TYPE_TURN),
            "dreamer erased message turns",
        )?,
        _ => return Ok(()),
    };
    for turn in &turns {
        sieve::erase_turn_in_txn(vault, txn, turn)?;
        projector::erase_turn_in_txn(vault, txn, turn)?;
        if turn != id {
            sieve::owe_read_in_txn(vault, txn, turn)?;
        }
    }
    Ok(())
}

// `settlement` is impl-only: it re-opens `impl DreamerWakeDriver` and owns no
// name the rest of the crate reaches for, so it needs no re-export.

#[cfg(test)]
mod tests;
#[cfg(test)]
use crate::attempt_queue::{AttemptId, AttemptResumePoint, LandingTrigger};
#[cfg(test)]
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerConsolidationScope, DreamerMilestoneKind,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    ParkDreamerAttempt,
};
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::WriteEnvelope;
#[cfg(test)]
use rmpv::Value;

#[cfg(test)]
pub(crate) use tests::block_on_ready;
