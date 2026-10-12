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
pub use self::projector::ProjectorPolicy;
pub(crate) use self::projector::apply_in_txn as apply_projection_in_txn;
pub use self::recipe::*;
pub use self::scheduling::*;
pub(crate) use self::sieve::owe_read_in_txn as owe_sieve_read_in_txn;
pub use self::sieve::{
    RuleClass, SievePass, SievePolicy, SieveRung, SieveSpan, SpanBand, SpanKind, SpanOrigin,
};
pub use self::types::*;

/// The erase hook, in the erasing transaction before the graph is torn down.
/// The shared physical tear calls it for every delete door (facade, batch,
/// cascade), and the soft erase beside its other derived-state hooks. An
/// erased TURN leaves the sieve and the projection; a TURN whose MESSAGE is
/// erased leaves them too and is owed a new read of the words it keeps.
pub(crate) fn erase_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    id: &crate::EntityId,
) -> crate::Result<()> {
    let turns = text_turns_in_txn(store, txn, id)?;
    for turn in &turns {
        sieve::erase_turn_in_txn(store, txn, turn)?;
        projector::erase_turn_in_txn(store, txn, turn)?;
        if turn != id {
            sieve::owe_read_in_txn(store, txn, turn)?;
        }
    }
    Ok(())
}

/// The publication hook: a TURN, or a MESSAGE inside one, whose text a
/// write changed owes that turn a new sieve read, committed with the text.
/// Unlike the tag and vector marks it needs no model configured.
pub(crate) fn mark_on_publication_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &crate::EntityId,
) -> crate::Result<()> {
    for turn in text_turns_in_txn(store, txn, entity)? {
        sieve::owe_read_in_txn(store, txn, &turn)?;
    }
    Ok(())
}

/// The TURNs whose words `id` is: itself for a TURN, every TURN a MESSAGE is
/// part of (each `PartOf` edge, however many), none for anything else.
fn text_turns_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &crate::EntityId,
) -> crate::Result<Vec<crate::EntityId>> {
    use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(Vec::new());
    };
    match row.entity_type {
        ENTITY_TYPE_TURN => Ok(vec![*id]),
        ENTITY_TYPE_MESSAGE => {
            let mut turns = Vec::new();
            let edges = store.port_edges(
                txn,
                id,
                EdgeDirection::Out,
                Some(crate::edge::EdgeKind::PartOf),
                None,
            )?;
            for edge in edges {
                let target = edge?.target;
                if store
                    .port_entity_record(txn, &target)?
                    .is_some_and(|row| row.entity_type == ENTITY_TYPE_TURN)
                {
                    turns.push(target);
                }
            }
            Ok(turns)
        }
        _ => Ok(Vec::new()),
    }
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
