//! Bounded CHAT-lane draining of durable session-end distill jobs.

use super::distill::{
    SessionActorDistiller, pending_session_actor_distills, run_session_end_actor_distill,
};
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The distill runner's durable rotation cursor: a singleton row.
const CURSOR: SideTable<(), EntityId, Raw> =
    SideTable::new(&side_table::ACTOR_CLAIMS_DISTILL_RUNNER_CURSOR);

/// Successful landings and retryable per-sitting failures from one host pump.
#[derive(Debug, Default)]
pub struct SessionDistillDrain {
    pub spent_sessions: Vec<EntityId>,
    pub claims: Vec<EntityId>,
    pub failures: Vec<(EntityId, Error)>,
    pub pending_sessions: usize,
}

/// Run at most `limit` session-end jobs without coupling model work to session close.
/// A failing sitting stays pending and cannot starve later jobs: the durable cursor
/// rotates over all pending identities, including when the host budget is one job.
/// Notes and job consumption still share the existing atomic distill transaction.
pub fn drain_pending_session_actor_distills(
    vault: &Vault,
    limit: usize,
    distiller: &dyn SessionActorDistiller,
) -> Result<SessionDistillDrain> {
    if !(1..=1024).contains(&limit) {
        return Err(Error::InvalidConfig(
            "session distill limit must be in 1..=1024".to_owned(),
        ));
    }
    let pending = pending_session_actor_distills(vault)?;
    let cursor = {
        let txn = vault.store.env.read_txn()?;
        CURSOR.get(&vault.store, &txn, &())?
    };
    let after = pending.partition_point(|id| cursor.is_some_and(|held| *id <= held));
    let mut report = SessionDistillDrain::default();
    for session in pending[after..].iter().chain(&pending[..after]).take(limit) {
        match run_session_end_actor_distill(vault, session, distiller) {
            Ok(claims) => {
                report.spent_sessions.push(*session);
                report.claims.extend(claims);
            }
            Err(error) => report.failures.push((*session, error)),
        }
        vault.with_write_txn(|txn| {
            CURSOR.put(&vault.store, txn, &(), session)?;
            Ok(())
        })?;
    }
    report.pending_sessions = pending_session_actor_distills(vault)?.len();
    Ok(report)
}
