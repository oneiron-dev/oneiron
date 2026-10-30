//! An owned promotion sink for a long-lived host. One sink serves every
//! attempt a supervisor admits: each sealed write names its own run, so the
//! host never builds (or can forge) a per-attempt run context.
use std::sync::Arc;

use super::{DreamerRunContext, promote_scoped_consolidation};
use crate::EntityId;
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::dreamer_consolidation::{
    ConsolidationSink, PromotionCandidate, ScopedConsolidationWrite,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{ClaimError, Error, ErrorKind, GateError, Result};
use crate::llm::BoundedAutoChecker;

/// [`ConsolidationSink`] over the one promotion door, owned rather than
/// borrowed, for executors built once and lent to many passes.
pub struct AttemptPromotionSink {
    vault: Arc<Vault>,
    /// The host's write-gate auto check, when it runs one.
    checker: Option<BoundedAutoChecker>,
}

impl AttemptPromotionSink {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self {
            vault,
            checker: None,
        }
    }

    /// The sink, each promotion through `checker`'s auto check.
    #[must_use]
    pub fn with_checker(mut self, checker: Option<BoundedAutoChecker>) -> Self {
        self.checker = checker;
        self
    }
}

impl ConsolidationSink for AttemptPromotionSink {
    fn fork(&self) -> Option<Box<dyn ConsolidationSink>> {
        Some(Box::new(
            Self::new(Arc::clone(&self.vault)).with_checker(self.checker.clone()),
        ))
    }

    /// Unsealed candidates carry no run, so this sink refuses them.
    fn accept(&mut self, _candidates: Vec<PromotionCandidate>) -> Result<()> {
        Err(Error::InvalidClaimBody(
            "attempt promotion sink needs a sealed scoped write",
        ))
    }

    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        self.promote(write, self.checker.as_ref())
    }

    /// [`Self::accept_scoped`], its checker's turn awaited first (FIX 9110):
    /// one place in line under the sealed write's own deadline, for its
    /// fence's actor, the principal each candidate's admission names, taken
    /// without holding the executor's thread. The promotion's writes then
    /// carry that turn and never queue for it twice.
    fn accept_scoped_in_line(
        &mut self,
        write: ScopedConsolidationWrite,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + '_>> {
        Box::pin(async move {
            let admitted = match &self.checker {
                Some(checker) => {
                    let checker = match write.checker_deadline {
                        Some(deadline) => checker.with_deadline(deadline),
                        None => checker.clone(),
                    };
                    let (agent_actor, _) = write.fence.run_identity();
                    let caller = agent_actor.entity_ref();
                    Some(
                        checker
                            .admit_for_writes_in_line(&self.vault.store, caller)?
                            .await,
                    )
                }
                None => None,
            };
            self.promote(write, admitted.as_ref())
        })
    }
}

impl AttemptPromotionSink {
    /// The sealed `write` through the one promotion door, each candidate's
    /// claim write through `checker`.
    fn promote(
        &self,
        write: ScopedConsolidationWrite,
        checker: Option<&BoundedAutoChecker>,
    ) -> Result<()> {
        let (agent_actor, attempt_id) = write.fence.run_identity();
        let run_id = AttemptQueue::new(&self.vault)
            .get(attempt_id)?
            .and_then(|row| row.run_id)
            .unwrap_or_else(|| bytes_to_hex_lower(attempt_id.as_bytes()));
        let run = DreamerRunContext {
            run_id,
            attempt_id,
            agent_actor,
            now_ms: self.vault.now_recorded_at().saturating_mul(1_000),
        };
        let outcome = promote_scoped_consolidation(&self.vault, &run, write, checker)?;
        let outputs: Vec<_> = outcome
            .landed
            .iter()
            .chain(&outcome.pended)
            .chain(&outcome.held)
            .copied()
            .collect();
        crate::dreamer_consolidation::nightly_merge::record_outputs(
            &self.vault,
            attempt_id,
            &outputs,
        )?;
        if outcome.rejected.is_empty() {
            Ok(())
        } else {
            // Each rejected candidate's code was logged where the door
            // rejected it (FIX 7271); the write's one error carries the
            // typed kind its door refused with (FIX 9429) and, when the
            // gate refused it, the gate's codes (FIX 10355).
            tracing::warn!(
                attempt_id = %bytes_to_hex_lower(attempt_id.as_bytes()),
                rejected = outcome.rejected.len(),
                landed = outcome.landed.len(),
                pended = outcome.pended.len(),
                held = outcome.held.len(),
                "scoped consolidation write refused"
            );
            Err(write_refusal(
                &outcome.rejected_kinds,
                &outcome.rejected_gates,
            ))
        }
    }
}

/// What a refused write's candidates were refused for.
const WRITE_REFUSED: &str = "scoped consolidation write refused";

/// A refused sealed write's one error (FIX 9429): the typed kind of its
/// first rejection whose kind waits on an owner act, else of its first
/// typed rejection, so the driver's existing park rules read the kind the
/// promotion door refused with. A gate refusal carries the gate's own
/// outcome and reason codes for that candidate (FIX 10355); a door's other
/// fields stay in its logged code and its gate record. A write no typed
/// rejection refused stays `InvalidClaimBody`, as before.
pub(super) fn write_refusal(
    kinds: &[(EntityId, ErrorKind)],
    gates: &[(EntityId, &'static str, Vec<&'static str>)],
) -> Error {
    let typed = |id: EntityId, kind: ErrorKind| -> Option<Error> {
        match kind {
            ErrorKind::ActorLacksClaimAuthority => Some(
                ClaimError::ActorLacksClaimAuthority {
                    reason: WRITE_REFUSED,
                }
                .into(),
            ),
            ErrorKind::GateWriteRejected => {
                let (outcome, reason_codes) = gates
                    .iter()
                    .find(|(gated, _, _)| *gated == id)
                    .map_or(("deny", Vec::new()), |(_, outcome, codes)| {
                        (*outcome, codes.clone())
                    });
                Some(
                    GateError::GateWriteRejected {
                        outcome,
                        reason_codes,
                    }
                    .into(),
                )
            }
            ErrorKind::EntityNotFound => Some(Error::EntityNotFound),
            _ => None,
        }
    };
    kinds
        .iter()
        .filter(|(_, kind)| crate::dreamer_wake::waits_on_owner_act(*kind))
        .chain(kinds)
        .find_map(|(id, kind)| typed(*id, *kind))
        .unwrap_or(Error::InvalidClaimBody(WRITE_REFUSED))
}
