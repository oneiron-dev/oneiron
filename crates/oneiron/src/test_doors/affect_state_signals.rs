//! Doors for `tests/affect_state_signal_live_support.rs`
//! (AFFECT-SIGNAL-HEX-REFS-FAIL-LIVE-SUPPORT): refresh one subject's composite
//! state index through the production writer, as the nightly action-mode pass
//! and `vault.affect.wellness.derive` do, and name the two signal claims it
//! wrote. A thin wrapper over the production API only. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use rmpv::Value;

use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateWindow};
use crate::vault::Vault;

/// The claims one refresh left: the composite index and the two signal
/// claims it read.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshedStateSignals {
    pub composite: EntityId,
    pub goal_velocity: EntityId,
    pub engagement: EntityId,
}

/// Measures `subject`'s window ending at `at` and refreshes its composite
/// index in one write (`Vault::refresh_state_index_in_txn`). `None` when a
/// source family is missing. The composite names neither signal claim
/// (REVIEW-9905 P1 round 2), so each signal is the one active claim about
/// `subject` of its predicate that the refresh wrote: valid from `at`, with
/// the number the composite carries for it.
///
/// # Errors
///
/// The vault's and the refresh's; a predicate with no such claim, or more
/// than one.
pub fn refresh_state_signals(
    vault: &Vault,
    subject: &EntityId,
    window: &StateWindow,
    at: u64,
) -> Result<Option<RefreshedStateSignals>> {
    let Some((composite, _)) =
        vault.with_write_txn(|txn| vault.refresh_state_index_in_txn(txn, subject, window, at))?
    else {
        return Ok(None);
    };
    let body = vault.get_claim(&composite)?.ok_or(Error::EntityNotFound)?;
    let unmatched = || Error::InvalidClaimBody("no single signal claim the refresh wrote");
    let Value::Map(fields) = &body.value else {
        return Err(unmatched());
    };
    let claims = vault.claims_for_subject(subject)?;
    let signal = |predicate: &str, field: &str| -> Result<EntityId> {
        let number = fields
            .iter()
            .find(|(name, _)| name.as_str() == Some(field))
            .map(|(_, value)| value.clone())
            .ok_or_else(unmatched)?;
        let mut found = None;
        for id in &claims {
            let Some(claim) = vault.get_claim(id)? else {
                continue;
            };
            if claim.predicate == predicate
                && claim.lifecycle == ClaimLifecycleStatus::Active
                && claim.valid_from == Some(at)
                && claim.value == number
            {
                if found.is_some() {
                    return Err(unmatched());
                }
                found = Some(*id);
            }
        }
        found.ok_or_else(unmatched)
    };
    Ok(Some(RefreshedStateSignals {
        composite,
        goal_velocity: signal(GOAL_VELOCITY, "goal_velocity")?,
        engagement: signal(ENGAGEMENT, "engagement")?,
    }))
}
