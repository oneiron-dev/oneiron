//! Doors for `tests/affect_state_signal_live_support.rs`
//! (AFFECT-SIGNAL-HEX-REFS-FAIL-LIVE-SUPPORT): refresh one subject's composite
//! state index through the production writer, as the nightly action-mode pass
//! and `vault.affect.wellness.derive` do, and name the two signal claims it
//! wrote. A thin wrapper over the production API only. Compiled only under
//! `--cfg oneiron_test_support` (`test_doors`); hidden, never API.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::state_index::{
    COMPOSITE_EVIDENCE_ENGAGEMENT_SIGNAL, COMPOSITE_EVIDENCE_GOAL_VELOCITY_SIGNAL, StateWindow,
};
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
/// source family is missing. The signal ids are read from the composite's
/// evidence, which counts the annotated turns and names the goal-velocity
/// and engagement signals.
///
/// # Errors
///
/// The vault's and the refresh's; a composite whose evidence names no signal
/// pair.
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
    let malformed = || Error::InvalidClaimBody("state index evidence names no signal pair");
    let Some(Value::Map(fields)) = body.evidence else {
        return Err(malformed());
    };
    let id = |key: &str| {
        fields
            .iter()
            .find(|(name, _)| name.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
            .ok_or_else(malformed)
            .and_then(EntityId::from_hex)
    };
    Ok(Some(RefreshedStateSignals {
        composite,
        goal_velocity: id(COMPOSITE_EVIDENCE_GOAL_VELOCITY_SIGNAL)?,
        engagement: id(COMPOSITE_EVIDENCE_ENGAGEMENT_SIGNAL)?,
    }))
}
