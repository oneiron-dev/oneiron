//! The last sealed bundle upkeep this process saw, per machine (FIX 4953;
//! CALLS "4953 relay report"): what the relay moved, with its counts of pad
//! objects still pending access and erases still held back, and when. The
//! upkeep runs as before and never waits on this record; it only notes each
//! result as it passes ([`observe_sealed_bundle_relay`]). Before any relay
//! finishes there is no observation, which is not zero. Nothing expires: a
//! newer relay replaces the older one. Held in memory, keyed by this
//! install's machine as the host's connections are, so a restart starts
//! unobserved.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::SealedBundleRelay;
use crate::sync::transport::TransportError;
use crate::{EntityId, Vault};

/// What this process last saw of one machine's sealed bundle upkeep. Each
/// part is an observation with its recorded-clock time, never a promise:
/// `None` is unobserved.
#[derive(Debug, Clone, Default)]
pub struct SealedBundleRelayObservation {
    /// The last relay that finished, and when.
    pub relayed: Option<(u64, SealedBundleRelay)>,
    /// The last relay that failed, and when, with its error. A later relay
    /// that finishes does not clear it: the times say which is newer.
    pub failed: Option<(u64, String)>,
}

fn observations() -> &'static Mutex<HashMap<EntityId, SealedBundleRelayObservation>> {
    static OBSERVED: OnceLock<Mutex<HashMap<EntityId, SealedBundleRelayObservation>>> =
        OnceLock::new();
    OBSERVED.get_or_init(Mutex::default)
}

/// The last upkeep this process saw for `machine`; `None` when it saw none.
#[must_use]
pub fn sealed_bundle_relay_observation(machine: &EntityId) -> Option<SealedBundleRelayObservation> {
    observations().lock().ok()?.get(machine).cloned()
}

/// Notes one upkeep relay's `result` for this install's machine and hands it
/// back unchanged. A relay with nothing to do (`InvalidPayload`) is no
/// observation; neither is a vault that is no machine yet.
pub(crate) fn observe_sealed_bundle_relay(
    vault: &Vault,
    result: Result<SealedBundleRelay, TransportError>,
) -> Result<SealedBundleRelay, TransportError> {
    if matches!(result, Err(TransportError::InvalidPayload(_))) {
        return result;
    }
    let machine = vault
        .store
        .env
        .read_txn()
        .ok()
        .and_then(|txn| crate::identity::read_machine_id_in_txn(vault, &txn).ok())
        .flatten();
    let (Some(machine), Ok(mut observed)) = (machine, observations().lock()) else {
        return result;
    };
    let at = vault.store.clock.peek_recorded_at();
    let entry = observed.entry(machine).or_default();
    match &result {
        Ok(relay) => entry.relayed = Some((at, relay.clone())),
        Err(error) => entry.failed = Some((at, error.to_string())),
    }
    result
}
