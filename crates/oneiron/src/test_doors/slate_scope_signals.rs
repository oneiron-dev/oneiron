//! The connector scope signals a vault holds, for the scope revision door
//! tests: no public read names a signal (owner asks name the held call), and
//! `vault.connectors.slates.scope_outcome` and `defer_revision` take one.

use crate::{Result, Vault};

/// Every scope signal's ref (32 hex, as the verbs take it), in table order,
/// over the signal scan `connector_slate_revision_offers` reads. It reads
/// only: no signal, ruling, offer, stamp or grant is written.
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn signal_refs(vault: &Vault) -> Result<Vec<String>> {
    Ok(crate::connector_key::scope_signals_for_test(vault)?
        .into_iter()
        .map(|signal| signal.signal_id.to_hex())
        .collect())
}
