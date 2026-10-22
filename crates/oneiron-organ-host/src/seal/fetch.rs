//! The seal's `net.fetch`: the host's guarded fetch, for a timestamp or a
//! CRL only, each fetch inside the fetch timeout as well as the call's
//! deadline. A body is read whole whatever its size (Rule 5): past the
//! seal's own row for its purpose (`seal_crl_bytes`, `seal_tsa_bytes`) the
//! vault asks whether everything is okay.

use std::time::Duration;

use oneiron::Vault;
use oneiron::limit_ask::EngineLimit;
use oneiron_organ_protocol::{AskCode, AskRefusal};

use crate::fetch::GuardedFetch;
use crate::handlers::{Answered, AskHandler, AskRequest};

/// `net.fetch` for one seal call.
pub(super) struct TimedFetch<'v> {
    pub(super) timeout: Duration,
    pub(super) vault: &'v Vault,
}

impl AskHandler for TimedFetch<'_> {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        // The fetch timeout runs on the call's clock: a wait for room to
        // hold the body moves both alike (FIX 6196).
        let clock = ask.clock.within(self.timeout);
        let purpose = ask.value.as_map().and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("purpose"))
                .and_then(|(_, value)| value.as_str())
        });
        let row = match purpose {
            Some("crl") => EngineLimit::SealCrlBytes,
            Some("tsa") => EngineLimit::SealTsaBytes,
            _ => {
                return Err(AskRefusal::new(
                    AskCode::NotGranted,
                    "the seal fetches only timestamps and CRLs",
                ));
            }
        };
        let answered = GuardedFetch.answer(&AskRequest {
            deadline: clock.deadline(),
            clock,
            ..*ask
        })?;
        let body = answered.data.as_ref().map_or(0, Vec::len);
        self.vault.measure_limit(row, body as u64);
        Ok(answered)
    }
}
