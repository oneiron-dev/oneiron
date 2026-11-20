//! The owner's live decision-band policy through the typed verb table. Every
//! transport uses the owner's own unattenuated credential, checked before
//! hooks by `door_admits` and again here. Rows are scoped by question id,
//! question version and reversibility. A learn or an enforce writes the row to
//! the vault first, which checks the version against the stored row, and then
//! installs it on the host's bands; the host loads every stored row when it
//! builds its bands, so a learned mode and version stay in effect after a
//! restart (ARCH-0076 promise-dura-10). The engine owns learning, version
//! checks, enforcement and resolution.
use std::sync::Arc;

use oneiron::llm::decision::{
    DecisionBandEnforceRequest, DecisionBandLearnRequest, DecisionBandPolicy,
    DecisionBandReadRequest, DecisionQuestion, LearnedBand, LearnedBandKey, Reversibility,
};
use oneiron::memory::MemoryError;

use super::host_doors::support::{Listed, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Live policy rows read no entity records, so the listing is empty. Every
/// policy clone shares the learned rows, including callers already holding one.
async fn as_owner(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&mut DecisionBandPolicy) -> oneiron::Result<LearnedBand> + Send + 'static,
) -> Listed<LearnedBand> {
    if let Err(error) = owner_proof(auth, server, verb) {
        return refused(error);
    }
    let mut bands = server.decision_host().bands();
    let answer =
        super::clock_ingress::run_blocking(move || act(&mut bands).map_err(MemoryError::from))
            .await
            .map_err(|_| internal(verb))
            .and_then(|answer| answer);
    (answer, Vec::new())
}

pub(crate) async fn vault_decisions_bands_read(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionBandReadRequest,
) -> Listed<LearnedBand> {
    as_owner(server, auth, "vault.decisions.bands.read", move |bands| {
        bands.resolve(&input.question, input.reversibility, input.seed)
    })
    .await
}

pub(crate) async fn vault_decisions_bands_learn(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionBandLearnRequest,
) -> Listed<LearnedBand> {
    let vault = Arc::clone(server.vault());
    as_owner(server, auth, "vault.decisions.bands.learn", move |bands| {
        let row = vault.learn_decision_band(
            &input.question,
            input.reversibility,
            input.band,
            input.version,
        )?;
        bands.install_learned_band(band_key(&input.question, input.reversibility), row);
        Ok(row)
    })
    .await
}

pub(crate) async fn vault_decisions_bands_enforce(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionBandEnforceRequest,
) -> Listed<LearnedBand> {
    let vault = Arc::clone(server.vault());
    as_owner(
        server,
        auth,
        "vault.decisions.bands.enforce",
        move |bands| {
            let row = vault.enforce_decision_band(&input.question, input.reversibility)?;
            bands.install_learned_band(band_key(&input.question, input.reversibility), row);
            Ok(row)
        },
    )
    .await
}

/// Where the host's bands keep the row of `question` under `reversibility`.
fn band_key(question: &DecisionQuestion, reversibility: Reversibility) -> LearnedBandKey {
    (question.id, question.version, reversibility)
}
