//! The owner's live decision-band policy through the typed verb table. Every
//! transport uses the owner's own unattenuated credential, checked before
//! hooks by `door_admits` and again here. Rows are scoped by question id,
//! question version and reversibility; they live for this host's lifetime.
//! The engine owns learning, version checks, enforcement and resolution.
use std::sync::Arc;

use oneiron::llm::decision::{
    DecisionBandEnforceRequest, DecisionBandLearnRequest, DecisionBandPolicy,
    DecisionBandReadRequest, LearnedBand,
};
use oneiron::memory::MemoryError;

use super::host_doors::{Listed, internal, owner_proof, refused};
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
    let answer = tokio::task::spawn_blocking(move || act(&mut bands).map_err(MemoryError::from))
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
    as_owner(server, auth, "vault.decisions.bands.learn", move |bands| {
        bands.learn_shadow(
            &input.question,
            input.reversibility,
            input.band,
            input.version,
        )
    })
    .await
}

pub(crate) async fn vault_decisions_bands_enforce(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: DecisionBandEnforceRequest,
) -> Listed<LearnedBand> {
    as_owner(server, auth, "vault.decisions.bands.enforce", move |bands| {
        bands.enforce(&input.question, input.reversibility)
    })
    .await
}
