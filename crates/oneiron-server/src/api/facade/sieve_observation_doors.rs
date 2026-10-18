//! The owner's evidence replay and recorded shared-scheduler observations.
use std::sync::Arc;

use oneiron::dreamer_runner::observation::{self, *};
use oneiron::dreamer_wake::sieve_evidence::{self, *};
use oneiron::dreamer_wake::{WakeCadenceRequest, WakeCadenceView, cadence_as_owner};
use oneiron::memory::MemoryError;

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_sieve_evidence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveEvidenceRequest,
) -> Listed<SieveEvidenceView> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.evidence",
        move |server, owner| {
            sieve_evidence::evidence_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |view| vec![view.turn],
    )
    .await
}

pub(crate) async fn vault_sieve_evidence_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: SieveEvidenceRequest,
) -> Listed<SieveEvidenceView> {
    let answer = as_owner_naming(
        server,
        auth,
        "vault.sieve.evidence.replay",
        move |server, owner| {
            sieve_evidence::replay_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |view| vec![view.turn],
    )
    .await;
    if answer.0.is_ok() {
        server
            .ai
            .turn_landed(server.vault(), oneiron::dreamer_wake::WakeTurnSubject::Vault);
    }
    answer
}

pub(crate) async fn vault_sieve_cadence(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WakeCadenceRequest,
) -> Listed<WakeCadenceView> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.cadence",
        move |server, owner| {
            cadence_as_owner(server.vault(), owner, &input).map_err(MemoryError::from)
        },
        |_| Vec::new(),
    )
    .await
}

fn conclusions(view: &WakeSettlementView) -> Vec<oneiron::EntityId> {
    view.jobs
        .iter()
        .flat_map(|job| job.conclusions.iter().copied())
        .collect()
}

pub(crate) async fn vault_sieve_settlements(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WakeSettlementsRequest,
) -> Listed<WakeSettlementsPage> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.settlements",
        move |server, owner| {
            observation::settlements_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |page| page.wakes.iter().flat_map(conclusions).collect(),
    )
    .await
}

pub(crate) async fn vault_sieve_settlements_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WakeSettlementRequest,
) -> Listed<Option<WakeSettlementView>> {
    as_owner_naming(
        server,
        auth,
        "vault.sieve.settlements.get",
        move |server, owner| {
            observation::settlement_as_owner(server.vault(), owner, &input)
                .map_err(MemoryError::from)
        },
        |view| view.as_ref().map_or_else(Vec::new, conclusions),
    )
    .await
}
