use super::host_doors::support::Listed;
//! Signed Connect ingress and owner lifecycle doors over the shared burst engine.
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::sync::SyncClient;
use oneiron::sync::federation_burst::*;
use oneiron::task_verb::sdk::{self, ConnectDelivery, EmptyRequest};
use std::sync::Arc;

pub(crate) async fn vault_federation_burst_baseline(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstPeerRequest,
) -> Listed<FederationBurstBaselineState> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.baseline",
        move |server, owner| sdk::federation_burst_baseline_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_policy(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstPeerRequest,
) -> Listed<FederationBurstPolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.policy",
        move |server, owner| sdk::federation_burst_policy_as_owner(server.vault(), owner, input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_policy_set(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstPolicySetRequest,
) -> Listed<FederationBurstPolicy> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.policy.set",
        move |server, owner| {
            sdk::set_federation_burst_policy_as_owner(server.vault(), owner, input)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_review(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Vec<FederationBurstReviewBundle>> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.review",
        move |server, owner| sdk::federation_burst_reviews_as_owner(server.vault(), owner),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_review_release(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstReviewRequest,
) -> Listed<FederationBurstReviewReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.review.release",
        move |server, owner| {
            sdk::release_federation_burst_review_as_owner(server.vault(), owner, input)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_review_reject(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstReviewRequest,
) -> Listed<FederationBurstReviewReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.review.reject",
        move |server, owner| {
            sdk::reject_federation_burst_review_as_owner(server.vault(), owner, input)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_ingress(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectDelivery,
) -> Listed<FederationBurstReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.ingress",
        move |server, owner| {
            Ok(SyncClient::rejoin_connect_with_burst_as(&server.reassert_manager, owner, input)?.1)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_disposition(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstReplayRequest,
) -> Listed<FederationBurstReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.disposition",
        move |server, owner| {
            Ok(server.vault().federation_burst_disposition_as_owner(
                owner,
                &input.peer.authorize(server.vault())?,
                &input.batch_ref,
            )?)
        },
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_federation_burst_replay(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: FederationBurstReplayRequest,
) -> Listed<FederationBurstReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.burst.replay",
        move |server, owner| {
            Ok(SyncClient::replay_federation_burst_as_owner(
                &server.reassert_manager,
                owner,
                input,
            )?)
        },
        |_| Vec::new(),
    )
    .await
}
