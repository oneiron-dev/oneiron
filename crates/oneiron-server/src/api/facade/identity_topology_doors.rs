//! Typed identity-topology host doors under the caller's own owner proof.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, IdentityAssertDistinctRequest, IdentityEntityRequest, IdentityEventRequest,
    IdentityFacetRequest, IdentityMergeRequest, IdentityPairProposals, IdentityPairRequest,
    IdentityProposalResolutionResult, IdentityProposalResolveRequest, IdentityProposeRequest,
    IdentityResolution, IdentitySplitRequest, IdentityTopologyReceipt, IdentityTopologyResult,
    IdentityUndoRequest,
};

use super::host_doors::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_identity_merge(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityMergeRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.merge",
        move |server, owner| sdk::merge_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_split(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentitySplitRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.split",
        move |server, owner| sdk::split_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_facet(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityFacetRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.facet",
        move |server, owner| sdk::facet_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_assert_distinct(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityAssertDistinctRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.assert_distinct",
        move |server, owner| sdk::assert_distinct_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_propose(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityProposeRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.propose",
        move |server, owner| sdk::propose_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_undo(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityUndoRequest,
) -> Listed<IdentityTopologyResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.undo",
        move |server, owner| sdk::undo_identity_as_owner(server.vault(), owner, input),
        IdentityTopologyResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityEntityRequest,
) -> Listed<IdentityResolution> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.resolve",
        move |server, owner| sdk::resolve_identity_as_owner(server.vault(), owner, input),
        IdentityResolution::rows,
    )
    .await
}

pub(crate) async fn vault_identity_events_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityEventRequest,
) -> Listed<IdentityTopologyReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.events.get",
        move |server, owner| sdk::identity_event_as_owner(server.vault(), owner, input),
        IdentityTopologyReceipt::rows,
    )
    .await
}

pub(crate) async fn vault_identity_proposals_resolve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityProposalResolveRequest,
) -> Listed<IdentityProposalResolutionResult> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.proposals.resolve",
        move |server, owner| sdk::resolve_identity_proposal_as_owner(server.vault(), owner, input),
        IdentityProposalResolutionResult::rows,
    )
    .await
}

pub(crate) async fn vault_identity_proposals_for_pair(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: IdentityPairRequest,
) -> Listed<IdentityPairProposals> {
    as_owner_naming(
        server,
        auth,
        "vault.identity.proposals.for_pair",
        move |server, owner| sdk::identity_pair_proposals_as_owner(server.vault(), owner, input),
        IdentityPairProposals::rows,
    )
    .await
}
