//! Class-aging profile reads and edits under the caller's own owner credential.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::policy_manifest_doors::{
    self, ClaimAgingProfilesConfigureRequest, ClaimAgingProfilesReceipt, ClaimAgingProfilesView,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::host_doors::support::{Listed, off_runtime_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_retrieval_aging_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<ClaimAgingProfilesView> {
    const VERB: &str = "vault.retrieval.aging.get";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::claim_aging_profiles_as_owner(server.vault(), &owner)
            .map_err(Into::into)
    })
    .await;
    if let Ok(view) = &answer {
        rows.extend(EntityId::from_hex(&view.manifest_ref).ok());
    }
    (answer, rows)
}

pub(crate) async fn vault_retrieval_aging_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ClaimAgingProfilesConfigureRequest,
) -> Listed<ClaimAgingProfilesReceipt> {
    const VERB: &str = "vault.retrieval.aging.configure";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::configure_claim_aging_profiles_as_owner(
            server.vault(),
            &owner,
            input,
        )
        .map_err(Into::into)
    })
    .await;
    if let Ok(receipt) = &answer {
        rows.extend(EntityId::from_hex(&receipt.configuration.manifest_ref).ok());
    }
    (answer, rows)
}
