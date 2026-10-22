//! Owner coreference doors: every transport reaches the engine's typed operations.
use std::sync::Arc;

use oneiron::task_verb::sdk::{
    self, CoreferenceLinkReceipt, CoreferenceLinkRequest, CoreferencePairRequest,
    CoreferenceShareConsentReceipt, CoreferenceShareConsentRequest, CoreferenceUnlinkReceipt,
};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_federation_coreference_link(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreferenceLinkRequest,
) -> Listed<CoreferenceLinkReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.coreference.link",
        move |server, owner| sdk::link_coreference_as_owner(server.vault(), owner, input),
        |receipt| {
            vec![
                receipt.local_person,
                receipt.other_person,
                receipt.status_claim,
            ]
        },
    )
    .await
}

pub(crate) async fn vault_federation_coreference_confirm(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreferencePairRequest,
) -> Listed<CoreferenceLinkReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.coreference.confirm",
        move |server, owner| sdk::confirm_coreference_as_owner(server.vault(), owner, input),
        |receipt| {
            vec![
                receipt.local_person,
                receipt.other_person,
                receipt.status_claim,
            ]
        },
    )
    .await
}

pub(crate) async fn vault_federation_coreference_share_consent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreferenceShareConsentRequest,
) -> Listed<CoreferenceShareConsentReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.coreference.share_consent",
        move |server, owner| sdk::share_coreference_as_owner(server.vault(), owner, input),
        |receipt| {
            vec![
                receipt.local_person,
                receipt.other_person,
                receipt.consent_claim,
            ]
        },
    )
    .await
}

pub(crate) async fn vault_federation_coreference_unlink(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CoreferencePairRequest,
) -> Listed<CoreferenceUnlinkReceipt> {
    as_owner_naming(
        server,
        auth,
        "vault.federation.coreference.unlink",
        move |server, owner| sdk::unlink_coreference_as_owner(server.vault(), owner, input),
        |receipt| {
            let mut rows = vec![receipt.local_person, receipt.other_person];
            rows.extend(&receipt.retracted_claims);
            rows
        },
    )
    .await
}
