//! Typed host configuration, work and completion receipts for HydeExpander.
use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::query_expansion::host::*;
use oneiron::task_verb::sdk::EmptyRequest;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, refused};
use super::legal_hold_doors::as_owner_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(super) fn hyde_caller(
    server: &SyncServer,
    auth: &CoreAuth,
) -> MemoryResult<(EntityId, EdgeActorClass)> {
    if auth.verified_slip().is_none() || auth.off_record_session().is_some() {
        return Err(MemoryError::new(
            oneiron::memory::MEMORY_CODE_FORBIDDEN,
            "HyDE host work requires its caller's verified on-record credential",
            &["Use the same credential that requested recall, outside an off-record session."],
        ));
    }
    super::owner_binding::facade_caller_or(server, auth, || {
        MemoryError::bad_request("HyDE host work requires an authenticated principal")
    })
}

pub(crate) async fn vault_retrieval_hyde_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HydeHostConfigureRequest,
) -> Listed<HydeHostConfiguration> {
    as_owner_naming(
        server,
        auth,
        "vault.retrieval.hyde.configure",
        move |server, _owner| server.hyde_host.configure(input),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_retrieval_hyde_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<HydeHostConfiguration> {
    as_owner_naming(
        server,
        auth,
        "vault.retrieval.hyde.get",
        |server, _owner| server.hyde_host.configuration(),
        |_| Vec::new(),
    )
    .await
}

pub(crate) async fn vault_retrieval_hyde_pending(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HydeHostPendingRequest,
) -> Listed<Vec<HydeHostWork>> {
    let caller = match hyde_caller(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error),
    };
    let (answer, mut listed) = credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.hyde.pending",
        move |server, _, memory| {
            server
                .hyde_host
                .pending(memory.hyde_host_credential_key()?, input)
        },
    )
    .await;
    // Evidence leaves through the same final read/egress fence as the sibling host doors.
    if let Ok(work) = &answer {
        listed.extend(work.iter().flat_map(|work| {
            match &work.input {
                HydeHostInput::Expansion { .. } => Vec::new(),
                HydeHostInput::Evidence { candidates, .. } => candidates
                    .iter()
                    .filter_map(|candidate| EntityId::from_hex(&candidate.id).ok())
                    .collect(),
            }
        }));
    }
    (answer, listed)
}

pub(crate) async fn vault_retrieval_hyde_complete(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HydeHostCompleteRequest,
) -> Listed<HydeHostReceipt> {
    let caller = match hyde_caller(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.hyde.complete",
        move |server, _, memory| {
            server
                .hyde_host
                .complete(server.vault(), memory.hyde_host_credential_key()?, input)
        },
    )
    .await
}

pub(crate) async fn vault_retrieval_hyde_receipt(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HydeHostReceiptRequest,
) -> Listed<Option<HydeHostReceipt>> {
    let caller = match hyde_caller(server, auth) {
        Ok(caller) => caller,
        Err(error) => return refused(error),
    };
    credential_listing(
        server,
        auth,
        caller,
        "vault.retrieval.hyde.receipt",
        move |server, _, memory| {
            server
                .hyde_host
                .receipt(memory.hyde_host_credential_key()?, input)
        },
    )
    .await
}
