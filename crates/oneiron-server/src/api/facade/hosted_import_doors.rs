//! The host doors of the hosted import's verbs (ARCH-0027 #hosted-import;
//! substrate behind grants): `vault.imports.get` and `vault.imports.cancel`.
//! Each admits the vault owner under its proof, or a person or agent on a
//! verified slip of its own, whose Steward grant the engine checks: `read`
//! at the read, `delete` in the cancel's own write. Anyone else keeps the
//! owner refusal.
//!
//! Each lists no row (`host_door_lists`): the job lives in a side table,
//! which holds none.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::ingest::history::{
    HostedImportCancel, HostedImportCanceller, HostedImportLookup, HostedImportView,
    hosted_import_cancel_as, hosted_import_get_as_owner, hosted_import_get_as_reader,
};

use super::host_doors::support::{Listed, internal};
use super::legal_hold_doors::as_owner_naming;
use super::substrate_read_doors::{as_reader, substrate_reader};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Who may cancel a hosted import: the owner under its proof (`Some`), or a
/// person or agent on its own verified slip (`None`), whose Steward `delete`
/// grant the cancel's writer checks. The same admission as a substrate read.
pub(super) fn import_canceller(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> oneiron::memory::MemoryResult<Option<AuthenticatedOwner>> {
    substrate_reader(server, auth, verb)
}

/// The caller of a cancel, resolved before the write.
enum Canceller {
    Owner(AuthenticatedOwner),
    Holder(EntityId),
}

/// `vault.imports.get`.
pub(crate) async fn vault_imports_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HostedImportLookup,
) -> Listed<Option<HostedImportView>> {
    const VERB: &str = "vault.imports.get";
    match substrate_reader(server, auth, VERB) {
        Ok(Some(_)) => {
            as_owner_naming(
                server,
                auth,
                VERB,
                move |server, owner| hosted_import_get_as_owner(server.vault(), owner, &input),
                |_| Vec::new(),
            )
            .await
        }
        Ok(None) => {
            let answer = as_reader(server, auth, VERB, move |server, reader| {
                hosted_import_get_as_reader(server.vault(), reader, &input)
            })
            .await;
            (answer, Vec::new())
        }
        Err(refusal) => (Err(refusal), Vec::new()),
    }
}

/// `vault.imports.cancel`.
pub(crate) async fn vault_imports_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: HostedImportLookup,
) -> Listed<Option<HostedImportCancel>> {
    const VERB: &str = "vault.imports.cancel";
    let canceller = match import_canceller(server, auth, VERB) {
        Ok(Some(owner)) => Canceller::Owner(owner),
        Ok(None) => match super::facade_actor(server, auth) {
            Ok((holder, _)) => Canceller::Holder(holder),
            Err(error) => return (Err(error.into_memory_error()), Vec::new()),
        },
        Err(refusal) => return (Err(refusal), Vec::new()),
    };
    let server = Arc::clone(server);
    let answer = super::clock_ingress::run_blocking(move || {
        let canceller = match &canceller {
            Canceller::Owner(owner) => HostedImportCanceller::Owner(owner),
            Canceller::Holder(holder) => HostedImportCanceller::Holder(*holder),
        };
        hosted_import_cancel_as(server.vault(), canceller, &input)
    })
    .await
    .map_err(|_| internal(VERB))
    .and_then(|answer| answer);
    (answer, Vec::new())
}
