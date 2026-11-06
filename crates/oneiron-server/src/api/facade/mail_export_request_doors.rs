//! An Owner's request for another member's personal mailbox in their next
//! whole-vault export (fix list row 15416, `vault.mail.export_request`), on
//! the caller's own credential handle, under the Owner's own proof. The
//! facade refuses a non-owner before any hook runs; the engine's writer
//! checks the proof again, with the Owner's standing. The request is
//! side-table state and the member's Ask a queue row, so the door lists no
//! record.

use super::host_doors::support::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron::mail_pack::{MailExportRequest, MailExportRequestView};
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(crate) async fn vault_mail_export_request(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: MailExportRequest,
) -> Listed<MailExportRequestView> {
    const VERB: &str = "vault.mail.export_request";
    let proof = match super::owner_binding::facade_owner(server, auth, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.mail_export_request_as_owner(&proof, &input)
    })
    .await
}
