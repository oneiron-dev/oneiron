//! `vault.mail.pack.install`, `vault.mail.sources.sync`, `vault.mail.sources.search`,
//! `vault.mail.reply.approve` and `vault.mail.export_request` on a served vault
//! (FIX 12559): the owner installs the engine's own Mail & Calendar pack, and
//! runs one import step of a source, under the proof `/v1/owner` takes from
//! the request. The generated HTTP and MCP dispatchers both enter here; an
//! embedded handle runs them as its embedded owner.

use std::sync::Arc;

use oneiron::mail_pack::{
    MailExportRequest, MailExportRequestView, MailReplyApproveRequest, MailReplyDraftView,
    MailSearchReport, MailSourceSearchRequest, MailSourceSyncRequest, MailSyncReport,
};
use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::{Listed, credential_listing, internal, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;
use oneiron_mail_pack::ext::MailPackPackVaultExt as _;

/// `vault.mail.pack.install`: installs the pack folder through the ordinary
/// owner install. It connects no source and grants nothing.
pub(crate) async fn vault_mail_pack_install(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<PackPutReceipt> {
    let owner = owner_proof(auth, server, "vault.mail.pack.install")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<PackPutReceipt> {
        Ok(server.vault().install_mail_calendar_pack(&owner)?.into())
    })
    .await
    .map_err(|_| internal("vault.mail.pack.install"))?
}

/// `vault.mail.sources.sync`: one bounded import step of a mail or calendar
/// source, on the blocking pool, as its wire reads the provider over
/// blocking HTTP.
pub(crate) async fn vault_mail_sources_sync(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MailSourceSyncRequest,
) -> MemoryResult<MailSyncReport> {
    let owner = owner_proof(auth, server, "vault.mail.sources.sync")?;
    let (source, budget) = input.step()?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<MailSyncReport> {
        server.vault().mail_source_sync_step(&owner, source, budget)
    })
    .await
    .map_err(|_| internal("vault.mail.sources.sync"))?
}

/// `vault.mail.sources.search` (fix list row 15424): the owner searches a
/// mailbox they read at its provider, under the proof `/v1/owner` takes
/// from the request, on the blocking pool, as the provider wires are
/// blocking HTTP.
pub(crate) async fn vault_mail_sources_search(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MailSourceSearchRequest,
) -> MemoryResult<MailSearchReport> {
    let owner = owner_proof(auth, server, "vault.mail.sources.search")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<MailSearchReport> {
        server.vault().mail_source_search(&owner, &input)
    })
    .await
    .map_err(|_| internal("vault.mail.sources.search"))?
}

/// `vault.mail.reply.approve` (FIX 15420): a mailbox's own person approves
/// one reviewed revision of a drafted reply from that mailbox, on their own
/// proof: the owner as `/v1/owner` admits them, or a member on their own
/// verified human slip (fix list row 17644 follow-up), which lends no owner
/// authority. Its send runs on the blocking pool, as the send wires are
/// blocking HTTP.
pub(crate) async fn vault_mail_reply_approve(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MailReplyApproveRequest,
) -> MemoryResult<MailReplyDraftView> {
    let person =
        super::agent_definition_doors::member_proof(server, auth, "vault.mail.reply.approve")?;
    let server = Arc::clone(server);
    super::clock_ingress::run_blocking(move || -> MemoryResult<MailReplyDraftView> {
        server.vault().approve_mail_reply(&person, &input)
    })
    .await
    .map_err(|_| internal("vault.mail.reply.approve"))?
}

/// `vault.mail.export_request` (fix list row 15416): an Owner's request for
/// another member's personal mailbox in their next whole-vault export, on
/// the caller's own credential handle, under the Owner's own proof. The
/// facade refuses a non-owner before any hook runs; the engine's writer
/// checks the proof again, with the Owner's standing. The request is
/// side-table state and the member's Ask a queue row, so the door lists no
/// record.
pub(crate) async fn vault_mail_export_request(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: MailExportRequest,
) -> Listed<MailExportRequestView> {
    const VERB: &str = "vault.mail.export_request";
    let proof = match owner_proof(auth, server, VERB) {
        Ok(proof) => proof,
        Err(refusal) => return refused(refusal),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.mail_export_request_as_owner(&proof, &input)
    })
    .await
}
