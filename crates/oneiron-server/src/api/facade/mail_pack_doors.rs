//! `vault.mail.pack.install`, `vault.mail.sources.sync` and `vault.mail.reply.approve` on a served vault
//! (FIX 12559): the owner installs the engine's own Mail & Calendar pack, and
//! runs one import step of a source, under the proof `/v1/owner` takes from
//! the request. The generated HTTP and MCP dispatchers both enter here; an
//! embedded handle runs them as its embedded owner.
//!
//! Each served vault's mail pack also runs its blocking mail work here
//! ([`install_mail_host`], fix list row 17645): an IMAP mailbox's drafted
//! reply with files asks its submission server the size it takes, and that
//! check waits on the network inside `vault.mail.reply.draft`. It runs on
//! this server's blocking hop, in the drafter's own call, with the drafter's
//! own handle and the mailbox's own credential: no owner proof is taken or
//! lent, and the verb's route is the one every draft takes. Under the
//! host's `[mail]` settings.

use std::sync::Arc;

use oneiron::Vault;
use oneiron::mail_pack::{
    MailBlockingRunner, MailReplyApproveRequest, MailReplyDraftView, MailSourceSyncRequest,
    MailSyncReport,
};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};

use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::config::MailConfig;
use crate::server::SyncServer;

/// The runner a served vault's blocking mail work runs on (fix list row
/// 17645): the caller's own thread, moved off the async runtime first
/// ([`crate::server::blocking`]), so a check that waits on a submission
/// server holds no runtime worker. The work keeps whatever its caller holds:
/// the drafter's handle, its credential and its call.
struct ServedMailBlocking;

impl MailBlockingRunner for ServedMailBlocking {
    fn run(&self, work: &mut (dyn FnMut() + Send)) {
        crate::server::blocking(work);
    }
}

/// Installs on `vault`, as this server opens it, the host's `[mail]`
/// settings `mail` and the blocking runner its mail pack's network checks
/// run on (fix list row 17645).
pub(crate) fn install_mail_host(vault: &Vault, mail: &MailConfig) {
    vault.install_mail_host(mail.host_settings(), Some(Arc::new(ServedMailBlocking)));
}

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
