//! `vault.mail.pack.install` and `vault.mail.sources.sync` on a served vault
//! (FIX 12559): the owner installs the engine's own Mail & Calendar pack, and
//! runs one import step of a source, under the proof `/v1/owner` takes from
//! the request. The generated HTTP and MCP dispatchers both enter here; an
//! embedded handle runs them as its embedded owner.

use std::sync::Arc;

use oneiron::mail_pack::{MailSourceSyncRequest, MailSyncReport};
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{EmptyRequest, PackPutReceipt};

use super::host_doors::support::{internal, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

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
