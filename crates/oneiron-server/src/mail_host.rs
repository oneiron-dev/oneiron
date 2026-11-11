//! The host's Mail & Calendar source sync (FIX 12559): every pass, as the
//! vault's local owner, one bounded import step of each Active source of
//! the pack, mailboxes and calendars, through the engine's wire for its
//! provider (`Vault::mail_source_sync_step`). Each step reads its provider
//! over blocking HTTP, so a pass runs on the blocking pool. A source's
//! failure is kept on the source for its owner (`vault.mail.sources.
//! sync_status`) and the pass goes on to the next. A vault with no standing
//! local owner (a managed one) syncs nothing here; its owner runs steps
//! through `vault.mail.sources.sync`.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::mail_pack::MailSyncBudget;

use crate::server::{HousekeepingAdmission, SyncServer};
use oneiron_mail_pack::ext::MailPackLocalSyncVaultExt as _;

/// How often the worker steps every source.
const MAIL_SYNC_TICK: Duration = Duration::from_secs(300);

/// Starts the worker. Each pass is admitted through `admit`, the way a
/// housekeeping pass is, so a vault frozen for reap syncs nothing.
pub(crate) fn spawn_mail_source_syncs(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(MAIL_SYNC_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(admission) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                sync_due_sources(server.vault());
            })
            .await;
            if let Err(error) = pass {
                tracing::warn!(error = %error, "mail source sync pass failed");
            }
        }
    })
}

/// One step of every due source, as the local owner.
fn sync_due_sources(vault: &Vault) {
    let owner = match crate::owner::local_owner(vault) {
        Ok(owner) => owner,
        Err(error) => {
            tracing::debug!(
                error = %format!("{error:#}"),
                "no local owner; mail sources sync on the owner's door"
            );
            return;
        }
    };
    let sources = match vault.mail_sources_due() {
        Ok(sources) => sources,
        Err(error) => {
            tracing::warn!(error = %error, "mail sources unreadable");
            return;
        }
    };
    for source in sources {
        if let Err(error) = vault.mail_source_sync_step(&owner, source, MailSyncBudget::default()) {
            tracing::warn!(
                source = %source.to_hex(),
                error = %error,
                "mail source sync step failed"
            );
        }
    }
}
