//! The host's Mail & Calendar source sync (FIX 12559): every pass, as the
//! vault's local owner, one bounded import step of each Active source of
//! the pack, mailboxes and calendars, through the engine's wire for its
//! provider (`Vault::mail_source_sync_step`). Each step reads its provider
//! over blocking HTTP, so a pass runs on the blocking pool. A source's
//! failure is kept on the source for its owner (`vault.mail.sources.
//! sync_status`) and the pass goes on to the next. A vault with no standing
//! local owner (a managed one) syncs nothing here; its owner runs steps
//! through `vault.mail.sources.sync`.
//!
//! Gmail push (census L2-17; ARCH-0063 #mail-import): with `[gmail_push]`
//! set, each pass also opens, renews or closes the push channel of every
//! source that owes it (`Vault::mail_source_watch_step`), and the hook
//! (`push_hook`) wakes the worker on a notice, which steps each woken
//! source at once. A notice can be dropped; the pass reads every source from
//! its committed anchor, so it is the reconcile.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use oneiron::mail_pack::MailSyncBudget;
use oneiron::{EntityId, Vault};
use tokio::sync::Notify;

use crate::server::{HousekeepingAdmission, SyncServer};
use oneiron_mail_pack::ext::MailPackLocalSyncVaultExt as _;

mod push_hook;

pub(crate) use push_hook::routes as push_routes;

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
            let pass = tokio::select! {
                _ = interval.tick() => Pass::Every,
                () = server.mail_push_wakes.notify.notified() => Pass::Woken,
            };
            let Some(admission) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let outcome = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                run_pass(&server, pass);
            })
            .await;
            if let Err(error) = outcome {
                tracing::warn!(error = %error, "mail source sync pass failed");
            }
        }
    })
}

/// The mail sources Gmail's notices woke, for the worker to step before its
/// next pass. The hook adds to it; the worker takes it whole. A notice that
/// comes while a step runs leaves one more wake.
#[derive(Default)]
pub(crate) struct MailPushWakes {
    woken: Mutex<BTreeSet<EntityId>>,
    notify: Notify,
}

impl MailPushWakes {
    /// Adds `sources` and wakes the worker, when there are any.
    pub(crate) fn wake(&self, sources: Vec<EntityId>) {
        if sources.is_empty() {
            return;
        }
        self.woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(sources);
        self.notify.notify_one();
    }

    /// Takes every woken source.
    fn take(&self) -> BTreeSet<EntityId> {
        std::mem::take(&mut *self.woken.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// What a worker pass steps.
#[derive(Clone, Copy)]
enum Pass {
    /// Every due source, then every push channel that owes an act.
    Every,
    /// The sources notices woke.
    Woken,
}

/// One pass, as the local owner.
fn run_pass(server: &SyncServer, pass: Pass) {
    let vault = server.vault();
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
    // A full pass steps every due source, so it takes the woken ones too.
    let woken = server.mail_push_wakes.take();
    let sources = match pass {
        Pass::Woken => woken.into_iter().collect(),
        Pass::Every => match vault.mail_sources_due() {
            Ok(sources) => sources,
            Err(error) => {
                tracing::warn!(error = %error, "mail sources unreadable");
                return;
            }
        },
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
    if matches!(pass, Pass::Every) {
        let topic = server
            .config
            .gmail_push
            .as_ref()
            .map(|push| push.topic.as_str());
        keep_push_channels(vault, topic);
    }
}

/// One act on each push channel that owes one under the host's `topic`:
/// open, renew, or close (`None` closes every channel still open).
fn keep_push_channels(vault: &Vault, topic: Option<&str>) {
    let sources = match vault.mail_watches_due(topic) {
        Ok(sources) => sources,
        Err(error) => {
            tracing::warn!(error = %error, "mail push channels unreadable");
            return;
        }
    };
    for source in sources {
        if let Err(error) = vault.mail_source_watch_step(source, topic) {
            tracing::warn!(
                source = %source.to_hex(),
                error = %error,
                "mail push channel step failed"
            );
        }
    }
}
