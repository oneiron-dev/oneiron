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
//!
//! A mailbox connected, or connected again, is stepped at once too
//! (`Vault::subscribe_mail_source_wakes`; ARCH-0063 #mail-copy): search
//! works on connect, recent mail copies first, and the copy's time is known
//! from that first step. A lost wake waits for the next pass.
//!
//! A mailbox that copies is stepped again when its last step says
//! (`MailSyncReport::next_step_at`, L3-16-COPY-PACE = A): once its quota
//! window opens after a step that ran out of it, at once after one that
//! ended on its budget. So a copy spends its share of the provider's quota,
//! 75% of Gmail's per-user minute, rather than one step per pass.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::mail_pack::MailSyncBudget;
use oneiron::{EntityId, Vault};
use tokio::sync::Notify;
use tokio::sync::broadcast::error::RecvError;

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
        let mut connected = server.vault().subscribe_mail_source_wakes();
        loop {
            let next_step = server.mail_source_wakes.next_scheduled();
            let pass = tokio::select! {
                _ = interval.tick() => Pass::Every,
                () = sleep_until_unix(next_step) => {
                    server.mail_source_wakes.take_due(unix_seconds_now());
                    Pass::Woken
                }
                () = server.mail_source_wakes.notify.notified() => Pass::Woken,
                received = connected.recv() => match received {
                    Ok(source) => {
                        server.mail_source_wakes.add(source);
                        Pass::Woken
                    }
                    // Wakes were lost: every due source steps now.
                    Err(RecvError::Lagged(_)) => Pass::Every,
                    // The vault's store holds the sender while this server
                    // holds the vault.
                    Err(RecvError::Closed) => return,
                },
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

/// The mail sources woken to step before the worker's next pass: by Gmail's
/// notices, which the hook adds, by a mailbox's connect, and by the next
/// step a copying mailbox's last step named. The worker takes it whole. A
/// notice that comes while a step runs leaves one more wake.
#[derive(Default)]
pub(crate) struct MailSourceWakes {
    woken: Mutex<BTreeSet<EntityId>>,
    /// When each source owing more is stepped next, Unix seconds, as its
    /// last step named it.
    scheduled: Mutex<BTreeMap<EntityId, u64>>,
    notify: Notify,
}

impl MailSourceWakes {
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

    /// Adds `source` for the pass the worker runs next, without a wake of
    /// its own.
    fn add(&self, source: EntityId) {
        self.woken
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(source);
    }

    /// Keeps `source`'s next step at `next`, as its last step named it; none
    /// once it owes nothing.
    fn schedule(&self, source: EntityId, next: Option<u64>) {
        let mut scheduled = self
            .scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match next {
            Some(at) => {
                scheduled.insert(source, at);
            }
            None => {
                scheduled.remove(&source);
            }
        }
    }

    /// The earliest next step kept.
    fn next_scheduled(&self) -> Option<u64> {
        self.scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .min()
            .copied()
    }

    /// Wakes each source whose next step has come by `now`.
    fn take_due(&self, now: u64) {
        let mut scheduled = self
            .scheduled
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let due: Vec<EntityId> = scheduled
            .iter()
            .filter(|(_, at)| **at <= now)
            .map(|(source, _)| *source)
            .collect();
        let mut woken = self.woken.lock().unwrap_or_else(PoisonError::into_inner);
        for source in due {
            scheduled.remove(&source);
            woken.insert(source);
        }
    }

    /// Takes every woken source.
    fn take(&self) -> BTreeSet<EntityId> {
        std::mem::take(&mut *self.woken.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Unix seconds now.
fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Sleeps until the Unix second `at`, or forever without one.
async fn sleep_until_unix(at: Option<u64>) {
    match at {
        Some(at) => {
            tokio::time::sleep(Duration::from_secs(at.saturating_sub(unix_seconds_now()))).await;
        }
        None => std::future::pending().await,
    }
}

/// What a worker pass steps.
#[derive(Clone, Copy)]
enum Pass {
    /// Every due source, then every push channel that owes an act.
    Every,
    /// The sources notices and connects woke, and those whose next step
    /// has come.
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
    let woken = server.mail_source_wakes.take();
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
        match vault.mail_source_sync_step(&owner, source, MailSyncBudget::default()) {
            Ok(report) => server
                .mail_source_wakes
                .schedule(source, report.next_step_at),
            Err(error) => {
                // A failed step is read again at the next pass.
                server.mail_source_wakes.schedule(source, None);
                tracing::warn!(
                    source = %source.to_hex(),
                    error = %error,
                    "mail source sync step failed"
                );
            }
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
