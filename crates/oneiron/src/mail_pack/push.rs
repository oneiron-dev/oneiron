//! New mail arrives through Gmail push, with a reconcile behind it
//! (MAIL-GOOGLE = A, ARCH-0027 #mail-drive; ARCH-0063 #mail-import). A
//! watched mailbox has its provider publish a notice to a Pub/Sub topic on
//! each change; the host's hook reads the notice and steps the source at
//! once. A notice names the mailbox and its new change anchor, never mail,
//! and can be dropped, so the host's periodic pass still steps every source
//! from its committed anchor: that pass is the reconcile.
//!
//! The topic is the host's (its owner's Google project), never the
//! engine's. A host that sets one opens a channel for each Active Gmail
//! mailbox and renews it daily (Google closes one after 7 days, and
//! suggests a daily renewal); a channel whose host set no topic is closed.
//! A source that left Active reads nothing through its credential, so its
//! channel is let go of with no provider call: it lapses within its week,
//! and its notices wake nothing meanwhile. Each open, renewal and close is
//! charged as any call, within the source's quota windows.

use serde::{Deserialize, Serialize};

use super::gmail::reads_google_mail;
use super::quota::{MeteredMailWire, is_resting};
use super::source::{MailProvider, MailSourceRow, MailSourceStatus, SOURCES};
use super::state::{MailSyncState, SYNC};
use super::wire::{MailProviderWire, MailSyncSource};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Result, Vault};

/// How long a channel stands before it is renewed, and how close to its
/// close a renewal comes at the latest.
pub(super) const WATCH_RENEW_SECS: u64 = 86_400;

/// A mailbox's open push channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct MailWatchState {
    /// The Pub/Sub topic its notices go to.
    pub(super) topic: String,
    /// When it was opened or last renewed, Unix seconds.
    pub(super) renewed_at: u64,
    /// When the provider closes it unless it is renewed, Unix seconds.
    pub(super) expires_at: u64,
}

/// What one act on a mailbox's push channel did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailWatchAct {
    /// Opened or renewed it, until `expires_at` (Unix seconds).
    Watched { expires_at: u64 },
    /// Closed it, or let go of one the provider had already closed.
    Stopped,
}

/// An act a source's push channel owes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owed<'t> {
    /// Open or renew it to this topic.
    Watch(&'t str),
    /// Close it.
    Stop,
}

/// What a source's push channel owes under the host's `topic` at `now`.
fn owed_act<'t>(
    row: &MailSourceRow,
    watch: Option<&MailWatchState>,
    topic: Option<&'t str>,
    now: u64,
) -> Option<Owed<'t>> {
    let wanted = topic.filter(|_| {
        row.status == MailSourceStatus::Active
            && row.kind.is_mailbox()
            && reads_google_mail(row.provider)
    });
    match (watch, wanted) {
        (None, None) => None,
        (Some(_), None) => Some(Owed::Stop),
        (None, Some(topic)) => Some(Owed::Watch(topic)),
        (Some(watch), Some(topic)) => (watch.topic != topic
            || now >= watch.renewed_at.saturating_add(WATCH_RENEW_SECS)
            || watch.expires_at <= now.saturating_add(WATCH_RENEW_SECS))
        .then_some(Owed::Watch(topic)),
    }
}

/// Whether the source's stored change anchor is older than the anchor
/// `notified`: compared as numbers where both read as one (Gmail's ids
/// rise, with gaps), and as older whenever they differ otherwise. A source
/// with no anchor yet is older.
fn anchor_is_older(anchor: Option<&str>, notified: &str) -> bool {
    let Some(anchor) = anchor else {
        return true;
    };
    match (anchor.parse::<u64>(), notified.parse::<u64>()) {
        (Ok(anchor), Ok(notified)) => anchor < notified,
        _ => anchor != notified,
    }
}

/// Whether a source of `provider` is read by the notices of `notifier`:
/// Gmail's notices name a Google or a Google Workspace mailbox alike.
fn same_push_provider(provider: MailProvider, notifier: MailProvider) -> bool {
    provider == notifier || (reads_google_mail(provider) && reads_google_mail(notifier))
}

impl Vault {
    /// The mail sources whose push channel owes an act under the host's
    /// `topic` (`None`: the host serves no push), while the pack is
    /// installed: an Active Gmail mailbox with no channel, one open to
    /// another topic, or one due its daily renewal; and any source still
    /// holding a channel once it left Active or the host set no topic.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn mail_watches_due(&self, topic: Option<&str>) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        if super::pack::require_pack_active_in(self, &txn).is_err() {
            return Ok(Vec::new());
        }
        let now = crate::unix_seconds_now();
        let mut due = Vec::new();
        for row in SOURCES.iter_from(&self.store, &txn, &[])? {
            let (source, row) = row?;
            let watch = SYNC
                .get(&self.store, &txn, &source)?
                .and_then(|state| state.watch);
            if owed_act(&row, watch.as_ref(), topic, now).is_some() {
                due.push(source);
            }
        }
        Ok(due)
    }

    /// One act on the push channel of the mail source `source` through
    /// `wire`, under the host's `topic`: opens or renews it, or closes it,
    /// as [`Vault::mail_watches_due`] lists it; `None` when nothing was
    /// owed, or when the source rests out of quota (it is due again once it
    /// does not). A channel the provider has already closed, or one of a
    /// source that left Active (its credential reads nothing then), is let
    /// go of with no provider call. It keeps the channel on the source and
    /// writes no row. Call it from the host only: the owner's own sync
    /// never opens a channel.
    ///
    /// # Errors
    ///
    /// No such source, a pack not installed, the provider's failure (the
    /// channel's record stays as it was, so the act is owed again), or
    /// storage failures.
    pub fn mail_watch_step(
        &self,
        source: EntityId,
        wire: &dyn MailProviderWire,
        topic: Option<&str>,
    ) -> MemoryResult<Option<MailWatchAct>> {
        let (row, state) = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            super::pack::require_pack_active_in(self, &txn)?;
            let row = SOURCES
                .get(&self.store, &txn, &source)?
                .ok_or_else(|| MemoryError::bad_request("no mail source by that ref"))?;
            let state = SYNC.get(&self.store, &txn, &source)?.unwrap_or_default();
            (row, state)
        };
        let now = crate::unix_seconds_now();
        let Some(owed) = owed_act(&row, state.watch.as_ref(), topic, now) else {
            return Ok(None);
        };
        let wire_source = MailSyncSource::of(source, &row);
        let metered = MeteredMailWire::new(wire, state.quota);
        let outcome = match owed {
            Owed::Watch(topic) => metered.watch(&wire_source, topic).map(|expires_at| {
                let watch = MailWatchState {
                    topic: topic.to_owned(),
                    renewed_at: now,
                    expires_at,
                };
                (Some(watch), MailWatchAct::Watched { expires_at })
            }),
            Owed::Stop
                if row.status == MailSourceStatus::Active
                    && state
                        .watch
                        .as_ref()
                        .is_some_and(|watch| watch.expires_at > now) =>
            {
                metered
                    .stop_watch(&wire_source)
                    .map(|()| (None, MailWatchAct::Stopped))
            }
            Owed::Stop => Ok((None, MailWatchAct::Stopped)),
        };
        let window = metered.window();
        match outcome {
            Ok((watch, act)) => {
                self.change_sync_state(source, |state| {
                    state.watch = watch;
                    state.quota = window;
                })?;
                Ok(Some(act))
            }
            Err(error) => {
                self.change_sync_state(source, |state| state.quota = window)?;
                if is_resting(&error) {
                    Ok(None)
                } else {
                    Err(error.into())
                }
            }
        }
    }

    /// Changes the sync state of `source` by `change`, in one write.
    fn change_sync_state(
        &self,
        source: EntityId,
        change: impl FnOnce(&mut MailSyncState),
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let mut state = SYNC.get(&self.store, txn, &source)?.unwrap_or_default();
            change(&mut state);
            SYNC.put(&self.store, txn, &source, &state)
        })
    }

    /// The mailboxes a provider's push notice wakes: each Active mailbox of
    /// `provider` at `address` (case-folded) whose stored change anchor is
    /// older than the notice's `anchor` (Gmail's `historyId`), less one
    /// resting out of quota. It writes nothing: a notice carries no mail,
    /// and the host steps each source it answers.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub fn mail_push_notice(
        &self,
        provider: MailProvider,
        address: &str,
        anchor: &str,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        if super::pack::require_pack_active_in(self, &txn).is_err() {
            return Ok(Vec::new());
        }
        let now = crate::unix_seconds_now();
        let address = address.trim().to_lowercase();
        let mut woken = Vec::new();
        for row in SOURCES.iter_from(&self.store, &txn, &[])? {
            let (source, row) = row?;
            if row.status != MailSourceStatus::Active
                || !row.kind.is_mailbox()
                || !same_push_provider(row.provider, provider)
                || row.address.trim().to_lowercase() != address
            {
                continue;
            }
            let state = SYNC.get(&self.store, &txn, &source)?.unwrap_or_default();
            if state.quota.resting_at(now).is_none()
                && anchor_is_older(state.anchor.as_deref(), anchor)
            {
                woken.push(source);
            }
        }
        Ok(woken)
    }
}
