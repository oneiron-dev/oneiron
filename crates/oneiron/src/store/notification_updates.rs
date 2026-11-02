//! The vault's one committed-notification signal (FIX 3084). A notification
//! put or inbox mark queues its change in the transaction that writes it; the
//! transaction's owner sends this signal only after that commit returned, so
//! a rolled-back write never wakes anyone. The value is a content-free
//! generation: a subscriber never takes a row from it, only re-reads the
//! committed notifications, and subscribes before that first read, so no
//! change between the two is lost. A burst of commits coalesces into one
//! wake whose re-read delivers all of it. Nothing survives a restart, and
//! nothing needs to: a fresh subscriber reads the committed rows at once.

use tokio::sync::watch;

use super::Store;
use crate::Vault;

impl Store {
    /// Wakes every subscriber to re-read this vault's notifications. Call it
    /// only once the commit that put or marked one returned.
    pub(crate) fn notify_notification_updates(&self) {
        self.notification_updates
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// A subscription to the signal, taken before the subscriber's first
    /// notification read.
    pub(crate) fn subscribe_notification_updates(&self) -> watch::Receiver<u64> {
        self.notification_updates.subscribe()
    }
}

impl Vault {
    /// Subscribes to this vault's committed notification changes (FIX 3084).
    /// Subscribe before the first notification read. Each change means
    /// "re-read the committed notifications", never "here is a row".
    pub fn subscribe_notification_updates(&self) -> watch::Receiver<u64> {
        self.store.subscribe_notification_updates()
    }
}
