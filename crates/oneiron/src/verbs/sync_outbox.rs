//! `vault.sync.outbox` (FIX 3966): what one of the owner's machines still
//! owes its home. Each row is a queued update its home has not durably
//! acknowledged, with the digest of the raw row and the home's answer to its
//! latest send. That answer is the typed acknowledgment the owner observes;
//! the row count is the "edits waiting to sync" a device shows. The named
//! machine's own `SyncConnection` reads its queue; a host reaches it through
//! the connection it registered for that machine id, and an embedded handle
//! reaches none. The answer is content-free: digests and sizes, never a body.

use serde::{Deserialize, Serialize};

use crate::EntityId;

/// `vault.sync.outbox`'s answer: the named machine's outbox, read through its
/// connection on this host, or that this host runs no connection for it.
/// `state` says which; a read answer carries [`SyncOutbox`]'s fields beside
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SyncOutboxAnswer {
    Read(SyncOutbox),
    Unreached(SyncOutboxUnreached),
}

/// The machine this host runs no sync connection for: its outbox is read on
/// the machine itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboxUnreached {
    pub machine: EntityId,
}

/// The updates a machine still owes its home, in queue order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutbox {
    pub machine: EntityId,
    /// How many queued updates are still owed, across every window.
    pub owed: u64,
    pub windows: Vec<SyncOutboxWindow>,
}

/// One window's owed updates. Windows are separate documents: a row the
/// home has not acknowledged holds back only the later rows of its own
/// window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboxWindow {
    pub window_key: String,
    pub rows: Vec<SyncOutboxRow>,
}

/// One queued update still owed to the home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOutboxRow {
    /// Its queue sequence: the replay order.
    pub seq: u64,
    /// The BLAKE3 digest of the raw queued row, 64 lowercase hex: the bytes
    /// the home's acknowledgment is bound to.
    pub digest: String,
    /// The raw row's size in bytes.
    pub bytes: u64,
    /// The home's answer to this row's latest send in this process; `None`
    /// while it is unsent, unanswered, or since the machine restarted.
    pub receipt: Option<SyncOutboxReceipt>,
}

/// The home's answer to a queued update it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncOutboxReceipt {
    /// The home persisted it. The row waits only on an earlier row of its
    /// window the home has not acknowledged.
    Durable,
    /// The home holds it without persisting it yet; the row stays owed.
    Held,
}
