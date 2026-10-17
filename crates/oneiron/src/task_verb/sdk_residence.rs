//! The owner's residence controls (OF-534, FIX 531): a machine's residence
//! mode, opening one item there, its thin index and pruning its opened-item
//! caches, as owner-vault rows that name the machine they act on. The named
//! machine's own `SyncConnection` applies each one; a host reaches it
//! through the connection it registered for that machine id, and an
//! embedded handle reaches none. The engine types have no wire form, so the
//! inputs and answers are spelled here.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use crate::sync::{OpenedItem, ResidenceIndexWindow, ResidenceModeChange, SyncResidenceMode};

/// `opened` (items fetched on demand) or `all` (full window replication).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResidenceModeName {
    Opened,
    All,
}

impl From<ResidenceModeName> for SyncResidenceMode {
    fn from(mode: ResidenceModeName) -> Self {
        match mode {
            ResidenceModeName::Opened => Self::Opened,
            ResidenceModeName::All => Self::All,
        }
    }
}

impl From<SyncResidenceMode> for ResidenceModeName {
    fn from(mode: SyncResidenceMode) -> Self {
        match mode {
            SyncResidenceMode::Opened => Self::Opened,
            SyncResidenceMode::All => Self::All,
        }
    }
}

/// `vault.residence.index`'s input: the machine whose thin index to read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceMachineRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
}

/// `vault.residence.mode`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceModeRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    pub mode: ResidenceModeName,
}

/// `vault.residence.open`'s input: one item of one window, opened on the
/// named machine.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidenceOpenRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    /// The item's month window, `YYYY-MM`.
    pub window: String,
    /// The item, 32 hex.
    pub item: EntityId,
}

/// `vault.residence.prune`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidencePruneRequest {
    /// The owner's machine, by its machine id (32 hex).
    pub machine: EntityId,
    /// Opened-item caches last touched before this (recorded-clock unix
    /// seconds) are dropped.
    pub before: u64,
}

/// What switching the machine's residence mode did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceModeChanged {
    /// The mode the machine runs now; the elected home always runs `all`.
    pub mode: ResidenceModeName,
    /// Held windows the home granted again, kept as promoted windows.
    pub retained: Vec<String>,
    /// Held windows the home did not grant again: still on disk, unsynced.
    pub unsynced: Vec<String>,
    /// Opened-item caches dropped on the way to `all`.
    pub pruned_items: usize,
}

impl From<ResidenceModeChange> for ResidenceModeChanged {
    fn from(change: ResidenceModeChange) -> Self {
        let keys = |keys: Vec<crate::sync::WindowKey>| {
            keys.iter().map(|key| key.as_str().to_owned()).collect()
        };
        Self {
            mode: change.mode.into(),
            retained: keys(change.retained),
            unsynced: keys(change.unsynced),
            pruned_items: change.pruned_items,
        }
    }
}

/// Where the opened item came from on the machine: its canonical row, or a
/// grant-checked read cache. Its bytes stay on the machine; reads reach the
/// item through the usual doors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceOpened {
    pub item: EntityId,
    pub window: String,
    /// `resident` (a canonical local row) or `thin` (a read cache).
    pub residence: String,
    /// The bytes the machine holds for it.
    pub bytes: usize,
}

impl From<OpenedItem> for ResidenceOpened {
    fn from(opened: OpenedItem) -> Self {
        match opened {
            OpenedItem::Resident {
                entity_id,
                window,
                raw,
            } => Self {
                item: entity_id,
                window: window.as_str().to_owned(),
                residence: "resident".to_owned(),
                bytes: raw.len(),
            },
            OpenedItem::Thin(thin) => Self {
                item: thin.entity_id,
                window: thin.window.as_str().to_owned(),
                residence: "thin".to_owned(),
                bytes: thin.raw.len() + thin.document.len(),
            },
        }
    }
}

/// One entry of a window's thin index: what exists, never a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexEntry {
    pub entity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub learned_at: u64,
}

/// One current window's thin index on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndexWindowView {
    pub window: String,
    pub items: Vec<ResidenceIndexEntry>,
}

/// `vault.residence.index`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidenceIndex {
    pub windows: Vec<ResidenceIndexWindowView>,
}

impl From<Vec<ResidenceIndexWindow>> for ResidenceIndex {
    fn from(windows: Vec<ResidenceIndexWindow>) -> Self {
        Self {
            windows: windows
                .into_iter()
                .map(|window| ResidenceIndexWindowView {
                    window: window.window.as_str().to_owned(),
                    items: window
                        .items
                        .into_iter()
                        .map(|entry| ResidenceIndexEntry {
                            entity_id: entry.entity_id,
                            title: entry.title,
                            learned_at: entry.learned_at,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// `vault.residence.prune`'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidencePruned {
    /// Opened-item caches dropped.
    pub dropped: usize,
}

/// A residence row on an embedded handle: refused, as no machine's sync
/// connection is reachable beneath an embedded vault. A server's host door
/// applies it through the named machine's connection.
///
/// # Errors
///
/// Always.
pub fn residence_host_only<I, T>(_memory: &Memory<'_>, verb: &str, _input: &I) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_MODEL_UNAVAILABLE,
        format!("{verb} acts on a machine's own sync connection; an embedded vault reaches none"),
        &["Call it through a server that runs the named machine's sync connection."],
    ))
}
