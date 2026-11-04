//! Read-only residence cache entries and complete or partial search results.

use crate::EntityId;
use crate::window_key::WindowKey;

/// Search explicitly distinguishes a complete home answer from a partial
/// offline answer over this device's previously opened, cached items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSource {
    Home,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceHit {
    pub entity_id: String,
    pub score: f32,
    /// The canonical window holding the hit, so a first touch can open it.
    pub window: WindowKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResidenceSearch {
    pub hits: Vec<ResidenceHit>,
    pub source: SearchSource,
    pub complete: bool,
}

/// One grant-checked read cache entry. It is NOT a writable ledger replica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThinItem {
    pub entity_id: EntityId,
    pub window: WindowKey,
    /// The entity header and body, exactly as returned by the home.
    pub raw: Vec<u8>,
    /// The separately grant-checked text document frame.
    pub document: Vec<u8>,
}

/// One item as a host shows it when a person opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenedItem {
    /// A canonical local row: a sync-all replica's, a promoted window's or
    /// one this machine wrote.
    Resident {
        entity_id: EntityId,
        window: WindowKey,
        raw: Vec<u8>,
    },
    /// A grant-checked read cache; its window is promoted before any edit.
    Thin(ThinItem),
}
