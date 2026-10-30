//! A window's history as a peer gets it, and a peer's history as the
//! canonical window takes it (CHANGED 4.HISTORY).
//!
//! Window carriers are root-map registers: a row is one `entities` value,
//! an edge one `edges` key, a tombstone one `tombstones` key. A register's
//! value may change length inside its one operation unit, so a projected
//! map operation keeps its id, counter, Lamport, dependencies and
//! timestamp, with its value replaced by the copy and every marked source
//! id in its key aliased (C1 of the s4 soundness read: per-op units kept,
//! aliases injective). Anything else that would carry marked bytes (a text
//! or list payload whose units a mask may change) is reported as not
//! preserving, and its release takes the separate copy lineage instead.
//!
//! The JSON is read with the ids it was exported with: either peer form
//! (compressed or not) is handled, and nothing below the export's start
//! is assumed present (a shallow root's state is the release adapter's,
//! through the root-map checkpoint).

use std::collections::BTreeSet;

use loro::json::{JsonOpContent, JsonSchema, ListOp, MapOp, MovableListOp, TextOp};
use loro::{ContainerID, ContainerType, ID, LoroDoc, LoroValue, PeerID};

use super::rows::{HeldEdit, Landing};
use super::{CopyRow, InboundRow, SyncSecretProjection};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// The root map an entity row is a register of.
const ENTITIES_MAP: &str = "entities";

/// A window history after [`SyncSecretProjection::project_history`].
#[derive(Debug, Default)]
pub(crate) struct ProjectedHistory {
    /// The marked sources the projected operations carry: the release's
    /// copy generation is taken over these.
    pub(crate) sources: BTreeSet<EntityId>,
    /// The operations whose value or key now differ from the source's.
    pub(crate) changed: Vec<ID>,
    /// Every changed operation is a root-map register with its unit kept.
    /// `false` when a text or list payload holds a marked blob's bytes: that
    /// history cannot keep its ids and ships as a separate copy lineage.
    pub(crate) preserving: bool,
}

/// A peer's window history after
/// [`SyncSecretProjection::translate_history`].
#[derive(Debug, Default)]
pub(crate) struct TranslatedHistory {
    /// The canonical sources the translated operations now target.
    pub(crate) sources: BTreeSet<EntityId>,
    /// Edits of a copy the visible diff holds on a ruled cause. Their
    /// operations are left untranslated: the caller imports and applies
    /// nothing of the update, and keeps only its held record (FIX 10598).
    pub(crate) held: Vec<HeldEdit>,
    /// The new bytes the translated operations land, for their writer to
    /// mark (FIX 10732).
    pub(crate) landings: Vec<Landing>,
}

impl SyncSecretProjection {
    /// Re-author `json` for a peer in place: every row register of a marked
    /// item carries its copy, and every key naming a marked source names its
    /// copy. Operation ids and units are kept.
    pub(crate) fn project_history(&self, json: &mut JsonSchema) -> ProjectedHistory {
        let mut out = ProjectedHistory {
            preserving: true,
            ..ProjectedHistory::default()
        };
        if self.is_empty() {
            return out;
        }
        let peers = json.peers.clone();
        for change in &mut json.changes {
            let peer = real_peer(peers.as_deref(), change.id.peer);
            for op in &mut change.ops {
                let Some(map) = root_map_name(&op.container) else {
                    if self.payload_carries_marked(&op.content) {
                        out.preserving = false;
                    }
                    continue;
                };
                let entities = map == ENTITIES_MAP;
                let touched = match &mut op.content {
                    JsonOpContent::Map(MapOp::Insert { key, value }) => {
                        let row = entities
                            .then(|| EntityId::from_hex(key).ok())
                            .flatten()
                            .zip(row_of(value));
                        match row.map(|(id, bytes)| (id, self.project_row(&id, &bytes))) {
                            Some((
                                id,
                                CopyRow::Copy { key: copy, row }
                                | CopyRow::Sealed { key: copy, row },
                            )) => {
                                out.sources.insert(self.source_for(&id));
                                *key = copy.to_hex();
                                *value = LoroValue::from(row);
                                true
                            }
                            _ => self.alias_key(key, &mut out.sources),
                        }
                    }
                    JsonOpContent::Map(MapOp::Delete { key }) => {
                        self.alias_key(key, &mut out.sources)
                    }
                    other => {
                        if self.payload_carries_marked(other) {
                            out.preserving = false;
                        }
                        false
                    }
                };
                if touched {
                    out.changed.push(ID::new(peer, op.counter));
                }
            }
        }
        out
    }

    /// Translate a peer's `json` onto the canonical window in place: every
    /// copy key names its source again, and every copy row carries the
    /// stored bytes or the visible diff applied to them. Placeholder or
    /// masked bytes never become a source row. Operation ids are kept: the
    /// peer's pending identity is the canonical one. `context` is this
    /// window, read for a re-authored row kept under its own id (FIX 10874).
    ///
    /// # Errors
    /// The visible diff's own failure.
    pub(crate) fn translate_history(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        json: &mut JsonSchema,
    ) -> Result<TranslatedHistory> {
        let mut out = TranslatedHistory::default();
        if self.is_empty() {
            return Ok(out);
        }
        let peers = json.peers.clone();
        for change in &mut json.changes {
            let peer = real_peer(peers.as_deref(), change.id.peer);
            for op in &mut change.ops {
                let Some(map) = root_map_name(&op.container) else {
                    continue;
                };
                let entities = map == ENTITIES_MAP;
                match &mut op.content {
                    JsonOpContent::Map(MapOp::Insert { key, value }) => {
                        let row = entities
                            .then(|| EntityId::from_hex(key).ok())
                            .flatten()
                            .zip(row_of(value));
                        let Some((id, bytes)) = row else {
                            self.unalias_key(key, &mut out.sources);
                            continue;
                        };
                        // A re-authored copy carries no edit (FIX 10729, FIX 10874).
                        let reauthored = self.reauthored_row(peer, &id, &bytes).or_else(|| {
                            self.reauthored_own_row(store, context, peer, &id, &bytes)
                        });
                        let inbound = match reauthored {
                            Some(row) => row,
                            None => self.source_row(&id, &bytes)?,
                        };
                        match inbound {
                            InboundRow::Source { id, row, landed } => {
                                out.sources.insert(id);
                                if let Some(blob) = landed {
                                    out.landings.push(Landing::of(id, blob, &row));
                                }
                                *key = id.to_hex();
                                *value = LoroValue::from(row);
                            }
                            InboundRow::Held(edit) => out.held.push(edit),
                            InboundRow::Ordinary => self.unalias_key(key, &mut out.sources),
                        }
                    }
                    JsonOpContent::Map(MapOp::Delete { key }) => {
                        self.unalias_key(key, &mut out.sources);
                    }
                    _ => {}
                }
            }
        }
        Ok(out)
    }

    /// The marked source `id` is or stands in place for.
    fn source_for(&self, id: &EntityId) -> EntityId {
        if self.sources.contains_key(id) {
            return *id;
        }
        self.source_of_copy(id).unwrap_or(*id)
    }

    /// Alias `key`'s marked source segments to their copies.
    fn alias_key(&self, key: &mut String, sources: &mut BTreeSet<EntityId>) -> bool {
        let Some(aliased) = self.rekey(key) else {
            return false;
        };
        for part in key.split(':') {
            if let Ok(id) = EntityId::from_hex(part)
                && self.sources.contains_key(&id)
            {
                sources.insert(id);
            }
        }
        *key = aliased;
        true
    }

    /// Resolve `key`'s copy segments to their sources.
    fn unalias_key(&self, key: &mut String, sources: &mut BTreeSet<EntityId>) {
        let Some(resolved) = self.source_key(key) else {
            return;
        };
        for part in key.split(':') {
            if let Some(source) = EntityId::from_hex(part)
                .ok()
                .and_then(|id| self.source_of_copy(&id))
            {
                sources.insert(source);
            }
        }
        *key = resolved;
    }

    /// Whether a non-register payload holds a marked blob's whole bytes, read
    /// or unread.
    fn payload_carries_marked(&self, content: &JsonOpContent) -> bool {
        let marked = |bytes: &[u8]| {
            let hash = blake3::hash(bytes);
            self.blobs.contains_key(hash.as_bytes()) || self.unread.contains_key(hash.as_bytes())
        };
        let values_marked = |values: &[LoroValue]| {
            values
                .iter()
                .any(|value| binary_of(value).is_some_and(|bytes| marked(&bytes)))
        };
        match content {
            JsonOpContent::Text(TextOp::Insert { text, .. }) => marked(text.as_bytes()),
            JsonOpContent::List(ListOp::Insert { value, .. })
            | JsonOpContent::MovableList(MovableListOp::Insert { value, .. }) => {
                values_marked(value)
            }
            JsonOpContent::MovableList(MovableListOp::Set { value, .. }) => {
                values_marked(std::slice::from_ref(value))
            }
            _ => false,
        }
    }
}

/// The name of `container` when it is a root map.
fn root_map_name(container: &ContainerID) -> Option<&str> {
    match container {
        ContainerID::Root {
            name,
            container_type: ContainerType::Map,
        } => Some(name.as_str()),
        _ => None,
    }
}

/// The bytes of an entity row register: rows are binary values.
fn row_of(value: &LoroValue) -> Option<Vec<u8>> {
    match value {
        LoroValue::Binary(bytes) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// The bytes of a binary or string value.
fn binary_of(value: &LoroValue) -> Option<Vec<u8>> {
    match value {
        LoroValue::Binary(bytes) => Some(bytes.to_vec()),
        LoroValue::String(text) => Some(text.as_bytes().to_vec()),
        _ => None,
    }
}

/// The peer a change id names: an index into the export's peer table when
/// the export compressed peers, else the peer itself.
fn real_peer(peers: Option<&[PeerID]>, peer: PeerID) -> PeerID {
    match peers {
        Some(table) => usize::try_from(peer)
            .ok()
            .and_then(|index| table.get(index).copied())
            .unwrap_or(peer),
        None => peer,
    }
}
