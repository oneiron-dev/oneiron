//! The common actor-stamped Loro document primitive.

use super::invalid;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::loro_support::{
    doc_from_snapshot, export_snapshot, map_get_bytes, map_insert_bytes,
};
use crate::write_envelope::WriteActor;
use loro::{CommitOptions, ExportMode, Frontiers, LoroDoc, LoroText};
use serde::{Deserialize, Serialize};

pub(super) const BODY: &str = "body";
const BIRTH: &str = "entity_doc_birth";

/// Immutable provenance copied from the original record at document birth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Birth {
    /// Entity owning the text.
    pub entity: String,
    /// Actor who wrote the original text, not the actor migrating it.
    pub actor: String,
    /// Original timestamp in seconds.
    pub at: u64,
}

/// One document, with stable cursor identity and an actor on every local commit.
pub struct EntityDoc {
    pub(crate) doc: LoroDoc,
    birth: Birth,
}

impl EntityDoc {
    /// Creates the first commit from the original text and birth provenance.
    pub fn open(entity: EntityId, initial: &str, actor: WriteActor, at: u64) -> Result<Self> {
        Self::open_initialized(entity, initial, actor, at, |_| Ok(()), None)
    }

    pub(crate) fn open_initialized(
        entity: EntityId,
        initial: &str,
        actor: WriteActor,
        at: u64,
        initialize: impl FnOnce(&LoroDoc) -> Result<()>,
        message: Option<&str>,
    ) -> Result<Self> {
        let doc = LoroDoc::new();
        doc.set_record_timestamp(true);
        let birth = Birth {
            entity: entity.to_hex(),
            actor: actor.entity_ref().to_hex(),
            at,
        };
        let bytes =
            rmp_serde::to_vec_named(&birth).map_err(|_| invalid("document birth encoding"))?;
        map_insert_bytes(&doc.get_map("meta"), BIRTH, &bytes)?;
        doc.get_text(BODY)
            .insert(0, initial)
            .map_err(|_| invalid("document birth text"))?;
        initialize(&doc)?;
        if let Some(message) = message {
            let timestamp =
                i64::try_from(at).map_err(|_| invalid("document timestamp overflow"))?;
            doc.commit_with(
                CommitOptions::new()
                    .commit_msg(message)
                    .timestamp(timestamp),
            );
        } else {
            stamp(&doc, actor, at, "birth")?;
        }
        Ok(Self { doc, birth })
    }

    /// Restores state and immutable birth metadata from a full or shallow snapshot.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        Self::from_loro(doc_from_snapshot(bytes)?)
    }

    pub(crate) fn from_loro(doc: LoroDoc) -> Result<Self> {
        doc.set_record_timestamp(true);
        let bytes = map_get_bytes(&doc.get_map("meta"), BIRTH)
            .ok_or(Error::CorruptedIndex("document birth metadata"))?;
        let birth: Birth = super::storage::decode(&bytes)?;
        EntityId::from_hex(&birth.entity)?;
        EntityId::from_hex(&birth.actor)?;
        Ok(Self { doc, birth })
    }

    /// Immutable provenance, retained even after an owner shallow purge.
    #[must_use]
    pub fn birth(&self) -> &Birth {
        &self.birth
    }

    /// Current text.
    #[must_use]
    pub fn text(&self) -> String {
        self.doc.get_text(BODY).to_string()
    }

    /// Current causal frontier, not a sortable scalar revision.
    #[must_use]
    pub fn frontier(&self) -> Vec<u8> {
        self.doc.oplog_frontiers().encode()
    }

    /// A durable snapshot. The registry persists incremental updates between snapshots.
    pub fn export_snapshot(&self) -> Result<Vec<u8>> {
        export_snapshot(&self.doc)
    }

    /// Applies and stamps one actor's operations. Pending partial work is stamped
    /// even on error. Vault transactions use private scratch docs and roll back
    /// failed calls, so this cannot leak an uncommitted cache mutation.
    pub fn edit_as(
        &mut self,
        actor: WriteActor,
        at: u64,
        edit: impl FnOnce(&LoroText) -> Result<()>,
    ) -> Result<()> {
        let result = edit(&self.doc.get_text(BODY));
        stamp(&self.doc, actor, at, "edit")?;
        result
    }

    /// Reads a retained historical version without changing the live head.
    pub fn text_at(&self, frontier: &[u8]) -> Result<String> {
        self.fork(frontier).map(|doc| doc.text())
    }

    pub(super) fn fork(&self, frontier: &[u8]) -> Result<Self> {
        let f = decode_frontier(frontier)?;
        if self.doc.is_shallow() {
            let vv = self
                .doc
                .frontiers_to_vv(&f)
                .ok_or(invalid("unknown or purged frontier"))?;
            if !vv.includes_vv(&self.doc.shallow_since_vv().to_vv()) {
                return Err(invalid("unknown or purged frontier"));
            }
            // Loro 1.13 deliberately does not implement SnapshotAt/fork_at on
            // shallow docs. StateOnly retains the requested causal state and
            // cursor identities without importing later edits into the fork.
            let bytes = self
                .doc
                .export(ExportMode::state_only(Some(&f)))
                .map_err(|_| invalid("retained frontier snapshot"))?;
            let fork = Self::from_snapshot(&bytes)?;
            if fork.doc.oplog_frontiers() != f {
                return Err(invalid("retained fork frontier mismatch"));
            }
            Ok(fork)
        } else {
            Self::from_loro(
                self.doc
                    .fork_at(&f)
                    .map_err(|_| invalid("unknown or purged frontier"))?,
            )
        }
    }

    pub(super) fn shallow_snapshot(&self, frontier: &[u8]) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::shallow_snapshot(&decode_frontier(frontier)?))
            .map_err(|_| invalid("invalid shallow frontier"))
    }
}

pub(super) fn decode_frontier(bytes: &[u8]) -> Result<Frontiers> {
    Frontiers::decode(bytes).map_err(|_| invalid("invalid document frontier"))
}

pub(super) fn stamp(doc: &LoroDoc, actor: WriteActor, at: u64, verb: &str) -> Result<()> {
    let at = i64::try_from(at).map_err(|_| invalid("document timestamp overflow"))?;
    // Sequence-bearing messages prevent Loro from folding two calls by the same
    // actor into one change. Peer bindings remain the authority for remote stamps.
    let message = format!(
        "oneiron.entity_doc.v1 {verb} actor={}.{} op={:?}",
        actor.entity_ref().to_hex(),
        crate::edit_distance::actor_class_token(actor.actor_class()),
        doc.oplog_vv()
    );
    doc.commit_with(CommitOptions::new().commit_msg(&message).timestamp(at));
    Ok(())
}

/// Persisted operation attribution resolved through the existing peer binding
/// ladder. A commit message alone never authenticates its claimed actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextChange {
    pub actor: Option<WriteActor>,
    pub peer: u64,
    pub timestamp: u64,
}

impl crate::Vault {
    /// Reads the attribution of retained changes; purged history is not invented.
    pub fn entity_text_changes(&self, entity: &EntityId) -> Result<Vec<TextChange>> {
        let snapshot = self.read_entity_doc(entity, EntityDoc::export_snapshot)??;
        let doc = EntityDoc::from_snapshot(&snapshot)?;
        let mut changes = Vec::new();
        doc.doc
            .travel_change_ancestors(&doc.doc.oplog_frontiers().to_vec(), &mut |meta| {
                changes.push(meta);
                std::ops::ControlFlow::Continue(())
            })
            .map_err(|_| Error::CorruptedIndex("document attribution history"))?;
        changes.sort_by_key(|meta| (meta.lamport, meta.id.peer));
        changes
            .into_iter()
            .map(|meta| {
                let at =
                    u64::try_from(meta.timestamp).map_err(|_| invalid("document timestamp"))?;
                let stamped = parse_actor(meta.message.as_deref());
                let actor = if let Some(actor) = stamped {
                    if crate::edit_distance::peer_actor_stamp_is_honored(
                        self,
                        meta.id.peer,
                        at,
                        &actor,
                    )? {
                        Some(actor)
                    } else {
                        crate::edit_distance::peer_actor_at(self, meta.id.peer, at)?
                    }
                } else {
                    crate::edit_distance::peer_actor_at(self, meta.id.peer, at)?
                };
                Ok(TextChange {
                    actor,
                    peer: meta.id.peer,
                    timestamp: at,
                })
            })
            .collect()
    }
}

fn parse_actor(message: Option<&str>) -> Option<WriteActor> {
    let mut tokens = message?.split_whitespace();
    if tokens.next()? != "oneiron.entity_doc.v1" {
        return None;
    }
    let _verb = tokens.next()?;
    let (id, class) = tokens.next()?.strip_prefix("actor=")?.split_once('.')?;
    Some(WriteActor::new(
        EntityId::from_hex(id).ok()?,
        crate::edit_distance::actor_class_from_token(class)?,
    ))
}
