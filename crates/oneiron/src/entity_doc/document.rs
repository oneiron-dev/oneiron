//! The common actor-stamped Loro document primitive.

use super::doc_actor::DocActor;
use super::invalid;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::provenance::made_by::{MadeBy, MadeByClass};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::write_envelope::WriteActor;
use loro::{
    CommitOptions, ExportMode, Frontiers, LoroDoc, LoroMap, LoroText, LoroValue, ValueOrContainer,
};
use serde::{Deserialize, Serialize};

pub(super) const BODY: &str = "body";
/// The root map a document keeps its birth and metadata in.
pub(super) const META: &str = "meta";
pub(super) const BIRTH: &str = "entity_doc_birth";
/// The engine stamp every local commit message opens with.
const STAMP: &str = "oneiron.entity_doc.v1";

/// Immutable provenance copied from the original record at document birth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Birth {
    /// Entity owning the text.
    pub entity: String,
    /// Actor who wrote the original text, not the actor migrating it; no one
    /// once that actor was erased (FIX 6072, Engine R2), which a reader shows
    /// as unknown and never fills from a peer binding.
    pub actor: DocActor,
    /// Original timestamp in seconds.
    pub at: u64,
}

impl Birth {
    /// The bytes a document stores its birth as.
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| invalid("document birth encoding"))
    }

    /// A stored birth: its entity an id, and its actor one or no one.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        let birth: Self = super::storage::decode(bytes)?;
        EntityId::from_hex(&birth.entity)?;
        Ok(birth)
    }
}

/// One document, with stable cursor identity and an actor on every local commit.
pub struct EntityDoc {
    pub(crate) doc: LoroDoc,
    birth: Birth,
}

impl EntityDoc {
    /// Creates the first commit from the original text and birth provenance.
    pub fn open(entity: EntityId, initial: &str, actor: WriteActor, at: u64) -> Result<Self> {
        Self::open_born(entity, initial, actor, at, None)
    }

    /// [`Self::open`] for a row that already holds its birth: `born`, its
    /// `RowBirth.made_by`, is the birth commit's receipt when it names this
    /// birth's actor at its time (FIX 10929).
    pub(super) fn open_born(
        entity: EntityId,
        initial: &str,
        actor: WriteActor,
        at: u64,
        born: Option<&MadeBy>,
    ) -> Result<Self> {
        let birth = BirthCommit::Stamp(born);
        Self::open_with(LoroDoc::new(), entity, initial, actor, at, |_| Ok(()), birth)
    }

    pub(super) fn open_with_metadata(
        entity: EntityId,
        initial: &str,
        metadata: &std::collections::BTreeMap<String, Vec<u8>>,
        actor: WriteActor,
        at: u64,
        born: Option<&MadeBy>,
    ) -> Result<Self> {
        Self::open_with(
            LoroDoc::new(),
            entity,
            initial,
            actor,
            at,
            |doc| {
                Self::replace_metadata(doc, metadata)?;
                Self::set_record_fields(doc, &metadata.keys().cloned().collect::<Vec<_>>())
            },
            BirthCommit::Stamp(born),
        )
    }

    // The caller may bind the fresh peer before choosing the birth timestamp.
    pub(crate) fn open_initialized(
        doc: LoroDoc,
        entity: EntityId,
        initial: &str,
        actor: WriteActor,
        at: u64,
        initialize: impl FnOnce(&LoroDoc) -> Result<()>,
        message: Option<&str>,
    ) -> Result<Self> {
        let birth = message.map_or(BirthCommit::Stamp(None), BirthCommit::Message);
        Self::open_with(doc, entity, initial, actor, at, initialize, birth)
    }

    /// [`Self::open_initialized`] with the engine stamp, its receipt `born`
    /// as [`Self::open_born`] takes it (FIX 10929).
    pub(super) fn open_initialized_born(
        doc: LoroDoc,
        entity: EntityId,
        initial: &str,
        actor: WriteActor,
        at: u64,
        initialize: impl FnOnce(&LoroDoc) -> Result<()>,
        born: Option<&MadeBy>,
    ) -> Result<Self> {
        let birth = BirthCommit::Stamp(born);
        Self::open_with(doc, entity, initial, actor, at, initialize, birth)
    }

    fn open_with(
        doc: LoroDoc,
        entity: EntityId,
        initial: &str,
        actor: WriteActor,
        at: u64,
        initialize: impl FnOnce(&LoroDoc) -> Result<()>,
        commit: BirthCommit<'_>,
    ) -> Result<Self> {
        doc.set_record_timestamp(true);
        let birth = Birth {
            entity: entity.to_hex(),
            actor: DocActor::Actor(actor.entity_ref()),
            at,
        };
        map_insert_bytes(&doc.get_map(META), BIRTH, &birth.encode()?)?;
        doc.get_text(BODY)
            .insert(0, initial)
            .map_err(|_| invalid("document birth text"))?;
        initialize(&doc)?;
        match commit {
            BirthCommit::Message(message) => {
                let timestamp =
                    i64::try_from(at).map_err(|_| invalid("document timestamp overflow"))?;
                doc.commit_with(
                    CommitOptions::new()
                        .commit_msg(message)
                        .timestamp(timestamp),
                );
            }
            BirthCommit::Stamp(born) => stamp_birth(&doc, actor, at, born)?,
        }
        Ok(Self { doc, birth })
    }

    /// Fresh value document for canonical recovery. Old frontiers are not
    /// imported; an erased birth actor stays no one. Its commit restates the
    /// row's birth (FIX 10929).
    pub(crate) fn rebuild_value(
        entity: EntityId,
        text: &str,
        actor: DocActor,
        at: u64,
    ) -> Result<Self> {
        let doc = LoroDoc::new();
        doc.set_record_timestamp(true);
        let birth = Birth {
            entity: entity.to_hex(),
            actor,
            at,
        };
        map_insert_bytes(&doc.get_map(META), BIRTH, &birth.encode()?)?;
        if !text.is_empty() {
            doc.get_text(BODY)
                .insert(0, text)
                .map_err(|_| invalid("document recovery text"))?;
        }
        restate_birth(&doc);
        Ok(Self { doc, birth })
    }

    /// Restores state and immutable birth metadata from a full or shallow snapshot.
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        Self::from_loro(doc_from_snapshot(bytes)?)
    }

    /// A stored document: its birth names its entity, and its actor or, once
    /// erased, no one; a document is never refused for an erased birth.
    pub(crate) fn from_loro(doc: LoroDoc) -> Result<Self> {
        doc.set_record_timestamp(true);
        let bytes = map_get_bytes(&doc.get_map(META), BIRTH)
            .ok_or(Error::CorruptedIndex("document birth metadata"))?;
        let birth = Birth::decode(&bytes)?;
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
        self.edit_with(actor, at, &[], edit)
    }

    /// [`Self::edit_as`], its receipt naming `sources`, the rows its writer
    /// read for it (FIX 7790).
    pub(super) fn edit_with(
        &mut self,
        actor: WriteActor,
        at: u64,
        sources: &[EntityId],
        edit: impl FnOnce(&LoroText) -> Result<()>,
    ) -> Result<()> {
        let result = edit(&self.doc.get_text(BODY));
        stamp_with(&self.doc, actor, at, "edit", sources)?;
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

// The document plane's own Loro codec, with the document error: a build
// without the sync layer keeps its documents and has no sync helpers to call.

/// A document from a full or shallow snapshot.
pub(super) fn doc_from_snapshot(bytes: &[u8]) -> Result<LoroDoc> {
    LoroDoc::from_snapshot(bytes).map_err(|_| invalid("document snapshot"))
}

/// A full snapshot of `doc`.
pub(super) fn export_snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|_| invalid("document snapshot export"))
}

/// The bytes under `key` in `map`; `None` when it holds none, or no bytes.
pub(super) fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// Puts `value` under `key` in `map`.
pub(super) fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) -> Result<()> {
    map.insert(key, value)
        .map_err(|_| invalid("document metadata write"))
}

/// How a document's birth commit is spelled.
enum BirthCommit<'a> {
    /// The caller's own message: a proposal artifact's receipted stamp.
    Message(&'a str),
    /// The engine stamp, with the row's own birth envelope as its receipt
    /// when it names this birth (FIX 10929), else the generic receipt.
    Stamp(Option<&'a MadeBy>),
}

pub(super) fn stamp(doc: &LoroDoc, actor: WriteActor, at: u64, verb: &str) -> Result<()> {
    stamp_with(doc, actor, at, verb, &[])
}

/// [`stamp`], its receipt naming `sources`, the rows its writer read for it.
pub(super) fn stamp_with(
    doc: &LoroDoc,
    actor: WriteActor,
    at: u64,
    verb: &str,
    sources: &[EntityId],
) -> Result<()> {
    let stamped = stamp_head(doc, actor, verb);
    // The commit carries its made_by receipt (FIX 7790).
    let message = super::commit_receipts::receipted(&stamped, actor, at, verb, sources)?;
    commit_at(doc, &message, at)
}

/// The birth commit's stamp. Its receipt is `born`, the row's own birth
/// envelope, when that names this birth's actor at its time with a class the
/// actor may hold, so the reader vouches for it as for any receipt (FIX
/// 10929); otherwise the generic receipt.
fn stamp_birth(doc: &LoroDoc, actor: WriteActor, at: u64, born: Option<&MadeBy>) -> Result<()> {
    let names_this_birth = |made_by: &&MadeBy| {
        made_by.process.actor == actor.entity_ref()
            && made_by.at == at
            && made_by.process.is_valid()
            && (made_by.process.class != MadeByClass::Stated
                || actor.actor_class() == crate::EdgeActorClass::Human)
    };
    let Some(made_by) = born.filter(names_this_birth) else {
        return stamp(doc, actor, at, "birth");
    };
    let stamped = stamp_head(doc, actor, "birth");
    let message = super::commit_receipts::receipted_as(&stamped, made_by)?;
    commit_at(doc, &message, at)
}

/// The engine stamp before its receipt. Sequence-bearing messages prevent
/// Loro from folding two calls by the same actor into one change. Peer
/// bindings remain the authority for remote stamps.
fn stamp_head(doc: &LoroDoc, actor: WriteActor, verb: &str) -> String {
    format!(
        "{STAMP} {verb} actor={}.{} op={:?}",
        actor.entity_ref().to_hex(),
        crate::edit_distance::actor_class_token(actor.actor_class()),
        doc.oplog_vv()
    )
}

fn commit_at(doc: &LoroDoc, message: &str, at: u64) -> Result<()> {
    let at = i64::try_from(at).map_err(|_| invalid("document timestamp overflow"))?;
    doc.commit_with(CommitOptions::new().commit_msg(message).timestamp(at));
    Ok(())
}

/// Commits what canonical recovery replayed into `doc`: the commit restates
/// the row's birth and names no one (FIX 10929).
pub(super) fn restate_birth(doc: &LoroDoc) {
    doc.commit_with(CommitOptions::new().commit_msg(super::commit_receipts::ROW_BIRTH_RESTATED));
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
                let actor = match parse_stamp(meta.message.as_deref()) {
                    Stamped::Live(actor) => {
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
                    }
                    // An erased stamp names no one, and no binding of its
                    // peer speaks for it.
                    Stamped::Erased => None,
                    Stamped::NotStamped => {
                        crate::edit_distance::peer_actor_at(self, meta.id.peer, at)?
                    }
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

/// What one commit message says of its actor (FIX 6072, Engine R2).
pub(super) enum Stamped {
    /// A live actor's engine stamp.
    Live(WriteActor),
    /// An engine stamp whose actor was erased: no one.
    Erased,
    /// No engine stamp: the peer binding may name the actor.
    NotStamped,
}

/// The one stamp grammar the reader and the checkpoint split share: what
/// one reads as a stamp is what the other cuts.
pub(super) fn parse_stamp(message: Option<&str>) -> Stamped {
    let Some((_, id, tail)) = message.and_then(cut_stamp) else {
        return Stamped::NotStamped;
    };
    if id == ERASED_CALL_IDENTITY {
        return Stamped::Erased;
    }
    match (EntityId::from_hex(id), stamp_class(tail)) {
        (Ok(id), Some(class)) => Stamped::Live(WriteActor::new(id, class)),
        _ => Stamped::NotStamped,
    }
}

/// The actor class a stamp names after its id: `.<class>`, to the next
/// space.
fn stamp_class(tail: &str) -> Option<crate::EdgeActorClass> {
    let class = tail.strip_prefix('.')?.split(' ').next()?;
    crate::edit_distance::actor_class_from_token(class)
}

/// `message` cut around its actor id, when it is an engine stamp spelled
/// as [`stamp`] writes it (`oneiron.entity_doc.v1 <verb> actor=<id>.<class>
/// op=...`, single spaced, then its receipt): the message before the id, the
/// id (an actor's, or [`ERASED_CALL_IDENTITY`]), and the rest from the class
/// on.
pub(super) fn cut_stamp(message: &str) -> Option<(&str, &str, &str)> {
    let rest = message.strip_prefix(STAMP)?.strip_prefix(' ')?;
    let (verb, rest) = rest.split_once(' ')?;
    if verb.is_empty() {
        return None;
    }
    let id_on = rest.strip_prefix("actor=")?;
    let (id, _) = id_on.split_once('.')?;
    let head = message.get(..message.len() - id_on.len())?;
    let tail = id_on.get(id.len()..)?;
    Some((head, id, tail))
}
