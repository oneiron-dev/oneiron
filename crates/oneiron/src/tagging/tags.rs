//! The saved tag sets: what save mode keeps for a tagged turn, the index of
//! the entities they name, and the doors that read and replace them.
//!
//! A tag set is derived and local (ARCH-0001): it lives in `vault_meta`,
//! which sync never reads, and tagging the turn again rebuilds it. Every
//! write of a tag set goes through [`replace_in_txn`], which keeps the
//! mention index in step and settles each provisional entity the change
//! touches.
//!
//! A tag set reads only while the text it was read from does: once its turn
//! or one of its messages reads deleted (a deletion published ahead of its
//! purge, an archive), no read door returns it, its mood or a provisional
//! name it holds.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::input::{TurnInput, turn_text_in_txn};
use super::provisional;
use crate::affect::Vad;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, TombstoneStoreRead};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// A turn's tag set. Key: the turn id.
const TAG_SET: SideTable<EntityId, TurnTags, Named> = SideTable::new(&side_table::TAGGING_TAG_SET);
/// The turns whose tag sets name an entity. Key: the entity id, then the
/// turn id.
const MENTION_REF: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::TAGGING_MENTION_REF);

/// The memo-key of one tag set (ARCH-0035). Two tag sets under one envelope
/// are interchangeable, so a save under the envelope the turn already holds
/// writes nothing, and a new tagger re-tags by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationEnvelope {
    /// Digest of the input the tags were read from.
    pub content_hash: String,
    /// What made them: `model@checkpoint` for the slot's tagger,
    /// `held@checkpoint` for tags an importer held.
    pub model_id: String,
    /// The save path's version.
    pub version: String,
    /// Digest of the decode parameters: the label table and the live window.
    pub params_hash: String,
}

/// Where an unconfirmed mention points. None of these is an edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MentionLink {
    /// The label maps to no entity kind: the span stays a tag.
    Tag,
    /// The identity key named these entities, real or provisional. A hit,
    /// even a single one, is a soft link: the linker decides whether the
    /// mention is any of them (ARCH-0055 §10).
    Candidates { kind: u8, entities: Vec<EntityId> },
    /// The key named nothing, so the save minted this provisional entity.
    Minted { kind: u8, entity: EntityId },
}

impl MentionLink {
    /// The entity kind the span was linked as; `None` for a tag.
    #[must_use]
    pub fn kind(&self) -> Option<u8> {
        match self {
            Self::Tag => None,
            Self::Candidates { kind, .. } | Self::Minted { kind, .. } => Some(*kind),
        }
    }

    /// Every entity the link names.
    #[must_use]
    pub fn entities(&self) -> &[EntityId] {
        match self {
            Self::Tag => &[],
            Self::Candidates { entities, .. } => entities,
            Self::Minted { entity, .. } => std::slice::from_ref(entity),
        }
    }

    /// The link with `entity` gone; a link left naming nothing is a tag.
    fn without(&self, entity: &EntityId) -> Self {
        match self {
            Self::Minted { entity: minted, .. } if minted == entity => Self::Tag,
            Self::Candidates { kind, entities } if entities.contains(entity) => {
                let entities: Vec<_> = entities.iter().filter(|e| *e != entity).copied().collect();
                if entities.is_empty() {
                    Self::Tag
                } else {
                    Self::Candidates {
                        kind: *kind,
                        entities,
                    }
                }
            }
            other => other.clone(),
        }
    }

    /// The link with `from` named as `to`.
    fn redirected(&self, from: &EntityId, to: EntityId) -> Self {
        match self {
            Self::Minted { kind, entity } if entity == from => Self::Minted {
                kind: *kind,
                entity: to,
            },
            Self::Candidates { kind, entities } if entities.contains(from) => {
                let entities: BTreeSet<_> = entities
                    .iter()
                    .map(|e| if e == from { to } else { *e })
                    .collect();
                Self::Candidates {
                    kind: *kind,
                    entities: entities.into_iter().collect(),
                }
            }
            other => other.clone(),
        }
    }
}

/// One span as a derived suggestion: never a `mentions` edge, never synced.
/// The Dreamer or an actor confirms it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaggedMention {
    /// The MESSAGE the span is in.
    pub message: EntityId,
    /// Byte offsets into the message's text.
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub confidence: f32,
    pub link: MentionLink,
    /// The span this one corefers with, when the tagger linked them. A
    /// coreferent span takes its antecedent's link unless its own name keys
    /// to an entity.
    pub antecedent: Option<usize>,
}

/// A coreference link that joins two spans linked to different entities:
/// evidence that they may be one, for the Dreamer. The save never merges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeEvidence {
    pub span: usize,
    pub antecedent: usize,
    pub confidence: f32,
}

/// One turn's saved tags under one derivation envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnTags {
    pub turn: EntityId,
    pub envelope: DerivationEnvelope,
    /// The MESSAGE rows the tags were read from, in the input's order.
    pub messages: Vec<EntityId>,
    pub mentions: Vec<TaggedMention>,
    pub merge_evidence: Vec<MergeEvidence>,
    /// The turn's mood, when the tagger returned one.
    pub mood: Option<Vad>,
    /// Store-clock seconds of the save.
    pub saved_at: u64,
}

impl TurnTags {
    /// Every entity the tag set names, once.
    #[must_use]
    pub fn entities(&self) -> BTreeSet<EntityId> {
        self.mentions
            .iter()
            .flat_map(|mention| mention.link.entities().iter().copied())
            .collect()
    }
}

/// One saved mention, found by the entity it names.
#[derive(Debug, Clone, PartialEq)]
pub struct MentionHit {
    pub turn: EntityId,
    /// The mention's place in its tag set.
    pub index: usize,
    pub mention: TaggedMention,
}

impl Vault {
    /// The tags saved for a turn, while the text they were read from reads.
    pub fn turn_tags(&self, turn: &EntityId) -> Result<Option<TurnTags>> {
        let txn = self.store.env.read_txn()?;
        readable_in_txn(&self.store, &txn, turn)
    }

    /// Every saved mention that names `entity`, or an entity merged into
    /// it, by turn and then by place in the turn's tag set.
    pub fn tagged_mentions(&self, entity: &EntityId) -> Result<Vec<MentionHit>> {
        let txn = self.store.env.read_txn()?;
        let mut named = crate::identity_redirect::inbound_redirect_shells_in_txn(
            &self.store,
            &txn,
            &BTreeSet::from([*entity]),
        )?;
        named.insert(*entity);
        let mut turns = BTreeSet::new();
        for id in &named {
            turns.extend(refs_in_txn(&self.store, &txn, id)?);
        }
        let mut hits = Vec::new();
        for turn in turns {
            let Some(tags) = readable_in_txn(&self.store, &txn, &turn)? else {
                continue;
            };
            for (index, mention) in tags.mentions.into_iter().enumerate() {
                if mention.link.entities().iter().any(|id| named.contains(id)) {
                    hits.push(MentionHit {
                        turn,
                        index,
                        mention,
                    });
                }
            }
        }
        Ok(hits)
    }

    /// Every saved mention of a name: the identity key's candidates for it,
    /// real or provisional, and the mentions that name each.
    pub fn tagged_mentions_of_name(&self, kind: u8, name: &str) -> Result<Vec<MentionHit>> {
        if !super::label_kind_admitted(kind) {
            return Ok(Vec::new());
        }
        let mut entities = BTreeSet::new();
        {
            let txn = self.store.env.read_txn()?;
            for found in self.lookup_identity_key_in_txn(&txn, kind, name)? {
                entities.extend(self.resolve_entity_in_txn(&txn, &found)?);
            }
            entities.extend(provisional::lookup_in_txn(&self.store, &txn, kind, name)?);
        }
        let mut hits = Vec::new();
        for entity in entities {
            hits.extend(self.tagged_mentions(&entity)?);
        }
        hits.sort_by_key(|hit| (hit.turn, hit.index));
        hits.dedup_by(|a, b| (a.turn, a.index) == (b.turn, b.index));
        Ok(hits)
    }
}

pub(super) fn tag_set_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnTags>> {
    TAG_SET.get(store, txn, turn)
}

/// The tag set of `turn` while the text it was read from reads: the turn and
/// every message it was read from are stored and none reads deleted.
fn readable_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnTags>> {
    let Some(tags) = TAG_SET.get(store, txn, turn)? else {
        return Ok(None);
    };
    for source in std::iter::once(&tags.turn).chain(&tags.messages) {
        if store.entities.get(txn, source.as_bytes())?.is_none()
            || store.port_deletion_state(txn, source)?.deleted
        {
            return Ok(None);
        }
    }
    Ok(Some(tags))
}

/// Whether the provisional entity `entity` reads: its origin turn's tag set
/// reads and names it.
pub(super) fn origin_reads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    origin: &EntityId,
    entity: &EntityId,
) -> Result<bool> {
    Ok(names_in_txn(store, txn, entity, origin)? && readable_in_txn(store, txn, origin)?.is_some())
}

/// The mood saved on a turn and when it was saved: what the turn-VAD read
/// door reads when no annotation was written on the turn.
pub(crate) fn saved_turn_mood_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<(Vad, u64)>> {
    Ok(readable_in_txn(store, txn, turn)?
        .and_then(|tags| tags.mood.map(|mood| (mood, tags.saved_at))))
}

/// Whether the tag set of `turn` names `entity`: one index read.
pub(super) fn names_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    turn: &EntityId,
) -> Result<bool> {
    MENTION_REF.contains(store, txn, &(*entity, *turn))
}

/// The first turn, in id order, after `after` whose tag set names `entity`:
/// one bounded read, so a name a great many turns hold costs a caller that
/// needs one of them one row.
pub(super) fn next_ref_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    after: Option<&EntityId>,
) -> Result<Option<EntityId>> {
    let next = match after {
        None => MENTION_REF
            .iter_from(store, txn, entity.as_bytes())?
            .next()
            .transpose()?,
        Some(turn) => MENTION_REF
            .iter_range(
                store,
                txn,
                Bound::Excluded(&(*entity, *turn)),
                Bound::Unbounded,
            )?
            .next()
            .transpose()?,
    };
    Ok(next.and_then(|((named, turn), ())| (named == *entity).then_some(turn)))
}

/// The turns whose tag sets name `entity`.
pub(super) fn refs_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<EntityId>> {
    Ok(MENTION_REF
        .scan_keys(store, txn, entity.as_bytes())?
        .into_iter()
        .map(|(_, turn)| turn)
        .collect())
}

/// Puts `tags` as the turn's tag set, or drops it for `None`, in the
/// caller's transaction. The mention index follows, and every provisional
/// entity either set names is settled: one no tag set names any more is
/// retired, and one whose origin turn stopped naming it moves to a turn that
/// still does.
pub(super) fn replace_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    tags: Option<&TurnTags>,
) -> Result<()> {
    let store = &vault.store;
    let before = TAG_SET
        .get(store, txn, turn)?
        .map(|old| old.entities())
        .unwrap_or_default();
    let after = tags.map(TurnTags::entities).unwrap_or_default();
    for gone in before.difference(&after) {
        MENTION_REF.delete(store, txn, &(*gone, *turn))?;
    }
    for added in after.difference(&before) {
        MENTION_REF.put(store, txn, &(*added, *turn), &())?;
    }
    match tags {
        Some(tags) => TAG_SET.put(store, txn, turn, tags)?,
        None => {
            TAG_SET.delete(store, txn, turn)?;
        }
    }
    for entity in before.union(&after) {
        provisional::settle_in_txn(vault, txn, entity)?;
    }
    Ok(())
}

/// Removes `entity` from every tag set that names it: a link left naming
/// nothing is a tag. Its index rows go with it.
pub(super) fn strip_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<bool> {
    let turns = refs_in_txn(store, txn, entity)?;
    for turn in &turns {
        if let Some(mut tags) = TAG_SET.get(store, txn, turn)? {
            for mention in &mut tags.mentions {
                mention.link = mention.link.without(entity);
            }
            TAG_SET.put(store, txn, turn, &tags)?;
        }
        MENTION_REF.delete(store, txn, &(*entity, *turn))?;
    }
    Ok(!turns.is_empty())
}

/// Names `to` wherever a tag set names `from`, moving the index rows.
pub(super) fn redirect_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    from: &EntityId,
    to: EntityId,
) -> Result<()> {
    for turn in refs_in_txn(store, txn, from)? {
        if let Some(mut tags) = TAG_SET.get(store, txn, &turn)? {
            for mention in &mut tags.mentions {
                mention.link = mention.link.redirected(from, to);
            }
            TAG_SET.put(store, txn, &turn, &tags)?;
        }
        MENTION_REF.delete(store, txn, &(*from, turn))?;
        MENTION_REF.put(store, txn, &(to, turn), &())?;
    }
    Ok(())
}

/// The text of a span in `turn` linked to `entity` whose own text keys to
/// `digest`: a name that turn still holds for the entity.
pub(super) fn keyed_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    entity: &EntityId,
    digest: &[u8; 32],
) -> Result<Option<String>> {
    let Some(tags) = TAG_SET.get(&vault.store, txn, turn)? else {
        return Ok(None);
    };
    let TurnInput::Ready { input, .. } = turn_text_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    for mention in &tags.mentions {
        if !mention.link.entities().contains(entity) {
            continue;
        }
        let message = mention.message.to_hex();
        let Some(text) = input
            .messages
            .iter()
            .find(|each| each.id == message)
            .and_then(|each| each.text.get(mention.start..mention.end))
            .map(str::trim)
        else {
            continue;
        };
        if !text.is_empty() && crate::ingest::identity_hint_digest(text) == *digest {
            return Ok(Some(text.to_owned()));
        }
    }
    Ok(None)
}

/// The erase hook, in the erasing transaction, before the graph is torn
/// down. A TURN loses its tag set; a MESSAGE's turns lose theirs, and each
/// is owed a new pass over the text it keeps. An entity a tag set names is
/// taken out of it, and a provisional entity is retired. Returns whether
/// anything was there.
pub(crate) fn erase_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let store = &vault.store;
    let mut existed = false;
    if TAG_SET.contains(store, txn, id)? {
        replace_in_txn(vault, txn, id, None)?;
        existed = true;
    }
    for turn in tagged_parts_of_in_txn(store, txn, id)? {
        replace_in_txn(vault, txn, &turn, None)?;
        super::mark_turn_in_txn(vault, txn, turn)?;
        existed = true;
    }
    existed |= strip_in_txn(store, txn, id)?;
    existed |= provisional::retire_in_txn(store, txn, id)?;
    Ok(existed)
}

/// The physical tear's hook, which every door that tears an entity down
/// reaches, a batch delete among them, with no vault in hand: `id` leaves
/// every tag set that names it and is retired if provisional. A tag set of
/// `id`, or of a turn `id` is part of, is the erase doors' to settle (they
/// run [`erase_in_txn`] first); one still here is dropped without reading
/// any text, so each provisional entity it was the origin of is retired
/// rather than moved.
pub(crate) fn tear_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let mut turns = tagged_parts_of_in_txn(store, txn, id)?;
    if TAG_SET.contains(store, txn, id)? {
        turns.push(*id);
    }
    for turn in turns {
        let Some(old) = TAG_SET.get(store, txn, &turn)? else {
            continue;
        };
        TAG_SET.delete(store, txn, &turn)?;
        for entity in old.entities() {
            MENTION_REF.delete(store, txn, &(entity, turn))?;
            if provisional::get_in_txn(store, txn, &entity)?
                .is_some_and(|minted| minted.origin == turn)
            {
                strip_in_txn(store, txn, &entity)?;
                provisional::retire_in_txn(store, txn, &entity)?;
            }
        }
    }
    strip_in_txn(store, txn, id)?;
    provisional::retire_in_txn(store, txn, id)?;
    Ok(())
}

/// The turns `id` is part of that hold a tag set. Every `PartOf` edge out of
/// `id` is read, however many there are: an erase never refuses for a
/// degree a query would cap.
fn tagged_parts_of_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut turns = Vec::new();
    for edge in store.port_edges(txn, id, EdgeDirection::Out, Some(EdgeKind::PartOf), None)? {
        let target = edge?.target;
        if TAG_SET.contains(store, txn, &target)? {
            turns.push(target);
        }
    }
    Ok(turns)
}

/// Whether erasing `id` has tagging rows to remove.
pub(crate) fn erase_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(TAG_SET.contains(store, txn, id)?
        || next_ref_in_txn(store, txn, id, None)?.is_some()
        || provisional::exists_in_txn(store, txn, id)?)
}
