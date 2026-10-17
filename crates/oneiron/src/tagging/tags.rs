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

use super::input::{TurnInput, turn_input_in_txn, turn_text_in_txn};
use super::provisional;
use crate::affect::Vad;
use crate::edge::EdgeKind;
use crate::error::Result;
use crate::memory::extraction::SpeakerTarget;
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
    /// The served stack the answer names beside the checkpoint, when it
    /// names one: a head swap at a fixed checkpoint is another derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
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
    /// The identity key named these entities, real or provisional, or the
    /// span took them from what it corefers with: an antecedent, an earlier
    /// turn's saved span, or the turn's speaker or addressee. A hit, even a
    /// single one, is a soft link: the linker decides whether the mention is
    /// any of them (ARCH-0055 §10).
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
    /// Where the tagger put this span's referent outside this turn's spans,
    /// when it did and the save kept the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<MentionReference>,
    /// The tagger's confidence in the span's link, context link or speaker
    /// link, when it gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_confidence: Option<f32>,
}

/// A coreference decision that reaches outside the turn's own spans. A span
/// takes the link it resolves to as it takes an antecedent's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MentionReference {
    /// The span corefers with a span of an earlier turn in its window, and
    /// the save found that span saved: the span took its link.
    Context,
    /// The span is its turn's speaker or addressee. `resolved` says whether
    /// the save named one person for it: the turn's author for the speaker,
    /// the one other party of a 1:1 room for the addressee. An unresolved
    /// decision names no one.
    Speaker {
        target: SpeakerTarget,
        resolved: bool,
    },
}

/// A coreference link that joins two spans linked to different entities:
/// evidence that they may be one, for the Dreamer. The save never merges.
/// It is kept only while the two spans name different entities.
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
    /// How surprising this set is beside the one it replaced, by the model
    /// families' deterministic gate ([`crate::llm::tagger::delta_surprise`]):
    /// 1 when the named entities or the coreference moved, else the largest
    /// mood shift. `None` for a turn's first tag set. The tagger only
    /// measures it; whether a generative render follows is the reader's
    /// (ARCH-0036: the reasoner runs only on a surprising delta).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surprise: Option<f32>,
}

impl TurnTags {
    /// The gate's surprise of this set beside `before`, the set it replaces.
    #[must_use]
    pub fn surprise_since(&self, before: &Self) -> f32 {
        let identity_changed =
            self.entities() != before.entities() || self.coreference() != before.coreference();
        let affect = |tags: &Self| {
            tags.mood.map_or([0.0; 3], |mood| {
                [mood.valence, mood.arousal, mood.dominance]
            })
        };
        crate::llm::tagger::delta_surprise(identity_changed, affect(before), affect(self))
    }

    /// The coreference as entities rather than span indices: each in-turn
    /// link as the entities its span names beside those its antecedent
    /// names. An edit that moves offsets leaves it as it was.
    fn coreference(&self) -> BTreeSet<(Vec<EntityId>, Vec<EntityId>)> {
        self.mentions
            .iter()
            .filter_map(|mention| {
                let antecedent = self.mentions.get(mention.antecedent?)?;
                Some((
                    mention.link.entities().to_vec(),
                    antecedent.link.entities().to_vec(),
                ))
            })
            .collect()
    }

    /// Every entity the tag set names, once.
    #[must_use]
    pub fn entities(&self) -> BTreeSet<EntityId> {
        self.mentions
            .iter()
            .flat_map(|mention| mention.link.entities().iter().copied())
            .collect()
    }

    /// Keeps the merge evidence whose two spans still name different
    /// entities, as the save found them: each names one or more, and they
    /// share none. A link changed after the save leaves no suggestion to
    /// merge one entity with itself, or with nothing.
    fn keep_live_evidence(&mut self) {
        let mentions = &self.mentions;
        self.merge_evidence.retain(|evidence| {
            let (Some(span), Some(antecedent)) = (
                mentions.get(evidence.span),
                mentions.get(evidence.antecedent),
            ) else {
                return false;
            };
            let (own, other) = (span.link.entities(), antecedent.link.entities());
            !own.is_empty() && !other.is_empty() && own.iter().all(|id| !other.contains(id))
        });
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

/// The tag set saved for `turn` as it is stored: whether it still indexes
/// the turn's words is the caller's to know.
pub(crate) fn tag_set_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnTags>> {
    TAG_SET.get(store, txn, turn)
}

/// The tag set of `turn` while the text it was read from reads: the turn and
/// every message it was read from are stored and none reads deleted.
pub(super) fn readable_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<Option<TurnTags>> {
    let Some(tags) = TAG_SET.get(store, txn, turn)? else {
        return Ok(None);
    };
    for source in std::iter::once(&tags.turn).chain(&tags.messages) {
        if crate::ports::EntityStoreRead::port_entity_raw(store, txn, source)?.is_none()
            || store.port_deletion_state(txn, source)?.deleted
        {
            return Ok(None);
        }
    }
    Ok(Some(tags))
}

/// The tags saved for `turn` while they index its words as they read now,
/// and the bytes of text hashed to tell: the envelope names the input a
/// tagger would read from the turn today, with or without its live window.
/// The sieve takes its name spans through this door; the tag set stays the
/// one copy.
pub(crate) fn current_tags_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
) -> Result<(Option<TurnTags>, usize)> {
    let Some(tags) = readable_in_txn(&vault.store, txn, turn)? else {
        return Ok((None, 0));
    };
    let TurnInput::Ready {
        input,
        hash,
        text_hash,
    } = turn_input_in_txn(vault, txn, turn)?
    else {
        return Ok((None, 0));
    };
    let text: usize = input
        .messages
        .iter()
        .map(|message| message.text.len())
        .sum();
    let window: usize = input
        .context
        .iter()
        .flat_map(|turn| &turn.messages)
        .map(|message| message.text.len())
        .sum();
    // The text is hashed alone, and once more with a live window.
    let hashed = if input.context.is_empty() {
        text
    } else {
        2 * text + window
    };
    let read = &tags.envelope.content_hash;
    Ok((
        (*read == hash || *read == text_hash).then_some(tags),
        hashed,
    ))
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
    // The sieve reads a turn's names from its tag set: a new set is a new read.
    crate::dreamer_wake::owe_sieve_read_in_txn(&vault.store, txn, turn)
}

/// Removes `entity` from every tag set that names it: a link left naming
/// nothing is a tag, and merge evidence it leaves naming nothing goes. Its
/// index rows go with it.
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
            tags.keep_live_evidence();
            TAG_SET.put(store, txn, turn, &tags)?;
        }
        MENTION_REF.delete(store, txn, &(*entity, *turn))?;
    }
    Ok(!turns.is_empty())
}

/// Names `to` wherever a tag set names `from`, moving the index rows. Merge
/// evidence whose spans now both name `to` goes.
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
            tags.keep_live_evidence();
            TAG_SET.put(store, txn, &turn, &tags)?;
        }
        MENTION_REF.delete(store, txn, &(*from, turn))?;
        MENTION_REF.put(store, txn, &(to, turn), &())?;
    }
    Ok(())
}

/// Up to `limit` readable tag sets in turn order after `after`, and the
/// last turn the walk passed, readable or not: the identity re-check's
/// page (OF-123). `None` for the last turn when the walk read nothing.
pub(crate) fn readable_page_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    after: Option<&EntityId>,
    limit: usize,
) -> Result<(Vec<TurnTags>, Option<EntityId>)> {
    let start = after.map_or(Bound::Unbounded, Bound::Excluded);
    let mut found = Vec::new();
    let mut last = None;
    for row in TAG_SET.iter_range(store, txn, start, Bound::Unbounded)? {
        if found.len() == limit {
            break;
        }
        let (turn, _) = row?;
        last = Some(turn);
        if let Some(tags) = readable_in_txn(store, txn, &turn)? {
            found.push(tags);
        }
    }
    Ok((found, last))
}

/// Settles the saved span of `turn` at `message`, `start`..`end` as
/// `entity` alone: the identity re-check's answer (OF-123). The link stays
/// a suggestion, now of one entity; the index and every provisional entity
/// the change touches follow as on any replace. `false` when the turn's
/// tags no longer read or hold no linked span there.
pub(crate) fn settle_mention_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    span: (&EntityId, usize, usize),
    entity: EntityId,
) -> Result<bool> {
    let Some(mut tags) = readable_in_txn(&vault.store, txn, turn)? else {
        return Ok(false);
    };
    let (message, start, end) = span;
    let Some(mention) = tags
        .mentions
        .iter_mut()
        .find(|each| each.message == *message && each.start == start && each.end == end)
    else {
        return Ok(false);
    };
    let Some(kind) = mention.link.kind() else {
        return Ok(false);
    };
    mention.link = MentionLink::Candidates {
        kind,
        entities: vec![entity],
    };
    tags.keep_live_evidence();
    replace_in_txn(vault, txn, turn, Some(&tags))?;
    Ok(true)
}

/// The text of `message` in `turn` as the tagger reads it: what a saved
/// span's offsets index (OF-123).
pub(crate) fn message_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &EntityId,
    message: &EntityId,
) -> Result<Option<String>> {
    let TurnInput::Ready { input, .. } = turn_text_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    let message = message.to_hex();
    Ok(input
        .messages
        .into_iter()
        .find(|each| each.id == message)
        .map(|each| each.text))
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
