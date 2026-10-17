//! Save mode: a checked answer becomes the turn's tag set (ARCH-0036,
//! serving the tagger).
//!
//! Each span whose label the label table maps to an entity kind is a name,
//! linked through the identity key (ARCH-0055 §10). The key is looked up
//! before anything is minted, over the vault's entities, archived ones
//! included, and the provisional ones; every hit is a candidate the linker
//! (the Dreamer) decides on, never a sure link; and a miss mints a
//! provisional entity under the source turn's facet. A span whose label the
//! table leaves out is never looked up: a pronoun, which a tagger labels as a
//! reference and not as a name, takes its antecedent's link, so a pronoun
//! that happens to spell someone's name is never linked to them. A
//! coreferent name the key misses takes its antecedent's link and never
//! mints; one whose own name keys elsewhere keeps its own and is merge
//! evidence. The mood lands on the turn. The save writes no claim, no edge
//! and no merge.
//!
//! A span's antecedent may sit outside the turn's spans. A context link
//! names a span of an earlier turn the window sent: the span takes the link
//! the engine saved for that turn at those coordinates, under the same
//! tagger, and nothing when no such save is there, which the trace counts;
//! no span is ever guessed from a surface. A speaker link names the turn's
//! author, or for the addressee the one other party of a 1:1 room, and
//! otherwise stays an unresolved decision. Either keeps only entities a
//! world of the turn holds.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use super::input::{TurnInput, input_hash, sent_text_offset_in_txn, sole_peer, turn_text_in_txn};
use super::marker::{TAGGING_MARKER_KIND, TaggingMarkerConfig, dedupe_key, label_kind_admitted};
use super::output::{check_output, context_text};
use super::provisional::{self, ProvisionalEntity};
use super::tags::{
    DerivationEnvelope, MentionLink, MentionReference, MergeEvidence, TaggedMention, TurnTags,
    readable_in_txn, replace_in_txn, tag_set_in_txn,
};
use crate::attempt_queue::AttemptQueue;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::federation::record_scope::{birth_facet, scope_for_blob};
use crate::federation::{ScopeAxis, ScopeId};
use crate::memory::extraction::{
    ContextLink, EncoderInput, EncoderOutput, SpeakerLink, SpeakerTarget,
};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::{EntityId, Vault};

/// The save path's version, the envelope's `version`.
const SAVE_VERSION: &str = "oneiron.tagging.save.v2";

/// What one save did.
pub(super) struct Saved {
    /// Spans linked to at least one entity.
    pub(super) linked: usize,
    /// Provisional entities it minted.
    pub(super) minted: usize,
    /// The saved set's surprise beside the set it replaced; `None` for a
    /// turn's first.
    pub(super) surprise: Option<f32>,
    /// Context links that found no saved span and kept no antecedent.
    pub(super) unresolved_context_links: usize,
    /// Speaker links that named no one person.
    pub(super) unresolved_speaker_links: usize,
}

/// The envelope of a tag set read from `content_hash` by `made_by`, of the
/// served `stack` when the answer names one, under `config`'s label table
/// and window.
pub(super) fn envelope(
    content_hash: &str,
    made_by: &str,
    config: &TaggingMarkerConfig,
    stack: Option<&str>,
) -> DerivationEnvelope {
    let mut hash = Sha256::new();
    hash.update(b"oneiron.tagging.params.v1\0");
    let mut field = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    };
    field(&config.live_window_tokens.to_le_bytes());
    for (label, kind) in &config.labels {
        field(label.as_bytes());
        field(&[*kind]);
    }
    DerivationEnvelope {
        content_hash: content_hash.to_owned(),
        model_id: format!("{made_by}@{}", config.checkpoint),
        stack: stack.map(str::to_owned),
        version: SAVE_VERSION.to_owned(),
        params_hash: format!("{:x}", hash.finalize()),
    }
}

/// A checked answer for one turn: the tags a save keeps.
pub(super) struct Answer<'a> {
    pub(super) turn: EntityId,
    /// The input whose messages the spans index.
    pub(super) input: &'a EncoderInput,
    /// The answer, checked against `input`.
    pub(super) output: &'a EncoderOutput,
    pub(super) envelope: DerivationEnvelope,
}

/// Saves an answer as its turn's tag set in the caller's transaction,
/// replacing the one the turn held. A turn that already holds a tag set
/// under the answer's envelope is left as it is.
pub(super) fn save_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    answer: Answer<'_>,
    config: &TaggingMarkerConfig,
    now: u64,
) -> Result<Saved> {
    let Answer {
        turn,
        input,
        output,
        envelope,
    } = answer;
    let messages = input
        .messages
        .iter()
        .map(|message| EntityId::from_hex(&message.id))
        .collect::<Result<Vec<_>>>()?;
    let held = tag_set_in_txn(&vault.store, txn, &turn)?;
    if let Some(held) = held.as_ref()
        && held.envelope == envelope
    {
        let kept = |wanted: fn(&MentionReference) -> bool| {
            held.mentions
                .iter()
                .filter(|mention| mention.reference.as_ref().is_some_and(wanted))
                .count()
        };
        return Ok(Saved {
            linked: held
                .mentions
                .iter()
                .filter(|mention| mention.link != MentionLink::Tag)
                .count(),
            minted: 0,
            surprise: held.surprise,
            unresolved_context_links: output
                .context_links
                .len()
                .saturating_sub(kept(|reference| *reference == MentionReference::Context)),
            unresolved_speaker_links: kept(|reference| {
                matches!(
                    reference,
                    MentionReference::Speaker {
                        resolved: false,
                        ..
                    }
                )
            }),
        });
    }
    let mut linker = Linker::new(vault, txn, turn, now)?;
    let mut coref = vec![Coref::None; output.spans.len()];
    for link in &output.links {
        coref[link.span] = Coref::InTurn {
            antecedent: link.antecedent,
            confidence: link.confidence,
        };
    }
    let mut unresolved_context_links = 0;
    for link in &output.context_links {
        match linker.context_link(txn, input, link, &envelope, config)? {
            Some(found) => {
                coref[link.span] = Coref::Context {
                    link: found,
                    confidence: link.confidence,
                }
            }
            None => unresolved_context_links += 1,
        }
    }
    let mut unresolved_speaker_links = 0;
    for link in &output.speaker_links {
        let found = linker.speaker_link(txn, &messages, link)?;
        unresolved_speaker_links += usize::from(found.is_none());
        coref[link.span] = Coref::Speaker {
            target: link.target,
            link: found,
            confidence: link.confidence,
        };
    }
    let mut mentions: Vec<TaggedMention> = Vec::with_capacity(output.spans.len());
    let mut merge_evidence = Vec::new();
    for (index, span) in output.spans.iter().enumerate() {
        let message_text = &input.messages[span.message].text;
        let text = message_text[span.start..span.end].trim();
        let own = config
            .labels
            .get(&span.label)
            .copied()
            .filter(|_| !text.is_empty());
        let (antecedent, reference, link_confidence) = coref[index].decision();
        let inherited = match &coref[index] {
            Coref::None => None,
            Coref::InTurn { antecedent, .. } => Some(&mentions[*antecedent].link),
            Coref::Context { link, .. } => Some(link),
            Coref::Speaker { link, .. } => link.as_ref(),
        }
        .filter(|link| **link != MentionLink::Tag);
        let link = match (inherited, own) {
            (None, None) => MentionLink::Tag,
            (None, Some(kind)) => {
                let link = linker.link(txn, kind, text)?;
                linker.hinted(txn, link, text, message_text, span.start, span.end)?
            }
            // A pronoun, or a label the table does not map, takes its
            // antecedent's link.
            (Some(inherited), None) => inherited.clone(),
            (Some(inherited), Some(kind)) => {
                let hits = linker.candidates(txn, kind, text)?;
                if hits.is_empty() {
                    // A name the key misses takes its antecedent's link and
                    // never mints a twin of it.
                    if inherited.kind() == Some(kind) {
                        inherited.clone()
                    } else {
                        linker.link(txn, kind, text)?
                    }
                } else {
                    // A name that keys elsewhere than its antecedent keeps
                    // its own candidates: the pair is evidence the Dreamer
                    // weighs, never a merge. Only a pair inside the turn is
                    // kept as such, since evidence names two of its spans.
                    if inherited.kind() == Some(kind)
                        && hits.iter().all(|hit| !inherited.entities().contains(hit))
                        && let Some(at) = antecedent
                    {
                        merge_evidence.push(MergeEvidence {
                            span: index,
                            antecedent: at,
                            confidence: link_confidence.unwrap_or(span.confidence),
                        });
                    }
                    let link = MentionLink::Candidates {
                        kind,
                        entities: hits,
                    };
                    linker.hinted(txn, link, text, message_text, span.start, span.end)?
                }
            }
        };
        mentions.push(TaggedMention {
            message: messages[span.message],
            start: span.start,
            end: span.end,
            label: span.label.clone(),
            confidence: span.confidence,
            link,
            antecedent,
            reference,
            link_confidence,
        });
    }
    let mut tags = TurnTags {
        turn,
        envelope,
        messages,
        mentions,
        merge_evidence,
        mood: output.vad,
        saved_at: now,
        surprise: None,
    };
    // The gate between the families runs here, on the set this save
    // replaces, so the reader of the tags finds the delta's surprise with
    // them and no model is called to measure it.
    tags.surprise = held.as_ref().map(|held| tags.surprise_since(held));
    let saved = Saved {
        linked: tags
            .mentions
            .iter()
            .filter(|mention| mention.link != MentionLink::Tag)
            .count(),
        minted: linker.minted,
        surprise: tags.surprise,
        unresolved_context_links,
        unresolved_speaker_links,
    };
    replace_in_txn(vault, txn, &turn, Some(&tags))?;
    Ok(saved)
}

/// What a span corefers with, as the save resolved it.
#[derive(Clone)]
enum Coref {
    None,
    /// An earlier span of this turn.
    InTurn {
        antecedent: usize,
        confidence: Option<f32>,
    },
    /// A span an earlier turn's tag set holds, and the link it holds.
    Context {
        link: MentionLink,
        confidence: f32,
    },
    /// The turn's speaker or addressee, and the person it named, if one.
    Speaker {
        target: SpeakerTarget,
        link: Option<MentionLink>,
        confidence: f32,
    },
}

impl Coref {
    /// What the saved mention keeps of it: its antecedent in the turn, its
    /// reference outside it, and the decision's confidence.
    fn decision(&self) -> (Option<usize>, Option<MentionReference>, Option<f32>) {
        match self {
            Self::None => (None, None, None),
            Self::InTurn {
                antecedent,
                confidence,
            } => (Some(*antecedent), None, *confidence),
            Self::Context { confidence, .. } => {
                (None, Some(MentionReference::Context), Some(*confidence))
            }
            Self::Speaker {
                target,
                link,
                confidence,
            } => (
                None,
                Some(MentionReference::Speaker {
                    target: *target,
                    resolved: link.is_some(),
                }),
                Some(*confidence),
            ),
        }
    }
}

/// Saves a host's shadow output for `turn`, made by `model`, in the caller's
/// transaction, under the vault's tagging configuration, when the turn's
/// text still reads as `input`'s messages. `None` when it does not: the
/// source changed after inference, and nothing is written.
pub(crate) fn save_shadow_output_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: EntityId,
    input: &EncoderInput,
    output: &EncoderOutput,
    model: &str,
    now: u64,
) -> Result<Option<TurnTags>> {
    let config = vault.config.tagging.as_ref().ok_or_else(|| {
        Error::InvalidConfig("tagging markers are not armed on this vault".to_owned())
    })?;
    let TurnInput::Ready { input: current, .. } = turn_text_in_txn(vault, txn, &turn)? else {
        return Ok(None);
    };
    // The same messages with the same text, in whatever order the host sent
    // them: the spans index `input` as the model read it.
    let read = |messages: &[crate::memory::extraction::EncoderMessage]| {
        messages
            .iter()
            .map(|message| (message.id.clone(), message.text.clone()))
            .collect::<BTreeSet<_>>()
    };
    let unchanged = current.messages.len() == input.messages.len()
        && read(&current.messages) == read(&input.messages);
    if !unchanged || check_output(input, output, config.stack.as_deref()).is_err() {
        return Ok(None);
    }
    let answer = Answer {
        turn,
        input,
        output,
        envelope: envelope(
            &input_hash(input),
            model,
            config,
            output.stack_sha16.as_deref(),
        ),
    };
    save_in_txn(vault, txn, answer, config, now)?;
    tag_set_in_txn(&vault.store, txn, &turn)
}

/// Whether `id` is an entity of `kind` a mention may be linked to: stored,
/// current, and live or archived. An archive keeps the row whole and
/// resolution sees it; a deletion, published or pending, does not.
pub(super) fn linkable_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> Result<bool> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(false);
    };
    Ok(row.entity_type == kind
        && !store.port_deletion_state(txn, id)?.stale
        && !crate::ports::removed_in_txn(store, txn, id)?)
}

/// Whether the record `id` can sit in a world the turn `turn` is in: the
/// Linker's own world filter, for a re-check that runs outside a save.
pub(crate) fn shares_world_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    id: &EntityId,
) -> Result<bool> {
    Linker::new(vault, txn, turn, 0)?.shares_world(txn, id)
}

/// Links mentions over the identity key. It never compares names itself:
/// candidates come only from the key's lookups.
struct Linker<'v> {
    vault: &'v Vault,
    turn: EntityId,
    /// The worlds the turn is in; `None` when it carries no stored scope.
    worlds: Option<ScopeAxis<ScopeId>>,
    /// The turn's facet, which a provisional entity minted from it takes.
    facet: Option<EntityId>,
    now: u64,
    minted: usize,
}

impl<'v> Linker<'v> {
    fn new(vault: &'v Vault, txn: &heed::RoTxn<'_>, turn: EntityId, now: u64) -> Result<Self> {
        let scope = match vault.store.port_entity_raw(txn, &turn)? {
            Some(raw) => scope_for_blob(&vault.store, txn, turn, &raw)?,
            None => None,
        };
        let facet = match birth_facet(&vault.store, txn, turn)? {
            Some(facet) => Some(facet),
            None => scope.as_ref().and_then(|scope| match &scope.facets {
                ScopeAxis::Some(facets) if facets.len() == 1 => facets.first().map(|facet| facet.0),
                _ => None,
            }),
        };
        Ok(Self {
            vault,
            turn,
            worlds: scope.map(|scope| scope.worlds),
            facet,
            now,
            minted: 0,
        })
    }

    /// The key's candidates for a mention: the canonical heads of the
    /// vault's live entities of `kind` whose hints match it, archived ones
    /// included (ARCH-0055 §10, resolution sees the archive), and the
    /// provisional entities of `kind` with its name; each in a world the
    /// turn is in.
    fn candidates(&self, txn: &heed::RoTxn<'_>, kind: u8, mention: &str) -> Result<Vec<EntityId>> {
        let mut found = BTreeSet::new();
        for hit in self.vault.lookup_identity_key_in_txn(txn, kind, mention)? {
            for head in self.vault.resolve_entity_in_txn(txn, &hit)? {
                if linkable_in_txn(&self.vault.store, txn, &head, kind)?
                    && self.shares_world(txn, &head)?
                {
                    found.insert(head);
                }
            }
        }
        for id in provisional::lookup_in_txn(&self.vault.store, txn, kind, mention)? {
            let origin =
                provisional::get_in_txn(&self.vault.store, txn, &id)?.map(|entity| entity.origin);
            if let Some(origin) = origin
                && self.shares_world(txn, &origin)?
            {
                found.insert(id);
            }
        }
        Ok(found.into_iter().collect())
    }

    /// `link` narrowed to the one candidate a saved identity hint picks for
    /// the mention `name` at `start..end` of `text`, as the nightly re-check
    /// would settle it; `link` itself when it names fewer than two or no
    /// hint picks one.
    fn hinted(
        &self,
        txn: &heed::RoTxn<'_>,
        link: MentionLink,
        name: &str,
        text: &str,
        start: usize,
        end: usize,
    ) -> Result<MentionLink> {
        let MentionLink::Candidates { kind, entities } = &link else {
            return Ok(link);
        };
        if entities.len() < 2 {
            return Ok(link);
        }
        let hinted = crate::dreamer_runner::maintenance::identity::hinted_mention_in_txn(
            self.vault, txn, *kind, name, text, start, end, entities,
        )?;
        Ok(match hinted {
            Some(entity) => MentionLink::Candidates {
                kind: *kind,
                entities: vec![entity],
            },
            None => link,
        })
    }

    /// Links a mention by its own name: its candidates, or a provisional
    /// entity minted for it when there are none.
    fn link(&mut self, txn: &mut heed::RwTxn<'_>, kind: u8, mention: &str) -> Result<MentionLink> {
        let entities = self.candidates(txn, kind, mention)?;
        if !entities.is_empty() {
            return Ok(MentionLink::Candidates { kind, entities });
        }
        let entity = self.vault.new_entity_id()?;
        // The id lives in a row no entity write stamps, so its floor is
        // persisted here: a reopen never allocates it again.
        crate::ports::persist_id_floor_in_txn(&self.vault.store, txn)?;
        provisional::mint_in_txn(
            &self.vault.store,
            txn,
            &entity,
            &ProvisionalEntity {
                kind,
                name: mention.to_owned(),
                origin: self.turn,
                facet: self.facet,
                minted_at: self.now,
            },
        )?;
        self.minted += 1;
        Ok(MentionLink::Minted { kind, entity })
    }

    /// The link a context link resolves to: the one the engine saved for
    /// the earlier turn at the link's coordinates, kept to the entities a
    /// world of this turn holds. `None` when no such save is there: the
    /// earlier turn reads in no world of this turn, or has no readable tag
    /// set, or one another tagger or decode made, or one owed a new pass;
    /// or its message no longer shows the text the window sent; or no span
    /// was saved at those coordinates.
    fn context_link(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &EncoderInput,
        link: &ContextLink,
        envelope: &DerivationEnvelope,
        config: &TaggingMarkerConfig,
    ) -> Result<Option<MentionLink>> {
        let store = &self.vault.store;
        let (Ok(earlier), Ok(message), Some(sent)) = (
            EntityId::from_hex(&link.turn),
            EntityId::from_hex(&link.message),
            context_text(input, &link.turn, &link.message),
        ) else {
            return Ok(None);
        };
        if earlier == self.turn || !self.shares_world(txn, &earlier)? {
            return Ok(None);
        }
        let Some(tags) = readable_in_txn(store, txn, &earlier)? else {
            return Ok(None);
        };
        let same_tagger = tags.envelope.model_id == envelope.model_id
            && tags.envelope.stack == envelope.stack
            && tags.envelope.version == envelope.version
            && tags.envelope.params_hash == envelope.params_hash;
        // A turn owed a pass may hold tags of text it no longer shows.
        let owed = AttemptQueue::from_store(store)
            .pending_dedupe_in_txn(txn, TAGGING_MARKER_KIND, &dedupe_key(&earlier, config))?
            .is_some();
        if !same_tagger || owed || !tags.messages.contains(&message) {
            return Ok(None);
        }
        let Some(offset) = sent_text_offset_in_txn(self.vault, txn, &message, sent)? else {
            return Ok(None);
        };
        let (start, end) = (offset + link.start, offset + link.end);
        let Some(saved) = tags.mentions.iter().find(|mention| {
            mention.message == message && mention.start == start && mention.end == end
        }) else {
            return Ok(None);
        };
        let Some(kind) = saved.link.kind() else {
            return Ok(Some(MentionLink::Tag));
        };
        let mut entities = Vec::new();
        for entity in saved.link.entities() {
            if self.admits(txn, kind, entity)? {
                entities.push(*entity);
            }
        }
        // This turn minted none of them: each is a candidate here.
        Ok(Some(if entities.is_empty() {
            MentionLink::Tag
        } else {
            MentionLink::Candidates { kind, entities }
        }))
    }

    /// The link a speaker link resolves to: the turn's author for the
    /// speaker, and for the addressee the one other party of the turn's
    /// room, when it is a room of two that has only ever held the two of
    /// them. `None` when no one person is it: the turn's messages name no
    /// single author, the room is not such a pair, or the person is no
    /// entity a mention may name in a world of this turn. One member of a
    /// group is never picked.
    fn speaker_link(
        &self,
        txn: &heed::RoTxn<'_>,
        messages: &[EntityId],
        link: &SpeakerLink,
    ) -> Result<Option<MentionLink>> {
        let store = &self.vault.store;
        let mut authors = BTreeSet::new();
        for message in messages {
            for edge in store.port_edges(
                txn,
                message,
                EdgeDirection::Out,
                Some(EdgeKind::AuthoredBy),
                None,
            )? {
                authors.insert(edge?.target);
            }
        }
        let mut authors = authors.into_iter();
        let (Some(author), None) = (authors.next(), authors.next()) else {
            return Ok(None);
        };
        let person = match link.target {
            SpeakerTarget::Speaker => author,
            SpeakerTarget::Addressee => {
                let Some(room) = sole_peer(self.vault, txn, &self.turn, EdgeKind::ChildOf)? else {
                    return Ok(None);
                };
                let read = |audience: Result<BTreeSet<EntityId>>| match audience {
                    Ok(audience) => Ok(Some(audience)),
                    Err(
                        error @ (Error::Storage(_)
                        | Error::Io(_)
                        | Error::MapFull
                        | Error::ConcurrentWrite(_)),
                    ) => Err(error),
                    // A room whose audience does not read has no one other
                    // party.
                    Err(_) => Ok(None),
                };
                // The room's audience now must be everyone its ledger has
                // ever held: someone who has left could have been the one
                // spoken to, and a second-precision clock cannot tell
                // whether they left before the turn was said.
                let (Some(audience), Some(ever)) = (
                    read(
                        self.vault
                            .room_audience_members_in_txn(txn, room)
                            .map(|audience| audience.into_iter().collect()),
                    )?,
                    read(self.vault.ever_members_in_txn(txn, room))?,
                ) else {
                    return Ok(None);
                };
                if audience != ever || !audience.contains(&author) {
                    return Ok(None);
                }
                let mut others = audience.into_iter().filter(|id| *id != author);
                let (Some(other), None) = (others.next(), others.next()) else {
                    return Ok(None);
                };
                other
            }
        };
        let Some(row) = store.port_entity_record(txn, &person)? else {
            return Ok(None);
        };
        let kind = row.entity_type;
        if !label_kind_admitted(kind) || !self.admits(txn, kind, &person)? {
            return Ok(None);
        }
        Ok(Some(MentionLink::Candidates {
            kind,
            entities: vec![person],
        }))
    }

    /// Whether this turn's mention may name `entity` as `kind`: a provisional
    /// entity of that kind whose origin turn shares a world with it, or a
    /// linkable entity ([`linkable_in_txn`]) that does.
    fn admits(&self, txn: &heed::RoTxn<'_>, kind: u8, entity: &EntityId) -> Result<bool> {
        if let Some(minted) = provisional::get_in_txn(&self.vault.store, txn, entity)? {
            return Ok(minted.kind == kind && self.shares_world(txn, &minted.origin)?);
        }
        Ok(linkable_in_txn(&self.vault.store, txn, entity, kind)?
            && self.shares_world(txn, entity)?)
    }

    /// Whether the record `id` can sit in a world the turn is in. A record
    /// with no stored scope cannot be placed in another world, so it can.
    fn shares_world(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
        let Some(worlds) = &self.worlds else {
            return Ok(true);
        };
        if *id == self.turn {
            return Ok(true);
        }
        let Some(raw) = self.vault.store.port_entity_raw(txn, id)? else {
            return Ok(true);
        };
        Ok(scope_for_blob(&self.vault.store, txn, *id, &raw)?
            .is_none_or(|scope| !scope.worlds.meet(worlds).is_bottom()))
    }
}
