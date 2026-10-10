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

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::input::{TurnInput, input_hash, turn_text_in_txn};
use super::marker::TaggingMarkerConfig;
use super::output::check_output;
use super::provisional::{self, ProvisionalEntity};
use super::tags::{
    DerivationEnvelope, MentionLink, MergeEvidence, TaggedMention, TurnTags, replace_in_txn,
    tag_set_in_txn,
};
use crate::error::{Error, Result};
use crate::federation::record_scope::{birth_facet, scope_for_blob};
use crate::federation::{ScopeAxis, ScopeId};
use crate::memory::extraction::{EncoderInput, EncoderOutput};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::{EntityId, Vault};

/// The save path's version, the envelope's `version`.
const SAVE_VERSION: &str = "oneiron.tagging.save.v1";

/// What one save did.
pub(super) struct Saved {
    /// Spans linked to at least one entity.
    pub(super) linked: usize,
    /// Provisional entities it minted.
    pub(super) minted: usize,
}

/// The envelope of a tag set read from `content_hash` by `made_by` under
/// `config`'s label table and window.
pub(super) fn envelope(
    content_hash: &str,
    made_by: &str,
    config: &TaggingMarkerConfig,
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
    labels: &BTreeMap<String, u8>,
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
    if let Some(held) = tag_set_in_txn(&vault.store, txn, &turn)?
        && held.envelope == envelope
    {
        return Ok(Saved {
            linked: held
                .mentions
                .iter()
                .filter(|mention| mention.link != MentionLink::Tag)
                .count(),
            minted: 0,
        });
    }
    let mut antecedent_of = vec![None; output.spans.len()];
    for link in &output.links {
        antecedent_of[link.span] = Some(link.antecedent);
    }
    let mut linker = Linker::new(vault, txn, turn, now)?;
    let mut mentions: Vec<TaggedMention> = Vec::with_capacity(output.spans.len());
    let mut merge_evidence = Vec::new();
    for (index, span) in output.spans.iter().enumerate() {
        let text = input.messages[span.message].text[span.start..span.end].trim();
        let own = labels
            .get(&span.label)
            .copied()
            .filter(|_| !text.is_empty());
        let antecedent = antecedent_of[index];
        let inherited = antecedent
            .map(|at| &mentions[at].link)
            .filter(|link| **link != MentionLink::Tag);
        let link = match (inherited, own) {
            (None, None) => MentionLink::Tag,
            (None, Some(kind)) => linker.link(txn, kind, text)?,
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
                    // weighs, never a merge.
                    if inherited.kind() == Some(kind)
                        && hits.iter().all(|hit| !inherited.entities().contains(hit))
                        && let Some(at) = antecedent
                    {
                        merge_evidence.push(MergeEvidence {
                            span: index,
                            antecedent: at,
                            confidence: span.confidence,
                        });
                    }
                    MentionLink::Candidates {
                        kind,
                        entities: hits,
                    }
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
        });
    }
    let saved = Saved {
        linked: mentions
            .iter()
            .filter(|mention| mention.link != MentionLink::Tag)
            .count(),
        minted: linker.minted,
    };
    let tags = TurnTags {
        turn,
        envelope,
        messages,
        mentions,
        merge_evidence,
        mood: output.vad,
        saved_at: now,
    };
    replace_in_txn(vault, txn, &turn, Some(&tags))?;
    Ok(saved)
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
    if !unchanged || check_output(input, output).is_err() {
        return Ok(None);
    }
    let answer = Answer {
        turn,
        input,
        output,
        envelope: envelope(&input_hash(input), model, config),
    };
    save_in_txn(vault, txn, answer, &config.labels, now)?;
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
