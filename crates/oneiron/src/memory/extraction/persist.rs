//! One transaction saves a turn's tags: unconfirmed mentions, links through the
//! identity key, provisional entities, the turn's mood and merge evidence, all
//! under one derivation envelope. It writes no claim, no edge and no merge.
use super::types::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::federation::{ScopeAxis, ScopeId, record_scope::scope_for_blob};
use crate::memory::{Memory, MemoryError};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, TimeRange, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The per-turn tag overlay: derived rows, local to this device, never
/// synced, rebuilt by tagging the turn again. Key: family byte + id16.
const TAG_OVERLAY: SideTable<([u8; 1], EntityId), OverlayRow, Named> =
    SideTable::new(&side_table::MEMORY_EXTRACTION_OVERLAY);
/// Family of a TURN's tag set, keyed by the turn id.
const TAG_SET: [u8; 1] = [0];
/// Family of a provisional entity's marker, keyed by the entity id.
const PROVISIONAL: [u8; 1] = [1];
const MAX_ENTRIES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum OverlayRow {
    TagSet(Box<ExtractionTagSet>),
    /// A cold entity the save path minted, waiting for the Dreamer.
    Provisional {
        turn: EntityId,
    },
}

impl Memory<'_> {
    /// Saves a parity-checked shadow output for its turn. Each span with a
    /// mapped label is linked through the engine's identity key: one canonical
    /// candidate links, several soft-link, none mints a provisional entity.
    /// A coreferent span takes its antecedent's link; a link joining two
    /// different entities is saved as merge evidence. Any refusal writes
    /// nothing. Saving the same envelope again is a no-op.
    pub fn persist_extraction(
        &self,
        trace: &ShadowTrace,
        parity: &EncoderParity,
        config: &ExtractionSaveConfig,
        now: u64,
    ) -> Result<ExtractionReceipt, ExtractionSaveError> {
        use ExtractionRefusal::{NoOutput, NoParity, SourceChanged};
        use ExtractionSaveError::Refused;
        if parity.model != trace.model {
            return Err(Refused(NoParity));
        }
        let output = trace.output.as_ref().ok_or(Refused(NoOutput))?;
        check_output(&trace.input, output).map_err(Refused)?;
        let turn = EntityId::from_hex(&trace.input.turn).map_err(|_| Refused(SourceChanged))?;
        let messages = trace
            .input
            .messages
            .iter()
            .map(|message| EntityId::from_hex(&message.id))
            .collect::<crate::Result<Vec<_>>>()
            .map_err(|_| Refused(SourceChanged))?;
        let envelope = config.envelope(trace);
        let mut refusal = None;
        let saved = self.with_verified_actor_write_txn(|txn| {
            if !source_unchanged(self.vault, txn, turn, &messages, &trace.input)? {
                refusal = Some(SourceChanged);
                return Err(MemoryError::bad_request(SourceChanged.as_str()));
            }
            if let Some(OverlayRow::TagSet(tags)) =
                TAG_OVERLAY.get(&self.vault.store, txn, &(TAG_SET, turn))?
                && tags.envelope == envelope
            {
                return Ok(ExtractionReceipt {
                    tags: *tags,
                    minted: Vec::new(),
                    unchanged: true,
                });
            }
            let mut linker = Linker::new(self.vault, txn, turn, now)?;
            let mut antecedent_of = vec![None; output.spans.len()];
            for link in &output.links {
                antecedent_of[link.span] = Some(link.antecedent);
            }
            let mut mentions: Vec<UnconfirmedMention> = Vec::with_capacity(output.spans.len());
            let mut merge_evidence = Vec::new();
            let mut pairs = BTreeSet::new();
            for (index, span) in output.spans.iter().enumerate() {
                let text = trace.input.messages[span.message].text[span.start..span.end].trim();
                let own = match config.labels().kind(&span.label) {
                    Some(kind) if !text.is_empty() => Some((kind, linker.lookup(txn, kind, text)?)),
                    _ => None,
                };
                let antecedent = antecedent_of[index];
                let link = match (antecedent.map(|at| &mentions[at].link), own) {
                    (None, None) => MentionLink::Tag,
                    (None, Some((kind, hit))) => linker.link(txn, kind, text, hit)?,
                    // A named span whose own key names one entity keeps it. If
                    // its antecedent names another, that pair is evidence.
                    (Some(inherited), Some((kind, Hit::One(entity)))) => {
                        if let (Some(at), Some(other)) = (antecedent, inherited.entity())
                            && other != entity
                            && inherited.kind() == Some(kind)
                            && pairs.insert((other.min(entity), other.max(entity)))
                        {
                            merge_evidence.push(MergeEvidence {
                                span: index,
                                antecedent: at,
                                entity,
                                antecedent_entity: other,
                                confidence: span.confidence,
                            });
                        }
                        linker.known(txn, kind, entity)?
                    }
                    (Some(MentionLink::Tag), Some((kind, Hit::Many(candidates)))) => {
                        linker.soft(txn, kind, candidates)?
                    }
                    // A pronoun, or a name the key misses, takes its
                    // antecedent's entity and never mints one.
                    (Some(inherited), _) => inherited.clone(),
                };
                mentions.push(UnconfirmedMention {
                    message: messages[span.message],
                    start: span.start,
                    end: span.end,
                    label: span.label.clone(),
                    confidence: span.confidence,
                    link,
                    antecedent,
                });
            }
            let tags = ExtractionTagSet {
                turn,
                envelope: envelope.clone(),
                mentions,
                merge_evidence,
                mood: output.vad,
                saved_at: now,
            };
            TAG_OVERLAY.put(
                &self.vault.store,
                txn,
                &(TAG_SET, turn),
                &OverlayRow::TagSet(Box::new(tags.clone())),
            )?;
            Ok(ExtractionReceipt {
                tags,
                minted: linker.minted,
                unchanged: false,
            })
        });
        saved.map_err(|error| match refusal {
            Some(refusal) => Refused(refusal),
            None => error.into(),
        })
    }
}

impl Vault {
    /// The tag set saved for a TURN, if any.
    pub fn extraction_tag_set(&self, turn: &EntityId) -> crate::Result<Option<ExtractionTagSet>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            match TAG_OVERLAY.get(&self.store, &txn, &(TAG_SET, *turn))? {
                Some(OverlayRow::TagSet(tags)) => Some(*tags),
                _ => None,
            },
        )
    }
    /// The turn whose tags minted `entity`, while it is still provisional.
    pub fn provisional_entity_origin(&self, entity: &EntityId) -> crate::Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        Ok(
            match TAG_OVERLAY.get(&self.store, &txn, &(PROVISIONAL, *entity))? {
                Some(OverlayRow::Provisional { turn }) => Some(turn),
                _ => None,
            },
        )
    }
}

/// Every overlay row of the vault, both families, so a test can count them.
#[cfg(test)]
pub(super) fn overlay_rows(vault: &Vault) -> crate::Result<usize> {
    let txn = vault.store.env.read_txn()?;
    Ok(TAG_OVERLAY.scan_keys(&vault.store, &txn, &[])?.len())
}

/// What the identity key returned for one mention, as canonical heads.
enum Hit {
    Miss,
    One(EntityId),
    Many(Vec<EntityId>),
}

/// Routes mentions over the engine's identity key. It never compares names
/// itself: candidates come only from the key's own lookup.
struct Linker<'v> {
    vault: &'v Vault,
    turn: EntityId,
    turn_worlds: Option<ScopeAxis<ScopeId>>,
    now: u64,
    minted: Vec<EntityId>,
}
impl<'v> Linker<'v> {
    fn new(
        vault: &'v Vault,
        txn: &heed::RoTxn<'_>,
        turn: EntityId,
        now: u64,
    ) -> crate::Result<Self> {
        let turn_worlds = match vault.store.port_entity_raw(txn, &turn)? {
            Some(raw) => scope_for_blob(&vault.store, txn, turn, &raw)?.map(|scope| scope.worlds),
            None => None,
        };
        Ok(Self {
            vault,
            turn,
            turn_worlds,
            now,
            minted: Vec::new(),
        })
    }
    fn lookup(&self, txn: &heed::RoTxn<'_>, kind: u8, mention: &str) -> crate::Result<Hit> {
        let mut heads = BTreeSet::new();
        for found in self.vault.lookup_identity_key_in_txn(txn, kind, mention)? {
            for head in self.vault.resolve_entity_in_txn(txn, &found)? {
                if self.vault.get_entity_type_in_txn(txn, &head)? == Some(kind)
                    && self.in_turn_world(txn, &head)?
                {
                    heads.insert(head);
                }
            }
        }
        let mut heads: Vec<_> = heads.into_iter().collect();
        Ok(match heads.len() {
            0 => Hit::Miss,
            1 => Hit::One(heads.remove(0)),
            _ => Hit::Many(heads),
        })
    }
    /// Lookups stay inside the turn's world. A row with no stored scope cannot
    /// be placed in another world and stays a candidate.
    fn in_turn_world(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> crate::Result<bool> {
        let Some(turn_worlds) = &self.turn_worlds else {
            return Ok(true);
        };
        let Some(raw) = self.vault.store.port_entity_raw(txn, id)? else {
            return Ok(false);
        };
        Ok(scope_for_blob(&self.vault.store, txn, *id, &raw)?
            .is_none_or(|scope| !scope.worlds.meet(turn_worlds).is_bottom()))
    }
    fn link(
        &mut self,
        txn: &mut heed::RwTxn<'_>,
        kind: u8,
        mention: &str,
        hit: Hit,
    ) -> crate::Result<MentionLink> {
        Ok(match hit {
            Hit::One(entity) => self.known(txn, kind, entity)?,
            Hit::Many(candidates) => self.soft(txn, kind, candidates)?,
            Hit::Miss => MentionLink::Provisional {
                kind,
                entity: self.mint(txn, kind, mention)?,
            },
        })
    }
    /// One entity the key named: a sure link, unless it is still provisional.
    fn known(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        entity: EntityId,
    ) -> crate::Result<MentionLink> {
        Ok(
            if TAG_OVERLAY.contains(&self.vault.store, txn, &(PROVISIONAL, entity))? {
                MentionLink::Provisional { kind, entity }
            } else {
                MentionLink::Sure { kind, entity }
            },
        )
    }
    /// Several candidates: a soft link that names which are still provisional.
    fn soft(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: u8,
        candidates: Vec<EntityId>,
    ) -> crate::Result<MentionLink> {
        let mut provisional = Vec::new();
        for candidate in &candidates {
            if TAG_OVERLAY.contains(&self.vault.store, txn, &(PROVISIONAL, *candidate))? {
                provisional.push(*candidate);
            }
        }
        Ok(MentionLink::Soft {
            kind,
            candidates,
            provisional,
        })
    }
    /// Mints a cold entity whose only identity hint is the mention, so the next
    /// lookup of the same key finds it instead of minting a twin.
    fn mint(
        &mut self,
        txn: &mut heed::RwTxn<'_>,
        kind: u8,
        mention: &str,
    ) -> crate::Result<EntityId> {
        let id = EntityId::now();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![("name".into(), mention.into())]),
        )
        .map_err(|_| Error::InvariantViolation("provisional entity encoding"))?;
        let at = TimeRange {
            start: self.now,
            end: self.now,
        };
        self.vault
            .batch_in()
            .put(&id, kind, at, self.now, &body)
            .apply(txn)?;
        TAG_OVERLAY.put(
            &self.vault.store,
            txn,
            &(PROVISIONAL, id),
            &OverlayRow::Provisional { turn: self.turn },
        )?;
        self.minted.push(id);
        Ok(id)
    }
}

/// Structural checks that need no store: span bounds against the text the
/// model read, link indices against the span list, and the mood's ranges.
fn check_output(input: &EncoderInput, output: &EncoderOutput) -> Result<(), ExtractionRefusal> {
    if output.spans.len() > MAX_ENTRIES || output.links.len() > MAX_ENTRIES {
        return Err(ExtractionRefusal::SpanCount);
    }
    for span in &output.spans {
        let Some(message) = input.messages.get(span.message) else {
            return Err(ExtractionRefusal::BadOffsets);
        };
        if span.start >= span.end
            || span.end > message.text.len()
            || !message.text.is_char_boundary(span.start)
            || !message.text.is_char_boundary(span.end)
        {
            return Err(ExtractionRefusal::BadOffsets);
        }
        if !(1..=64).contains(&span.label.len()) || !(0.0..=1.0).contains(&span.confidence) {
            return Err(ExtractionRefusal::BadSpan);
        }
    }
    let mut linked = BTreeSet::new();
    for link in &output.links {
        if link.span >= output.spans.len()
            || link.antecedent >= link.span
            || !linked.insert(link.span)
        {
            return Err(ExtractionRefusal::SpanCount);
        }
    }
    if output.vad.is_some_and(|vad| vad.validate().is_err()) {
        return Err(ExtractionRefusal::MoodOutOfRange);
    }
    Ok(())
}

/// The turn and every message still exist with their types, and each
/// message's stored text is the text the model read.
fn source_unchanged(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    messages: &[EntityId],
    input: &EncoderInput,
) -> crate::Result<bool> {
    if body_of(vault, txn, &turn, ENTITY_TYPE_TURN)?.is_none() {
        return Ok(false);
    }
    for (id, message) in messages.iter().zip(&input.messages) {
        let Some(raw) = body_of(vault, txn, id, ENTITY_TYPE_MESSAGE)? else {
            return Ok(false);
        };
        let value = rmpv::decode::read_value(&mut &raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("extraction source message"))?;
        let stored = value
            .as_map()
            .and_then(|map| map.iter().find(|(key, _)| key.as_str() == Some("content")))
            .and_then(|(_, value)| value.as_str());
        if stored != Some(message.text.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn body_of(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
) -> crate::Result<Option<Vec<u8>>> {
    let Some(raw) = vault.store.port_entity_raw(txn, id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("extraction source header"))?;
    Ok((header.entity_type == kind).then_some(raw))
}
