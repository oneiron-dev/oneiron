//! The continuous sieve (ARCH-0026, the Continuous recipe): the cheap check
//! that tags what is new on the local head.
//!
//! It reads each turn chunk once: rules flag dates and names, a turn's saved
//! oneiroNER tags stand in for the rule names while they index its current
//! words, and every span takes a kind, a ref (the TURN, the source row and
//! the byte range, versioned by the source text's digest), a confidence, a
//! band and an interest score from the policy row. Every span waits in the
//! interest queue, a persistent list ordered by score. Nothing drops: a low,
//! uncertain or unreached span keeps its place, and a span names the model
//! rungs it still owes (the novelty question, and the typing rung for the
//! uncertain band), so a rung that is missing leaves its work queued.
//!
//! The queue, the read records and the cursor commit together in the pass's
//! one transaction, so a restart neither loses a reading nor makes it twice.
//! A turn is read again only when its words or its saved tags change: the
//! re-dirty door, the text publication doors (an entity document's write,
//! its restore, an idle revision) and the tag save owe it a read, and so
//! does a MESSAGE erased from it. A generic re-put that keeps a TURN's
//! temporal key behind the cursor owes nothing, the same limit consolidation
//! documents for it. The rows are derived and local, like the tag sets they
//! point at; the sieve keeps no copy of a tag, only its place in the turn's
//! tag set and the envelope it was read under.

mod chunks;
mod policy;
mod rules;
#[cfg(test)]
mod tests;

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use chunks::{Chunk, turn_chunks_in_txn};
pub use policy::SievePolicy;
pub use rules::RuleClass;

use crate::error::Result;
use crate::ports::{EntityStoreRead, EntityTime, TimelineQuery};
use crate::registry::ENTITY_TYPE_TURN;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// The version of the rules in [`rules`]. Readings and spans name it, so a
/// turn read under a later version is new work.
const RULES_VERSION: u32 = 1;

/// Where the sieve stands on the TURN timeline. Key: ().
const CURSOR: SideTable<(), SieveCursor, Named> = SideTable::new(&side_table::DREAMER_SIEVE_CURSOR);
/// What the sieve last read of one TURN. Key: TURN id.
const READ: SideTable<EntityId, SievedTurn, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_TURN);
/// The interest queue. Key: inverted score (u32 BE), then the span id.
const QUEUE: SideTable<QueueKey, SieveSpan, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_QUEUE);
/// Turns owed a new read: changed words, newly saved tags. Key: TURN id.
const OWED: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::DREAMER_SIEVE_OWED);

type QueueKey = ([u8; 4], [u8; 32]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SieveCursor {
    learned_at: u64,
    turn: EntityId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SievedTurn {
    /// The version of the turn's words the read saw.
    reading: [u8; 32],
    names: NameSource,
    spans: Vec<QueueKey>,
}

/// Where a reading took its names from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NameSource {
    Rules { rules: u32 },
    SavedTags { envelope: [u8; 32] },
}

/// What a span is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Date,
    Name,
}

/// What flagged a span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanOrigin {
    /// A rule of the given rules version.
    Rule { rules: u32, class: RuleClass },
    /// The turn's saved tag set: the mention at `index`, under the tag set's
    /// envelope as BLAKE3 `envelope`. The label and links stay in the tag set.
    SavedTag { envelope: [u8; 32], index: u32 },
}

/// Where a span's confidence falls on the policy row's band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanBand {
    Low,
    Uncertain,
    Sure,
}

/// A model rung a span still waits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SieveRung {
    /// What is new here, and of what kind (the NER question).
    Novelty,
    /// The uncertain band's typed question.
    Typing,
}

/// One queued span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SieveSpan {
    /// BLAKE3 identity of the span's reading: its ref, kind, origin and the
    /// digest of the text it indexes.
    pub id: [u8; 32],
    pub turn: EntityId,
    /// The MESSAGE whose text the offsets index, or the TURN for body text.
    pub source: EntityId,
    pub start: u32,
    pub end: u32,
    pub kind: SpanKind,
    pub origin: SpanOrigin,
    /// BLAKE3 of the source text the offsets index.
    pub source_digest: [u8; 32],
    /// BLAKE3 of the policy row that scored the span.
    pub policy_digest: [u8; 32],
    /// Percent.
    pub confidence: u8,
    pub score: u32,
    pub band: SpanBand,
    pub owed: Vec<SieveRung>,
    pub queued_at: u64,
}

/// What one pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SievePass {
    /// Turns read (owed or new) whose spans changed.
    pub turns_read: usize,
    pub spans_queued: usize,
    /// Spans of an earlier reading the new one replaced.
    pub spans_retired: usize,
    /// Work is left for the next pass.
    pub more: bool,
}

impl Vault {
    /// Runs one bounded sieve pass in its own transaction.
    pub fn sieve_pass(&self, now: u64) -> Result<SievePass> {
        self.with_write_txn(|txn| sieve_pass_in_txn(self, txn, now))
    }

    /// The first `limit` spans of the interest queue, highest score first.
    pub fn sieve_queue(&self, limit: usize) -> Result<Vec<SieveSpan>> {
        let txn = self.store.env.read_txn()?;
        QUEUE
            .iter_from(&self.store, &txn, &[])?
            .take(limit)
            .map(|row| row.map(|(_, span)| span))
            .collect()
    }
}

/// Owes `turn` a new read in the caller's transaction: its words or its saved
/// tags changed.
pub(crate) fn owe_read_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    OWED.put(store, txn, turn, &())
}

/// Takes `turn` out of the sieve in an erasing transaction: its spans, its
/// reading and any read it was owed.
pub(crate) fn erase_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    retire_in_txn(store, txn, turn)?;
    OWED.delete(store, txn, turn)?;
    Ok(())
}

/// One bounded pass, in the caller's transaction: the turns owed a read
/// first, then any turn that landed in the cursor's own second behind it, then
/// new turns past the cursor.
pub(crate) fn sieve_pass_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<SievePass> {
    let policy = policy::policy_in_txn(vault, txn)?;
    let reader = Reader {
        policy,
        policy_digest: policy.digest()?,
        rules: rules::Rules::new(),
        now,
    };
    let mut pass = SievePass::default();
    let mut left = policy.max_turns_per_pass as usize;
    let owed = OWED.scan_keys(&vault.store, txn, &[])?;
    for turn in owed.iter().take(left) {
        // An owed read admits the turn as the scans do: a turn the live
        // sieve does not read (imported, or a role GATE-10 keeps out) keeps
        // no spans here.
        if sieved_turn_in_txn(vault, txn, turn)? {
            reader.read_in_txn(vault, txn, turn, &mut pass)?;
        } else {
            pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
        }
        OWED.delete(&vault.store, txn, turn)?;
    }
    if owed.len() >= left {
        pass.more = true;
        return Ok(pass);
    }
    left -= owed.len();
    let cursor = CURSOR.get(&vault.store, txn, &())?;
    if let Some(at) = cursor {
        left -= reader.sweep_late_in_txn(vault, txn, at, left, &mut pass)?;
    }
    reader.scan_new_in_txn(vault, txn, cursor, left, &mut pass)?;
    Ok(pass)
}

/// Whether the sieve reads this timeline row: a live TURN the Dreamer may
/// extract from (GATE-10), not an imported one, whose import's review owns
/// it (ARCH-0027).
fn sieved_turn_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(row) = vault.store.port_entity_record(txn, id)? else {
        return Ok(false);
    };
    if row.entity_type != ENTITY_TYPE_TURN {
        return Ok(false);
    }
    let facts = crate::dreamer_consolidation::decode_turn_body(&row.body);
    let role = crate::dreamer_runner::dreamer_turn_role(
        facts.speaker.as_deref(),
        &vault.config.assistant_display_names,
    );
    Ok(!facts.imported && crate::dreamer_runner::dreamer_extraction_role_admissible(role))
}

/// Removes a turn's reading and every span it queued.
fn retire_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<usize> {
    let Some(held) = READ.get(store, txn, turn)? else {
        return Ok(0);
    };
    for key in &held.spans {
        QUEUE.delete(store, txn, key)?;
    }
    READ.delete(store, txn, turn)?;
    Ok(held.spans.len())
}

/// One pass's fixed inputs.
struct Reader {
    policy: SievePolicy,
    policy_digest: [u8; 32],
    rules: rules::Rules,
    now: u64,
}

impl Reader {
    /// Reads the rows that landed in the cursor's own second after it moved
    /// on, behind it in id order: a same-second write the forward scan never
    /// sees. A turn the sieve has read is skipped here; its changes are owed.
    /// The sweep reads the whole second up to the cursor, never a first page
    /// of it, and a sweep the budget cuts short keeps the cursor in place.
    fn sweep_late_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        at: SieveCursor,
        left: usize,
        pass: &mut SievePass,
    ) -> Result<usize> {
        let query = TimelineQuery {
            start: Bound::Included(at.learned_at),
            end: Bound::Included(at.learned_at),
            ..Default::default()
        };
        let mut behind = Vec::new();
        for entry in vault.store.port_entity_timeline(txn, query)? {
            let entry = entry?;
            if entry.id >= at.turn {
                break;
            }
            behind.push(entry.id);
        }
        let mut read = 0;
        for id in &behind {
            if read >= left {
                pass.more = true;
                break;
            }
            // A turn that reads gone has nothing to hold its place; it costs
            // the budget nothing, so it can never keep a pass coming back.
            if !READ.contains(&vault.store, txn, id)?
                && sieved_turn_in_txn(vault, txn, id)?
                && self.read_in_txn(vault, txn, id, pass)?
            {
                read += 1;
            }
        }
        Ok(read)
    }

    /// Reads new turns past the cursor, at most `left`, and moves the cursor
    /// to the last row it stepped over.
    fn scan_new_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        cursor: Option<SieveCursor>,
        left: usize,
        pass: &mut SievePass,
    ) -> Result<()> {
        let query = TimelineQuery {
            after: cursor.map(|at| EntityTime {
                timestamp: at.learned_at,
                id: at.turn,
            }),
            ..Default::default()
        };
        let scan = self.policy.max_scan_per_pass as usize;
        let entries = vault
            .store
            .port_entity_timeline(txn, query)?
            .take(scan)
            .collect::<Result<Vec<_>>>()?;
        let mut read = 0;
        let mut last = None;
        for entry in &entries {
            if read >= left {
                pass.more = true;
                break;
            }
            last = Some(*entry);
            if sieved_turn_in_txn(vault, txn, &entry.id)? {
                self.read_in_txn(vault, txn, &entry.id, pass)?;
                read += 1;
            }
        }
        pass.more |= entries.len() == scan && last == entries.last().copied();
        let Some(last) = last else {
            return Ok(());
        };
        let cursor = SieveCursor {
            learned_at: last.timestamp,
            turn: last.id,
        };
        CURSOR.put(&vault.store, txn, &(), &cursor)
    }

    /// Reads `turn` once: a reading of the same words from the same name
    /// source writes nothing; a new one replaces the turn's spans. A turn
    /// that reads gone loses its spans; `false` then.
    fn read_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        pass: &mut SievePass,
    ) -> Result<bool> {
        let Some(chunks) = turn_chunks_in_txn(vault, txn, turn)? else {
            pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
            return Ok(false);
        };
        let reading = chunks::reading_digest(&chunks);
        let tags = crate::tagging::current_tags_in_txn(vault, txn, turn)?;
        let names = tags.as_ref().map_or(
            NameSource::Rules {
                rules: RULES_VERSION,
            },
            |tags| NameSource::SavedTags {
                envelope: envelope_digest(&tags.envelope),
            },
        );
        let held = READ.get(&vault.store, txn, turn)?;
        if held
            .as_ref()
            .is_some_and(|held| held.reading == reading && held.names == names)
        {
            return Ok(true);
        }
        let mut spans = self.rule_spans(turn, &chunks, tags.is_none());
        if let (Some(tags), NameSource::SavedTags { envelope }) = (&tags, names) {
            spans.extend(self.tag_spans(turn, &chunks, tags, envelope));
        }
        pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
        let mut keys = Vec::with_capacity(spans.len());
        for span in spans {
            let key = ((u32::MAX - span.score).to_be_bytes(), span.id);
            QUEUE.put(&vault.store, txn, &key, &span)?;
            keys.push(key);
        }
        keys.sort_unstable();
        keys.dedup();
        pass.turns_read += 1;
        pass.spans_queued += keys.len();
        let read = SievedTurn {
            reading,
            names,
            spans: keys,
        };
        READ.put(&vault.store, txn, turn, &read)?;
        Ok(true)
    }

    /// The rule spans of every chunk: dates always, names only when no
    /// saved tags stand in for them.
    fn rule_spans(&self, turn: &EntityId, chunks: &[Chunk], names: bool) -> Vec<SieveSpan> {
        let mut spans = Vec::new();
        for chunk in chunks {
            for span in self.rules.spans(&chunk.text) {
                let kind = if span.class.is_date() {
                    SpanKind::Date
                } else if names {
                    SpanKind::Name
                } else {
                    continue;
                };
                let origin = SpanOrigin::Rule {
                    rules: RULES_VERSION,
                    class: span.class,
                };
                let confidence = self.policy.rule_confidence(span.class);
                let range = (span.start, span.end);
                spans.push(self.span(turn, chunk, range, kind, origin, confidence));
            }
        }
        spans
    }

    /// The saved tag set's mentions as name spans: refs into the tag set,
    /// which keeps their labels and links.
    fn tag_spans(
        &self,
        turn: &EntityId,
        chunks: &[Chunk],
        tags: &crate::tagging::TurnTags,
        envelope: [u8; 32],
    ) -> Vec<SieveSpan> {
        let mut spans = Vec::new();
        for (index, mention) in tags.mentions.iter().enumerate() {
            let Some(chunk) = chunks.iter().find(|chunk| chunk.source == mention.message) else {
                continue;
            };
            if chunk.text.get(mention.start..mention.end).is_none() {
                continue;
            }
            let origin = SpanOrigin::SavedTag {
                envelope,
                index: u32::try_from(index).unwrap_or(u32::MAX),
            };
            let confidence = percent(mention.confidence);
            let range = (mention.start, mention.end);
            spans.push(self.span(turn, chunk, range, SpanKind::Name, origin, confidence));
        }
        spans
    }

    fn span(
        &self,
        turn: &EntityId,
        chunk: &Chunk,
        (start, end): (usize, usize),
        kind: SpanKind,
        origin: SpanOrigin,
        confidence: u8,
    ) -> SieveSpan {
        let start = u32::try_from(start).unwrap_or(u32::MAX);
        let end = u32::try_from(end).unwrap_or(u32::MAX);
        let mut id = blake3::Hasher::new();
        id.update(b"oneiron:dreamer-sieve:span:v1");
        id.update(turn.as_bytes());
        id.update(chunk.source.as_bytes());
        id.update(&start.to_be_bytes());
        id.update(&end.to_be_bytes());
        id.update(&chunk.digest);
        match origin {
            SpanOrigin::Rule { rules, class } => {
                id.update(&[0, kind as u8, class as u8]);
                id.update(&rules.to_be_bytes());
            }
            SpanOrigin::SavedTag { envelope, index } => {
                id.update(&[1, kind as u8]);
                id.update(&envelope);
                id.update(&index.to_be_bytes());
            }
        }
        let interest = match kind {
            SpanKind::Date => self.policy.date_interest,
            SpanKind::Name => self.policy.name_interest,
        };
        let band = if confidence < self.policy.uncertain_low {
            SpanBand::Low
        } else if confidence < self.policy.uncertain_high {
            SpanBand::Uncertain
        } else {
            SpanBand::Sure
        };
        let mut owed = vec![SieveRung::Novelty];
        if band == SpanBand::Uncertain {
            owed.push(SieveRung::Typing);
        }
        SieveSpan {
            id: *id.finalize().as_bytes(),
            turn: *turn,
            source: chunk.source,
            start,
            end,
            kind,
            origin,
            source_digest: chunk.digest,
            policy_digest: self.policy_digest,
            confidence,
            score: interest.saturating_mul(u32::from(confidence)),
            band,
            owed,
            queued_at: self.now,
        }
    }
}

fn percent(confidence: f32) -> u8 {
    if confidence.is_nan() {
        return 0;
    }
    let scaled = (confidence.clamp(0.0, 1.0) * 100.0).round();
    // In range by the clamp above.
    scaled as u8
}

fn envelope_digest(envelope: &crate::tagging::DerivationEnvelope) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-sieve:tag-envelope:v1");
    for field in [
        &envelope.content_hash,
        &envelope.model_id,
        &envelope.version,
        &envelope.params_hash,
    ] {
        hash.update(&(field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    *hash.finalize().as_bytes()
}
