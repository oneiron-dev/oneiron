//! One turn's read: a whole read from its rows, a read that goes on where
//! the text bound stopped it, and the spans each segment queues.

use super::chunks::{self, Chunk, ChunkRef, TurnChunks};
use super::rules::{self, Carry};
use super::{
    CONTINUE, NameSource, QUEUE, READ, RULES_VERSION, Read, Reader, Resume, SPANS, SievePass,
    SieveRung, SieveSpan, SievedTurn, SpanBand, SpanKind, SpanOrigin, WITHHELD, retire_in_txn,
    retire_spans_in_txn,
};
use crate::error::Result;
use crate::store::Store;
use crate::tagging::TurnTags;
use crate::{EntityId, Vault};

/// The turn a read queues its spans for, and the saved tag set that names
/// it with its envelope's digest, when one does.
#[derive(Clone, Copy)]
struct Names<'a> {
    turn: &'a EntityId,
    tags: Option<(&'a TurnTags, [u8; 32])>,
}

/// One chunk as a read holds it, and its text.
#[derive(Clone, Copy)]
struct ChunkText<'a> {
    held: &'a ChunkRef,
    text: &'a str,
}

impl Reader<'_> {
    /// Reads `turn` whole from its rows: a reading of the same words from
    /// the same name source writes nothing, or goes on where the text bound
    /// stopped it; a new one replaces the turn's spans. A turn that reads
    /// gone loses its spans. The pass's bound pays for the bytes it hashes.
    /// A turn whose tagged MESSAGE this replica does not hold is not read:
    /// it waits, [`Read::Deferred`], with every row it holds.
    pub(super) fn read_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        pass: &mut SievePass,
    ) -> Result<Read> {
        let store = &vault.store;
        // Its words read only partly here until a promotion brings the row
        // back (OF-534): a read of the rest would retire spans and replace
        // the reading it holds with a fragment's.
        if crate::tagging::tagged_messages_absent_in_txn(store, txn, turn)? {
            return Ok(Read::Deferred);
        }
        let Some(TurnChunks { chunks, withheld }) = self.texts.turn_chunks(vault, txn, turn)?
        else {
            pass.spans_retired += retire_in_txn(store, txn, turn)?;
            return Ok(Read::Gone);
        };
        self.charge(chunks.iter().map(|chunk| chunk.text.len()).sum());
        // Words the Dreamer may not read wait for a grant, whether or not the
        // words it may read changed.
        if withheld {
            WITHHELD.put(store, txn, turn, &self.epoch)?;
        } else {
            WITHHELD.delete(store, txn, turn)?;
        }
        let held: Vec<ChunkRef> = chunks.iter().map(Chunk::held).collect();
        let reading = chunks::reading_digest(&held);
        // With no words to read there are no names to take: the tag set is
        // not read. Telling whether it still names the words hashes the
        // tagger's input, which the bound pays for too.
        let (tags, hashed) = if chunks.is_empty() {
            (None, 0)
        } else {
            self.texts.current_tags(vault, txn, turn)?
        };
        self.charge(hashed);
        let names = tags.as_ref().map_or(
            NameSource::Rules {
                rules: RULES_VERSION,
            },
            |tags| NameSource::SavedTags {
                envelope: envelope_digest(&tags.envelope),
            },
        );
        let same = READ
            .get(store, txn, turn)?
            .filter(|read| read.reading == reading && read.names == names);
        let from = match same.map(|read| read.next) {
            Some(None) => {
                CONTINUE.delete(store, txn, turn)?;
                return Ok(Read::Whole);
            }
            // A stored resume goes on only where the text has it.
            Some(Some(next))
                if chunks
                    .get(next.chunk)
                    .is_some_and(|chunk| chunk.text.is_char_boundary(next.at)) =>
            {
                next
            }
            _ => {
                pass.spans_retired += retire_spans_in_txn(store, txn, turn)?;
                pass.turns_read += 1;
                Resume::default()
            }
        };
        let tags = match (&tags, names) {
            (Some(tags), NameSource::SavedTags { envelope }) => Some((tags, envelope)),
            _ => None,
        };
        let names_for = Names { turn, tags };
        let mut next = None;
        for (index, chunk) in chunks.iter().enumerate().skip(from.chunk) {
            let text = ChunkText {
                held: &held[index],
                text: &chunk.text,
            };
            let stop =
                self.read_chunk_in_txn(store, txn, names_for, text, from.within(index), pass)?;
            if let Some((at, carry)) = stop {
                next = Some(Resume {
                    chunk: index,
                    at,
                    carry,
                });
                break;
            }
        }
        if next.is_some() {
            CONTINUE.put(store, txn, turn, &held)?;
        } else {
            CONTINUE.delete(store, txn, turn)?;
        }
        settle_in_txn(
            store,
            txn,
            turn,
            SievedTurn {
                reading,
                names,
                next,
            },
        )
    }

    /// Reads on in `turn` where the text bound stopped its read, from the
    /// chunks the read holds: it reads the row of the chunk it is in and of
    /// those after it, and neither reads nor hashes again a chunk before.
    /// The rows hold the same words while the row is held, since a change
    /// to them owes the turn a new read and drops it. A chunk the turn no
    /// longer holds or the Dreamer may no longer read, or a row that no
    /// longer reads at the held length, sends the turn to a whole read: a
    /// chunk it reads on in when it reads it, and a chunk before the resume
    /// point when the read is about to settle, checked once for the read
    /// and paid for by the bound. A turn whose tagged MESSAGE this replica
    /// does not hold waits with its continuation, here and at the whole read
    /// every fallback above sends it to.
    pub(super) fn read_on_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        pass: &mut SievePass,
    ) -> Result<Read> {
        let store = &vault.store;
        if crate::tagging::tagged_messages_absent_in_txn(store, txn, turn)? {
            return Ok(Read::Deferred);
        }
        let (Some(held), Some(read)) =
            (CONTINUE.get(store, txn, turn)?, READ.get(store, txn, turn)?)
        else {
            return self.read_in_txn(vault, txn, turn, pass);
        };
        let Some(from) = read.next else {
            return self.read_in_txn(vault, txn, turn, pass);
        };
        if from.chunk >= held.len() {
            return self.read_in_txn(vault, txn, turn, pass);
        }
        let tags = match read.names {
            NameSource::Rules { rules } if rules == RULES_VERSION => None,
            NameSource::SavedTags { envelope } => {
                match crate::tagging::readable_view_in_txn(store, txn, turn)? {
                    Some(tags) if envelope_digest(&tags.envelope) == envelope => {
                        Some((tags, envelope))
                    }
                    _ => return self.read_in_txn(vault, txn, turn, pass),
                }
            }
            NameSource::Rules { .. } => return self.read_in_txn(vault, txn, turn, pass),
        };
        let names = Names {
            turn,
            tags: tags.as_ref().map(|(tags, envelope)| (tags, *envelope)),
        };
        let mut next = None;
        for (index, chunk) in held.iter().enumerate().skip(from.chunk) {
            let (at, carry) = from.within(index);
            let text = self
                .texts
                .chunk_text(vault, txn, turn, &chunk.source)?
                .filter(|text| text.len() as u64 == chunk.len && text.is_char_boundary(at));
            let Some(text) = text else {
                return self.read_in_txn(vault, txn, turn, pass);
            };
            let text = ChunkText {
                held: chunk,
                text: &text,
            };
            if let Some((at, carry)) =
                self.read_chunk_in_txn(store, txn, names, text, (at, carry), pass)?
            {
                next = Some(Resume {
                    chunk: index,
                    at,
                    carry,
                });
                break;
            }
        }
        if next.is_none() {
            // The read settles: the chunks it passed in passes before must
            // still be the turn's, and words the Dreamer may read.
            let passed = &held[..from.chunk];
            self.charge(
                passed
                    .iter()
                    .map(|chunk| usize::try_from(chunk.len).unwrap_or(usize::MAX))
                    .fold(0, usize::saturating_add),
            );
            let sources: Vec<EntityId> = passed.iter().map(|chunk| chunk.source).collect();
            if !chunks::still_held_in_txn(vault, txn, turn, &sources)? {
                return self.read_in_txn(vault, txn, turn, pass);
            }
            CONTINUE.delete(store, txn, turn)?;
        }
        settle_in_txn(store, txn, turn, SievedTurn { next, ..read })
    }

    /// Reads one chunk a segment at a time from `from` while the pass's
    /// bound lasts, and queues each segment's spans and the saved tags'
    /// mentions that start in it. Returns where it stopped, `None` once the
    /// chunk is read to its end.
    fn read_chunk_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        names: Names<'_>,
        chunk: ChunkText<'_>,
        (mut at, mut carry): (usize, Carry),
        pass: &mut SievePass,
    ) -> Result<Option<(usize, Carry)>> {
        let mut mentions: Vec<(usize, usize)> = names.tags.map_or_else(Vec::new, |(tags, _)| {
            tags.mentions
                .iter()
                .enumerate()
                .filter(|(_, mention)| {
                    mention.message == chunk.held.source
                        && mention.start >= at
                        && chunk.text.get(mention.start..mention.end).is_some()
                })
                .map(|(index, mention)| (mention.start, index))
                .collect()
        });
        mentions.sort_unstable();
        let mut mentions = mentions.into_iter().peekable();
        while at < chunk.text.len() {
            if !self.reads_segment((chunk.text.len() - at).min(rules::SEGMENT_WINDOW)) {
                return Ok(Some((at, carry)));
            }
            let segment = self.rules.segment(chunk.text, at, carry);
            self.charge(segment.read);
            for span in &segment.spans {
                let kind = if span.class.is_date() {
                    SpanKind::Date
                } else if names.tags.is_none() {
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
                let queued = self.span(names.turn, chunk.held, range, kind, origin, confidence);
                queue_in_txn(store, txn, &queued, pass)?;
            }
            if let Some((tags, envelope)) = names.tags {
                while let Some((start, index)) = mentions.next_if(|&(start, _)| start < segment.end)
                {
                    let mention = &tags.mentions[index];
                    let origin = SpanOrigin::SavedTag {
                        envelope,
                        index: index as u64,
                    };
                    let confidence = percent(mention.confidence);
                    let range = (start, mention.end);
                    let queued = self.span(
                        names.turn,
                        chunk.held,
                        range,
                        SpanKind::Name,
                        origin,
                        confidence,
                    );
                    queue_in_txn(store, txn, &queued, pass)?;
                }
            }
            at = segment.end;
            carry = segment.carry;
        }
        Ok(None)
    }

    /// Takes `bytes` off what the pass may still read.
    fn charge(&self, bytes: usize) {
        self.budget.set(self.budget.get().saturating_sub(bytes));
    }

    /// Whether the pass reads one more segment of `cost` bytes. A pass's
    /// first segment always reads, so every pass moves a read on; past it,
    /// a segment the bound cannot pay for ends the pass.
    fn reads_segment(&self, cost: usize) -> bool {
        if self.segmented.replace(true) && cost > self.budget.get() {
            self.budget.set(0);
            return false;
        }
        true
    }

    fn span(
        &self,
        turn: &EntityId,
        chunk: &ChunkRef,
        (start, end): (usize, usize),
        kind: SpanKind,
        origin: SpanOrigin,
        confidence: u8,
    ) -> SieveSpan {
        let (start, end) = (start as u64, end as u64);
        let mut id = blake3::Hasher::new();
        id.update(b"oneiron:dreamer-sieve:span:v2");
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
            entity: None,
            novel: None,
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

/// Writes a turn's reading; whether it is whole or reads on.
fn settle_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    read: SievedTurn,
) -> Result<Read> {
    READ.put(store, txn, turn, &read)?;
    Ok(if read.next.is_some() {
        Read::Cut
    } else {
        Read::Whole
    })
}

/// Puts `span` in the queue and in its turn's list of spans.
fn queue_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    span: &SieveSpan,
    pass: &mut SievePass,
) -> Result<()> {
    let key = ((u32::MAX - span.score).to_be_bytes(), span.id);
    QUEUE.put(store, txn, &key, span)?;
    super::recipes::remember_in_txn(store, txn, span)?;
    let listed = (span.turn, key);
    if !SPANS.contains(store, txn, &listed)? {
        SPANS.put(store, txn, &listed, &())?;
        pass.spans_queued += 1;
    }
    Ok(())
}

fn percent(confidence: f32) -> u8 {
    if confidence.is_nan() {
        return 0;
    }
    let scaled = (confidence.clamp(0.0, 1.0) * 100.0).round();
    // In range by the clamp above.
    scaled as u8
}

/// The version of a tag set: every field of its envelope. The served stack
/// is one, so a head swap at a fixed checkpoint is another derivation and
/// owes the turn a new read; a stack absent and a stack named empty differ.
pub(super) fn envelope_digest(envelope: &crate::tagging::DerivationEnvelope) -> [u8; 32] {
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
    match &envelope.stack {
        Some(stack) => {
            hash.update(&[1]);
            hash.update(&(stack.len() as u64).to_be_bytes());
            hash.update(stack.as_bytes());
        }
        None => {
            hash.update(&[0]);
        }
    }
    *hash.finalize().as_bytes()
}
