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
//! A new TURN is owed its first read in the transaction that writes it,
//! whatever time it claims. A turn is read again only when its words or its
//! saved tags change: the re-dirty door, a re-put of its TURN or MESSAGE
//! rows, the text publication doors (an entity document's write, its
//! restore, an idle revision) and the tag save owe it a read, and so does a
//! MESSAGE erased from it. The rows are derived and local, like the tag sets
//! they point at; the sieve keeps no copy of a tag, only its place in the
//! turn's tag set and the envelope it was read under.
//!
//! The sieve reads what the Dreamer may read. A MESSAGE that is private, or
//! a relationship row without the Dreamer's live grant, gives no span; its
//! turn waits, and a grant written later owes it a new read. One pass reads
//! at most the policy row's bytes of text: a longer turn stops at a line,
//! sentence or word end and keeps its place, and the next pass reads on.

mod chunks;
mod policy;
mod rules;
#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use chunks::{Chunk, TurnChunks, turn_chunks_in_txn};
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
/// Turns read with a MESSAGE the Dreamer may not read, owed again when a
/// grant is written. Key: TURN id.
const WITHHELD: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::DREAMER_SIEVE_WITHHELD);

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
    /// Where a reading the text bound stopped reads on; `None` once whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<Resume>,
}

/// A place in a turn's words: a chunk, and a byte of its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Resume {
    chunk: usize,
    at: usize,
}

/// How one turn's read ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Read {
    /// The turn reads gone, and its spans went.
    Gone,
    /// Its reading is whole.
    Whole,
    /// The pass's text bound stopped it: it reads on in the next pass.
    Cut,
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

/// A grant was written: every turn read with a MESSAGE the Dreamer could
/// not read is owed a new read, which takes what the grant now lets it.
pub(crate) fn grant_written_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    for turn in WITHHELD.scan_keys(store, txn, &[])? {
        OWED.put(store, txn, &turn, &())?;
    }
    Ok(())
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
    // A grant is judged at a persisted clock floor, as a branch's read
    // snapshot judges it.
    crate::ports::observe_clock_floor_in_txn(&vault.store, txn)?;
    let policy = policy::policy_in_txn(vault, txn)?;
    let reader = Reader {
        policy,
        policy_digest: policy.digest()?,
        rules: rules::Rules::new(),
        now,
        budget: Cell::new(policy.max_text_bytes_per_pass as usize),
    };
    let mut pass = SievePass::default();
    let mut left = policy.max_turns_per_pass as usize;
    let owed = OWED.scan_keys(&vault.store, txn, &[])?;
    for turn in owed.iter().take(left) {
        if reader.spent() {
            pass.more = true;
            return Ok(pass);
        }
        // An owed read admits the turn as the scans do: a turn the live
        // sieve does not read (imported, or a role GATE-10 keeps out) keeps
        // no spans here.
        let read = if sieved_turn_in_txn(vault, txn, turn)? {
            reader.read_in_txn(vault, txn, turn, &mut pass)?
        } else {
            pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
            Read::Gone
        };
        // A read the text bound cut stays owed; the next pass reads on.
        if read == Read::Cut {
            pass.more = true;
            return Ok(pass);
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
    WITHHELD.delete(store, txn, turn)?;
    let Some(held) = READ.get(store, txn, turn)? else {
        return Ok(0);
    };
    for key in &held.spans {
        QUEUE.delete(store, txn, key)?;
    }
    READ.delete(store, txn, turn)?;
    Ok(held.spans.len())
}

/// One pass's fixed inputs, and the text it may still read.
struct Reader {
    policy: SievePolicy,
    policy_digest: [u8; 32],
    rules: rules::Rules,
    now: u64,
    /// Bytes of text left under the policy row's bound.
    budget: Cell<usize>,
}

impl Reader {
    fn spent(&self) -> bool {
        self.budget.get() == 0
    }

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
            if read >= left || self.spent() {
                pass.more = true;
                break;
            }
            if READ.contains(&vault.store, txn, id)? || !sieved_turn_in_txn(vault, txn, id)? {
                continue;
            }
            // A turn that reads gone has nothing to hold its place; it costs
            // the budget nothing, so it can never keep a pass coming back.
            match self.read_in_txn(vault, txn, id, pass)? {
                Read::Gone => {}
                Read::Whole => read += 1,
                Read::Cut => {
                    OWED.put(&vault.store, txn, id, &())?;
                    pass.more = true;
                    return Ok(read + 1);
                }
            }
        }
        Ok(read)
    }

    /// Reads new turns past the cursor, at most `left`, and moves the cursor
    /// to the last row it stepped over. A turn already read is stepped over:
    /// a new turn is owed its read from its birth, and a change is owed.
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
            if read >= left || self.spent() {
                pass.more = true;
                break;
            }
            last = Some(*entry);
            if READ.contains(&vault.store, txn, &entry.id)?
                || !sieved_turn_in_txn(vault, txn, &entry.id)?
            {
                continue;
            }
            read += 1;
            if self.read_in_txn(vault, txn, &entry.id, pass)? == Read::Cut {
                OWED.put(&vault.store, txn, &entry.id, &())?;
                pass.more = true;
                break;
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
    /// source writes nothing; a new one replaces the turn's spans; a reading
    /// the text bound stopped reads on from where it stopped. A turn that
    /// reads gone loses its spans.
    fn read_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        pass: &mut SievePass,
    ) -> Result<Read> {
        let store = &vault.store;
        let Some(TurnChunks { chunks, withheld }) = turn_chunks_in_txn(vault, txn, turn)? else {
            pass.spans_retired += retire_in_txn(store, txn, turn)?;
            return Ok(Read::Gone);
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
        let (mut keys, from) = match READ.get(store, txn, turn)? {
            Some(held) if held.reading == reading && held.names == names => match held.next {
                None => return Ok(Read::Whole),
                Some(next) => (held.spans, next),
            },
            _ => {
                pass.spans_retired += retire_in_txn(store, txn, turn)?;
                pass.turns_read += 1;
                (Vec::new(), Resume { chunk: 0, at: 0 })
            }
        };
        // Words the Dreamer may not read wait for a grant.
        if withheld {
            WITHHELD.put(store, txn, turn, &())?;
        } else {
            WITHHELD.delete(store, txn, turn)?;
        }
        let tags = match (&tags, names) {
            (Some(tags), NameSource::SavedTags { envelope }) => Some((tags, envelope)),
            _ => None,
        };
        let before = keys.len();
        let (queued, next) = self.queue_from(vault, txn, turn, &chunks, tags, from)?;
        keys.extend(queued);
        keys.sort_unstable();
        keys.dedup();
        pass.spans_queued += keys.len().saturating_sub(before);
        let read = SievedTurn {
            reading,
            names,
            spans: keys,
            next,
        };
        READ.put(store, txn, turn, &read)?;
        Ok(if next.is_some() {
            Read::Cut
        } else {
            Read::Whole
        })
    }

    /// Queues the spans of `chunks` from `from` on, one slice at a time
    /// while the pass's text bound lasts. Returns their keys and where it
    /// stopped, `None` once the last chunk is read.
    fn queue_from(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: &EntityId,
        chunks: &[Chunk],
        tags: Option<(&crate::tagging::TurnTags, [u8; 32])>,
        from: Resume,
    ) -> Result<(Vec<QueueKey>, Option<Resume>)> {
        let mut keys = Vec::new();
        for (index, chunk) in chunks.iter().enumerate().skip(from.chunk) {
            let mut at = if index == from.chunk { from.at } else { 0 };
            if at >= chunk.text.len() {
                continue;
            }
            let code = rules::code_ranges(&chunk.text);
            while at < chunk.text.len() {
                let budget = self.budget.get();
                if budget == 0 {
                    return Ok((keys, Some(Resume { chunk: index, at })));
                }
                let end = slice_end(&chunk.text, at, budget);
                for span in self.slice_spans(turn, chunk, &code, (at, end), tags) {
                    let key = ((u32::MAX - span.score).to_be_bytes(), span.id);
                    QUEUE.put(&vault.store, txn, &key, &span)?;
                    keys.push(key);
                }
                self.budget.set(budget.saturating_sub(end - at));
                at = end;
            }
        }
        Ok((keys, None))
    }

    /// The spans of one slice `[from, to)` of a chunk: rule dates always,
    /// rule names only when no saved tags stand in for them, and the saved
    /// tag set's mentions that start in it, as refs into the tag set, which
    /// keeps their labels and links.
    fn slice_spans(
        &self,
        turn: &EntityId,
        chunk: &Chunk,
        code: &[(usize, usize)],
        (from, to): (usize, usize),
        tags: Option<(&crate::tagging::TurnTags, [u8; 32])>,
    ) -> Vec<SieveSpan> {
        let first = code.partition_point(|&(_, end)| end <= from);
        let local: Vec<(usize, usize)> = code[first..]
            .iter()
            .take_while(|&&(start, _)| start < to)
            .map(|&(start, end)| (start.max(from) - from, end.min(to) - from))
            .collect();
        let mut spans = Vec::new();
        for span in self.rules.spans(&chunk.text[from..to], &local) {
            let kind = if span.class.is_date() {
                SpanKind::Date
            } else if tags.is_none() {
                SpanKind::Name
            } else {
                continue;
            };
            let origin = SpanOrigin::Rule {
                rules: RULES_VERSION,
                class: span.class,
            };
            let confidence = self.policy.rule_confidence(span.class);
            let range = (from + span.start, from + span.end);
            spans.push(self.span(turn, chunk, range, kind, origin, confidence));
        }
        let Some((tags, envelope)) = tags else {
            return spans;
        };
        for (index, mention) in tags.mentions.iter().enumerate() {
            if mention.message != chunk.source
                || !(from..to).contains(&mention.start)
                || chunk.text.get(mention.start..mention.end).is_none()
            {
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

/// Where a slice of `text` read from `at` ends: within `budget` bytes, after
/// the last line break in reach, else the last sentence end, else the last
/// space. A word longer than the bound runs on to its end, so no word is cut.
fn slice_end(text: &str, at: usize, budget: usize) -> usize {
    let rest = &text[at..];
    if rest.len() <= budget {
        return text.len();
    }
    let mut reach = budget;
    while !rest.is_char_boundary(reach) {
        reach -= 1;
    }
    if reach == 0 {
        reach = rest.chars().next().map_or(rest.len(), char::len_utf8);
    }
    let window = &rest[..reach];
    let back = || window.char_indices().rev();
    let after = |found: Option<(usize, char)>| found.map(|(index, ch)| index + ch.len_utf8());
    let cut = after(back().find(|&(_, ch)| ch == '\n'))
        .or_else(|| after(back().find(|&(index, ch)| ends_sentence(window, index, ch))))
        .or_else(|| after(back().find(|&(_, ch)| ch.is_whitespace())));
    match cut {
        Some(cut) => at + cut,
        None => rest[reach..]
            .find(char::is_whitespace)
            .map_or(text.len(), |space| at + reach + space),
    }
}

/// Whether the character at `index` of `text` ends a sentence: a CJK full
/// stop, or `.`, `!` or `?` before a space.
fn ends_sentence(text: &str, index: usize, ch: char) -> bool {
    matches!(ch, '。' | '！' | '？')
        || (matches!(ch, '.' | '!' | '?') && text[index + 1..].starts_with(char::is_whitespace))
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
