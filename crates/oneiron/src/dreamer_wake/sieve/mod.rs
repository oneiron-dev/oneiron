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
//! turn waits. A grant written later moves the grant epoch on, and a sweep
//! that keeps its place across passes reads the waiting turns again on what
//! a pass has left after new words, so a grant never holds new words back.
//! The queue serves a span only while the Dreamer may read its turn and its
//! source: a span whose MESSAGE grant is revoked after the read, or whose
//! TURN the Dreamer's policy read no longer reaches, stays queued, unserved,
//! until a grant lets the Dreamer read it again.
//!
//! One pass reads at most the policy row's bytes of text. A longer turn is
//! read a segment at a time (see [`rules`]) and keeps its place: the next
//! pass reads on from the segment it stopped at, from the chunks the read
//! holds, with nothing it has read read or hashed again, and each segment's
//! spans go in the queue as it reads, so a pass writes only what it read.

mod chunks;
mod policy;
mod read;
mod recipes;
pub use recipes::SieveAudit;
pub(crate) use recipes::*;
mod rules;
#[cfg(test)]
mod tests;
mod words;

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap};
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use chunks::{Admission, ChunkRef};
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
/// Each TURN's queued spans. Key: TURN id, then the span's queue key.
const SPANS: SideTable<(EntityId, QueueKey), (), Raw> =
    SideTable::new(&side_table::DREAMER_SIEVE_SPANS);
/// Turns owed a new read: new, changed words, newly saved tags. Key: TURN id.
const OWED: SideTable<EntityId, (), Raw> = SideTable::new(&side_table::DREAMER_SIEVE_OWED);
/// Turns whose read the text bound stopped, with the chunks it reads on in.
/// A change to the turn's words owes it a new read and drops this row.
/// Key: TURN id.
const CONTINUE: SideTable<EntityId, Vec<ChunkRef>, Named> =
    SideTable::new(&side_table::DREAMER_SIEVE_CONTINUE);
/// Turns read with a MESSAGE the Dreamer may not read, and the grant epoch
/// they were read at. Key: TURN id.
const WITHHELD: SideTable<EntityId, u64, Raw> = SideTable::new(&side_table::DREAMER_SIEVE_WITHHELD);
/// The grant epoch, and the sweep that reads the withheld turns again.
/// Key: ().
const RETRY: SideTable<(), Retry, Named> = SideTable::new(&side_table::DREAMER_SIEVE_RETRY);

type QueueKey = ([u8; 4], [u8; 32]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SieveCursor {
    learned_at: u64,
    turn: EntityId,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct SievedTurn {
    /// The version of the turn's words the read saw.
    reading: [u8; 32],
    names: NameSource,
    /// Where a reading the text bound stopped reads on; `None` once whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<Resume>,
}

/// A place in a turn's words: a chunk, the byte of its text a segment
/// starts at, and what the text before it leaves that segment's reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Resume {
    chunk: usize,
    at: usize,
    carry: rules::Carry,
}

impl Resume {
    /// Where chunk `index` reads from: here in the chunk the read stopped
    /// in, its start in a later one.
    fn within(self, index: usize) -> (usize, rules::Carry) {
        if index == self.chunk {
            (self.at, self.carry)
        } else {
            (0, rules::Carry::default())
        }
    }
}

/// The grant epoch, and how far the withheld turns have been read again.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct Retry {
    /// Moved on by every grant written.
    epoch: u64,
    /// Every withheld turn was read at this epoch or a later one.
    done: u64,
    /// The sweep under way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sweep: Option<Sweep>,
}

/// A sweep of the withheld turns: the epoch it reads them up to, and the
/// last turn it stepped over.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct Sweep {
    epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after: Option<EntityId>,
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
    /// A model-confirmed existing entity; unresolved spans remain topics.
    pub entity: Option<EntityId>,
    pub novel: Option<bool>,
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

/// What the interest queue serves. A span's words are the Dreamer's to
/// read only while its turn and its source are: a span whose TURN or
/// MESSAGE the Dreamer may no longer read, or that left its turn, stays
/// queued but is not served, and a later grant serves it again with no new
/// read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SieveQueue {
    /// The spans served, highest score first.
    pub spans: Vec<SieveSpan>,
    pub skipped: SieveSkipped,
}

/// The queued spans a readout passed over, by why.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SieveSkipped {
    /// The Dreamer's gate refuses the turn or the source now: a private
    /// row, a relationship row whose grant is revoked or expired, or a TURN
    /// its policy read no longer reaches.
    pub unreadable: usize,
    /// The source is no longer part of its turn, or it or its turn is
    /// archived or gone.
    pub detached: usize,
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

    /// The first `limit` spans of the interest queue whose source the
    /// Dreamer may read now, highest score first, and the spans passed over
    /// on the way. Every source is admitted under the Dreamer's current read
    /// in one snapshot, taken after the grant clock is persisted, and the
    /// readout holds no writer. It admits the queue a window at a time, each
    /// twice the last, so a long run of spans it may not serve costs the
    /// gate one call per window, not one per source.
    pub fn sieve_queue(&self, limit: usize) -> Result<SieveQueue> {
        // A grant is judged at a persisted clock floor, as a pass judges it.
        self.store.authorization_now()?;
        let txn = self.store.env.read_txn()?;
        let mut queue = SieveQueue::default();
        let mut admitted: HashMap<(EntityId, EntityId), Admission> = HashMap::new();
        let mut rows = QUEUE.iter_from(&self.store, &txn, &[])?;
        let mut window = limit;
        while queue.spans.len() < limit {
            let spans = rows
                .by_ref()
                .take(window)
                .map(|row| row.map(|(_, span)| span))
                .collect::<Result<Vec<SieveSpan>>>()?;
            if spans.is_empty() {
                break;
            }
            let unseen: Vec<(EntityId, EntityId)> = spans
                .iter()
                .map(|span| (span.turn, span.source))
                .filter(|pair| !admitted.contains_key(pair))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let admissions = chunks::admissions_in_txn(self, &txn, &unseen)?;
            admitted.extend(unseen.into_iter().zip(admissions));
            for span in spans {
                if queue.spans.len() >= limit {
                    break;
                }
                match admitted[&(span.turn, span.source)] {
                    Admission::Readable => queue.spans.push(span),
                    Admission::Unreadable => queue.skipped.unreadable += 1,
                    Admission::Detached => queue.skipped.detached += 1,
                }
            }
            window = window.saturating_mul(2);
        }
        Ok(queue)
    }
}

/// Owes `turn` a new read in the caller's transaction: its words or its saved
/// tags changed. A read the text bound stopped no longer goes on from the
/// chunks it holds; the new read goes on where it stopped only if the words
/// read the same.
pub(crate) fn owe_read_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    CONTINUE.delete(store, txn, turn)?;
    OWED.put(store, txn, turn, &())
}

/// A grant was written: it moves the grant epoch on, and the retry sweep
/// reads every turn withheld before it again, to take what it now lets the
/// Dreamer read.
pub(crate) fn grant_written_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    let mut retry = RETRY.get(store, txn, &())?.unwrap_or_default();
    retry.epoch += 1;
    RETRY.put(store, txn, &(), &retry)
}

/// Takes `turn` out of the sieve in an erasing transaction: its spans, its
/// reading and any read it was owed.
pub(crate) fn erase_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    retire_in_txn(store, txn, turn)?;
    recipes::forget_in_txn(store, txn, turn)?;
    OWED.delete(store, txn, turn)?;
    Ok(())
}

/// Takes a TURN a window demotion removes out of the sieve's working state,
/// in the remover's transaction (OF-534): its queued spans, its reading, the
/// read it goes on with, its wait for a grant and any read it was owed. The
/// turn is not erased, so its spans' history and every audit stay: a
/// pending audit still reads what the cheap path saw. A promotion that
/// brings the turn back owes it a read; the cursor has passed it.
#[cfg(feature = "sync")]
pub(crate) fn demote_turn_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
) -> Result<()> {
    let spans = SPANS.scan_keys(store, txn, turn.as_bytes())?;
    for (_, key) in &spans {
        QUEUE.delete(store, txn, key)?;
    }
    SPANS.delete_from(store, txn, turn.as_bytes())?;
    READ.delete(store, txn, turn)?;
    CONTINUE.delete(store, txn, turn)?;
    WITHHELD.delete(store, txn, turn)?;
    OWED.delete(store, txn, turn)?;
    Ok(())
}

/// One bounded pass, in the caller's transaction: a read the text bound
/// stopped reads on first, then the turns owed a read, then any turn that
/// landed in the cursor's own second behind it, then new turns past the
/// cursor, and last, on what the pass has left, the withheld turns a grant
/// may now let it read.
pub(crate) fn sieve_pass_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<SievePass> {
    // A grant is judged at a persisted clock floor, as a branch's read
    // snapshot judges it.
    crate::ports::observe_clock_floor_in_txn(&vault.store, txn)?;
    let policy = policy::policy_in_txn(vault, txn)?;
    let retry = RETRY.get(&vault.store, txn, &())?.unwrap_or_default();
    let reader = Reader {
        policy,
        policy_digest: policy.digest()?,
        rules: rules::Rules::new(),
        now,
        epoch: retry.epoch,
        budget: Cell::new(policy.max_text_bytes_per_pass as usize),
        segmented: Cell::new(false),
    };
    let mut pass = SievePass::default();
    let mut left = policy.max_turns_per_pass as usize;
    let continuing = first_keys(&vault.store, txn, &CONTINUE, left)?;
    if !reader.listed_in_txn(vault, txn, &continuing, true, &mut left, &mut pass)? {
        return Ok(pass);
    }
    let owed = first_keys(&vault.store, txn, &OWED, left)?;
    if !reader.listed_in_txn(vault, txn, &owed, false, &mut left, &mut pass)? {
        return Ok(pass);
    }
    let cursor = CURSOR.get(&vault.store, txn, &())?;
    if let Some(at) = cursor {
        left -= reader.sweep_late_in_txn(vault, txn, at, left, &mut pass)?;
    }
    left -= reader.scan_new_in_txn(vault, txn, cursor, left, &mut pass)?;
    reader.retry_in_txn(vault, txn, retry, left, &mut pass)?;
    Ok(pass)
}

/// The first `limit` turns of a table keyed by TURN id, and one more if
/// there is one, so a pass that takes `limit` knows work is left.
fn first_keys<V: 'static, C: side_table::SideCodec<V> + 'static>(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    table: &SideTable<EntityId, V, C>,
    limit: usize,
) -> Result<Vec<EntityId>> {
    table
        .iter_from(store, txn, &[])?
        .take(limit.saturating_add(1))
        .map(|row| row.map(|(turn, _)| turn))
        .collect()
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

/// Takes `turn` out of the sieve's reads: its reading, its spans, the read
/// it goes on with and its wait for a grant.
fn retire_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<usize> {
    WITHHELD.delete(store, txn, turn)?;
    retire_spans_in_txn(store, txn, turn)
}

/// Removes a turn's reading, every span it queued and the read it goes on
/// with; returns how many spans went.
fn retire_spans_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &EntityId) -> Result<usize> {
    recipes::retire_history_in_txn(store, txn, turn)?;
    let spans = SPANS.scan_keys(store, txn, turn.as_bytes())?;
    for (_, key) in &spans {
        QUEUE.delete(store, txn, key)?;
    }
    SPANS.delete_from(store, txn, turn.as_bytes())?;
    READ.delete(store, txn, turn)?;
    CONTINUE.delete(store, txn, turn)?;
    Ok(spans.len())
}

/// One pass's fixed inputs, and the text it may still read.
struct Reader {
    policy: SievePolicy,
    policy_digest: [u8; 32],
    rules: rules::Rules,
    now: u64,
    /// The grant epoch the pass reads at.
    epoch: u64,
    /// Bytes of text left under the policy row's bound.
    budget: Cell<usize>,
    /// Whether the pass has read a segment yet.
    segmented: Cell<bool>,
}

impl Reader {
    fn spent(&self) -> bool {
        self.budget.get() == 0
    }

    /// Reads `turns` in order while the pass lasts: reads that go on
    /// (`continues`), or turns owed a read. Returns whether the pass goes on
    /// past them.
    fn listed_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turns: &[EntityId],
        continues: bool,
        left: &mut usize,
        pass: &mut SievePass,
    ) -> Result<bool> {
        for turn in turns {
            if *left == 0 || self.spent() {
                pass.more = true;
                return Ok(false);
            }
            *left -= 1;
            // A listed turn is admitted as the scans admit it: a turn the
            // live sieve does not read (imported, or a role GATE-10 keeps
            // out) keeps no spans here.
            let read = if !sieved_turn_in_txn(vault, txn, turn)? {
                pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
                Read::Gone
            } else if continues {
                self.read_on_in_txn(vault, txn, turn, pass)?
            } else {
                self.read_in_txn(vault, txn, turn, pass)?
            };
            if !continues {
                OWED.delete(&vault.store, txn, turn)?;
            }
            // A read the text bound cut goes on first in the next pass.
            if read == Read::Cut {
                pass.more = true;
                return Ok(false);
            }
        }
        Ok(true)
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
                    pass.more = true;
                    return Ok(read + 1);
                }
            }
        }
        Ok(read)
    }

    /// Reads new turns past the cursor, at most `left`, and moves the cursor
    /// to the last row it stepped over; returns how many it read. A turn
    /// already read is stepped over: a new turn is owed its read from its
    /// birth, and a change is owed.
    fn scan_new_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        cursor: Option<SieveCursor>,
        left: usize,
        pass: &mut SievePass,
    ) -> Result<usize> {
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
                pass.more = true;
                break;
            }
        }
        pass.more |= entries.len() == scan && last == entries.last().copied();
        let Some(last) = last else {
            return Ok(read);
        };
        let cursor = SieveCursor {
            learned_at: last.timestamp,
            turn: last.id,
        };
        CURSOR.put(&vault.store, txn, &(), &cursor)?;
        Ok(read)
    }

    /// Reads again, on what the pass has left, the withheld turns read before
    /// the latest grant: a sweep in turn order that keeps its place across
    /// passes and steps over at most the policy row's scan of rows. A grant
    /// written mid-sweep starts another sweep once this one ends, so a grant
    /// neither restarts the sweep nor puts a turn ahead of new words.
    fn retry_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        mut retry: Retry,
        left: usize,
        pass: &mut SievePass,
    ) -> Result<()> {
        if retry.done >= retry.epoch {
            return Ok(());
        }
        let mut sweep = retry.sweep.unwrap_or(Sweep {
            epoch: retry.epoch,
            after: None,
        });
        let scan = self.policy.max_scan_per_pass as usize;
        let rows = WITHHELD
            .iter_range(
                &vault.store,
                txn,
                sweep
                    .after
                    .as_ref()
                    .map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            )?
            .take(scan)
            .collect::<Result<Vec<_>>>()?;
        let mut ended = rows.len() < scan;
        let mut read = 0;
        for (turn, epoch) in &rows {
            if read >= left || self.spent() {
                ended = false;
                break;
            }
            sweep.after = Some(*turn);
            if *epoch >= sweep.epoch {
                continue;
            }
            if sieved_turn_in_txn(vault, txn, turn)? {
                read += 1;
                // A cut read goes on first in the next pass.
                if self.read_in_txn(vault, txn, turn, pass)? == Read::Cut {
                    pass.more = true;
                }
            } else {
                pass.spans_retired += retire_in_txn(&vault.store, txn, turn)?;
            }
        }
        if ended {
            retry.done = sweep.epoch;
            retry.sweep = None;
        } else {
            retry.sweep = Some(sweep);
        }
        pass.more |= retry.done < retry.epoch;
        RETRY.put(&vault.store, txn, &(), &retry)
    }
}
