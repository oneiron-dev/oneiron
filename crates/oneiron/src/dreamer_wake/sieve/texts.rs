//! The sieve pass's read phase (FIX 11568): its text reads, made in a read
//! snapshot before its writer opens, and the scans the pass and the read
//! phase share. A read the snapshot did not make is made live in the writer.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

use super::chunks::{TurnChunks, chunk_text_in_txn, turn_chunks_in_txn};
use super::{
    CONTINUE, CURSOR, OWED, READ, RETRY, SieveCursor, SievePass, Sweep, WITHHELD, first_keys,
    sieved_turn_in_txn,
};
use crate::dreamer_wake::read_phase::{OnStale, ReadWrite, WakeStop, read_then_write};
use crate::error::Result;
use crate::ports::{EntityStoreRead, EntityTime, TimelineQuery};
use crate::store::Store;
use crate::tagging::TurnTags;
use crate::{EntityId, Vault};

/// The pass's prefetched text reads: turn chunks, tag sets and resume
/// texts, each taken once by the pass that reads them.
#[derive(Default)]
pub(super) struct SieveTexts {
    chunks: RefCell<BTreeMap<EntityId, Option<TurnChunks>>>,
    tags: RefCell<BTreeMap<EntityId, (Option<TurnTags>, usize)>>,
    texts: RefCell<BTreeMap<(EntityId, EntityId), Option<String>>>,
}

impl SieveTexts {
    /// The chunks of `turn`, prefetched or live.
    pub(super) fn turn_chunks(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<Option<TurnChunks>> {
        let hit = self.chunks.borrow_mut().remove(turn);
        if let Some(cached) = hit {
            return Ok(cached);
        }
        turn_chunks_in_txn(vault, txn, turn)
    }

    /// The tags of `turn`, prefetched or live.
    pub(super) fn current_tags(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<(Option<TurnTags>, usize)> {
        let hit = self.tags.borrow_mut().remove(turn);
        if let Some(cached) = hit {
            return Ok(cached);
        }
        crate::tagging::current_tags_in_txn(vault, txn, turn)
    }

    /// The text of `source` as a chunk of `turn`, prefetched or live.
    pub(super) fn chunk_text(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
        source: &EntityId,
    ) -> Result<Option<String>> {
        let hit = self.texts.borrow_mut().remove(&(*turn, *source));
        if let Some(cached) = hit {
            return Ok(cached);
        }
        chunk_text_in_txn(vault, txn, turn, source)
    }

    /// Prefetches the pass's text reads without writing, in the pass's own
    /// order and bounds; `None` when `stop` stopped it. A miss only costs a
    /// live read in the writer, so the bounds decide speed, never results.
    pub(super) fn read_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        stop: WakeStop<'_>,
    ) -> Result<Option<Self>> {
        if stop.stopped() {
            return Ok(None);
        }
        let policy = super::policy::policy_in_txn(vault, txn)?;
        let retry = RETRY.get(&vault.store, txn, &())?.unwrap_or_default();
        let cursor = CURSOR.get(&vault.store, txn, &())?;
        let max_turns = policy.max_turns_per_pass as usize;
        let max_scan = policy.max_scan_per_pass as usize;
        let max_bytes = policy.max_text_bytes_per_pass as usize;
        let continuing = first_keys(&vault.store, txn, &CONTINUE, max_turns)?;
        let owed = first_keys(&vault.store, txn, &OWED, max_turns)?;
        let late = match cursor {
            Some(at) => late_ids_in_txn(vault, txn, at)?,
            None => Vec::new(),
        };
        let new: Vec<EntityId> = new_entries_in_txn(vault, txn, cursor, max_scan)?
            .into_iter()
            .map(|entry| entry.id)
            .collect();
        let withheld: Vec<EntityId> = if retry.done < retry.epoch {
            let sweep = retry.sweep.unwrap_or(Sweep {
                epoch: retry.epoch,
                after: None,
            });
            withheld_rows_in_txn(&vault.store, txn, sweep.after, max_scan)?
                .into_iter()
                .filter(|(_, epoch)| *epoch < sweep.epoch)
                .map(|(turn, _)| turn)
                .collect()
        } else {
            Vec::new()
        };
        let texts = Self::default();
        let mut prefetched = BTreeSet::new();
        let mut turns = 0;
        let mut bytes = 0;
        for turn in &continuing {
            if stop.stopped() {
                return Ok(None);
            }
            if prefetched.contains(turn) {
                continue;
            }
            if crate::tagging::tagged_messages_absent_in_txn(&vault.store, txn, turn)? {
                continue;
            }
            if !sieved_turn_in_txn(vault, txn, turn)? {
                continue;
            }
            let resume = match (
                CONTINUE.get(&vault.store, txn, turn)?,
                READ.get(&vault.store, txn, turn)?,
            ) {
                (Some(held), Some(read)) => {
                    let len = held.len();
                    read.next
                        .filter(|from| from.chunk < len)
                        .map(|from| (held, from))
                }
                _ => None,
            };
            if let Some((held, from)) = resume {
                for chunk in &held[from.chunk..] {
                    let text = chunk_text_in_txn(vault, txn, turn, &chunk.source)?;
                    if let Some(text) = &text {
                        bytes = bytes.saturating_add(text.len());
                    }
                    texts.texts.borrow_mut().insert((*turn, chunk.source), text);
                }
            } else {
                bytes = bytes.saturating_add(texts.prefetch_turn(vault, txn, turn)?);
            }
            prefetched.insert(*turn);
            turns += 1;
            if turns >= max_turns || bytes >= max_bytes {
                return Ok(Some(texts));
            }
        }
        let rest = owed
            .iter()
            .map(|turn| (*turn, false))
            .chain(late.iter().map(|turn| (*turn, true)))
            .chain(new.iter().map(|turn| (*turn, true)))
            .chain(withheld.iter().map(|turn| (*turn, false)));
        for (turn, check_read) in rest {
            if stop.stopped() {
                return Ok(None);
            }
            if prefetched.contains(&turn) {
                continue;
            }
            if crate::tagging::tagged_messages_absent_in_txn(&vault.store, txn, &turn)? {
                continue;
            }
            if check_read && READ.contains(&vault.store, txn, &turn)? {
                continue;
            }
            if !sieved_turn_in_txn(vault, txn, &turn)? {
                continue;
            }
            bytes = bytes.saturating_add(texts.prefetch_turn(vault, txn, &turn)?);
            prefetched.insert(turn);
            turns += 1;
            if turns >= max_turns || bytes >= max_bytes {
                return Ok(Some(texts));
            }
        }
        Ok(Some(texts))
    }

    /// Prefetches `turn`'s chunks and, when it has words, its tags; returns
    /// the bytes counted.
    fn prefetch_turn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &EntityId,
    ) -> Result<usize> {
        let mut bytes = 0;
        let chunks = turn_chunks_in_txn(vault, txn, turn)?;
        if let Some(chunks) = &chunks {
            bytes = bytes.saturating_add(
                chunks
                    .chunks
                    .iter()
                    .map(|chunk| chunk.text.len())
                    .sum::<usize>(),
            );
            if !chunks.chunks.is_empty() {
                let (tags, hashed) = crate::tagging::current_tags_in_txn(vault, txn, turn)?;
                bytes = bytes.saturating_add(hashed);
                self.tags.borrow_mut().insert(*turn, (tags, hashed));
            }
        }
        self.chunks.borrow_mut().insert(*turn, chunks);
        Ok(bytes)
    }
}

/// One sieve pass and whether the follower woke in its commit.
pub(crate) struct SieveCommit {
    pub(crate) pass: SievePass,
    pub(crate) followed: bool,
}

impl Vault {
    /// Prefetches the pass's text reads in a read snapshot, then runs the
    /// pass in a short writer the commit generation guards; with `follow`
    /// the follower wakes in the same commit when spans queued (FIX 7510).
    /// `Stopped` when `stop` stopped the read phase and `Deferred` when
    /// every guarded try went stale, both with nothing written.
    pub(crate) fn sieve_pass_until(
        &self,
        now: u64,
        stop: WakeStop<'_>,
        on_stale: OnStale,
        follow: bool,
    ) -> Result<ReadWrite<SieveCommit>> {
        self.store.authorization_now()?;
        read_then_write(
            self,
            "sieve",
            on_stale,
            |txn| SieveTexts::read_in_txn(self, txn, stop),
            |txn, texts| {
                let pass = super::sieve_pass_in_txn(self, txn, now, &texts)?;
                let followed = follow
                    && pass.spans_queued > 0
                    && crate::dreamer_wake::follower::wake_queued_in_txn(self, txn, now)?;
                Ok(SieveCommit { pass, followed })
            },
        )
    }
}

/// The ids behind `at` in its own second, in id order: the pass and the
/// prefetch share them.
pub(super) fn late_ids_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    at: SieveCursor,
) -> Result<Vec<EntityId>> {
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
    Ok(behind)
}

/// The timeline rows after the cursor, at most `scan`: the pass and the
/// prefetch share them.
pub(super) fn new_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cursor: Option<SieveCursor>,
    scan: usize,
) -> Result<Vec<EntityTime>> {
    let query = TimelineQuery {
        after: cursor.map(|at| EntityTime {
            timestamp: at.learned_at,
            id: at.turn,
        }),
        ..Default::default()
    };
    vault
        .store
        .port_entity_timeline(txn, query)?
        .take(scan)
        .collect::<Result<Vec<_>>>()
}

/// The withheld rows after `after`, at most `scan`, in turn order: the pass
/// and the prefetch share them.
pub(super) fn withheld_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    after: Option<EntityId>,
    scan: usize,
) -> Result<Vec<(EntityId, u64)>> {
    WITHHELD
        .iter_range(
            store,
            txn,
            after.as_ref().map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        )?
        .take(scan)
        .collect::<Result<Vec<_>>>()
}
