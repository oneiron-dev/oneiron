//! Reader pins: a result body a reader holds is never deleted.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The result bodies one vault handle's readers hold, counted by digest. In
/// memory only: no pin outlives the process that reads.
#[derive(Default)]
pub(crate) struct ResultBodyPins {
    counts: Arc<Mutex<PinCounts>>,
}

/// Issued search-credit windows kept per vault handle (#4311 P1-B): one
/// latest entry per key, FIFO-evicted. Eviction only loses the FIX 1189
/// discount; a resume without it scans at its own bound.
const SEARCH_CREDIT_KEYS: usize = 64;

#[derive(Default)]
struct PinCounts {
    /// Holds on every body at once, by readers of a whole set.
    every: usize,
    bodies: HashMap<[u8; 32], usize>,
    /// The vault instance an off-record body was promoted as, before the
    /// save transaction that names it opened (KS-2A): kept while its pin
    /// is held, read by that transaction.
    promoted: HashMap<[u8; 32], [u8; 16]>,
    /// Detached line-index rebuilds one read noted (FIX 1186b), by digest.
    /// In memory only, like pins: a restart drops the queue and reads
    /// re-note.
    rebuild: HashMap<[u8; 32], RebuildEntry>,
    /// Latest issued scan-bound credit per window, by
    /// (raw body digest, window base, window len) to the exact emitted
    /// (offset, line, credit). Offsets are window-relative, so the window
    /// joins the key: the same relative tuple in another window attests
    /// different bytes. In memory only, like the pins beside it.
    search_credit: HashMap<([u8; 32], u64, u64), (u64, u64, u64)>,
    /// Insertion order of `search_credit` keys, oldest first.
    search_credit_order: VecDeque<([u8; 32], u64, u64)>,
}

/// One queued line-index rebuild (FIX 1186b): the body's length from its
/// manifest and whether the sweep holds it in flight. Same digest means
/// same bytes means same length, so the digest keys the entry exactly.
#[derive(Clone, Copy)]
struct RebuildEntry {
    len: u64,
    in_flight: bool,
}

impl PinCounts {
    fn holds(&self, digest: &[u8; 32]) -> bool {
        self.every > 0 || self.bodies.contains_key(digest)
    }
}

fn lock(counts: &Mutex<PinCounts>) -> MutexGuard<'_, PinCounts> {
    counts.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ResultBodyPins {
    /// Pins `digest`, or every body when `None`.
    fn pin(&self, digest: Option<[u8; 32]>) -> ResultBodyPin {
        let mut counts = lock(&self.counts);
        match digest {
            Some(digest) => *counts.bodies.entry(digest).or_insert(0) += 1,
            None => counts.every += 1,
        }
        drop(counts);
        ResultBodyPin {
            counts: Arc::clone(&self.counts),
            digest,
        }
    }

    /// The vault instance the body `digest` was promoted as, while the pin
    /// its promotion took is held.
    pub(crate) fn promoted(&self, digest: &[u8; 32]) -> Option<[u8; 16]> {
        lock(&self.counts).promoted.get(digest).copied()
    }

    /// Notes the scan-bound credit this handle issued for the window
    /// (`digest`, `base`, `len`): the exact emitted (`offset`, `line`,
    /// `credit`). One latest value per key; a new key past the cap evicts
    /// the oldest, and replacing a key keeps its FIFO place.
    fn note_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) {
        let mut counts = lock(&self.counts);
        let key = (digest, base, len);
        if !counts.search_credit.contains_key(&key) {
            while counts.search_credit.len() >= SEARCH_CREDIT_KEYS {
                match counts.search_credit_order.pop_front() {
                    Some(oldest) => {
                        counts.search_credit.remove(&oldest);
                    }
                    None => break,
                }
            }
            counts.search_credit_order.push_back(key);
        }
        counts.search_credit.insert(key, (offset, line, credit));
    }

    /// Whether (`offset`, `line`, `credit`) is the tuple this handle last
    /// issued for the window (`digest`, `base`, `len`). Any mismatch, miss,
    /// or eviction reads as no discount; the resume then scans at its own
    /// bound.
    fn valid_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) -> bool {
        lock(&self.counts)
            .search_credit
            .get(&(digest, base, len))
            .is_some_and(|&issued| issued == (offset, line, credit))
    }

    /// Runs `remove` unless a reader holds `digest`, keeping new pins out
    /// until it returns: the collector's retirement of a body's rows and key
    /// row, then its unlink (FIX 5348). `None` when a reader holds it.
    pub(crate) fn unless_pinned<T>(
        &self,
        digest: &[u8; 32],
        remove: impl FnOnce() -> T,
    ) -> Option<T> {
        let counts = lock(&self.counts);
        (!counts.holds(digest)).then(remove)
    }
}

/// One reader's hold on a result body, or on every body, given back when
/// dropped. Taken before the read transaction that finds the body's row and
/// held until its file is closed, it keeps the collector off row and file.
#[must_use = "a body stays pinned only while its pin is held"]
pub(crate) struct ResultBodyPin {
    counts: Arc<Mutex<PinCounts>>,
    digest: Option<[u8; 32]>,
}

impl ResultBodyPin {
    /// The body this pin holds; `None` for a pin on every body.
    pub(crate) fn digest(&self) -> Option<[u8; 32]> {
        self.digest
    }
}

impl Drop for ResultBodyPin {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts);
        match self.digest {
            Some(digest) => {
                if let Entry::Occupied(mut held) = counts.bodies.entry(digest) {
                    let left = held.get().saturating_sub(1);
                    if left == 0 {
                        held.remove();
                        counts.promoted.remove(&digest);
                    } else {
                        *held.get_mut() = left;
                    }
                }
            }
            None => counts.every = counts.every.saturating_sub(1),
        }
    }
}

impl crate::Vault {
    /// Pins the result body `digest`: until the pin drops, the collector
    /// leaves its row and file alone. A reader takes it before the read
    /// transaction that finds the body's row and holds it until the file is
    /// closed.
    pub(crate) fn pin_result_body(&self, digest: [u8; 32]) -> ResultBodyPin {
        self.result_body_pins.pin(Some(digest))
    }

    /// [`Self::pin_result_body`] for a body an off-record promotion brought
    /// in as the vault instance `instance`, before the save transaction
    /// that names it opened: that transaction reads the instance while the
    /// pin is held (KS-2A).
    pub(crate) fn pin_promoted_result_body(
        &self,
        digest: [u8; 32],
        instance: [u8; 16],
    ) -> ResultBodyPin {
        let pin = self.result_body_pins.pin(Some(digest));
        lock(&self.result_body_pins.counts)
            .promoted
            .insert(digest, instance);
        pin
    }

    /// Pins every result body at once, for a reader that finds its bodies
    /// inside its read transaction (a checkpoint snapshot, an export). Taken
    /// before that transaction opens, held until its last file is closed.
    pub(crate) fn pin_all_result_bodies(&self) -> ResultBodyPin {
        self.result_body_pins.pin(None)
    }

    /// Notes the scan-bound search credit issued for the window (`digest`,
    /// `base`, `len`): the exact emitted (`offset`, `line`, `credit`), kept
    /// in memory on this handle only (FIX 1189 discount, #4311 P1-B).
    pub(crate) fn note_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) {
        self.result_body_pins
            .note_search_credit(digest, base, len, offset, line, credit);
    }

    /// Whether (`offset`, `line`, `credit`) is the credit this handle last
    /// issued for the window (`digest`, `base`, `len`): the full tuple must
    /// match, else the resume takes no discount.
    pub(crate) fn valid_search_credit(
        &self,
        digest: [u8; 32],
        base: u64,
        len: u64,
        offset: u64,
        line: u64,
        credit: u64,
    ) -> bool {
        self.result_body_pins
            .valid_search_credit(digest, base, len, offset, line, credit)
    }
}

impl crate::Vault {
    /// Notes a detached line-index rebuild for the body `digest`, `len` bytes
    /// long (FIX 1186b): a read whose lookup found no index calls this and
    /// scans as today. Insert-if-absent, whether queued or in flight, so a
    /// read during an in-flight rebuild is a no-op; only the sweep requeues
    /// a failure.
    pub(crate) fn note_body_line_index_rebuild(&self, digest: [u8; 32], len: u64) {
        lock(&self.result_body_pins.counts)
            .rebuild
            .entry(digest)
            .or_insert(RebuildEntry {
                len,
                in_flight: false,
            });
    }

    /// Begins up to `limit` queued rebuilds, marking them in flight without
    /// removing them: the sweep's in-flight set, one per body per handle.
    /// Entries already in flight stay out, so concurrent notes never double
    /// a body.
    pub(crate) fn begin_body_line_index_rebuilds(&self, limit: usize) -> Vec<([u8; 32], u64)> {
        let mut counts = lock(&self.result_body_pins.counts);
        let mut begun = Vec::new();
        for (digest, entry) in counts.rebuild.iter_mut() {
            if begun.len() >= limit {
                break;
            }
            if !entry.in_flight {
                entry.in_flight = true;
                begun.push((*digest, entry.len));
            }
        }
        begun
    }

    /// Finishes the rebuild for `digest`, after a rebuilt index or a terminal
    /// drop (already fixed, inline, gone): removes it, whether queued or in
    /// flight.
    pub(crate) fn finish_body_line_index_rebuild(&self, digest: &[u8; 32]) {
        lock(&self.result_body_pins.counts).rebuild.remove(digest);
    }

    /// Requeues the rebuild for `digest` after a failure, marking it queued
    /// again for the next sweep. A digest already finished stays finished.
    pub(crate) fn retry_body_line_index_rebuild(&self, digest: &[u8; 32]) {
        if let Some(entry) = lock(&self.result_body_pins.counts).rebuild.get_mut(digest) {
            entry.in_flight = false;
        }
    }

    /// Whether any rebuild waits queued (not in flight).
    pub(crate) fn has_queued_body_line_index_rebuilds(&self) -> bool {
        lock(&self.result_body_pins.counts)
            .rebuild
            .values()
            .any(|entry| !entry.in_flight)
    }
}
