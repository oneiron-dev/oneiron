//! Reader pins: a result body a reader holds is never deleted.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// The result bodies one vault handle's readers hold, counted by digest. In
/// memory only: no pin outlives the process that reads.
/// A clone shares the table: the store's writers and the vault's readers
/// and collector meet in one (FIX 22101).
#[derive(Clone, Default)]
pub struct ResultBodyPins {
    pub counts: Arc<Mutex<PinCounts>>,
}

/// Issued search-credit windows kept per vault handle (#4311 P1-B): one
/// latest entry per key, FIFO-evicted. Eviction only loses the FIX 1189
/// discount; a resume without it scans at its own bound.
const SEARCH_CREDIT_KEYS: usize = 64;

#[derive(Default)]
pub struct PinCounts {
    /// Holds on every body at once, by readers of a whole set.
    pub every: usize,
    pub bodies: HashMap<[u8; 32], usize>,
    /// The vault instance an off-record body was promoted as, before the
    /// save transaction that names it opened (KS-2A): kept while its pin
    /// is held, read by that transaction.
    pub promoted: HashMap<[u8; 32], [u8; 16]>,
    /// Detached line-index rebuilds one read noted (FIX 1186b), by digest.
    /// In memory only, like pins: a restart drops the queue and reads
    /// re-note.
    pub rebuild: HashMap<[u8; 32], RebuildEntry>,
    /// Latest issued scan-bound credit per window, by
    /// (raw body digest, window base, window len) to the exact emitted
    /// (offset, line, credit). Offsets are window-relative, so the window
    /// joins the key: the same relative tuple in another window attests
    /// different bytes. In memory only, like the pins beside it.
    pub search_credit: HashMap<([u8; 32], u64, u64), (u64, u64, u64)>,
    /// Insertion order of `search_credit` keys, oldest first.
    pub search_credit_order: VecDeque<([u8; 32], u64, u64)>,
    /// Body files a write transaction found unnamed (FIX 22101), by digest,
    /// then by file, to that transaction's id. A file goes once every live
    /// read transaction is at least that id, so no snapshot that still
    /// names it is left. A write that names a body holds a pin on it across
    /// its commit, so a pin dropping forgets its digest's notes: the body
    /// may be named again. In memory only: a restart leaves them to the
    /// orphan sweep.
    pub retiring: HashMap<[u8; 32], HashMap<RetiringFile, usize>>,
}

/// A body file the collector noted as unnamed (FIX 22101).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetiringFile {
    /// A released body whose rows went: its plain file and, in a sealed
    /// vault, the instance its key row named, each with its line index.
    Released(Option<[u8; 16]>),
    /// One directory entry: a body file with its line index, or (`index`)
    /// a line index whose body is gone.
    Entry {
        instance: Option<[u8; 16]>,
        index: bool,
    },
}

/// One queued line-index rebuild (FIX 1186b): the body's length from its
/// manifest and whether the sweep holds it in flight. Same digest means
/// same bytes means same length, so the digest keys the entry exactly.
#[derive(Clone, Copy)]
pub struct RebuildEntry {
    pub len: u64,
    pub in_flight: bool,
}

impl PinCounts {
    pub fn holds(&self, digest: &[u8; 32]) -> bool {
        self.every > 0 || self.bodies.contains_key(digest)
    }
}

pub fn lock(counts: &Mutex<PinCounts>) -> MutexGuard<'_, PinCounts> {
    counts.lock().unwrap_or_else(PoisonError::into_inner)
}

impl ResultBodyPins {
    /// Pins `digest`, or every body when `None`.
    pub fn pin(&self, digest: Option<[u8; 32]>) -> ResultBodyPin {
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
    pub fn promoted(&self, digest: &[u8; 32]) -> Option<[u8; 16]> {
        lock(&self.counts).promoted.get(digest).copied()
    }

    /// Notes the scan-bound credit this handle issued for the window
    /// (`digest`, `base`, `len`): the exact emitted (`offset`, `line`,
    /// `credit`). One latest value per key; a new key past the cap evicts
    /// the oldest, and replacing a key keeps its FIFO place.
    pub fn note_search_credit(
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
    pub fn valid_search_credit(
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

    /// Whether a reader holds `digest`, or every body.
    pub fn holds(&self, digest: &[u8; 32]) -> bool {
        lock(&self.counts).holds(digest)
    }

    /// Notes `file` of `digest` as unnamed by write transaction `since`
    /// (FIX 22101). A file noted again keeps its first note: a note stands
    /// only while no pin on its digest has dropped, so the file has stayed
    /// unnamed since. A released body's note replaces every older note of
    /// its digest: a body released again was named again in between.
    pub fn retire(&self, digest: [u8; 32], file: RetiringFile, since: usize) {
        let mut counts = lock(&self.counts);
        let notes = counts.retiring.entry(digest).or_default();
        if matches!(file, RetiringFile::Released(_)) {
            notes.retain(|_, noted| *noted >= since);
        }
        notes.entry(file).or_insert(since);
    }

    /// Forgets every note of `digest`: a writer names its file again (FIX
    /// 22101). A writer that files a body without a pin calls it before it
    /// commits; one that holds a pin across its commit needs not.
    pub fn named_again(&self, digest: &[u8; 32]) {
        lock(&self.counts).retiring.remove(digest);
    }

    /// Up to `limit` noted files `wanted` takes that may go now: no live
    /// reader can still see them named (`oldest`, the oldest live read
    /// transaction's id, is none or at least each one's note), and no
    /// reader holds their digest (FIX 22101). Beside them, how many other
    /// notes `wanted` takes wait for an older reader or a pin. They all stay
    /// noted until [`Self::remove_retiring`] or [`Self::forget_retiring`].
    pub fn due_retiring(
        &self,
        oldest: Option<usize>,
        limit: usize,
        wanted: impl Fn(&[u8; 32], &RetiringFile) -> bool,
    ) -> (Vec<([u8; 32], RetiringFile, usize)>, usize) {
        let counts = lock(&self.counts);
        let mut due = Vec::new();
        let mut waiting = 0;
        for (digest, files) in &counts.retiring {
            for (file, since) in files {
                if !wanted(digest, file) {
                    continue;
                }
                if oldest.is_none_or(|oldest| oldest >= *since) && !counts.holds(digest) {
                    if due.len() < limit {
                        due.push((*digest, *file, *since));
                    }
                } else {
                    waiting += 1;
                }
            }
        }
        (due, waiting)
    }

    /// Runs `remove` and forgets the note when `file` of `digest` is still
    /// noted as of `since` and no reader holds the digest, keeping new pins
    /// out until it returns (FIX 22101). `None` otherwise: a file a reader
    /// holds stays noted for a later pass, and one whose note a dropped pin
    /// forgot is left to the orphan sweep.
    pub fn remove_retiring<T>(
        &self,
        digest: &[u8; 32],
        file: RetiringFile,
        since: usize,
        remove: impl FnOnce() -> T,
    ) -> Option<T> {
        let mut counts = lock(&self.counts);
        if counts.holds(digest) {
            return None;
        }
        if counts
            .retiring
            .get(digest)
            .and_then(|files| files.get(&file))
            != Some(&since)
        {
            return None;
        }
        forget_in(&mut counts, digest, file);
        Some(remove())
    }

    /// Forgets the note on `file` of `digest`: a write names it again.
    pub fn forget_retiring(&self, digest: &[u8; 32], file: RetiringFile) {
        forget_in(&mut lock(&self.counts), digest, file);
    }

    /// Runs `remove` unless a reader holds `digest`, keeping new pins out
    /// until it returns: the collector's retirement of a body's rows and key
    /// row, then its unlink (FIX 5348). `None` when a reader holds it.
    pub fn unless_pinned<T>(&self, digest: &[u8; 32], remove: impl FnOnce() -> T) -> Option<T> {
        let counts = lock(&self.counts);
        (!counts.holds(digest)).then(remove)
    }
}

/// Drops the note on `file` of `digest`, and the digest's entry once it
/// notes nothing (FIX 22101).
fn forget_in(counts: &mut PinCounts, digest: &[u8; 32], file: RetiringFile) {
    let emptied = counts.retiring.get_mut(digest).is_some_and(|files| {
        files.remove(&file);
        files.is_empty()
    });
    if emptied {
        counts.retiring.remove(digest);
    }
}

/// One reader's hold on a result body, or on every body, given back when
/// dropped. Taken before the read transaction that finds the body's row and
/// held until its file is closed, it keeps the collector off row and file.
#[must_use = "a body stays pinned only while its pin is held"]
pub struct ResultBodyPin {
    pub counts: Arc<Mutex<PinCounts>>,
    pub digest: Option<[u8; 32]>,
}

impl ResultBodyPin {
    /// The body this pin holds; `None` for a pin on every body.
    pub fn digest(&self) -> Option<[u8; 32]> {
        self.digest
    }
}

impl Drop for ResultBodyPin {
    fn drop(&mut self) {
        let mut counts = lock(&self.counts);
        // A write that named the body held this pin across its commit, so
        // the collector's notes on it no longer hold (FIX 22101).
        match self.digest {
            Some(digest) => {
                counts.retiring.remove(&digest);
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
            None => {
                counts.retiring.clear();
                counts.every = counts.every.saturating_sub(1);
            }
        }
    }
}
