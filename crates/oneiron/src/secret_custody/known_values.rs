//! The known-value index (OF-560 C): a value custody holds, or a reveal
//! delivered, that comes back in a later write, a model reply or a run's
//! output is replaced by its EXISTING handle, never minted again.
//!
//! The index keeps no plaintext. Each custody write records, under the
//! record's id, its value's byte length, a keyed fingerprint of the whole
//! value and a keyed tag of its first bytes (all of a value shorter than
//! the tag's window), for each value the record held. Both keys derive from
//! one random master key; without it a fingerprint cannot be tested against
//! a guess. A match reads the incoming bytes: each window whose tag is known
//! is fingerprinted at each length that tag holds, longest first, and the
//! leftmost match wins. Every non-empty value is indexed, however short (FIX
//! 5270): a short one masks text that merely contains it, as custody holds
//! it. An empty body is a revoked record's absent value, never a match.
//!
//! KS-3 (FIX 5684 = FIX 5503 card A): the master and every entry live in
//! typed custody (`store::known_history`), LMDB and every image keeping
//! references only. A revoked record keeps its entries (its value is still
//! masked, never used) and a rotated one keeps every value it held, so a
//! restore masks what the vault masked: one whose custody lacks an entry its
//! rows commit to refuses, never indexing the restored values again under a
//! new key. Only the holder's erase drops its entries; another record that
//! holds the same bytes keeps masking them.
//!
//! A pass holds the matcher for as long as it reads, and wipes it after: in
//! the writer it runs in ([`KnownValues::load_in_writer`]), or, for a
//! stream, once per frame through the ids the stream began with
//! ([`KnownSource`]), under the custody read guard.

use std::ops::Range;
use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use zeroize::{Zeroize, Zeroizing};

use super::types::SecretCustodyRecord;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::ShortIdStoreRead;
use crate::store::{KNOWN_TAG_BYTES, KnownEntry, KnownHistory, KnownHistoryIds, Store};
use crate::vault::Vault;

/// The shortest value matched exactly: every non-empty value (FIX 5270). An
/// empty body is a revoked record's absent value. One constant, so a ruling
/// changes one line.
pub const KNOWN_VALUE_MIN_BYTES: usize = 1;

/// How many of a value's first bytes its tag keys: all of a shorter value's.
/// A window this long keeps each tag's candidates few.
const TAG_WINDOW: usize = 12;

/// How many bytes of a value's first window its tag keeps.
const TAG_BYTES: usize = KNOWN_TAG_BYTES;

const FINGERPRINT_CONTEXT: &str = "oneiron secret_custody known-value fingerprint v1";
const TAG_CONTEXT: &str = "oneiron secret_custody known-value tag v1";

/// The two keys derived from the index's master.
struct Keys {
    fingerprint: Zeroizing<[u8; 32]>,
    tag: Zeroizing<[u8; 32]>,
}

impl Keys {
    fn derive(key: &[u8; 32]) -> Self {
        Self {
            fingerprint: Zeroizing::new(blake3::derive_key(FINGERPRINT_CONTEXT, key)),
            tag: Zeroizing::new(blake3::derive_key(TAG_CONTEXT, key)),
        }
    }

    fn fingerprint(&self, value: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.fingerprint, value).as_bytes()
    }

    /// The tag of a value's first window: its first [`TAG_WINDOW`] bytes, or
    /// all of a shorter value.
    fn tag(&self, window: &[u8]) -> [u8; TAG_BYTES] {
        tag_of(&blake3::keyed_hash(&self.tag, window))
    }
}

fn tag_of(hash: &blake3::Hash) -> [u8; TAG_BYTES] {
    let mut tag = [0; TAG_BYTES];
    tag.copy_from_slice(&hash.as_bytes()[..TAG_BYTES]);
    tag
}

/// Records `rec`'s value under `id`, in the custody write's transaction: its
/// entry, under the master key custody holds (minted with the first value),
/// is published to custody and referenced in `wtxn` (KS-3).
pub(super) fn remember_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    rec: &SecretCustodyRecord,
) -> Result<()> {
    let value = rec.value_bytes.as_slice();
    // An empty body is a revoked record's absent value: nothing to match.
    if value.len() < KNOWN_VALUE_MIN_BYTES {
        return Ok(());
    }
    let len =
        u32::try_from(value.len()).map_err(|_| Error::ArithmeticOverflow("known value length"))?;
    store.remember_known_entry_in_txn(wtxn, id, rec.rotation_generation, |master| {
        let keys = Keys::derive(master);
        KnownEntry {
            len,
            tag: keys.tag(&value[..value.len().min(TAG_WINDOW)]),
            fingerprint: keys.fingerprint(value),
        }
    })
}

/// One value the index knows, as a match reads it. Its fingerprint is
/// wiped when it drops.
struct Known {
    len: usize,
    fingerprint: [u8; 32],
    custody: EntityId,
    handle: String,
}

impl Drop for Known {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
    }
}

/// One tag's candidates, longest first.
struct Bucket {
    tag: [u8; TAG_BYTES],
    known: Vec<Known>,
}

impl Drop for Bucket {
    fn drop(&mut self) {
        self.tag.zeroize();
    }
}

/// The index, loaded for one pass over incoming bytes. Never kept past the
/// pass that loaded it: the writer it was read in, or one stream frame.
pub(crate) struct KnownValues {
    keys: Keys,
    /// Candidates by the tag of their first window, in tag order.
    buckets: Vec<Bucket>,
    /// Each tag window length some value has, ascending: [`TAG_WINDOW`], and
    /// the length of each shorter value.
    windows: Vec<usize>,
    longest: usize,
}

/// One known value in incoming bytes: where, the custody record that holds
/// it, and that record's handle.
pub(crate) struct KnownSpan<'k> {
    pub(crate) span: Range<usize>,
    pub(crate) custody: EntityId,
    pub(crate) handle: &'k str,
}

impl KnownValues {
    /// The matcher over `history`, or `None` when it knows no value. A value
    /// two records hold is matched to the first in id order; a record
    /// `handle_of` gives no handle is skipped.
    fn of(
        history: &KnownHistory,
        handle_of: impl Fn(&EntityId) -> Result<Option<String>>,
    ) -> Result<Option<Self>> {
        let mut buckets: Vec<Bucket> = Vec::new();
        let mut windows = Vec::new();
        let mut longest = 0;
        for (custody, entries) in &history.holders {
            let Some(handle) = handle_of(custody)? else {
                continue;
            };
            for entry in entries {
                let len = usize::try_from(entry.len)
                    .map_err(|_| Error::ArithmeticOverflow("known value length"))?;
                // An empty value is absent: it never matches.
                if len == 0 {
                    continue;
                }
                let window = len.min(TAG_WINDOW);
                if !windows.contains(&window) {
                    windows.push(window);
                }
                let at = match buckets.binary_search_by(|bucket| bucket.tag.cmp(&entry.tag)) {
                    Ok(at) => at,
                    Err(at) => {
                        buckets.insert(
                            at,
                            Bucket {
                                tag: entry.tag,
                                known: Vec::new(),
                            },
                        );
                        at
                    }
                };
                let bucket = &mut buckets[at];
                if bucket
                    .known
                    .iter()
                    .any(|known| known.len == len && known.fingerprint == entry.fingerprint)
                {
                    continue;
                }
                longest = longest.max(len);
                bucket.known.push(Known {
                    len,
                    fingerprint: entry.fingerprint,
                    custody: *custody,
                    handle: handle.clone(),
                });
            }
        }
        if buckets.is_empty() {
            return Ok(None);
        }
        for bucket in &mut buckets {
            bucket
                .known
                .sort_by_key(|known| std::cmp::Reverse(known.len));
        }
        windows.sort_unstable();
        Ok(Some(Self {
            keys: Keys::derive(&history.master),
            buckets,
            windows,
            longest,
        }))
    }

    /// The index as the writer `wtxn` reads it, for a pass inside that
    /// writer, or `None` when it knows no value (KS-3). The writer keeps the
    /// custody finisher from every entry, so no custody guard is taken: a
    /// caller holding a writer never takes one.
    pub(crate) fn load_in_writer(store: &Store, wtxn: &RwTxn<'_>) -> Result<Option<Self>> {
        let Some(history) = store.known_history_in_writer(wtxn)? else {
            return Ok(None);
        };
        let txn: &RoTxn<'_> = wtxn;
        Self::of(&history, |custody| {
            Ok(store
                .port_short_id_reference(txn, custody)?
                .map(|(handle, _)| handle))
        })
    }

    /// The longest value the index knows, in bytes.
    pub(crate) const fn longest(&self) -> usize {
        self.longest
    }

    /// Each known value in `data`, leftmost first, never overlapping: at
    /// each place the longest value there wins.
    pub(crate) fn spans(&self, data: &[u8]) -> Vec<KnownSpan<'_>> {
        let mut spans = Vec::new();
        let mut at = 0;
        while at < data.len() {
            match self.longest_at(&data[at..]) {
                Some(known) => {
                    spans.push(KnownSpan {
                        span: at..at + known.len,
                        custody: known.custody,
                        handle: &known.handle,
                    });
                    at += known.len;
                }
                None => at += 1,
            }
        }
        spans
    }

    /// The candidates whose first window has `tag`.
    fn bucket(&self, tag: &[u8; TAG_BYTES]) -> Option<&[Known]> {
        let at = self
            .buckets
            .binary_search_by(|bucket| bucket.tag.cmp(tag))
            .ok()?;
        Some(&self.buckets[at].known)
    }

    /// The longest known value `rest` starts with. Each window's tag is
    /// hashed once, the shorter ones on the way to the longer.
    fn longest_at(&self, rest: &[u8]) -> Option<&Known> {
        let mut hasher = blake3::Hasher::new_keyed(&self.keys.tag);
        let mut tags = [None; TAG_WINDOW];
        let mut hashed = 0;
        for &window in &self.windows {
            if window > rest.len() {
                break;
            }
            hasher.update(&rest[hashed..window]);
            hashed = window;
            tags[window - 1] = Some(tag_of(&hasher.finalize()));
        }
        self.windows.iter().rev().find_map(|&window| {
            let tag = tags[window - 1]?;
            self.bucket(&tag)?.iter().find(|known| {
                known.len.min(TAG_WINDOW) == window
                    && known.len <= rest.len()
                    && self.keys.fingerprint(&rest[..known.len]) == known.fingerprint
            })
        })
    }

    /// `data` with each known value replaced by its handle's text, as far
    /// as `limit`: a value that starts before it is replaced whole. Returns
    /// the bytes and where in `data` they end.
    fn replaced_until(&self, data: &[u8], limit: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::with_capacity(data.len());
        let mut from = 0;
        for known in self.spans(data) {
            if known.span.start >= limit {
                break;
            }
            out.extend_from_slice(&data[from..known.span.start]);
            out.extend_from_slice(handle_text(known.handle).as_bytes());
            from = known.span.end;
        }
        let end = from.max(limit);
        out.extend_from_slice(&data[from..end]);
        (out, end)
    }
}

/// What a stream's sweep reads known values through (KS-3): the ids and
/// handles of the history the index held when the stream began, never a
/// payload. Each pass reads the entries again under the custody read guard
/// and wipes them before it returns, so no erase waits on a stream and no
/// fingerprint outlives a pass; an entry retired since, or a holder whose
/// erase is staged, is passed over.
#[derive(Clone)]
pub(crate) struct KnownSource {
    ids: KnownHistoryIds,
    /// Each holder's handle, holders in id order.
    handles: Vec<(EntityId, String)>,
}

impl KnownSource {
    fn handle(&self, custody: &EntityId) -> Option<String> {
        let at = self
            .handles
            .binary_search_by(|(held, _)| held.cmp(custody))
            .ok()?;
        Some(self.handles[at].1.clone())
    }

    /// Runs `use_pass` over the index this source names, read now.
    fn pass<T>(&self, use_pass: impl FnOnce(Option<&KnownValues>) -> T) -> Result<T> {
        self.ids.with_history(|history| {
            let known = match history {
                Some(history) => KnownValues::of(history, |custody| Ok(self.handle(custody)))?,
                None => None,
            };
            Ok(use_pass(known.as_ref()))
        })
    }
}

impl Vault {
    /// What a stream's sweep over what a run writes reads known values
    /// through (KS-3): the ids and handles of the history the index holds
    /// now, read under the custody read guard. `None` when it knows no
    /// value. Its passes take the custody read guard: feed it outside any
    /// write transaction.
    pub(crate) fn known_source(&self) -> Result<Option<KnownSource>> {
        let snapshot = self.store.custody_snapshot()?;
        let txn: &RoTxn<'_> = &snapshot;
        let Some(ids) = self.store.known_history_ids_in_txn(txn)? else {
            return Ok(None);
        };
        let mut handles = Vec::new();
        for holder in ids.holders() {
            // A record with no handle is skipped, as a pass skips it.
            if let Some((handle, _)) = self.store.port_short_id_reference(txn, holder)? {
                handles.push((*holder, handle));
            }
        }
        if handles.is_empty() {
            return Ok(None);
        }
        Ok(Some(KnownSource { ids, handles }))
    }
}

/// A handle as a text stands it in for a value: `[secret sc12]`.
fn handle_text(handle: &str) -> String {
    format!("[secret {handle}]")
}

/// Where a sweep's passes read: a stream's source, or the index its
/// caller's writer read, for a sink fed inside that writer.
enum SweepFrom {
    Source(KnownSource),
    Writer(Arc<KnownValues>),
}

impl SweepFrom {
    fn pass<T>(&self, use_pass: impl FnOnce(Option<&KnownValues>) -> T) -> Result<T> {
        match self {
            Self::Source(source) => source.pass(use_pass),
            Self::Writer(known) => Ok(use_pass(Some(&**known))),
        }
    }
}

/// A stream's sweep: what each frame forwards once its known values are
/// replaced, holding back the bytes a value could still be arriving in.
pub(crate) struct KnownSweep {
    from: SweepFrom,
    held: Zeroizing<Vec<u8>>,
}

impl KnownSweep {
    /// A sweep that reads `source` once per frame (KS-3).
    pub(crate) fn new(source: KnownSource) -> Self {
        Self {
            from: SweepFrom::Source(source),
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// A sweep fed inside the writer `known` was read in
    /// ([`KnownValues::load_in_writer`]), dropped before that writer ends.
    pub(crate) fn in_writer(known: Arc<KnownValues>) -> Self {
        Self {
            from: SweepFrom::Writer(known),
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// The bytes `frame` lets through: every value that starts far enough
    /// from the end to be whole is replaced, and the rest is held. With no
    /// value left to know, everything held goes through.
    pub(crate) fn feed(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.held.extend_from_slice(frame);
        let held = &mut self.held;
        self.from.pass(|known| {
            let Some(known) = known else {
                return held.drain(..).collect::<Vec<u8>>();
            };
            let hold = known.longest().saturating_sub(1);
            if held.len() <= hold {
                return Vec::new();
            }
            let limit = held.len() - hold;
            let (out, end) = known.replaced_until(&held[..], limit);
            held.drain(..end).for_each(drop);
            out
        })
    }

    /// What the stream's end lets through: the held bytes, replaced.
    pub(crate) fn tail(&self) -> Result<Vec<u8>> {
        self.from.pass(|known| match known {
            Some(known) => known.replaced_until(&self.held, self.held.len()).0,
            None => self.held.to_vec(),
        })
    }
}
