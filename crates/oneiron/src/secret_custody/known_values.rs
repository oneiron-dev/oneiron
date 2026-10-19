//! The known-value index (OF-560 C): a value custody holds, or a reveal
//! delivered, that comes back in a later write, a model reply or a run's
//! output is replaced by its EXISTING handle, never minted again.
//!
//! The index keeps no plaintext. Each custody write records, under the
//! record's id, its value's byte length, a keyed fingerprint of the whole
//! value and a keyed tag of its first bytes (all of a value shorter than
//! the tag's window), for each generation the record held. Both keys derive
//! from one random key this node minted, in its own `vault_meta` row that no
//! export, checkpoint image or sync carries; without it a fingerprint cannot
//! be tested against a guess. A match reads the incoming bytes: each window
//! whose tag is known is fingerprinted at each length that tag holds,
//! longest first, and the leftmost match wins. Every non-empty value is
//! indexed, however short (FIX 5270): a short one masks text that merely
//! contains it, as custody holds it. An empty body is a revoked record's
//! absent value, never a match.
//!
//! The index is derived and node-local: it rebuilds as each custody record is
//! written here, a revoked record keeps its entries (its value is still
//! masked, never used), and a rotated one keeps every generation it held. A
//! checkpoint restore carries neither the key nor the entries: the restore
//! rebuild mints a new key and indexes each value the restored custody
//! records hold, and a writer that finds no key while custody records hold
//! values does the same in its own transaction, once
//! ([`KnownValues::load_backfilled_in_txn`]). A value erased or rotated away
//! before the checkpoint is not masked after the restore (FIX 5270).

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::codec::decode_secret_custody_body;
use super::doors::read_secret_custody_in_txn;
use super::types::SecretCustodyRecord;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::vault::Vault;

/// The shortest value matched exactly: every non-empty value (FIX 5270). An
/// empty body is a revoked record's absent value. One constant, so a ruling
/// changes one line.
pub const KNOWN_VALUE_MIN_BYTES: usize = 1;

/// How many of a value's first bytes its tag keys: all of a shorter value's.
/// A window this long keeps each tag's candidates few.
const TAG_WINDOW: usize = 12;

/// How many bytes of a value's first window its tag keeps.
const TAG_BYTES: usize = 8;

const FINGERPRINT_CONTEXT: &str = "oneiron secret_custody known-value fingerprint v1";
const TAG_CONTEXT: &str = "oneiron secret_custody known-value tag v1";

/// The node's key over every fingerprint the index holds. Key: ().
const KNOWN_KEY: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::SECRET_KNOWN_VALUE_KEY_LOCAL);

/// Each custody record's known values, by the record's id.
const KNOWN: SideTable<EntityId, KnownRow, Named> = SideTable::new(&side_table::SECRET_KNOWN_VALUE);

/// One record's known values: one entry per generation it held.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct KnownRow {
    entries: Vec<KnownEntry>,
}

/// One value, as the index keeps it: no plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct KnownEntry {
    generation: u32,
    len: u32,
    tag: [u8; TAG_BYTES],
    fingerprint: [u8; 32],
}

/// The two keys derived from the node's key.
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

/// Records `rec`'s value under `id`, in the custody write's transaction. The
/// node's key is minted on the first value it keys.
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
    let key = match KNOWN_KEY.get(store, wtxn, &())? {
        Some(key) => Zeroizing::new(key),
        None => {
            let mut key = Zeroizing::new([0_u8; 32]);
            OsRng.fill_bytes(&mut *key);
            KNOWN_KEY.put(store, wtxn, &(), &*key)?;
            key
        }
    };
    let keys = Keys::derive(&key);
    let entry = KnownEntry {
        generation: rec.rotation_generation,
        len: u32::try_from(value.len())
            .map_err(|_| Error::ArithmeticOverflow("known value length"))?,
        tag: keys.tag(&value[..value.len().min(TAG_WINDOW)]),
        fingerprint: keys.fingerprint(value),
    };
    let mut row = KNOWN.get(store, wtxn, id)?.unwrap_or_default();
    if row.entries.contains(&entry) {
        return Ok(());
    }
    row.entries.push(entry);
    KNOWN.put(store, wtxn, id, &row)
}

/// Indexes the value of the restored custody record `id`, whose body is
/// `body`, as a checkpoint restore rebuilds the node's index (FIX 5270): the
/// image carries neither the key nor the entries. Entries this node already
/// holds stay. A body that does not decode is left out, logged by kind.
pub(crate) fn reindex_restored_known_value_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    body: &[u8],
) -> Result<()> {
    match decode_secret_custody_body(body) {
        Ok(rec) => remember_in_txn(store, wtxn, id, &rec),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "a restored custody record was left out of the known-value index"
            );
            Ok(())
        }
    }
}

/// Indexes every value the custody records in `wtxn` hold, when this node
/// has no index key yet (FIX 5270): a restored or carried-in vault whose
/// records were never written here. The first value mints the key, so it
/// runs once; entries already held stay. A record that does not read is
/// left out, logged by kind.
fn backfill_in_txn(store: &Store, wtxn: &mut RwTxn<'_>) -> Result<()> {
    if KNOWN_KEY.get(store, wtxn, &())?.is_some() {
        return Ok(());
    }
    let ids = store
        .port_entity_ids_by_type(wtxn, ENTITY_TYPE_SECRET_CUSTODY, None)?
        .collect::<Result<Vec<_>>>()?;
    for id in ids {
        match read_secret_custody_in_txn(store, wtxn, &id) {
            Ok(Some(rec)) => remember_in_txn(store, wtxn, &id, &rec)?,
            Ok(None) => {}
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a custody record was left out of the known-value index"
            ),
        }
    }
    Ok(())
}

/// One value the index knows, as a match reads it.
struct Known {
    len: usize,
    fingerprint: [u8; 32],
    custody: EntityId,
    handle: String,
}

/// The index, loaded for one pass over incoming bytes.
pub(crate) struct KnownValues {
    keys: Keys,
    /// Candidates by the tag of their first window, longest first.
    by_tag: HashMap<[u8; TAG_BYTES], Vec<Known>>,
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
    /// The index as `txn` reads it, or `None` when it knows no value. A
    /// value two records hold is matched to the first in id order; a record
    /// with no handle is skipped.
    pub(crate) fn load_in_txn(store: &Store, txn: &RoTxn<'_>) -> Result<Option<Self>> {
        let Some(key) = KNOWN_KEY.get(store, txn, &())? else {
            return Ok(None);
        };
        let key = Zeroizing::new(key);
        let mut by_tag: HashMap<[u8; TAG_BYTES], Vec<Known>> = HashMap::new();
        let mut windows = Vec::new();
        let mut longest = 0;
        for (custody, row) in KNOWN.scan(store, txn)? {
            let Some((handle, _)) =
                crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, &custody)?
            else {
                continue;
            };
            for entry in row.entries {
                let len = entry.len as usize;
                // An empty value is absent: it never matches.
                if len == 0 {
                    continue;
                }
                let window = len.min(TAG_WINDOW);
                if !windows.contains(&window) {
                    windows.push(window);
                }
                let bucket = by_tag.entry(entry.tag).or_default();
                if bucket
                    .iter()
                    .any(|known| known.len == len && known.fingerprint == entry.fingerprint)
                {
                    continue;
                }
                longest = longest.max(len);
                bucket.push(Known {
                    len,
                    fingerprint: entry.fingerprint,
                    custody,
                    handle: handle.clone(),
                });
            }
        }
        if by_tag.is_empty() {
            return Ok(None);
        }
        for bucket in by_tag.values_mut() {
            bucket.sort_by_key(|known| std::cmp::Reverse(known.len));
        }
        windows.sort_unstable();
        Ok(Some(Self {
            keys: Keys::derive(&key),
            by_tag,
            windows,
            longest,
        }))
    }

    /// [`Self::load_in_txn`] for a writer: when this node has no index key
    /// yet while custody records hold values, it indexes them first, in
    /// `wtxn`, once (FIX 5270).
    pub(crate) fn load_backfilled_in_txn(
        store: &Store,
        wtxn: &mut RwTxn<'_>,
    ) -> Result<Option<Self>> {
        backfill_in_txn(store, wtxn)?;
        Self::load_in_txn(store, wtxn)
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
            self.by_tag.get(&tag)?.iter().find(|known| {
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

impl Vault {
    /// The known-value index as the store holds it now, for a sweep over
    /// what a run writes. `None` when it knows no value. When this node has
    /// no index key yet while custody records hold values, it indexes them
    /// first in a write transaction of its own, once (FIX 5270): call it
    /// outside any write transaction.
    pub(crate) fn known_values(&self) -> Result<Option<Arc<KnownValues>>> {
        {
            let txn = self.store.env.read_txn()?;
            if KNOWN_KEY.get(&self.store, &txn, &())?.is_some()
                || self
                    .store
                    .port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)?
                    .next()
                    .is_none()
            {
                return Ok(KnownValues::load_in_txn(&self.store, &txn)?.map(Arc::new));
            }
        }
        let mut wtxn = self.store.env.write_txn()?;
        let known = KnownValues::load_backfilled_in_txn(&self.store, &mut wtxn)?;
        wtxn.commit()?;
        Ok(known.map(Arc::new))
    }
}

/// A handle as a text stands it in for a value: `[secret sc12]`.
fn handle_text(handle: &str) -> String {
    format!("[secret {handle}]")
}

/// A stream's sweep: what each frame forwards once its known values are
/// replaced, holding back the bytes a value could still be arriving in.
pub(crate) struct KnownSweep {
    known: Arc<KnownValues>,
    held: Zeroizing<Vec<u8>>,
}

impl KnownSweep {
    pub(crate) fn new(known: Arc<KnownValues>) -> Self {
        Self {
            known,
            held: Zeroizing::new(Vec::new()),
        }
    }

    /// The bytes `frame` lets through: every value that starts far enough
    /// from the end to be whole is replaced, and the rest is held.
    pub(crate) fn feed(&mut self, frame: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(frame);
        let hold = self.known.longest().saturating_sub(1);
        if self.held.len() <= hold {
            return Vec::new();
        }
        let limit = self.held.len() - hold;
        let (out, end) = self.known.replaced_until(&self.held, limit);
        self.held.drain(..end).for_each(drop);
        out
    }

    /// What the stream's end lets through: the held bytes, replaced.
    pub(crate) fn tail(&self) -> Vec<u8> {
        self.known.replaced_until(&self.held, self.held.len()).0
    }
}
