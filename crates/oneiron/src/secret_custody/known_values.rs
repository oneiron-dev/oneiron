//! The known-value index (OF-560 C): a value custody holds, or a reveal
//! delivered, that comes back in a later write, a model reply or a run's
//! output is replaced by its EXISTING handle, never minted again.
//!
//! The index keeps no plaintext. Each custody write records, under the
//! record's id, its value's byte length, a keyed fingerprint of the whole
//! value and a keyed tag of its first [`KNOWN_VALUE_MIN_BYTES`] bytes, for
//! each generation the record held. Both keys derive from one random key this
//! node minted, in its own `vault_meta` row that no export, checkpoint image
//! or sync carries; without it a fingerprint cannot be tested against a
//! guess. A match reads the incoming bytes: each window whose tag is known
//! is fingerprinted at each length that tag holds, longest first, and the
//! leftmost match wins. A value shorter than the minimum is not indexed: it
//! would match text that merely contains it.
//!
//! The index is derived and node-local: it rebuilds as each custody record is
//! written here, a revoked record keeps its entries (its value is still
//! masked, never used), and a rotated one keeps every generation it held.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

use heed::{RoTxn, RwTxn};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::types::SecretCustodyRecord;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::vault::Vault;

/// The shortest value matched exactly. One constant, so a ruling changes one
/// line.
pub const KNOWN_VALUE_MIN_BYTES: usize = 12;

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

    /// The tag of a value's first window. Its caller passes exactly
    /// [`KNOWN_VALUE_MIN_BYTES`] bytes.
    fn tag(&self, window: &[u8]) -> [u8; TAG_BYTES] {
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&blake3::keyed_hash(&self.tag, window).as_bytes()[..TAG_BYTES]);
        tag
    }
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
        tag: keys.tag(&value[..KNOWN_VALUE_MIN_BYTES]),
        fingerprint: keys.fingerprint(value),
    };
    let mut row = KNOWN.get(store, wtxn, id)?.unwrap_or_default();
    if row.entries.contains(&entry) {
        return Ok(());
    }
    row.entries.push(entry);
    KNOWN.put(store, wtxn, id, &row)
}

/// One value the index knows, as a match reads it.
struct Known {
    len: usize,
    fingerprint: [u8; 32],
    handle: String,
}

/// The index, loaded for one pass over incoming bytes.
pub(crate) struct KnownValues {
    keys: Keys,
    /// Candidates by the tag of their first window, longest first.
    by_tag: HashMap<[u8; TAG_BYTES], Vec<Known>>,
    longest: usize,
}

/// One known value in incoming bytes: where, and the handle of the custody
/// record that holds it.
pub(crate) struct KnownSpan<'k> {
    pub(crate) span: Range<usize>,
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
        let mut longest = 0;
        for (custody, row) in KNOWN.scan(store, txn)? {
            let Some((handle, _)) =
                crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, &custody)?
            else {
                continue;
            };
            for entry in row.entries {
                let len = entry.len as usize;
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
        Ok(Some(Self {
            keys: Keys::derive(&key),
            by_tag,
            longest,
        }))
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
        while at + KNOWN_VALUE_MIN_BYTES <= data.len() {
            let tag = self.keys.tag(&data[at..at + KNOWN_VALUE_MIN_BYTES]);
            let hit = self.by_tag.get(&tag).and_then(|bucket| {
                bucket.iter().find(|known| {
                    at + known.len <= data.len()
                        && self.keys.fingerprint(&data[at..at + known.len]) == known.fingerprint
                })
            });
            match hit {
                Some(known) => {
                    spans.push(KnownSpan {
                        span: at..at + known.len,
                        handle: &known.handle,
                    });
                    at += known.len;
                }
                None => at += 1,
            }
        }
        spans
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

    /// `text` with each known value replaced by its handle's text, or `None`
    /// when it holds none. A match is on whole UTF-8 values, so it never
    /// splits a character.
    pub(crate) fn replaced_text(&self, text: &str) -> Option<String> {
        let spans = self.spans(text.as_bytes());
        if spans.is_empty() {
            return None;
        }
        let mut out = String::with_capacity(text.len());
        let mut from = 0;
        for known in spans {
            out.push_str(text.get(from..known.span.start)?);
            out.push_str(&handle_text(known.handle));
            from = known.span.end;
        }
        out.push_str(text.get(from..)?);
        Some(out)
    }
}

impl Vault {
    /// The known-value index as the store holds it now, for a sweep over
    /// what a run writes. `None` when it knows no value.
    pub(crate) fn known_values(&self) -> Result<Option<Arc<KnownValues>>> {
        let txn = self.store.env.read_txn()?;
        Ok(KnownValues::load_in_txn(&self.store, &txn)?.map(Arc::new))
    }
}

/// A handle as a text stands it in for a value: `[secret sc12]`.
pub(crate) fn handle_text(handle: &str) -> String {
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
        self.held.drain(..end);
        out
    }

    /// What the stream's end lets through: the held bytes, replaced.
    pub(crate) fn tail(&self) -> Vec<u8> {
        self.known.replaced_until(&self.held, self.held.len()).0
    }
}
