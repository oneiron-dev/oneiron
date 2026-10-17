//! One typed keyspace over the `vault_meta` and `sync_state` side tables.
//!
//! A module's private rows live under a prefix declared once in [`decls`], with a key type that
//! encodes to the bytes after the prefix and a value type read and written through one declared
//! codec. Every read, write, scan and delete runs inside the caller's transaction against a
//! [`SideTableDbs`] target (any [`ManifestDbs`] write target, or the bare `vault_meta` handle an
//! open gate holds before a store exists), so a session view stages into its overlay and the base store
//! writes the base table through the same body.

mod codec;
mod decls;
mod key;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::marker::PhantomData;
use std::ops::Bound;

use heed::{RoTxn, RwTxn};

use crate::error::{Error, Result, SideTableRowProblem, StoreError};
use crate::overlay_db::{OverlayDb, OverlayStrDb};
use crate::secret_custody::CustodyWrite;
use crate::store::ManifestDbs;

pub(crate) use codec::{
    CodecError, LegacyCompact, LegacyJson, Named, Raw, RawValue, SideCodec, VersionedNamed,
};
pub(crate) use decls::*;
pub(crate) use key::{FixedSideKey, HexId, SideKey};

/// Where a side table's rows live: the two side databases of a write target.
pub(crate) trait SideTableDbs {
    fn side_vault_meta(&self) -> &OverlayDb;
    /// `None` for a target that holds only `vault_meta` (an open gate before the store exists).
    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb>;

    fn side_sync_state(&self) -> Result<&OverlayStrDb> {
        self.side_sync_state_opt().ok_or(Error::InvariantViolation(
            "a sync_state side table needs a target that holds sync_state",
        ))
    }

    /// The custody door a mask on write mints through (OF-067): a vault's. A
    /// bare store, a session view or an open gate holds none, so a hit the
    /// side-row wall finds in a row written there refuses the write.
    fn side_custody(&self) -> Option<CustodyWrite<'_>> {
        None
    }
}

impl<T: ManifestDbs> SideTableDbs for T {
    fn side_vault_meta(&self) -> &OverlayDb {
        self.vault_meta()
    }

    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb> {
        Some(self.sync_state())
    }
}

/// One routed transaction's side databases: the vault's own, or an off-record session's view
/// composed over them, which stages its writes into the session's overlay. Only the vault's own
/// holds the custody door, so an off-record view refuses a secret the side-row wall would mint.
#[derive(Clone, Copy)]
pub(crate) enum RoutedDbs<'v> {
    Base(&'v crate::Vault),
    Session(&'v crate::store::SessionStoreView<'v>),
}

impl SideTableDbs for RoutedDbs<'_> {
    fn side_vault_meta(&self) -> &OverlayDb {
        match self {
            Self::Base(vault) => vault.store.side_vault_meta(),
            Self::Session(view) => view.side_vault_meta(),
        }
    }

    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb> {
        match self {
            Self::Base(vault) => vault.store.side_sync_state_opt(),
            Self::Session(view) => view.side_sync_state_opt(),
        }
    }

    fn side_custody(&self) -> Option<CustodyWrite<'_>> {
        match self {
            Self::Base(vault) => vault.side_custody(),
            Self::Session(_) => None,
        }
    }
}

/// A vault writes its own store's side tables, and holds the custody door the side-row wall
/// mints through.
impl SideTableDbs for crate::Vault {
    fn side_vault_meta(&self) -> &OverlayDb {
        self.store.side_vault_meta()
    }

    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb> {
        self.store.side_sync_state_opt()
    }

    fn side_custody(&self) -> Option<CustodyWrite<'_>> {
        Some(CustodyWrite::of(self))
    }
}

/// The bare `vault_meta` handle, for the open gates that read declared rows before a store exists.
impl SideTableDbs for OverlayDb {
    fn side_vault_meta(&self) -> &OverlayDb {
        self
    }

    fn side_sync_state_opt(&self) -> Option<&OverlayStrDb> {
        None
    }
}

/// One encoded row of a declared table, staged by the module that owns it for a writer that
/// commits it inside a later transaction (the batch entry commits birth markers this way).
#[derive(Debug, Clone)]
pub(crate) struct StagedRow {
    decl: &'static SideTableDecl,
    key: Vec<u8>,
    value: Vec<u8>,
    /// The table's codec over a masked copy of `value`.
    decodes: fn(&[u8]) -> bool,
}

impl StagedRow {
    pub(crate) fn put(&self, dbs: &impl SideTableDbs, txn: &mut RwTxn<'_>) -> Result<()> {
        let admitted = self
            .decl
            .admit(dbs, txn, &self.key, &self.value, self.decodes)?;
        let value = admitted.as_deref().unwrap_or(&self.value);
        match self.decl.db {
            SideDb::VaultMeta => dbs.side_vault_meta().put(txn, &self.key, value),
            SideDb::SyncState => {
                let key = std::str::from_utf8(&self.key)
                    .map_err(|_| self.decl.row_error(SideTableRowProblem::KeyNotUtf8))?;
                dbs.side_sync_state()?.put(txn, key, value)
            }
        }
    }
}

/// The named database a side table lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SideDb {
    VaultMeta,
    /// String-keyed: a key's bytes must be UTF-8.
    SyncState,
}

/// The declared value encoding of a table. `Named` is the codec; the others keep the bytes an
/// existing row already has and are listed for the next ABI bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodecName {
    /// `rmp_serde::to_vec_named` on write, a strict decode on read.
    Named,
    /// One leading version byte, then `Named`.
    VersionedNamed,
    /// Legacy: `serde_json`.
    LegacyJson,
    /// Legacy: positional `rmp_serde::to_vec`.
    LegacyCompact,
    /// A fixed byte layout the value type spells itself.
    Raw,
}

/// What a table's rows carry, for the side-row wall (OF-067; ARCH-0069 #mask-on-write). Only an
/// `Authored` table's writes are admitted: read by the batch door's rules, each secret the mask
/// places lifted into custody with its handle left in the row, any other hit refused. Every other
/// class, and a table the catalog does not class, is written as given; the class says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SidePayload {
    /// Not classed: written as given, as before the wall.
    Unclassed,
    /// Text or fields a person, a model or a provider wrote. A writer whose target holds no
    /// custody door (a bare store) refuses a hit instead of masking it: one does on purpose
    /// where the row's content names its own key or is compared on a replay, since a fresh
    /// handle would change it on every write.
    Authored,
    /// A copy of a value another door already admitted.
    Admitted,
    /// Ids, counts, hashes, states and times the engine writes.
    Engine,
    /// Sealed bytes.
    Ciphertext,
    /// The custody plane a mask writes: the value's home, or a row that names one and holds no
    /// value. Never read again.
    Custody,
}

/// One entry of the declaration list: where a table lives, how its rows are encoded and what
/// they carry.
#[derive(Debug)]
pub(crate) struct SideTableDecl {
    pub(crate) name: &'static str,
    pub(crate) db: SideDb,
    pub(crate) prefix: &'static [u8],
    pub(crate) codec: CodecName,
    pub(crate) payload: SidePayload,
}

impl SideTableDecl {
    /// The declared prefix as the `sync_state` key spelling.
    fn prefix_str(&self) -> Result<&'static str> {
        std::str::from_utf8(self.prefix)
            .map_err(|_| self.row_error(SideTableRowProblem::KeyNotUtf8))
    }

    pub(crate) fn row_error(&self, problem: SideTableRowProblem) -> Error {
        Error::Store(StoreError::SideTableRow {
            table: self.name,
            problem,
        })
    }

    fn codec_error(&self, error: CodecError) -> Error {
        match error {
            CodecError::Row(problem) => self.row_error(problem),
            CodecError::Value(error) => error,
        }
    }

    /// The side-row wall at one write: an `Authored` table's row as admitted, `None` to write
    /// it as given. `decodes` is the table's codec over a masked copy.
    fn admit(
        &'static self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        full: &[u8],
        bytes: &[u8],
        decodes: impl Fn(&[u8]) -> bool,
    ) -> Result<Option<Vec<u8>>> {
        if self.payload != SidePayload::Authored {
            return Ok(None);
        }
        crate::batch::secret_scan::admit_side_row(dbs, txn, self, full, bytes, decodes)
    }
}

/// Whether `bytes` decode as a table's value, for the wall's check of a masked copy.
fn decodes<V, C: SideCodec<V>>(bytes: &[u8]) -> bool {
    C::decode(bytes).is_ok()
}

type RawRows<'txn> = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'txn>;

/// The exclusive upper bound of every key that starts with `prefix`; `None` when no byte string
/// is above them all.
fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return Some(end);
        }
    }
    None
}

/// A typed view of one declared table.
pub(crate) struct SideTable<K, V, C> {
    decl: &'static SideTableDecl,
    _types: TableTypes<K, V, C>,
}

/// The key, value and codec a table binds; carries no data.
type TableTypes<K, V, C> = PhantomData<fn() -> (K, V, C)>;

impl<K, V, C> Clone for SideTable<K, V, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K, V, C> Copy for SideTable<K, V, C> {}

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// Binds a declared prefix to its key and value types. The codec must be the declared one;
    /// a table used as a `const` fails to compile when they differ.
    pub(crate) const fn new(decl: &'static SideTableDecl) -> Self {
        assert!(
            decl.codec as u8 == C::NAME as u8,
            "a side table's codec must be its declared codec"
        );
        Self {
            decl,
            _types: PhantomData,
        }
    }

    pub(crate) fn decl(&self) -> &'static SideTableDecl {
        self.decl
    }

    /// The full stored key of one row.
    pub(crate) fn key_bytes(&self, key: &K) -> Vec<u8> {
        let mut out = self.decl.prefix.to_vec();
        key.encode_into(&mut out);
        out
    }

    fn decode_row_key(&self, full: &[u8]) -> Result<K> {
        full.strip_prefix(self.decl.prefix)
            .and_then(K::decode_key)
            .ok_or_else(|| self.decl.row_error(SideTableRowProblem::KeyShape))
    }

    pub(crate) fn encode_value(&self, value: &V) -> Result<Vec<u8>> {
        C::encode(value).map_err(|error| self.decl.codec_error(error))
    }

    pub(crate) fn decode_value(&self, bytes: &[u8]) -> Result<V> {
        C::decode(bytes).map_err(|error| self.decl.codec_error(error))
    }

    /// Encodes one row for a writer that commits it later; see [`StagedRow`].
    pub(crate) fn stage(&self, key: &K, value: &V) -> Result<StagedRow> {
        Ok(StagedRow {
            decl: self.decl,
            key: self.key_bytes(key),
            value: self.encode_value(value)?,
            decodes: decodes::<V, C>,
        })
    }

    /// Writes bytes the codec would never produce, for fixtures that plant a damaged row.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn put_undecodable(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
        bytes: &[u8],
    ) -> Result<()> {
        self.put_raw(dbs, txn, &self.key_bytes(key), bytes)
    }

    pub(crate) fn get(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &K,
    ) -> Result<Option<V>> {
        self.get_raw(dbs, txn, &self.key_bytes(key))?
            .map(|bytes| self.decode_value(&bytes))
            .transpose()
    }

    /// The stored bytes of one row, undecoded, for a reader that must check them before it
    /// decodes (a digest over the stored bytes, a size budget).
    pub(crate) fn get_bytes(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &K,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .get_raw(dbs, txn, &self.key_bytes(key))?
            .map(Cow::into_owned))
    }

    /// The stored bytes of one row, lent by the read transaction where the store can lend
    /// them (an overlay row is still a copy), for a reader that needs part of a large value.
    pub(crate) fn get_borrowed<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key: &K,
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        self.get_raw(dbs, txn, &self.key_bytes(key))
    }

    /// Reads one row, treating a row that does not decode as absent, for readers whose rows
    /// were always read leniently (a damaged sidecar falls back to its default). A storage error
    /// still fails the read.
    pub(crate) fn get_lenient(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &K,
    ) -> Result<Option<V>> {
        Ok(self
            .get_raw(dbs, txn, &self.key_bytes(key))?
            .and_then(|bytes| self.decode_value(&bytes).ok()))
    }

    pub(crate) fn contains(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key: &K,
    ) -> Result<bool> {
        Ok(self.get_raw(dbs, txn, &self.key_bytes(key))?.is_some())
    }

    pub(crate) fn put(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
        value: &V,
    ) -> Result<()> {
        let bytes = self.encode_value(value)?;
        self.put_raw(dbs, txn, &self.key_bytes(key), &bytes)
    }

    /// [`Self::put`], returning the bytes the row holds now, as the side-row wall stored them,
    /// for a writer that keeps its own copy of what it wrote.
    pub(crate) fn put_as_stored(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
        value: &V,
    ) -> Result<Vec<u8>> {
        let bytes = self.encode_value(value)?;
        let full = self.key_bytes(key);
        let stored = self
            .decl
            .admit(dbs, txn, &full, &bytes, decodes::<V, C>)?
            .unwrap_or(bytes);
        self.write_raw(dbs, txn, &full, &stored)?;
        Ok(stored)
    }

    /// Reads `value` as the side-row wall will store it, before the writer derives anything
    /// from it (an id, a hash, a copy it hands back): each secret the wall places becomes its
    /// handle in `value` too, and the later [`Self::put`] finds the row clean. A table the
    /// catalog does not class as authored leaves `value` as it is.
    pub(crate) fn admit(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
        value: &mut V,
    ) -> Result<()> {
        let bytes = self.encode_value(value)?;
        if let Some(masked) =
            self.decl
                .admit(dbs, txn, &self.key_bytes(key), &bytes, decodes::<V, C>)?
        {
            *value = self.decode_value(&masked)?;
        }
        Ok(())
    }

    /// Deletes one row; `true` when a row was present.
    pub(crate) fn delete(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
    ) -> Result<bool> {
        let full = self.key_bytes(key);
        match self.decl.db {
            SideDb::VaultMeta => dbs.side_vault_meta().delete(txn, &full),
            SideDb::SyncState => dbs.side_sync_state()?.delete(txn, self.str_key(&full)?),
        }
    }

    /// Every row of the table in key order.
    pub(crate) fn scan(&self, dbs: &impl SideTableDbs, txn: &RoTxn<'_>) -> Result<Vec<(K, V)>> {
        self.iter_from(dbs, txn, &[])?.collect()
    }

    /// The rows whose key bytes after the prefix start with `key_prefix`, in key order.
    pub(crate) fn scan_from(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<Vec<(K, V)>> {
        self.iter_from(dbs, txn, key_prefix)?.collect()
    }

    /// The keys of every row under `key_prefix`, without decoding values.
    pub(crate) fn scan_keys(
        &self,
        dbs: &impl SideTableDbs,
        txn: &RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<Vec<K>> {
        self.raw_rows(dbs, txn, key_prefix, false)?
            .map(|row| row.and_then(|(key, _)| self.decode_row_key(&key)))
            .collect()
    }

    /// The rows under `key_prefix` in key order, decoded as the caller pulls them, so a scan
    /// that stops early reads no further.
    pub(crate) fn iter_from<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'txn>
    where
        K: 'txn,
        V: 'txn,
        C: 'txn,
    {
        let table = *self;
        Ok(self
            .raw_rows(dbs, txn, key_prefix, false)?
            .map(move |row| table.decode_row(row?)))
    }

    /// The rows under `key_prefix` in descending key order, decoded as the caller pulls them.
    pub(crate) fn iter_rev_from<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'txn>
    where
        K: 'txn,
        V: 'txn,
        C: 'txn,
    {
        let table = *self;
        Ok(self
            .raw_rows(dbs, txn, key_prefix, true)?
            .map(move |row| table.decode_row(row?)))
    }

    /// The rows under `key_prefix` undecoded: the key bytes after the table prefix and the stored
    /// value, for a reader whose contract is to surface a malformed row rather than refuse the
    /// scan. Decode each value with [`Self::decode_value`].
    pub(crate) fn iter_raw_from<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> + 'txn> {
        let prefix_len = self.decl.prefix.len();
        Ok(self
            .raw_rows(dbs, txn, key_prefix, false)?
            .map(move |row| row.map(|(key, value)| (key[prefix_len..].to_vec(), value))))
    }

    /// The rows whose keys fall between `start` and `end`, ascending, decoded as the caller pulls
    /// them. An unbounded end is the end of the table.
    pub(crate) fn iter_range<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        start: Bound<&K>,
        end: Bound<&K>,
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'txn>
    where
        K: 'txn,
        V: 'txn,
        C: 'txn,
    {
        let table = *self;
        Ok(self
            .raw_range(dbs, txn, start, end, false)?
            .map(move |row| table.decode_row(row?)))
    }

    /// The rows whose keys fall between `start` and `end`, descending.
    pub(crate) fn iter_rev_range<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        start: Bound<&K>,
        end: Bound<&K>,
    ) -> Result<impl Iterator<Item = Result<(K, V)>> + 'txn>
    where
        K: 'txn,
        V: 'txn,
        C: 'txn,
    {
        let table = *self;
        Ok(self
            .raw_range(dbs, txn, start, end, true)?
            .map(move |row| table.decode_row(row?)))
    }

    /// Deletes every row under `key_prefix`; returns how many went.
    pub(crate) fn delete_from(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key_prefix: &[u8],
    ) -> Result<usize> {
        let keys = self
            .raw_rows(dbs, txn, key_prefix, false)?
            .map(|row| row.map(|(key, _)| key))
            .collect::<Result<Vec<_>>>()?;
        for full in &keys {
            match self.decl.db {
                SideDb::VaultMeta => dbs.side_vault_meta().delete(txn, full)?,
                SideDb::SyncState => dbs.side_sync_state()?.delete(txn, self.str_key(full)?)?,
            };
        }
        Ok(keys.len())
    }

    fn decode_row(&self, (key, value): (Vec<u8>, Vec<u8>)) -> Result<(K, V)> {
        Ok((self.decode_row_key(&key)?, self.decode_value(&value)?))
    }

    /// The raw rows between two keys of this table, forward or descending.
    fn raw_range<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        start: Bound<&K>,
        end: Bound<&K>,
        descending: bool,
    ) -> Result<RawRows<'txn>> {
        let bound = |key: Bound<&K>, open: Option<Vec<u8>>| match key {
            Bound::Included(key) => Bound::Included(self.key_bytes(key)),
            Bound::Excluded(key) => Bound::Excluded(self.key_bytes(key)),
            Bound::Unbounded => open.map_or(Bound::Unbounded, Bound::Excluded),
        };
        let lower = match bound(start, None) {
            Bound::Unbounded => Bound::Included(self.decl.prefix.to_vec()),
            other => other,
        };
        let upper = bound(end, prefix_end(self.decl.prefix));
        match self.decl.db {
            SideDb::VaultMeta => {
                let range = (
                    lower.as_ref().map(Vec::as_slice),
                    upper.as_ref().map(Vec::as_slice),
                );
                let rows: RawRows<'txn> =
                    if descending {
                        Box::new(dbs.side_vault_meta().rev_range(txn, &range)?.map(|row| {
                            row.map(|(key, value)| (key.into_owned(), value.into_owned()))
                        }))
                    } else {
                        Box::new(dbs.side_vault_meta().range(txn, &range)?.map(|row| {
                            row.map(|(key, value)| (key.into_owned(), value.into_owned()))
                        }))
                    };
                Ok(rows)
            }
            SideDb::SyncState => {
                let within = move |key: &[u8]| {
                    (match &lower {
                        Bound::Included(low) => key >= low.as_slice(),
                        Bound::Excluded(low) => key > low.as_slice(),
                        Bound::Unbounded => true,
                    }) && (match &upper {
                        Bound::Included(high) => key <= high.as_slice(),
                        Bound::Excluded(high) => key < high.as_slice(),
                        Bound::Unbounded => true,
                    })
                };
                let mut rows = self
                    .raw_rows(dbs, txn, &[], false)?
                    .filter(|row| row.as_ref().map_or(true, |(key, _)| within(key)))
                    .collect::<Result<Vec<_>>>()?;
                if descending {
                    rows.reverse();
                }
                Ok(Box::new(rows.into_iter().map(Ok)))
            }
        }
    }

    /// The raw rows under the table prefix plus `key_prefix`, forward or descending.
    fn raw_rows<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        key_prefix: &[u8],
        descending: bool,
    ) -> Result<RawRows<'txn>> {
        let mut scan = self.decl.prefix.to_vec();
        scan.extend_from_slice(key_prefix);
        Ok(match self.decl.db {
            SideDb::VaultMeta if descending => {
                let end = prefix_end(&scan);
                let range = (
                    Bound::Included(scan.as_slice()),
                    end.as_deref().map_or(Bound::Unbounded, Bound::Excluded),
                );
                Box::new(
                    dbs.side_vault_meta()
                        .rev_range(txn, &range)?
                        .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned()))),
                )
            }
            SideDb::VaultMeta => Box::new(
                dbs.side_vault_meta()
                    .prefix_iter(txn, &scan)?
                    .map(|row| row.map(|(key, value)| (key.into_owned(), value.into_owned()))),
            ),
            SideDb::SyncState => {
                let rows = dbs
                    .side_sync_state()?
                    .prefix_iter(txn, self.str_key(&scan)?)?
                    .map(|row| {
                        row.map(|(key, value)| (key.as_bytes().to_vec(), value.into_owned()))
                    });
                if descending {
                    let mut all = rows.collect::<Result<Vec<_>>>()?;
                    all.reverse();
                    Box::new(all.into_iter().map(Ok))
                } else {
                    Box::new(rows)
                }
            }
        })
    }

    fn get_raw<'txn>(
        &self,
        dbs: &impl SideTableDbs,
        txn: &'txn RoTxn<'_>,
        full: &[u8],
    ) -> Result<Option<Cow<'txn, [u8]>>> {
        match self.decl.db {
            SideDb::VaultMeta => dbs.side_vault_meta().get(txn, full),
            SideDb::SyncState => dbs.side_sync_state()?.get(txn, self.str_key(full)?),
        }
    }

    /// Writes one row through the side-row wall.
    fn put_raw(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        full: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        let admitted = self.decl.admit(dbs, txn, full, bytes, decodes::<V, C>)?;
        self.write_raw(dbs, txn, full, admitted.as_deref().unwrap_or(bytes))
    }

    fn write_raw(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        full: &[u8],
        bytes: &[u8],
    ) -> Result<()> {
        match self.decl.db {
            SideDb::VaultMeta => dbs.side_vault_meta().put(txn, full, bytes),
            SideDb::SyncState => dbs.side_sync_state()?.put(txn, self.str_key(full)?, bytes),
        }
    }

    fn str_key<'k>(&self, full: &'k [u8]) -> Result<&'k str> {
        self.decl.prefix_str()?;
        std::str::from_utf8(full).map_err(|_| self.decl.row_error(SideTableRowProblem::KeyNotUtf8))
    }
}

// ─── Generic host doors ────────────────────────────────────────────────
//
// `Vault::sync_state_get`/`put`/`put_in_write_txn`/`delete`/
// `keys_with_prefix`/`visit_prefix_in_write_txn` (`vault/transactions.rs`)
// take a caller-chosen key instead of a bound [`SideTable`]: they exist for
// `crates/oneiron-server`, which owns rows this crate never declares a typed
// key/value shape for. A crate-internal writer always goes through a bound
// table and never reaches these; the check below is what stands in for that
// binding when the caller is outside the crate.

/// `key` must fall under a declared `SyncState` table. Refuses with a typed
/// error instead of letting a host door read or write a row no declaration
/// owns. For an exact key (`sync_state_get`, `sync_state_put` and their
/// `_in_write_txn`/`delete` siblings): a lookup or a write always names one
/// specific row, so it must name one a table actually declares.
#[cfg(feature = "sync")]
pub(crate) fn host_declared_sync_state(key: &str) -> Result<()> {
    declared_for(SideDb::SyncState, key.as_bytes())
        .map(|_| ())
        .ok_or_else(|| {
            Error::Store(StoreError::SideTableKeyUndeclared {
                key: key.to_owned(),
            })
        })
}

/// `prefix` must overlap a declared `SyncState` table, for the scan-shaped
/// host doors (`sync_state_keys_with_prefix`, `sync_state_visit_prefix_in_write_txn`).
/// Looser than [`host_declared_sync_state`] in two ways a lookup does not
/// need: `prefix` may be shorter than a declared prefix (a family scan, see
/// [`side_table::decls::declared_overlaps`](decls::declared_overlaps)), and a
/// prefix of 0 or 1 bytes is accepted unconditionally — no declared table is
/// that short, and LMDB refuses an empty prefix, so a caller walking the
/// whole keyspace one leading byte at a time (a diagnostic byte-scan, not a
/// lookup) is a legitimate read this check cannot usefully judge either way.
/// An overlapping prefix can also match undeclared rows planted by legacy or
/// damaged writers. Scan callers must check each returned key with
/// [`host_declared_sync_state`] before exposing it.
#[cfg(feature = "sync")]
pub(crate) fn host_declared_sync_state_scan(prefix: &str) -> Result<()> {
    if prefix.len() <= 1 || declared_overlaps(SideDb::SyncState, prefix.as_bytes()) {
        return Ok(());
    }
    Err(Error::Store(StoreError::SideTableKeyUndeclared {
        key: prefix.to_owned(),
    }))
}

/// The write half of the generic host door: checks [`host_declared_sync_state`],
/// then puts through the same `sync_state` handle every declared table writes
/// through, so the raw call lives here rather than in `vault/transactions.rs`.
#[cfg(feature = "sync")]
pub(crate) fn host_sync_state_put(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    key: &str,
    value: &[u8],
) -> Result<()> {
    host_declared_sync_state(key)?;
    // A host row has no typed shape in this crate: its masked copy keeps the declared encoding,
    // and the host reads it back.
    let admitted = match declared_for(SideDb::SyncState, key.as_bytes()) {
        Some(decl) => decl.admit(dbs, txn, key.as_bytes(), value, |_| true)?,
        None => None,
    };
    dbs.side_sync_state()?
        .put(txn, key, admitted.as_deref().unwrap_or(value))
}

/// The delete half of the generic host door: checks [`host_declared_sync_state`],
/// then deletes. `true` when a row was present.
#[cfg(feature = "sync")]
pub(crate) fn host_sync_state_delete(
    dbs: &impl SideTableDbs,
    txn: &mut RwTxn<'_>,
    key: &str,
) -> Result<bool> {
    host_declared_sync_state(key)?;
    dbs.side_sync_state()?.delete(txn, key)
}
