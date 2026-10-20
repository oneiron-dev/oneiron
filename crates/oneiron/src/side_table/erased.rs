//! The one side-table put that skips the side-row wall (FIX 5718): an
//! erase's own write of a row's erased form. An erase always lands, so the
//! wall, which admits new content and may refuse it, never stands between an
//! erase and the row it scrubs. What this put writes is restricted by its
//! argument: an [`Erased`] value, which only the row type's own erase
//! transform ([`ErasedForm::into_erased`]) makes, from a row as it was
//! stored, admitted then. Every other put keeps the wall.

use heed::RwTxn;

use super::{SideCodec, SideKey, SideTable, SideTableDbs};
use crate::error::Result;

/// A row type with an erased form: what an erase of its actor leaves of a
/// value, which holds nothing the wall would admit anew.
pub(crate) trait ErasedForm: Sized {
    /// This value as its erase leaves it. Erasing an erased value changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// A value whose erased form does not encode.
    fn into_erased(self) -> Result<Self>;
}

/// A value in its erased form: the only value [`SideTable::put_erased`]
/// takes.
pub(crate) struct Erased<V>(V);

impl<V: ErasedForm> Erased<V> {
    /// `value` as its erase leaves it.
    ///
    /// # Errors
    ///
    /// As [`ErasedForm::into_erased`].
    pub(crate) fn of(value: V) -> Result<Self> {
        value.into_erased().map(Self)
    }
}

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// Writes `value`, a row's erased form, at `key` as given, past the
    /// side-row wall: an erase's own write, which the wall never refuses.
    ///
    /// # Errors
    ///
    /// Storage errors, and a value the codec does not encode.
    pub(crate) fn put_erased(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
        value: Erased<V>,
    ) -> Result<()> {
        let bytes = self.encode_value(&value.0)?;
        self.write_raw(dbs, txn, &self.key_bytes(key), &bytes)
    }
}
