//! The one side-table put that skips the side-row wall (FIX 5718): an
//! erase's own write of a row's erased form. An erase always lands, so the
//! wall, which admits new content and may refuse it, never stands between an
//! erase and the row it scrubs. What this put writes is restricted by its
//! argument: an [`Erased`] value, made only by the row type's actor-erasure
//! transform ([`ErasedForm::into_erased`]) or a concrete content-removal
//! projection, from a row as it was stored, admitted then. Every other put
//! keeps the wall.

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

/// What an erase writes over a row that no longer decodes (FIX 6533): none
/// of the row's own bytes, and still no value of any row type, so every
/// reader reads it as the unreadable row it replaced.
pub(crate) const ERASED_UNREADABLE_ROW: &[u8] = b"oneiron:erased-unreadable-row:v1";

impl<K: SideKey, V, C: SideCodec<V>> SideTable<K, V, C> {
    /// Writes [`ERASED_UNREADABLE_ROW`] at `key`, past the side-row wall: an
    /// erase's own write over a row whose value does not decode, so it has
    /// no erased form to take (FIX 6533). It keeps none of the row's bytes.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn put_erased_unreadable(
        &self,
        dbs: &impl SideTableDbs,
        txn: &mut RwTxn<'_>,
        key: &K,
    ) -> Result<()> {
        self.write_raw(dbs, txn, &self.key_bytes(key), ERASED_UNREADABLE_ROW)
    }

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

impl Erased<crate::code_run::CodeRunReplayRecord> {
    /// Erases only the named output previews of the stored replay record.
    /// Unlike the actor-erased form, this preserves every bridge outcome
    /// and every unrelated output. The source erase releases the selected
    /// body occurrences in the same writer.
    pub(crate) fn code_run_output_previews(
        mut record: crate::code_run::CodeRunReplayRecord,
        paths: &std::collections::BTreeSet<String>,
    ) -> Self {
        for output in &mut record.outputs {
            if paths.contains(&output.path) {
                output.preview.text = crate::code_run::CODE_RUN_OUTPUT_PREVIEW_ERASED.to_owned();
            }
        }
        Self(record)
    }

    /// Takes the named fold answers from the stored replay record (FIX
    /// 18924): each call fails with `response_erased` and keeps the folds it
    /// named, and the preview of each body one spilled to reads erased.
    /// Every other outcome and output stays as it was. The withdrawal
    /// releases the spilled bodies in the same writer.
    ///
    /// # Errors
    ///
    /// An erased outcome that does not encode.
    pub(crate) fn code_run_fold_answers(
        mut record: crate::code_run::CodeRunReplayRecord,
        answers: &[crate::code_run::WithdrawnFoldAnswer],
    ) -> Result<Self> {
        crate::code_run::redact_fold_answers(&mut record, answers)?;
        Ok(Self(record))
    }
}
