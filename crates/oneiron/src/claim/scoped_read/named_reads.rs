//! Named point reads (FIX 5226): a read whose caller named each target says
//! when a legal non-use order keeps a row this reader otherwise reads from
//! use, where every collection read keeps omitting that row as before.
//!
//! The order is asked only after every ordinary gate admits the row, in the
//! read's own snapshot, so a row the reader may not read stays absent and
//! counted exactly as before, and a legally held body is never projected or
//! used to decide it.
use super::access_gate::HeldAuthority;
use super::point_reads::{PointRead, ReadRow, ReadTarget};
use super::{RetrievalFilter, ScopedRead, ScopedReadResult};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::vault::ReadMode;
use crate::{EntityId, Error, Result};

/// One slot of a named read: the admitted row, `None` where a collection
/// read omits it (a missing or withheld row, as before), or the typed
/// refusal of the legal order that keeps a row this reader otherwise reads
/// from use.
pub(crate) type NamedSlot = std::result::Result<Option<ReadRow>, Error>;

/// What one named point read found.
enum PointReadOutcome {
    /// The row, as every read admits it.
    Visible(ReadRow),
    /// No row stands at the target, or none this reader may learn of.
    Missing,
    /// An existing row an ordinary gate withholds from this reader.
    Withheld,
    /// A row every ordinary gate admits, kept from use by a legal order this
    /// reader may see: the order's own refusal.
    UseRestricted(Error),
}

impl PointReadOutcome {
    /// The answer every read gives today: the row, or its absence.
    fn ordinary(row: Option<ReadRow>, withheld: usize) -> Self {
        match row {
            Some(row) => Self::Visible(row),
            None if withheld > 0 => Self::Withheld,
            None => Self::Missing,
        }
    }

    fn into_slot(self) -> NamedSlot {
        match self {
            Self::Visible(row) => Ok(Some(row)),
            Self::Missing | Self::Withheld => Ok(None),
            Self::UseRestricted(refusal) => Err(refusal),
        }
    }
}

impl ScopedRead<'_> {
    /// [`Self::read`] for a door whose caller named each target, keeping the
    /// rows, their receipt and a dependent projection in one snapshot as
    /// [`Self::read_projected`] does. Each slot answers its own read, and one
    /// slot's legal refusal never aborts the others. The receipt counts
    /// exactly what [`Self::read`] counts for the same slice.
    pub(crate) fn read_named_projected<T, E: From<Error>>(
        &self,
        reads: &[PointRead<'_>],
        requested: Option<&RetrievalFilter>,
        project: impl FnOnce(&heed::RoTxn<'_>, Vec<NamedSlot>) -> std::result::Result<T, E>,
    ) -> std::result::Result<ScopedReadResult<T>, E> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut value = Vec::with_capacity(reads.len());
        let mut suppressed = 0;
        for read in reads {
            let (outcome, withheld) = self.point_outcome_in(&txn, &policy, &filter, read)?;
            suppressed += withheld;
            value.push(outcome.into_slot());
        }
        let receipt = self.receipt_for(requested, &policy, &filter, suppressed);
        Ok(ScopedReadResult {
            value: project(&txn, value)?,
            receipt,
        })
    }

    /// One named target: what it found, and the count [`Self::read`] gives
    /// it. A deleted shell a short reference names answers as before.
    fn point_outcome_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        read: &PointRead<'_>,
    ) -> Result<(PointReadOutcome, usize)> {
        let (row, withheld) = match read.target {
            ReadTarget::Id(id) => self.id_row_in(txn, policy, filter, id, read.mode)?,
            ReadTarget::ShortRef {
                short_id,
                content_hash,
            } => self.short_ref_in(txn, policy, filter, short_id, content_hash, read.mode)?,
        };
        if row.is_some() {
            return Ok((PointReadOutcome::ordinary(row, withheld), withheld));
        }
        let named = match read.target {
            ReadTarget::Id(id) => Some(id),
            ReadTarget::ShortRef {
                short_id,
                content_hash,
            } => self.short_ref_row_in(txn, short_id, content_hash, read.mode)?,
        };
        if let Some(id) = named
            && let Some(refusal) = self.use_restricted_in(txn, policy, filter, id, read.mode)?
        {
            return Ok((PointReadOutcome::UseRestricted(refusal), withheld));
        }
        Ok((PointReadOutcome::ordinary(row, withheld), withheld))
    }

    /// The row a short reference names with a body at `mode`, resolved again
    /// in `txn` as the point read resolved it; a deleted shell names none.
    fn short_ref_row_in(
        &self,
        txn: &heed::RoTxn<'_>,
        short_id: &str,
        content_hash: u8,
        mode: ReadMode,
    ) -> Result<Option<EntityId>> {
        match mode {
            ReadMode::Pinned(revision) => self.vault.resolve_pinned_entity_reference_in(
                txn,
                &format!("{short_id}:{content_hash:02x}"),
                revision,
            ),
            ReadMode::Live | ReadMode::Indexed => Ok(self
                .vault
                .hydrate_short_id_in(txn, short_id, content_hash)?
                .filter(|hydrated| hydrated.body.is_some())
                .map(|hydrated| hydrated.id)),
        }
    }

    /// The refusal of the legal order that keeps `id` from use, for a reader
    /// every ordinary gate admits to its row at `mode` in `txn`, the order's
    /// own conjunct asked last. `None` while no order keeps it from use, or
    /// while an ordinary gate withholds the row; an order whose silence runs
    /// gives no refusal of its own, so the row stays as absent as before.
    fn use_restricted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: EntityId,
        mode: ReadMode,
    ) -> Result<Option<Error>> {
        if crate::store::legal_hold::use_limit_in_txn(&self.vault.store, txn, &id)?.is_none() {
            return Ok(None);
        }
        let asked = HeldAuthority::asking_use_of(id);
        if self
            .admitted_raw_in(txn, policy, filter, &id, mode, &asked)?
            .is_none()
        {
            return Ok(None);
        }
        Ok(self
            .vault
            .store
            .use_restricted_in_txn(txn, &id)?
            .filter(|refusal| !matches!(refusal, Error::EntityNotFound)))
    }
}
