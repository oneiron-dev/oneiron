//! What an Owner's whole-vault JSON bundle judges beside each row's own
//! lineage before the row is read whole (fix list row 15416): what the side
//! ledgers record its body was made from, and the rows a blob version's
//! ledger claim names, as an archive and an OKF copy judge them
//! ([`super::copy_release::MailboxLineage`]).

use super::copy_release::version_claim_names;
use super::side_provenance::SideProvenance;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::source_audience::ExportJudge;
use crate::store::Store;

/// One JSON bundle pass's reading of what the side ledgers record each row's
/// body was made from, read once in the pass's snapshot.
pub(super) struct BundleLineage {
    recorded: SideProvenance,
}

impl BundleLineage {
    /// What the side ledgers record in the snapshot `txn`, for a pass the
    /// rule judges (`judged`): every row meets it before its body is read.
    /// Nothing for a pass the rule does not judge.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn read_in(store: &Store, txn: &heed::RoTxn<'_>, judged: bool) -> Result<Self> {
        let recorded = if judged {
            SideProvenance::read_in(store, txn)?
        } else {
            SideProvenance::default()
        };
        Ok(Self { recorded })
    }

    /// Whether the pass's `judge`, when it has one, carries the stored row
    /// `id` of type `entity_type` and bytes `raw`: the row, every row the side
    /// ledgers record its body was made from, and every row a blob version's
    /// ledger claim names. The rows that count as carried once the row ships
    /// ([`Self::ships`]), none without a judge; `None` when it stays home.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn admitted(
        &self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        id: EntityId,
        entity_type: u8,
        raw: &[u8],
    ) -> Result<Option<Vec<EntityId>>> {
        let mut sources = Vec::new();
        if let Some(judge) = judge {
            let carried = judge.carries(id, Some(raw))?;
            match self.recorded.admitted(judge, id)? {
                Some(admitted) if carried => sources = admitted,
                Some(_) | None => return Ok(None),
            }
            if let Some(names) = version_claim_names(entity_type, raw) {
                if !judge.carries_all(names.as_deref())? {
                    return Ok(None);
                }
                sources.extend(names.into_iter().flatten());
            }
        }
        Ok(Some(sources))
    }

    /// Whether the pass's `judge`, when it has one, carries the row `id` and
    /// every row the side ledgers record its body was made from.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(super) fn carried_by(
        &self,
        judge: Option<&mut ExportJudge<'_, '_, '_>>,
        id: EntityId,
    ) -> Result<bool> {
        let Some(judge) = judge else {
            return Ok(true);
        };
        let carried = judge.carries(id, None)?;
        Ok(self.recorded.admitted(judge, id)?.is_some() && carried)
    }

    /// The row `id` goes into the copy, and with it the rows `sources` its
    /// admission ([`Self::admitted`]) counts as carried once it ships.
    pub(super) fn ships(judge: &mut ExportJudge<'_, '_, '_>, id: EntityId, sources: Vec<EntityId>) {
        judge.ships(id);
        for source in sources {
            judge.ships(source);
        }
    }
}
