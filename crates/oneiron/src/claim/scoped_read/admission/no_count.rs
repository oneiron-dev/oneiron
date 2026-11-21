//! The rows a scoped read refuses with no count (DEC-0005: no name, no
//! count): its receipt counts none of them among the rows it suppressed,
//! and no statistic a BM25 scan of the read scores with counts their
//! postings.

use super::super::access_gate::HeldAuthority;
use super::*;

/// Whom a refused row's count is for ([`ScopedRead::refused_row_counts_in`]).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CountFor {
    /// The read's receipt: a row outside the worlds the read asked for is
    /// not counted there either; scope honesty names its world instead.
    Receipt,
    /// The document frequency of a BM25 scan the read scores with. The
    /// worlds the read asked for are its own selection, not a refusal, so a
    /// row outside them still counts there (FIX
    /// WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS).
    Statistics,
}

impl ScopedRead<'_> {
    /// Whether this read, refusing the stored row `row` of `id`, still
    /// counts it (as suppressed in its receipt, or in a scan's statistics,
    /// as `count` says). `authority` is the serving txn's held authority, if
    /// any; `verdicts` the room admissions this read holds in `txn`.
    ///
    /// Inside a room turn a withheld row may be another room's or a peer's
    /// private one; its count would say it exists, so it reads as absent,
    /// and so does a row a room stretch staged that a member's own windows
    /// or a private thread keep from them. A row in a world the credential
    /// cannot read, or one a device-local world keeps from a caller off
    /// this device, has no name and no count (DEC-0005), and neither has a
    /// TASK outside the credential's worlds or facets, nor any row outside
    /// the facets it is limited to, nor any row its channel or records
    /// caveat does not reach. A room's row or turn the room keeps from this
    /// reader is a missing row at every door (L9-52), and so is one whose
    /// room's say does not resolve here. A private thread's row counts only
    /// to a reader standing in that thread, a private CLAIM never to a
    /// relationship-gated reader, a NOTE never, and a guest's only inside
    /// its grant's current scope in this snapshot. A row outside the worlds
    /// the read asked for counts in statistics alone ([`CountFor`]).
    pub(super) fn refused_row_counts_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
        authority: Option<&HeldAuthority>,
        verdicts: &crate::conversation_dag::RoomVerdicts,
        count: CountFor,
    ) -> Result<bool> {
        let raw = row.encode();
        Ok(self.actor_key.room_turn.is_none()
            && self.credential_allows_row_in(txn, id)
            && self.private_threads_readable_in(txn, id, &raw)?
            && !self.relationship_private_claim_in(txn, id, &raw, authority)?
            && self.guest_bound_admits_in(txn, id, &raw)
            && !self.stretch_staged_in(txn, id, row)?
            && (count == CountFor::Statistics || !self.outside_asked_worlds_in(txn, id, row)?)
            && !self.outside_credential_worlds_in(txn, id, row)?
            && !self.device_withholds_in(txn, id, None)?
            && !self.outside_credential_task_position_in(txn, id, row)?
            && !self.outside_credential_facets_in(txn, id, row, authority)?
            && crate::note::countable_read_suppression(row.entity_type, &row.body)
            && matches!(
                self.vault
                    .room_structure_admitted_held_in(self, txn, id, verdicts),
                Ok(true)
            )
            && crate::store::legal_hold::use_limit_in_txn(&self.vault.store, txn, id)?.is_none())
    }

    /// The own-row test of a BM25 scan whose every posting `serves` admits
    /// ([`crate::ports::TextQuery::hidden_row`]), read in `txn` through this
    /// read's own store: whether the read keeps the row from its reader with
    /// no count. That is a row a world keeps from the read
    /// ([`ScopedReadActorKey::world_withheld_rows_in`]), and any other row
    /// `serves` refuses and the read counts nowhere
    /// ([`Self::refused_row_counts_in`] for [`CountFor::Statistics`]: a
    /// records caveat, a facet limit, a private thread or NOTE, a narrowed
    /// guest pact, a room's structure, a row this read cannot place). The
    /// scan serves no such row; with this test its words move no readable
    /// row's score either (FIX SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS).
    /// A row the read refuses and counts (one its status, its band or its
    /// selection keeps out) still counts, as in its receipt.
    ///
    /// The row's count is judged first, so `serves` runs only for a row the
    /// read would not count.
    ///
    /// # Errors
    /// A store, fold or clock failure reading the holder's Grants or the
    /// device-local worlds; the test fails as `serves` and the row reads do.
    pub(crate) fn withheld_row_test_in<'t>(
        &'t self,
        txn: &'t heed::RoTxn<'_>,
        serves: &'t dyn Fn(&EntityId) -> Result<bool>,
    ) -> Result<crate::bm25::HiddenRowTest<'t>> {
        let worlds = self.actor_key.world_withheld_rows_in(self.vault, txn)?;
        let store = self.store_read();
        let authority = self.held_for(None);
        let verdicts = crate::conversation_dag::RoomVerdicts::default();
        Ok(Box::new(move |id: &EntityId| {
            if let Some(worlds) = &worlds
                && worlds.withholds_in(&store, txn, id)?
            {
                return Ok(true);
            }
            let Some(row) = self.entity_record_in(txn, id)? else {
                return Ok(true);
            };
            if self.refused_row_counts_in(
                txn,
                id,
                &row,
                Some(&authority),
                &verdicts,
                CountFor::Statistics,
            )? {
                return Ok(false);
            }
            Ok(!serves(id)?)
        }))
    }
}
