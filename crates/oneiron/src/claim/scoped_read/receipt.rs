//! Mandatory read receipts. Responses carry the requested/ceiling/intersection tuple.
use super::ScopedRead;
use super::access_gate::HeldAuthority;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalPolicyFloor};
use oneiron_contracts::gate::RetrievalFilter;
use std::collections::BTreeSet;

pub use oneiron_contracts::claim::{ReadScope, ScopedReadReceipt};

pub use crate::ports::ScopedReadResult;

/// The applied scope a resolved policy filter produced.
fn read_scope_from_resolved(filter: &ResolvedRetrievalFilter) -> ReadScope {
    ReadScope {
        entity_types: filter.entity_types.clone(),
        max_sensitivity_band: filter.max_sensitivity_band,
        include_stale: filter.include_stale,
        min_confidence: filter.min_confidence,
        min_salience: filter.min_salience,
        deny_all: filter.deny_all,
    }
}

impl ScopedRead<'_> {
    /// The receipt of a read `applied` admitted, its ceiling the key's own
    /// floor alone. A lane's live Grants enter a receipt only through
    /// [`Self::receipt_in`], built in the serving snapshot.
    pub(super) fn receipt_for(
        &self,
        requested: Option<&RetrievalFilter>,
        policy: &PolicyManifestResolution,
        applied: &ResolvedRetrievalFilter,
        suppressed_count: usize,
    ) -> ScopedReadReceipt {
        let floor = policy.retrieval_floor_for_actor(Some(&self.actor_key));
        let grant_scope = floor.has_grant_scope_bound(self.actor_key.authority_scope())
            || policy.scoped_read_grants_all_bounded(&self.actor_key);
        self.receipt_under(requested, floor, grant_scope, applied, suppressed_count)
    }

    /// This lane reporting its live Grants in each receipt it builds in a
    /// serving snapshot (`receipt_in`). Set on an answer whose receipt tells
    /// its caller what admitted its rows: vault.recall, vault.search.bm25,
    /// vault.claims.list, vault.get and vault.hydrate, and the server's core
    /// query and memory reason routes (FIX-LIST
    /// GRANT-RECEIPT-OTHER-READ-LANES). The retrieval loop reports them on
    /// any lane (`receipt_reporting_in`). It reports and never admits a row.
    /// A lane whose receipt caps content no row gate judged must not take it
    /// (the people roster's about lines, the core timeline's deleted
    /// records): one envelope over two Grants' bands would widen that cap.
    #[must_use]
    pub fn with_live_grant_receipts(mut self) -> Self {
        self.receipts_include_live_grants = true;
        self
    }

    /// [`Self::receipt_for`] in the serving snapshot `rtxn`. On a lane that
    /// reports its live Grants ([`Self::with_live_grant_receipts`]), a key A
    /// may stand for reports its own floor and each of its own live Grants'
    /// as its ceiling, and `applied` joined with what each live Grant reads
    /// under the request: the reach that admitted its rows, not its own
    /// floor alone (FIX GRANT-READ-NARROWING-SAYS-DENY-ALL). It reports and
    /// never authorizes: each row took the row gate, B first, then each
    /// Grant alone. Every other lane reports as [`Self::receipt_for`].
    /// `held` is the authority the read's row gate held in `rtxn`, when it
    /// held one: the receipt then reports the Grants that gate judged under.
    pub(super) fn receipt_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
        policy: &PolicyManifestResolution,
        applied: &ResolvedRetrievalFilter,
        suppressed_count: usize,
        held: Option<&HeldAuthority>,
    ) -> ScopedReadReceipt {
        self.receipt_reporting_in(
            rtxn,
            requested,
            policy,
            applied,
            suppressed_count,
            held,
            self.receipts_include_live_grants,
        )
    }

    /// [`Self::receipt_in`], reporting the key's live Grants when
    /// `report_live_grants`, whatever this lane's own setting. The retrieval
    /// loop passes `true` (FIX-LIST GRANT-RECEIPT-OTHER-READ-LANES): it runs
    /// on a lane its embedder made and lends it, so it cannot opt that lane
    /// in, and its receipts only tell its planner what admitted its rows; no
    /// consumer caps unjudged content by them. Its applied scope stays the
    /// candidates it asks its next step under, which already join each live
    /// Grant's.
    #[expect(
        clippy::too_many_arguments,
        reason = "a receipt takes its snapshot, request, policy, scope, count, held authority and reach"
    )]
    pub(super) fn receipt_reporting_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
        policy: &PolicyManifestResolution,
        applied: &ResolvedRetrievalFilter,
        suppressed_count: usize,
        held: Option<&HeldAuthority>,
        report_live_grants: bool,
    ) -> ScopedReadReceipt {
        match self.live_grant_receipt_scope_in(
            rtxn,
            policy,
            applied,
            requested,
            held,
            report_live_grants,
        ) {
            Some(scope) => self.receipt_under(
                requested,
                scope.ceiling,
                scope.statically_bounded,
                &scope.applied,
                suppressed_count,
            ),
            None => self.receipt_for(requested, policy, applied, suppressed_count),
        }
    }

    /// The receipt under the ceiling `floor`; `grant_scope` adds the static
    /// boundary hint.
    fn receipt_under(
        &self,
        requested: Option<&RetrievalFilter>,
        floor: RetrievalPolicyFloor,
        grant_scope: bool,
        applied: &ResolvedRetrievalFilter,
        suppressed_count: usize,
    ) -> ScopedReadReceipt {
        let actor_ceiling = ReadScope {
            entity_types: floor.allowed_entity_types,
            max_sensitivity_band: floor.max_sensitivity_band,
            include_stale: floor.include_stale,
            min_confidence: floor.min_confidence,
            min_salience: floor.min_salience,
            deny_all: floor.deny_all,
        };
        let applied = read_scope_from_resolved(applied);
        // The receipt names what the read asked: its bound caller filter met
        // with its door's request (FIX 3977).
        let requested = self.asked_request(requested);
        let requested = requested.as_deref().map_or_else(
            || actor_ceiling.clone(),
            |req| ReadScope {
                entity_types: req
                    .entity_types
                    .clone()
                    .or_else(|| actor_ceiling.entity_types.clone()),
                max_sensitivity_band: req
                    .max_sensitivity_band
                    .unwrap_or(actor_ceiling.max_sensitivity_band),
                include_stale: req.include_stale.unwrap_or(actor_ceiling.include_stale),
                min_confidence: req.min_confidence.unwrap_or(actor_ceiling.min_confidence),
                min_salience: req.min_salience.unwrap_or(actor_ceiling.min_salience),
                deny_all: req.entity_types.as_ref().is_some_and(BTreeSet::is_empty),
            },
        );
        let mut receipt = ScopedReadReceipt {
            requested,
            actor_ceiling,
            applied,
            replan_hint: Vec::new(),
            narrowed_axes: Vec::new(),
            // Inside a room turn a withheld row may be another room's or a
            // peer's private one, so no count says it exists.
            suppressed_count: if self.actor_key.room_turn.is_some() {
                0
            } else {
                suppressed_count
            },
        };
        receipt.record_axes();
        if grant_scope {
            receipt.record_grant_scope();
        }
        receipt
    }

    /// Returns the same mandatory receipt even when no row was withheld.
    pub fn read_receipt(
        &self,
        requested: Option<&RetrievalFilter>,
        suppressed: usize,
    ) -> crate::Result<ScopedReadReceipt> {
        let txn = self.grant_read_txn()?;
        self.read_receipt_in(&txn, requested, suppressed)
    }

    /// [`Self::read_receipt`] for a search (FIX 7528): its applied scope is
    /// the candidates the search ranks, the key's own rows and those each of
    /// its own live Grants reads (`SearchPlan::candidates`), so a search
    /// whose key reads nothing by itself still runs when a Grant reads some
    /// rows. It reports, never authorizes: every row still takes the row gate.
    /// A receipt that reports the live Grants loads them once
    /// ([`Self::receipt_candidates_in`]).
    pub(crate) fn search_receipt(
        &self,
        requested: Option<&RetrievalFilter>,
        suppressed: usize,
    ) -> crate::Result<ScopedReadReceipt> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let candidates = self.receipt_candidates_in(
            &txn,
            &policy,
            &filter,
            requested,
            self.receipts_include_live_grants,
        );
        Ok(self.receipt_in(&txn, requested, &policy, &candidates, suppressed, None))
    }

    /// The receipt for a scan that already holds its transaction: the
    /// authority is resolved in that snapshot, never a newer one.
    pub(crate) fn read_receipt_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: Option<&RetrievalFilter>,
        suppressed: usize,
    ) -> crate::Result<ScopedReadReceipt> {
        let (applied, policy) = self.resolve_retrieval_filter_in(txn, requested)?;
        Ok(self.receipt_in(txn, requested, &policy, &applied, suppressed, None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_read_door_reports_intersection_even_without_narrowing() -> crate::Result<()> {
        let (_dir, vault) =
            crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config());
        let read = vault.scoped_read(crate::claim::ScopedReadActorKey::new("reader").unwrap());
        let plain = read.search_text("absent", 1, None)?;
        assert_eq!(plain.receipt.requested, plain.receipt.applied);
        assert_eq!(plain.receipt.suppressed_count, 0);
        let filtered = read.filter_scored_entities(vec![])?;
        assert_eq!(filtered.receipt.requested, filtered.receipt.applied);
        assert!(
            read.read(&[super::super::PointRead::short("cl999999", 0)], None)?
                .single()
                .value
                .is_none()
        );
        for band in 0..=3 {
            for confidence in [0.0, 0.25, 0.5, 1.0] {
                let requested = RetrievalFilter {
                    max_sensitivity_band: Some(band),
                    min_confidence: Some(confidence),
                    include_stale: Some(true),
                    ..Default::default()
                };
                let receipt = read.read_receipt(Some(&requested), 0)?;
                assert!(receipt.applied.max_sensitivity_band <= band);
                assert!(receipt.applied.min_confidence >= confidence);
                assert!(!receipt.applied.include_stale || receipt.actor_ceiling.include_stale);
                assert_eq!(receipt.replan_hint, receipt.narrowed_axes);
            }
        }
        Ok(())
    }
}
