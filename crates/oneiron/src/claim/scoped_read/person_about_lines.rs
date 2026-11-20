//! The `about` lines the people roster shows a read (FIX-LIST
//! GRANT-RECEIPT-OTHER-READ-LANES part 4).
//!
//! A reader sees a person's stored `about` line of the highest band its read
//! admits (ARCH-0067 PEOPLE: "The renderer shows the highest line at or below
//! the reader's ceiling"). The key's own floor (B) sets that band, as before.
//! An identity agent's own floor reads nothing, so a person its live Grant
//! reads (FIX 7462) stood on its roster with no line at all. Each live Grant
//! A may stand on is now one more alternative, judged alone (RULING
//! GRANT-COMBINE Q1 = A: Grants are never unioned): under one Grant, the line
//! of the highest band at or below that Grant's band shows only where that
//! same Grant reads the PERSON and every CLAIM the line was written from, in
//! one snapshot. No Grant lends its band or a fact to another, and the line
//! shown is the highest any one alternative shows.
//!
//! The key's own floor is one such alternative too: its line shows only where
//! that floor alone reads the PERSON and every fact, in the same snapshot,
//! since a line written from a world follows its strictest input (DEC-0005;
//! FIX-LIST PEOPLE-ABOUT-OWN-FLOOR-FACTS-UNJUDGED). No Grant lends it a fact.

use super::ScopedRead;
use super::access_gate::HeldAuthority;
use super::agent_grants::GrantAlternative;
use crate::dreamer_consolidation::ShownAboutLine;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::{EntityId, Result};

/// An `about` line and the CLAIM ids it stands on, as the roster sets it.
type SourcedAbout = Option<(String, Vec<EntityId>)>;

impl ScopedRead<'_> {
    /// Runs `run` with the `about` line each person shows this read: the
    /// line of the highest band the key's own floor reads, or, where higher,
    /// the line one live Grant alone shows, the floor or that Grant reading
    /// the PERSON and every fact of the line. Every person is judged in one
    /// snapshot, under one policy and the Grants live in it. A person this
    /// read does not list still needs the roster's own row check: this only
    /// picks lines.
    ///
    /// # Errors
    /// The snapshot's, a credential no longer live, a policy that does not
    /// resolve, or `run`'s. A failure judging one Grant shows no line from
    /// it, counted as the row gate counts it.
    pub(crate) fn with_about_lines<T>(
        &self,
        run: impl FnOnce(&mut dyn FnMut(EntityId) -> Result<SourcedAbout>) -> Result<T>,
    ) -> Result<T> {
        let txn = self.vault.person_about_snapshot()?;
        let (own, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let own = (!own.deny_all).then_some(own);
        let held = self.held_for(None);
        let grants = self.grant_alternatives_in(&txn, &policy, &held);
        run(&mut |person| {
            Ok(self
                .about_line_in(&txn, &policy, &held, own.as_ref(), &grants, person)?
                .map(|line| (line.text, line.fact_claim_ids)))
        })
    }

    /// The line `person` shows this read in `txn`: the one the key's own
    /// filter `own` shows, or a higher one a single Grant of `grants` shows.
    fn about_line_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        held: &HeldAuthority,
        own: Option<&ResolvedRetrievalFilter>,
        grants: &[GrantAlternative],
        person: EntityId,
    ) -> Result<Option<ShownAboutLine>> {
        let mut shown = None;
        if let Some(filter) = own
            && let Some(line) =
                self.vault
                    .person_about_line_in(txn, person, filter.max_sensitivity_band)?
            && self.own_floor_reads_all_in(txn, policy, held, filter, person, &line)?
        {
            shown = Some(line);
        }
        for alternative in grants {
            let band = alternative.filter.max_sensitivity_band;
            if alternative.filter.deny_all || shown.as_ref().is_some_and(|line| line.band >= band) {
                continue;
            }
            let Some(line) = self.vault.person_about_line_in(txn, person, band)? else {
                continue;
            };
            if shown.as_ref().is_some_and(|best| best.band >= line.band) {
                continue;
            }
            if self.grant_reads_all_in(txn, policy, held, alternative, person, &line) {
                shown = Some(line);
            }
        }
        Ok(shown)
    }

    /// Whether `alternative` alone reads `person` and every fact `line`
    /// stands on, in `txn`.
    fn grant_reads_all_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        held: &HeldAuthority,
        alternative: &GrantAlternative,
        person: EntityId,
        line: &ShownAboutLine,
    ) -> bool {
        std::iter::once(&person)
            .chain(&line.fact_claim_ids)
            .all(|id| self.row_readable_under_grant_in(txn, policy, id, held, alternative))
    }

    /// Whether the key's own floor alone reads `person` and every fact
    /// `line` stands on, in `txn`: each row under `filter`, the one the read
    /// resolved (B), and each row it was written from at the key's floor, as
    /// the row gate judges a source. No live Grant stands in for B here, so
    /// none lends the own-floor line a fact; a line a Grant reads is that
    /// Grant's alternative. The owner's key, which no Grant stands for, takes
    /// the row gate itself, with the owner's own rule for what a row was
    /// written from.
    ///
    /// # Errors
    /// B's: a store or decode failure judging a row, as the row gate fails.
    fn own_floor_reads_all_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        held: &HeldAuthority,
        filter: &ResolvedRetrievalFilter,
        person: EntityId,
        line: &ShownAboutLine,
    ) -> Result<bool> {
        if self.actor_key.vault_owner_ref().is_some() {
            for id in std::iter::once(&person).chain(&line.fact_claim_ids) {
                if !self.is_entity_readable_held_in(txn, policy, id, filter, held)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        let floor = self.actor_retrieval_floor(policy)?;
        for id in std::iter::once(&person).chain(&line.fact_claim_ids) {
            let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode()) else {
                return Ok(false);
            };
            if !self.own_row_readable_in(txn, policy, id, &raw, filter, held, None)?
                || !self.written_from_each_readable_in(txn, id, &raw, |source, raw| {
                    self.own_row_readable_in(txn, policy, source, raw, &floor, held, None)
                })?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
