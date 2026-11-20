//! The `about` lines the people roster shows a read (FIX-LIST
//! GRANT-RECEIPT-OTHER-READ-LANES part 4).
//!
//! A reader sees a person's stored `about` line of the highest band its read
//! admits (ARCH-0067 PEOPLE: "The renderer shows the highest line at or below
//! the reader's ceiling"). The key's own floor (B) sets that band, as before.
//! An identity agent's own floor reads nothing, so a person its live Grant
//! reads (FIX 7462) stood on its roster with no line at all. Each live Grant
//! A may stand on is now one more alternative, judged alone (RULING
//! GRANT-COMBINE Q1 = A: Grants are never unioned): under one Grant, a line
//! at or below that Grant's band shows only where that same Grant reads the
//! PERSON and every CLAIM the line was written from, in one snapshot. No
//! Grant lends its band or a fact to another, and the line shown is the
//! highest any one alternative shows.
//!
//! The key's own floor is one such alternative too: its line shows only where
//! that floor alone reads the PERSON and every fact, in the same snapshot,
//! since a line written from a world follows its strictest input (DEC-0005;
//! FIX-LIST PEOPLE-ABOUT-OWN-FLOOR-FACTS-UNJUDGED). No Grant lends it a fact,
//! and where the owner's agent Grants bind the key, one of them alone reads
//! every row the line stands on.
//!
//! Each alternative shows the highest line it reads whole: where the line at
//! its band stands on a fact it does not read, the next lower line, written
//! from the facts of the lower bands alone, may still show (FIX-LIST
//! PEOPLE-ABOUT-GRANT-LOWER-LINE). A line the Dreamer no longer stands
//! behind (moved or stale facts) ends the walk, as it hides the person's
//! lines today.

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
        let mut shown: Option<ShownAboutLine> = None;
        if let Some(filter) = own {
            shown = self.highest_line_read_whole_in(
                txn,
                person,
                filter.max_sensitivity_band,
                None,
                |line| self.own_floor_reads_all_in(txn, policy, held, filter, person, line),
            )?;
        }
        for alternative in grants {
            let band = alternative.filter.max_sensitivity_band;
            let above = shown.as_ref().map(|line| line.band);
            if alternative.filter.deny_all || above.is_some_and(|above| above >= band) {
                continue;
            }
            if let Some(line) =
                self.highest_line_read_whole_in(txn, person, band, above, |line| {
                    Ok(self.grant_reads_all_in(txn, policy, held, alternative, person, line))
                })?
            {
                shown = Some(line);
            }
        }
        Ok(shown)
    }

    /// The highest line of `person` at or below `ceiling`, and above the
    /// band `above` when one is named, that `reads_whole` admits, in `txn`.
    /// Each line it does not admit gives way to the next lower one; a band
    /// with no line the Dreamer stands behind
    /// ([`crate::Vault::person_about_line_in`]) ends the walk.
    ///
    /// # Errors
    /// A store or decode failure reading a line, or `reads_whole`'s.
    fn highest_line_read_whole_in(
        &self,
        txn: &heed::RoTxn<'_>,
        person: EntityId,
        ceiling: u8,
        above: Option<u8>,
        mut reads_whole: impl FnMut(&ShownAboutLine) -> Result<bool>,
    ) -> Result<Option<ShownAboutLine>> {
        let mut ceiling = Some(ceiling);
        while let Some(band) = ceiling {
            let Some(line) = self.vault.person_about_line_in(txn, person, band)? else {
                return Ok(None);
            };
            if above.is_some_and(|above| line.band <= above) {
                return Ok(None);
            }
            if reads_whole(&line)? {
                return Ok(Some(line));
            }
            ceiling = line.band.checked_sub(1);
        }
        Ok(None)
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
    /// Grant's alternative. Where the owner's agent Grants bind the key, B
    /// is their envelope and the row gate finds a Grant for each row on its
    /// own, so one of those Grants alone must also admit the PERSON, every
    /// fact and every source ([`Self::one_grant_alternative_admits_each_in`]).
    /// The owner's key, which no Grant stands for, takes the row gate itself,
    /// with the owner's own rule for what a row was written from.
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
        let mut rows = Vec::new();
        for id in std::iter::once(&person).chain(&line.fact_claim_ids) {
            let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode()) else {
                return Ok(false);
            };
            if !self.own_row_readable_in(txn, policy, id, &raw, filter, held, None)?
                || !self.written_from_each_readable_in(txn, id, &raw, |source, raw| {
                    rows.push((*source, raw.to_vec()));
                    self.own_row_readable_in(txn, policy, source, raw, &floor, held, None)
                })?
            {
                return Ok(false);
            }
            rows.push((*id, raw));
        }
        self.one_grant_alternative_admits_each_in(txn, &rows, held)
    }
}
