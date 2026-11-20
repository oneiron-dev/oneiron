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

use super::ScopedRead;
use super::access_gate::HeldAuthority;
use super::agent_grants::GrantAlternative;
use crate::dreamer_consolidation::ShownAboutLine;
use crate::gate::PolicyManifestResolution;
use crate::{EntityId, Result};

/// An `about` line and the CLAIM ids it stands on, as the roster sets it.
type SourcedAbout = Option<(String, Vec<EntityId>)>;

impl ScopedRead<'_> {
    /// Runs `run` with the `about` line each person shows this read: the
    /// line of the highest band the key's own floor reads, or, where higher,
    /// the line one live Grant alone shows, that Grant reading the PERSON and
    /// every fact of the line. Every person is judged in one snapshot, under
    /// one policy and the Grants live in it. A person this read does not
    /// list still needs the roster's own row check: this only picks lines.
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
        let own = (!own.deny_all).then_some(own.max_sensitivity_band);
        let held = self.held_for(None);
        let grants = self.grant_alternatives_in(&txn, &policy, &held);
        run(&mut |person| {
            Ok(self
                .about_line_in(&txn, &policy, &held, own, &grants, person)?
                .map(|line| (line.text, line.fact_claim_ids)))
        })
    }

    /// The line `person` shows this read in `txn`: the one the key's own
    /// band `own` shows, or a higher one a single Grant of `grants` shows.
    fn about_line_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        held: &HeldAuthority,
        own: Option<u8>,
        grants: &[GrantAlternative],
        person: EntityId,
    ) -> Result<Option<ShownAboutLine>> {
        let mut shown = match own {
            Some(band) => self.vault.person_about_line_in(txn, person, band)?,
            None => None,
        };
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
}
