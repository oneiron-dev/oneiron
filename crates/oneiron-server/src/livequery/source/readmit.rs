//! A bound source's re-admission of retained pushes at resume (FIX 9493): every row a retained
//! result was derived from must still read for the source's caller now.
//! `BoundSource::readmitted` and `BoundSource::anchor_readmitted` are its call surface.
//! The source root defines `BoundSource`; `history` keeps each retained entry's rows.

use super::*;

impl BoundSource {
    /// Whether every row the results of `pushes` were derived from still
    /// reads for this source's caller: under its live credential and current
    /// grants, at its destination, and not erased since. A row that is no
    /// entity row (a local notification's id) is judged by nothing here. A
    /// check that cannot be read keeps the payload here: the resume falls to
    /// a gap and a fresh scoped snapshot, never to a refusal.
    pub(super) fn readmitted(&self, pushes: &[subscriptions::Push]) -> Result<bool, AppError> {
        let mut rows: Vec<_> = pushes
            .iter()
            .filter(|push| push.result.is_some())
            .flat_map(|push| push.rows.iter().copied())
            .collect();
        if rows.is_empty() {
            return Ok(true);
        }
        rows.sort_unstable();
        rows.dedup();
        let server = self.server()?;
        Ok(rows_read(server.vault(), &self.auth, &rows))
    }

    /// [`Self::readmitted`] for the retained entry at `cursor`, the anchor a
    /// resume compares the fresh view with: its rows must still read too.
    /// An anchor the journal no longer holds is judged by nothing here.
    pub(super) fn anchor_readmitted(
        &self,
        journal: &LoroDoc,
        view: &ScopedView,
        channel: Channel,
        cursor: &Cursor,
    ) -> Result<bool, AppError> {
        let retained = super::history::History::rows_at(journal, view, channel, cursor)?;
        let Some(mut rows) = retained else {
            return Ok(true);
        };
        if rows.is_empty() {
            return Ok(true);
        }
        rows.sort_unstable();
        rows.dedup();
        let server = self.server()?;
        Ok(rows_read(server.vault(), &self.auth, &rows))
    }
}

/// Whether every one of `rows` reads for `auth` now (FIX 9493): no local
/// erase removed it, and the credential's current read admits it at its
/// destination. A row that is no entity row passes; a read that fails does
/// not.
fn rows_read(vault: &oneiron::Vault, auth: &CoreAuth, rows: &[oneiron::EntityId]) -> bool {
    rows.iter().all(|row| {
        match oneiron::sync::bridge::local_deletion_is_materialized(vault, row) {
            Ok(false) => {}
            Ok(true) | Err(_) => return false,
        }
        match vault.get_entity_type(row) {
            Ok(None) => true,
            Ok(Some(_)) => matches!(auth.can_read_entity(vault, row), Ok(true)),
            Err(_) => false,
        }
    })
}
