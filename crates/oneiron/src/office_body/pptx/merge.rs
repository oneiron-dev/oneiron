//! A deck fork's merge candidate as the body would hold it once landed: the
//! head's document with the fork's own changes imported, read as a deck
//! (ARCH-0077: one deck, one document; a table's rows, columns, cells and
//! merges join by identity). Review, preview and landing all read this one
//! candidate, never a replay of the fork's operations over the head.

use super::{doc, live};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::office_body::{OfficeBodyFork, OfficeBodyKind, invalid};
use crate::typed_body::typed_body_fork_in_txn;
use heed::RoTxn;
use loro::ExportMode;
use oneiron_docedit::live::{DeckFork, LiveDeck, PreflightReport, preflight_merged};

impl Vault {
    /// The open fork `record`'s merged deck over the head, or why it does
    /// not read as a deck.
    fn deck_candidate(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        record: &OfficeBodyFork,
    ) -> Result<std::result::Result<LiveDeck, String>> {
        let (_, head) = self.loro_body(txn, artifact, OfficeBodyKind::Pptx, None)?;
        let (_, fork) = typed_body_fork_in_txn(&self.store, txn, artifact, &record.id)?
            .ok_or(Error::EntityNotFound)?;
        let fork = fork.ok_or_else(|| invalid("the fork is not open"))?;
        let updates = fork
            .export(ExportMode::updates(&head.oplog_vv()))
            .map_err(|_| invalid("deck fork export"))?;
        let merged = head.fork();
        merged
            .import(&updates)
            .map_err(|_| invalid("deck fork import"))?;
        Ok(doc::read(&merged)
            .map(|body| body.deck)
            .map_err(|error| error.to_string()))
    }

    /// The fork's merge preflight against `head`, over its actual merged
    /// candidate.
    pub(super) fn deck_preflight(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        head: &LiveDeck,
        record: &OfficeBodyFork,
        work: &DeckFork,
    ) -> Result<PreflightReport> {
        let merged = self.deck_candidate(txn, artifact, record)?;
        preflight_merged(head, work, merged).map_err(live)
    }
}
