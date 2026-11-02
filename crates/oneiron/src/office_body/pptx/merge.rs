//! A deck fork's merge candidate as the body would hold it once landed: the
//! head's document with the fork's own changes imported, read as a deck
//! (ARCH-0077: one deck, one document; a table's rows, columns, cells and
//! merges join by identity). Review, preview and landing all read this one
//! candidate, never a replay of the fork's operations over the head.
//!
//! A review reads one fork document and returns its frontier beside the
//! head's; a landing reads the fork's document up to that frontier, never
//! the fork as it stands then, so work the opener appended after the review
//! lands only after a review of its own (FIX 9992).

use super::{doc, live, log};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::office_body::{OfficeBodyFork, OfficeBodyKind, invalid};
use crate::typed_body::reviewed_fork::reviewed_fork_doc_in_txn;
use crate::typed_body::typed_body_fork_in_txn;
use heed::RoTxn;
use loro::{ExportMode, LoroDoc};
use oneiron_docedit::live::{DeckFork, LiveDeck, PreflightReport, preflight_merged};

impl Vault {
    /// The open fork `record`'s document as it stands, and its base.
    pub(super) fn deck_fork_doc(
        &self,
        txn: &RoTxn<'_>,
        record: &OfficeBodyFork,
    ) -> Result<(Vec<u8>, LoroDoc)> {
        let (typed, proposal) =
            typed_body_fork_in_txn(&self.store, txn, &record.artifact, &record.id)?
                .ok_or(Error::EntityNotFound)?;
        Ok((
            typed.base,
            proposal.ok_or_else(|| invalid("the fork is not open"))?,
        ))
    }

    /// The open fork `record`'s document up to `reviewed`, the fork frontier
    /// a review returned, and its base.
    pub(super) fn reviewed_fork_doc(
        &self,
        txn: &RoTxn<'_>,
        record: &OfficeBodyFork,
        reviewed: &[u8],
    ) -> Result<(Vec<u8>, LoroDoc)> {
        let (base, _) = self.deck_fork_doc(txn, record)?;
        let proposal =
            reviewed_fork_doc_in_txn(&self.store, txn, &record.artifact, &record.id, reviewed)?;
        Ok((base, proposal))
    }

    /// The fork `record` as the live model's work: the body at `base` and
    /// the operations `proposal`, a document of the fork, logged past it.
    pub(super) fn deck_fork_of(
        &self,
        txn: &RoTxn<'_>,
        record: &OfficeBodyFork,
        (base, proposal): (&[u8], &LoroDoc),
    ) -> Result<DeckFork> {
        let proposal = doc::read(proposal)?;
        let (_, base) = self.loro_body(txn, &record.artifact, OfficeBodyKind::Pptx, Some(base))?;
        let base = doc::read(&base)?;
        let logged = proposal
            .log
            .get(base.log.len()..)
            .ok_or(Error::CorruptedIndex("deck fork log"))?;
        let ops = log::stamped(&self.store, txn, &record.artifact, logged)?;
        // The stamped try, never a run a caller named (FIX 3551).
        let run_root = record
            .origin
            .map(|origin| crate::entity_id::bytes_to_hex_lower(origin.as_bytes()));
        let mut work = base.deck.fork_at(
            &record.id.to_hex(),
            &record.opener.to_hex(),
            run_root.as_deref(),
        );
        for op in ops {
            work.record(op);
        }
        Ok(work)
    }

    /// The open fork `record`'s merged deck over the head, or why it does
    /// not read as a deck.
    fn deck_candidate(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        record: &OfficeBodyFork,
    ) -> Result<std::result::Result<LiveDeck, String>> {
        let (_, fork) = self.deck_fork_doc(txn, record)?;
        self.deck_candidate_of(txn, artifact, &fork)
    }

    /// `fork`, a document of a deck fork, merged over the head, read as a
    /// deck, or why it does not read as one.
    fn deck_candidate_of(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        fork: &LoroDoc,
    ) -> Result<std::result::Result<LiveDeck, String>> {
        let (_, head) = self.loro_body(txn, artifact, OfficeBodyKind::Pptx, None)?;
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

    /// [`Self::deck_preflight`] over `fork`, one document of the fork read
    /// once: the work and its preflight both from it.
    pub(super) fn deck_preflight_of(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        head: &LiveDeck,
        record: &OfficeBodyFork,
        (base, fork): (&[u8], &LoroDoc),
    ) -> Result<(DeckFork, PreflightReport)> {
        let work = self.deck_fork_of(txn, record, (base, fork))?;
        let merged = self.deck_candidate_of(txn, artifact, fork)?;
        let report = preflight_merged(head, &work, merged).map_err(live)?;
        Ok((work, report))
    }
}
