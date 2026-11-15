//! The proof that another machine of this vault keeps an archive's rows
//! (census L5-22 PR 2; DEC-0005 #vault:8; identity #checkpoints: "Archive
//! copies are verified durable before any local eviction").
//!
//! A custody proof is this machine's own measurement. It fetched, from one
//! custodian machine, every row that one archive manifest of its kept
//! checkpoint image lists, and each carried row's bytes hash to a listed
//! row. An entry hash is BLAKE3 of the row's signed bytes, so a carried row
//! whose hash the manifest lists is that signed row, byte for byte. The
//! rows this vault holds itself count for nothing: only what the
//! custodian's pages carried does. The manifest's custodian list is
//! advertised availability and is not read: the custodian is the machine
//! the connection proved, judged again against the fold in the writer.
//!
//! Archive custody grants no authority: no fold, quorum, attestation or
//! grant check reads a proof, and cold offload alone will. A proof stays
//! on the install that measured it: it never syncs, and no checkpoint
//! image carries it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    AuthorityEntryHash, AuthorityHistoryFetch, AuthorityHistoryPage, AuthorityHistorySelection,
    PeerMachine,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::side_table::{self, Named, SideTable};

/// One archive custody proof this machine recorded
/// ([`Vault::record_archive_custody_proof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityArchiveCustodyProof {
    /// The archive's content id.
    pub archive: [u8; 32],
    /// The machine whose pages carried the archive's rows.
    pub custodian: EntityId,
    /// The kept checkpoint image whose manifest lists the archive.
    pub checkpoint: [u8; 32],
    /// The machine key the custodian proved on the connection that carried
    /// the rows.
    pub custodian_key: [u8; 32],
    /// How many rows the pages carried: every row the manifest lists.
    pub rows: u64,
    /// When this machine verified them, in recording-clock seconds.
    pub verified_at: u64,
}

/// What one proof row holds beside its key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCustodyProof {
    checkpoint: [u8; 32],
    custodian_key: [u8; 32],
    rows: u64,
    verified_at: u64,
}

/// One proof per archive and custodian. Key: (archive id, custodian
/// MACHINE).
const CUSTODY_PROOF: SideTable<([u8; 32], EntityId), StoredCustodyProof, Named> =
    SideTable::new(&side_table::AUTHORITY_ARCHIVE_CUSTODY_PROOF);

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

fn custody_proof(
    (archive, custodian): ([u8; 32], EntityId),
    stored: StoredCustodyProof,
) -> AuthorityArchiveCustodyProof {
    AuthorityArchiveCustodyProof {
        archive,
        custodian,
        checkpoint: stored.checkpoint,
        custodian_key: stored.custodian_key,
        rows: stored.rows,
        verified_at: stored.verified_at,
    }
}

impl Vault {
    /// Records that `custodian` keeps every row of the archive `fetch`
    /// selects, from the `pages` it served for `fetch` (census L5-22 PR 2).
    /// The selection is one whole archive manifest of a checkpoint image
    /// this vault keeps: no bounds. In one writer: the fold proves
    /// `custodian` here on the key it proved, and it is not this install's
    /// own machine; each carried row's entry hash, BLAKE3 of its signed
    /// bytes, is a row this vault's own copy of the manifest lists; and the
    /// carried rows are all of them. A proof already recorded for that
    /// archive and custodian is replaced, with this verification's time.
    ///
    /// # Errors
    /// Refuses, and writes nothing: a selection that is not one whole
    /// archive; an unproved custodian, one the fold does not prove here on
    /// that key, or this install's own machine; an image this vault does
    /// not keep or a manifest it does not list; a page served for another
    /// selection; a carried row the manifest does not list; pages that
    /// leave out a row it lists. Storage faults.
    pub fn record_archive_custody_proof(
        &self,
        custodian: PeerMachine,
        fetch: &AuthorityHistoryFetch,
        pages: &[AuthorityHistoryPage],
    ) -> Result<AuthorityArchiveCustodyProof> {
        let AuthorityHistorySelection::Covered {
            checkpoint,
            archive: Some(archive),
            lower_exclusive: None,
            upper_inclusive: None,
        } = &fetch.selection
        else {
            return Err(refused("a custody proof needs one whole archive"));
        };
        let PeerMachine::Proven { machine, key } = custodian else {
            return Err(refused("a custody proof needs a proved custodian"));
        };
        let selection = fetch.selection.id();
        if pages.iter().any(|page| page.selection != selection) {
            return Err(refused("a history page served for another selection"));
        }
        let carried: BTreeSet<AuthorityEntryHash> = pages
            .iter()
            .flat_map(|page| &page.rows)
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            .collect();
        self.with_write_txn_grouped(|txn| {
            let fold = self.authority_fold_readonly_in_txn(txn)?;
            if fold.machine_proof_key(machine) != Some(key) {
                return Err(refused(
                    "a custody proof names a machine not proved here on that key",
                ));
            }
            if crate::identity::read_machine_id_in_txn(self, txn)? == Some(machine) {
                return Err(refused("a machine proves no archive custody to itself"));
            }
            let listed = super::history_fetch::selection_rows_in_txn(self, txn, &fetch.selection)?;
            if !carried.is_subset(&listed) {
                return Err(refused(
                    "a custody proof row the archive manifest does not list",
                ));
            }
            if carried.len() != listed.len() {
                return Err(refused("a custody proof short of the archive's rows"));
            }
            let stored = StoredCustodyProof {
                checkpoint: *checkpoint,
                custodian_key: key,
                rows: u64::try_from(listed.len()).unwrap_or(u64::MAX),
                verified_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
            };
            CUSTODY_PROOF.put(&self.store, txn, &(*archive, machine), &stored)?;
            Ok(custody_proof((*archive, machine), stored))
        })
    }

    /// Every archive custody proof this machine recorded
    /// ([`Self::record_archive_custody_proof`]), by archive id and then
    /// custodian.
    ///
    /// # Errors
    /// Storage faults; a proof row that does not decode.
    pub fn authority_archive_custody_proofs(&self) -> Result<Vec<AuthorityArchiveCustodyProof>> {
        let txn = self.store.env.read_txn()?;
        Ok(CUSTODY_PROOF
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(key, stored)| custody_proof(key, stored))
            .collect())
    }
}
