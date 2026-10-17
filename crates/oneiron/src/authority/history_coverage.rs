//! What authority history this vault holds, and exactly what it lacks (OF-469).
//!
//! Missing history is never verified history. The parents a held row or the
//! local checkpoint names but this vault does not hold come back as one typed
//! request, so delivery fetches exactly those (range fetch); meanwhile the
//! fold holds every row above a gap invalid instead of folding the rows it has
//! as complete. Coverage reports each requested hash by its evidence: a held
//! signed row is scaffold and semantic availability, never authorization.
//! `attested` waits for hash-signed checkpoints (OF-570) and `erased` for an
//! erasure record, so both stay empty until those exist.

use std::collections::BTreeSet;

use super::*;
use crate::store::Store;
use crate::{Vault, error::Result};

/// Exactly the authority rows this vault needs and does not hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryRequest {
    /// The vault the history belongs to, as its held rows name it.
    pub vault_id: Option<AuthorityVaultId>,
    /// The local checkpoint head the request was computed against.
    pub checkpoint: Option<AuthorityEntryHash>,
    /// Hashes a held row names as a parent, or the checkpoint covers, that no
    /// held row has. Fetching them may name further ancestors: ask again after
    /// each import.
    pub missing: BTreeSet<AuthorityEntryHash>,
}

impl AuthorityHistoryRequest {
    /// Whether every named ancestor is held.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.missing.is_empty()
    }
}

/// The evidence this vault holds for each requested authority hash. The sets
/// overlap; `unavailable` is everything requested with no held scaffold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryCoverage {
    pub requested: BTreeSet<AuthorityEntryHash>,
    /// A signed row is held at this hash.
    pub scaffold: BTreeSet<AuthorityEntryHash>,
    /// Its operation body is held and decodes.
    pub semantic: BTreeSet<AuthorityEntryHash>,
    /// Covered by a hash-signed checkpoint (none until OF-570).
    pub attested: BTreeSet<AuthorityEntryHash>,
    /// Known erased by an erasure record (none until one exists).
    pub erased: BTreeSet<AuthorityEntryHash>,
    pub unavailable: BTreeSet<AuthorityEntryHash>,
}

/// [`Vault::authority_missing_history`] on the caller's snapshot.
pub(crate) fn authority_missing_history_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityHistoryRequest> {
    authority_history_request_in_txn(store, txn, &BTreeSet::new())
}

/// [`Vault::authority_history_request`] on the caller's snapshot: what a
/// held row names as a parent, the local checkpoint covers, the fold this
/// snapshot resumes from has folded, or `required` names, that no held row
/// has. The fold's own refusal for missing history names no hash outside it.
pub(crate) fn authority_history_request_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityHistoryRequest> {
    let mut held = BTreeSet::new();
    let mut named = required.clone();
    named.extend(super::readonly_fold::resumed_hashes_in_txn(store, txn)?);
    let mut vault_id = None;
    for (_, body) in super::readonly_fold::authority_log_rows_in_txn(store, txn)? {
        let entry = decode_authority_log_entry_body(&body)?;
        held.insert(authority_entry_hash(&entry)?);
        named.extend(entry.parent_hashes.iter().copied());
        if vault_id.is_none() {
            vault_id = entry.vault_id;
        }
    }
    let checkpoint = match super::checkpoint::checkpoint_head_coverage_in_txn(store, txn)? {
        Some((head, covered)) => {
            named.extend(covered);
            Some(head)
        }
        None => None,
    };
    named.retain(|hash| !held.contains(hash));
    Ok(AuthorityHistoryRequest {
        vault_id,
        checkpoint,
        missing: named,
    })
}

/// [`Vault::authority_history_coverage`] on the caller's snapshot.
pub(crate) fn authority_history_coverage_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    requested: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityHistoryCoverage> {
    let mut coverage = AuthorityHistoryCoverage {
        requested: requested.clone(),
        ..AuthorityHistoryCoverage::default()
    };
    for hash in requested {
        // A row that does not decode, or decodes to another hash, proves
        // nothing about this one.
        if let Some(entry) = super::stored_authority_row(store, txn, hash)?
            && authority_entry_hash(&entry)? == *hash
        {
            coverage.scaffold.insert(*hash);
            coverage.semantic.insert(*hash);
        }
    }
    coverage.unavailable = requested.difference(&coverage.scaffold).copied().collect();
    Ok(coverage)
}

impl Vault {
    /// The authority history this vault's own rows and checkpoint name but it
    /// does not hold: the exact request delivery fetches. Complete when empty.
    pub fn authority_missing_history(&self) -> Result<AuthorityHistoryRequest> {
        let txn = self.store.env.read_txn()?;
        authority_missing_history_in_txn(&self.store, &txn)
    }

    /// [`Vault::authority_missing_history`], also naming the rows the fold
    /// this vault resumes from has folded and the `required` hashes an
    /// evaluation or delivery needs (a tail manifest's expectations, a
    /// refused row's parents), each that this vault does not hold. A fold
    /// that refuses for missing history asks for nothing outside it, so
    /// delivery asks here before and after each page. Complete when empty.
    pub fn authority_history_request(
        &self,
        required: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<AuthorityHistoryRequest> {
        let txn = self.store.env.read_txn()?;
        authority_history_request_in_txn(&self.store, &txn, required)
    }

    /// Which of `requested` this vault holds, by evidence. A gap is reported
    /// as unavailable, never as verified.
    pub fn authority_history_coverage(
        &self,
        requested: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<AuthorityHistoryCoverage> {
        let txn = self.store.env.read_txn()?;
        authority_history_coverage_in_txn(&self.store, &txn, requested)
    }
}
