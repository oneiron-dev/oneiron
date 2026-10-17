//! What authority history this vault holds, and exactly what it lacks (OF-469).
//!
//! Missing history is never verified history. The parents a held row or the
//! local checkpoint names but this vault does not hold come back as one typed
//! request, so delivery fetches exactly those (range fetch); meanwhile the
//! fold holds every row above a gap invalid instead of folding the rows it has
//! as complete. Coverage reports each requested hash by its evidence: a held
//! signed row is scaffold and semantic availability, never authorization; a
//! row the adopted checkpoint image covers is attested, held or not.
//! `erased` waits for an erasure record, so it stays empty until one exists.
//! Archive coverage ([`AuthorityArchiveCoverage`]) adds where the original
//! signed scaffold stands: held here, or advertised by an archive manifest of
//! the adopted image under another custodian. An advertisement is
//! availability elsewhere, never verified scaffold: such a row stays
//! unavailable until its bytes are fetched, verified and held.
//!
//! A vault that adopted a checkpoint image asks for what its fold past the
//! image needs, through that fold's own preflight: nothing while the fold
//! answers, and never a covered row left out for being attested when the fold
//! needs it (a late fork, an op the image cannot fold past).

use std::collections::{BTreeMap, BTreeSet};

use super::checkpoint_adopt::VerifiedAuthorityCheckpoint;
use super::*;
use crate::store::Store;
use crate::{HostingPrivacyPosture, Vault, error::Result};

/// Exactly the authority rows this vault needs and does not hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityHistoryRequest {
    /// The vault the history belongs to, as its held rows name it.
    pub vault_id: Option<AuthorityVaultId>,
    /// The id of the local checkpoint v2 head the request was computed
    /// against: its image's covered rows count as named history.
    pub checkpoint: Option<[u8; 32]>,
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
    /// Covered by the verified checkpoint image this vault adopted.
    pub attested: BTreeSet<AuthorityEntryHash>,
    /// Known erased by an erasure record (none until one exists).
    pub erased: BTreeSet<AuthorityEntryHash>,
    pub unavailable: BTreeSet<AuthorityEntryHash>,
    /// The same hashes by archive evidence.
    pub archive: AuthorityArchiveCoverage,
}

/// Where each requested hash's original signed scaffold stands, by evidence
/// (OF-469). The sets overlap: one hash can be attested, advertised
/// elsewhere and unavailable at once, and each set stays visible.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityArchiveCoverage {
    /// Its original signed bytes are held here and decode to the hash.
    pub held: BTreeSet<AuthorityEntryHash>,
    /// The archives the adopted image's manifests list it in under a
    /// custodian other than this install's machine: advertised
    /// availability, never fetched or verified evidence.
    pub archived_elsewhere: BTreeMap<AuthorityEntryHash, BTreeSet<[u8; 32]>>,
    /// Covered by the verified checkpoint image this vault adopted.
    pub checkpoint_attested: BTreeSet<AuthorityEntryHash>,
    /// Known erased by an erasure record (none until one exists).
    pub erased: BTreeSet<AuthorityEntryHash>,
    /// Requested and not held here, advertised or attested or not: never
    /// erased, never permission.
    pub unavailable: BTreeSet<AuthorityEntryHash>,
}

/// The archive coverage of `requested` on the caller's snapshot, against
/// `adopted`, the image this vault adopted (verified).
pub(super) fn archive_coverage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    adopted: Option<&VerifiedAuthorityCheckpoint>,
    requested: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityArchiveCoverage> {
    let mut coverage = AuthorityArchiveCoverage::default();
    for hash in requested {
        // A row that does not decode, or decodes to another hash, proves
        // nothing about this one.
        if let Some(entry) = super::stored_authority_row(&vault.store, txn, hash)?
            && authority_entry_hash(&entry)? == *hash
        {
            coverage.held.insert(*hash);
        }
    }
    coverage.unavailable = requested.difference(&coverage.held).copied().collect();
    let Some(adopted) = adopted else {
        return Ok(coverage);
    };
    let image = adopted.image();
    coverage.checkpoint_attested = requested
        .iter()
        .filter(|hash| image.rows.contains_key(*hash))
        .copied()
        .collect();
    let machine = crate::identity::read_machine_id_in_txn(vault, txn)?;
    for manifest in &image.archive_manifests {
        if manifest
            .custodians
            .iter()
            .all(|custodian| Some(custodian.machine) == machine)
        {
            continue;
        }
        for hash in manifest
            .rows
            .iter()
            .filter(|hash| requested.contains(*hash))
        {
            coverage
                .archived_elsewhere
                .entry(*hash)
                .or_default()
                .insert(manifest.archive);
        }
    }
    Ok(coverage)
}

/// [`Vault::authority_missing_history`] on the caller's snapshot.
pub(crate) fn authority_missing_history_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityHistoryRequest> {
    authority_history_request_in_txn(store, posture, txn, &BTreeSet::new())
}

/// [`Vault::authority_history_request`] on the caller's snapshot: what a
/// held row names as a parent, the local checkpoint covers, the fold this
/// snapshot resumes from has folded, or `required` names, that no held row
/// has. The fold's own refusal for missing history names no hash outside it.
/// On a vault that adopted a checkpoint image it is the fold's own request
/// past the image (`readonly_fold::adopted_history_request_in_txn`).
pub(crate) fn authority_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityHistoryRequest> {
    if let Some(request) =
        super::readonly_fold::adopted_history_request_in_txn(store, posture, txn, required)?
    {
        return Ok(request);
    }
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

/// [`Vault::authority_history_coverage`] on the caller's snapshot: a held
/// row is scaffold and semantic availability; attested, never replayed, so
/// `unavailable` still names a covered row with no scaffold here.
pub(crate) fn authority_history_coverage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    requested: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityHistoryCoverage> {
    let adopted = super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(&vault.store, txn)?;
    let archive = archive_coverage_in_txn(vault, txn, adopted.as_ref(), requested)?;
    Ok(AuthorityHistoryCoverage {
        requested: requested.clone(),
        scaffold: archive.held.clone(),
        semantic: archive.held.clone(),
        attested: archive.checkpoint_attested.clone(),
        erased: archive.erased.clone(),
        unavailable: archive.unavailable.clone(),
        archive,
    })
}

impl Vault {
    /// The authority history this vault's own rows and checkpoint name but it
    /// does not hold: the exact request delivery fetches. Complete when empty.
    pub fn authority_missing_history(&self) -> Result<AuthorityHistoryRequest> {
        let txn = self.store.env.read_txn()?;
        authority_missing_history_in_txn(&self.store, self.privacy_posture(), &txn)
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
        authority_history_request_in_txn(&self.store, self.privacy_posture(), &txn, required)
    }

    /// Which of `requested` this vault holds, by evidence, and where its
    /// archives advertise the rest. A gap is reported as unavailable, never
    /// as verified.
    pub fn authority_history_coverage(
        &self,
        requested: &BTreeSet<AuthorityEntryHash>,
    ) -> Result<AuthorityHistoryCoverage> {
        let txn = self.store.env.read_txn()?;
        authority_history_coverage_in_txn(self, &txn, requested)
    }
}
