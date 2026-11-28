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
use oneiron_contracts::authority::AuthorityHistoryReason;

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
    /// Why a fold or door named them: the first refusal's where requests
    /// merge. None where the request names nothing a fold refused for.
    pub reason: Option<AuthorityHistoryReason>,
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
    authority_history_request_in_txn(store, posture, txn, &BTreeSet::new(), NamingRows::Every)
}

/// [`Vault::authority_missing_believed_history`] on the caller's snapshot.
pub(crate) fn authority_missing_believed_history_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityHistoryRequest> {
    authority_history_request_in_txn(store, posture, txn, &BTreeSet::new(), NamingRows::Believed)
}

/// Which held rows' parents a history request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamingRows {
    /// Every held row's, whoever admitted it: what delivery fetches.
    Every,
    /// Only the history the rows this install believes
    /// (`AuthorityStructure::believes`) rest on: their parents and, below
    /// every held row they reach, whoever signed it, its parents. What the
    /// peer route's settled gate waits for. A chain is read only by a reader
    /// that believes its admitter (design pass 29), so history only a
    /// stranger's rows rest on is not history this install lacks. The
    /// checkpoint cover, the resumed hashes, `required` and the pending
    /// evidence's needs count under either naming.
    Believed,
}

/// [`Vault::authority_history_request`] on the caller's snapshot: what a
/// held row names as a parent, the local checkpoint covers, the fold this
/// snapshot resumes from has folded, or `required` names, that no held row
/// has. The fold's own refusal for missing history names no hash outside it.
/// On a vault that adopted a checkpoint image it is the fold's own request
/// past the image (`readonly_fold::adopted_history_request_in_txn`). Either
/// way it names what the pending evidence's fold still needs too (FIX 2989).
pub(crate) fn authority_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
    naming: NamingRows,
) -> Result<AuthorityHistoryRequest> {
    let mut request = held_history_request_in_txn(store, posture, txn, required, naming)?;
    if let Some(pending) =
        super::history_admission::pending_history_request_in_txn(store, posture, txn)?
    {
        request.missing.extend(pending.missing);
        request.reason = request.reason.or(pending.reason);
    }
    Ok(request)
}

/// [`authority_history_request_in_txn`] of the held log alone. Under
/// [`NamingRows::Believed`] it names the held ancestry of the rows the store
/// gate's view of this snapshot believes: their parents and, walking down
/// through every held row they reach, its parents; the checkpoint cover, the
/// resumed hashes and `required` count either way. A vault that adopted a
/// checkpoint image answers the fold's own request past the image, which
/// names only the gaps the believed tail rows rest on; under
/// [`NamingRows::Every`] it also names every other parent the stored tail
/// names, which the fold reads past (FIX
/// [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]).
fn held_history_request_in_txn(
    store: &Store,
    posture: HostingPrivacyPosture,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
    naming: NamingRows,
) -> Result<AuthorityHistoryRequest> {
    if let Some(mut request) =
        super::readonly_fold::adopted_history_request_in_txn(store, posture, txn, required)?
    {
        if naming == NamingRows::Every {
            let every = adopted_every_tail_gaps_in_txn(store, txn, required)?;
            // A row only this naming adds is one a fetch of it closes, as
            // the held request below names it.
            request.reason = request
                .reason
                .or((!every.is_empty()).then_some(AuthorityHistoryReason::UnheldRows));
            request.missing.extend(every);
        }
        return Ok(request);
    }
    let believed = match naming {
        NamingRows::Every => None,
        NamingRows::Believed => Some(super::log_budget::door_view(store, txn)?),
    };
    let mut held = BTreeSet::new();
    let mut named = required.clone();
    named.extend(super::readonly_fold::resumed_hashes_in_txn(store, txn)?);
    // Under `Believed`: each held row's parents, and the believed rows'
    // parents, from which the walk below starts.
    let mut parents_of = BTreeMap::new();
    let mut below = Vec::new();
    let mut vault_id = None;
    for (_, body) in super::readonly_fold::authority_log_rows_in_txn(store, txn)? {
        let read = read_authority_log_entry_body(&body)?;
        let hash = match &read {
            AuthorityEntryRead::Open(entry) => authority_entry_hash(entry)?,
            AuthorityEntryRead::Sealed(scaffold) => scaffold.hash,
        };
        held.insert(hash);
        match &believed {
            None => named.extend(read.parent_hashes().iter().copied()),
            Some(view) => {
                // The door view counts each row opened with its record
                // (`door_view`), so a sealed row is judged opened here too.
                let opened;
                let entry = match &read {
                    AuthorityEntryRead::Open(entry) => entry,
                    AuthorityEntryRead::Sealed(_) => {
                        opened = open_vault_authority_body_in_txn(store, txn, &body)?;
                        &opened
                    }
                };
                if view.believes(entry) {
                    below.extend(entry.parent_hashes.iter().copied());
                }
                parents_of.insert(hash, entry.parent_hashes.clone());
            }
        }
        if vault_id.is_none() {
            vault_id = read.vault_id();
        }
    }
    // A believed row rests on every row below it, whoever signed that row:
    // walk down through the held rows, so a gap under a held row a believed
    // row reaches still counts. Rows no believed row reaches name nothing.
    let mut walked = BTreeSet::new();
    while let Some(hash) = below.pop() {
        if walked.insert(hash) {
            named.insert(hash);
            below.extend(parents_of.get(&hash).into_iter().flatten().copied());
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
    let reason = (!named.is_empty()).then_some(AuthorityHistoryReason::UnheldRows);
    Ok(AuthorityHistoryRequest {
        vault_id,
        checkpoint,
        missing: named,
        reason,
    })
}

/// What the [`NamingRows::Every`] request names past an adopted image: each
/// parent a stored row past the image names that the image does not cover and
/// this vault does not hold, and each `required` hash neither held nor a kept
/// frontier state, as the adopted fold counted every gap before it counted
/// only the believed rows' (FIX [STRANGER-GAP-STALLS-ADOPTED-TAIL-FOLD]).
/// Nothing on a vault with no adoption.
fn adopted_every_tail_gaps_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    required: &BTreeSet<AuthorityEntryHash>,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let Some(adopted) =
        super::checkpoint_adopt::cached_adopted_authority_checkpoint_in_txn(store, txn)?
    else {
        return Ok(BTreeSet::new());
    };
    let image = adopted.image();
    let covered: BTreeSet<_> = image.covered.iter().copied().collect();
    // Split as the fold splits: a covered row stored here is held, any other
    // stored row is tail.
    let mut held_covered = BTreeSet::new();
    let mut tail = BTreeSet::new();
    let mut parents = BTreeSet::new();
    for (_, body) in super::readonly_fold::authority_log_rows_in_txn(store, txn)? {
        let read = read_authority_log_entry_body(&body)?;
        let hash = match &read {
            AuthorityEntryRead::Open(entry) => authority_entry_hash(entry)?,
            AuthorityEntryRead::Sealed(scaffold) => scaffold.hash,
        };
        if covered.contains(&hash) || image.rows.contains_key(&hash) {
            held_covered.insert(hash);
        } else {
            tail.insert(hash);
            parents.extend(read.parent_hashes().iter().copied());
        }
    }
    Ok(parents
        .into_iter()
        .filter(|parent| !image.rows.contains_key(parent))
        .chain(
            required
                .iter()
                .filter(|hash| !held_covered.contains(*hash))
                .filter(|hash| !image.keeps_state(hash))
                .copied(),
        )
        .filter(|hash| !tail.contains(hash))
        .collect())
}

/// [`Vault::authority_history_coverage`] on the caller's snapshot: a held
/// row is scaffold and semantic availability; attested, never replayed, so
/// `unavailable` still names a covered row with no scaffold here.
pub(crate) fn authority_history_coverage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    requested: &BTreeSet<AuthorityEntryHash>,
) -> Result<AuthorityHistoryCoverage> {
    // The adoption's attestation and archive stand whatever the image covers.
    let adopted = super::checkpoint_adopt::cached_verified_adoption_in_txn(&vault.store, txn)?;
    let archive = archive_coverage_in_txn(vault, txn, adopted.as_deref(), requested)?;
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

    /// The history [`Self::authority_missing_history`] names that this
    /// install believes it lacks: what the rows it believes (the roster's and
    /// its own anchors', never a root it only awaits) rest on, down through
    /// every held row they reach, with the checkpoint cover, the resumed
    /// hashes and the pending evidence's needs as there. A parent only rows no
    /// believed row reaches name, such as a stranger's, leaves it as it was
    /// before those rows arrived (FIX
    /// [STRANGER-WITHHELD-PARENT-STALLS-PEER-SETTLED]). On a vault that adopted
    /// a checkpoint image it is the adopted fold's own request, as there. The
    /// peer route's settled gate reads this; delivery still fetches the whole
    /// request.
    pub fn authority_missing_believed_history(&self) -> Result<AuthorityHistoryRequest> {
        let txn = self.store.env.read_txn()?;
        authority_missing_believed_history_in_txn(&self.store, self.privacy_posture(), &txn)
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
        authority_history_request_in_txn(
            &self.store,
            self.privacy_posture(),
            &txn,
            required,
            NamingRows::Every,
        )
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
