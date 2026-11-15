//! Cold offload of covered authority history (census L5-22 PR 3; DEC-0005
//! #vault:8; identity #checkpoints: "Archive copies are verified durable
//! before any local eviction").
//!
//! A device whose kept head is the checkpoint image it adopted folds from
//! that image, and never folds the covered rows it holds in its place
//! (`fold_stored_tail_in_txn`). Offload drops those rows' bytes once a
//! custody proof stands for each: another machine of the vault served every
//! row of an archive manifest that lists it ([`Vault::record_archive_custody_proof`]),
//! and the fold still proves that machine here on the key it proved then.
//! The home keeps the whole log (RULING L5-22-3-OFFLOAD-MACHINE = A): the
//! door refuses on the node the vault elected its home, whatever image it
//! adopted. Once rows went, a whole-vault export refuses with the history
//! this vault lacks ([`offloaded_history_refusal_in_txn`]).
//!
//! An image that covers a sealed row has no fold view: its adoption landed
//! every covered row and the stored log folds whole, so offload refuses it
//! (RULING L5-22-3-SEALED-COVER = A). A durable copy never stands on rented
//! compute: an execution node's proof lets nothing go (RULING
//! L5-22-3-EVICTION-ROLES = B).
//!
//! What goes, per dropped row: the entity row with its type and temporal
//! index rows, its first-seen sidecar, and its store-order sequence (the
//! index is resequenced whole). What stays: its sealed overlay and erasure
//! marks (a later erasure still reaches them), its sequence-observation
//! receipt (it never refreshes, so a row that arrives again is no new
//! growth), the images, attestations, proofs and every projection. Signed
//! rows stay verifiable: the custodian serves them, and the image attests
//! them.
//!
//! Off by default: the policy-manifest row `authority.history.offload`
//! (RULING L5-22-OFFLOAD-SWITCH = A).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::archive_custody::archive_custody_proofs_in_txn;
use super::{AuthorityEntryHash, MachineRole, VerifiedAuthorityCheckpoint};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::{EntityStoreRead, EntityStoreStaging};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;

/// One offload this machine made ([`Vault::offload_authority_history`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityHistoryOffload {
    /// The adopted checkpoint image whose covered rows it dropped.
    pub image: [u8; 32],
    /// The archives whose custody proofs stood for the dropped rows,
    /// ascending.
    pub archives: Vec<[u8; 32]>,
    /// How many covered rows it dropped under this image, in all.
    pub evicted: u64,
    /// When it last dropped rows under this image, in recording-clock
    /// seconds.
    pub at: u64,
}

/// What one offload row holds beside its key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOffload {
    archives: Vec<[u8; 32]>,
    evicted: u64,
    at: u64,
}

/// One row per adopted image this machine offloaded under. Key: the image id.
const OFFLOAD: SideTable<[u8; 32], StoredOffload, Named> =
    SideTable::new(&side_table::AUTHORITY_HISTORY_OFFLOAD);

fn refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidAuthorityLogBody(reason))
}

fn history_offload(image: [u8; 32], stored: StoredOffload) -> AuthorityHistoryOffload {
    AuthorityHistoryOffload {
        image,
        archives: stored.archives,
        evicted: stored.evicted,
        at: stored.at,
    }
}

/// Drops one held covered row: its bytes, the type and temporal index rows
/// the put staged beside them, and its first-seen sidecar. The caller
/// resequences the store order.
fn evict_covered_row_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hash: &AuthorityEntryHash,
    header: &EntityMetadataHeader,
) -> Result<()> {
    crate::batch::delete_entity_index_rows(
        store,
        txn,
        id,
        header.entity_type,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    store.port_remove_entity_row(txn, id)?;
    super::AUTHORITY_FIRST_SEEN.delete(
        store,
        txn,
        &super::authority_first_seen_sidecar_key(hash),
    )?;
    Ok(())
}

/// Every row of every archive an offload of this machine names, each read
/// from its own kept copy of the image the offload was made under: what its
/// custody proofs found another machine keeping.
pub(super) fn offloaded_rows_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<AuthorityEntryHash>> {
    let mut rows = BTreeSet::new();
    for (image, stored) in OFFLOAD.scan(&vault.store, txn)? {
        for archive in stored.archives {
            rows.extend(super::history_fetch::selection_rows_in_txn(
                vault,
                txn,
                &super::AuthorityHistorySelection::Covered {
                    checkpoint: image,
                    archive: Some(archive),
                    lower_exclusive: None,
                    upper_inclusive: None,
                },
            )?);
        }
    }
    Ok(rows)
}

/// The offload the client's authority catch-up owes (census L5-22 PR 3):
/// the adopted head, and each archive of it that lists a covered row this
/// vault holds and that no standing custody proof keeps yet.
#[cfg(feature = "sync")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorityOffloadDue {
    /// The adopted head image.
    pub(crate) image: [u8; 32],
    /// The vault the image is of, as a history fetch names it.
    pub(crate) vault_id: super::AuthorityVaultId,
    /// The archives to prove custody of first, ascending.
    pub(crate) unproved: Vec<[u8; 32]>,
}

/// The covered rows a vault holds under its adopted head: each row's store id
/// and stored header, by entry hash.
type HeldCovered = BTreeMap<AuthorityEntryHash, (EntityId, EntityMetadataHeader)>;

/// The covered rows of `adopted` this vault holds in `txn`.
fn held_covered_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    adopted: &VerifiedAuthorityCheckpoint,
) -> Result<HeldCovered> {
    let mut held = BTreeMap::new();
    for hash in &adopted.image().covered {
        let id = super::authority_log_entity_id_from_hash(hash)?;
        let Some(raw) = vault.store.port_entity_raw(txn, &id)? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        // A row of another kind at the content-derived key is no held
        // authority row; the put path displaces it when the row lands.
        if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
            held.insert(*hash, (id, header));
        }
    }
    Ok(held)
}

/// Whether this install is the node the vault elected its home: the one its
/// devices dial, which keeps the whole log (RULING L5-22-3-OFFLOAD-MACHINE =
/// A), whatever image it adopted.
fn elected_home_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let Some(node) = crate::identity::read_client_id_in_txn(vault, txn)? else {
        return Ok(false);
    };
    Ok(crate::dreamer_runner::DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)?
        .is_some_and(|home| home.node_id == node))
}

/// The refusal a whole-vault export gives once this vault offloaded covered
/// history (census L5-22 PR 3): the archive would carry the vault without
/// the rows it dropped, so the export names what this vault lacks, as the
/// signed-history export does on an adopted vault, and writes nothing.
/// `None` on a vault that never offloaded, or that holds every covered row
/// again.
pub(crate) fn offloaded_history_refusal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<Error>> {
    if OFFLOAD.scan(&vault.store, txn)?.is_empty() {
        return Ok(None);
    }
    let Some(adopted) =
        super::checkpoint_adopt::cached_verified_adoption_in_txn(&vault.store, txn)?
    else {
        return Ok(None);
    };
    let held = held_covered_in_txn(vault, txn, &adopted)?;
    let missing: BTreeSet<AuthorityEntryHash> = adopted
        .image()
        .covered
        .iter()
        .filter(|hash| !held.contains_key(*hash))
        .copied()
        .collect();
    Ok((!missing.is_empty()).then(|| {
        super::readonly_fold::history_required(&super::AuthorityHistoryRequest {
            vault_id: Some(adopted.pin().genesis),
            checkpoint: Some(adopted.id()),
            missing,
        })
    }))
}

/// What an offload in `txn` would stand on: the adopted head and the covered
/// rows this vault holds under it. The inner `Err` is the refusal the door
/// gives: the switch off, this install the vault's elected home, no adopted
/// image, an adopted image that is not the kept head, or one that covers a
/// sealed row.
fn offload_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<std::result::Result<(Arc<VerifiedAuthorityCheckpoint>, HeldCovered), &'static str>> {
    if !crate::gate::resolve_policy_manifest(&vault.store, txn)?.authority_history_offload_enabled()
    {
        return Ok(Err("authority history offload is disabled"));
    }
    if elected_home_in_txn(vault, txn)? {
        return Ok(Err(
            "the vault's elected home keeps its whole authority log",
        ));
    }
    let Some(adopted) =
        super::checkpoint_adopt::cached_verified_adoption_in_txn(&vault.store, txn)?
    else {
        return Ok(Err(
            "authority history offload needs an adopted checkpoint image",
        ));
    };
    if super::checkpoint::checkpoint_head_in_txn(&vault.store, txn)? != Some(adopted.id()) {
        return Ok(Err(
            "authority history offload names an image that is not the adopted head",
        ));
    }
    if adopted.image().covers_sealed_row() {
        return Ok(Err(
            "an image that covers a sealed row folds its stored log whole",
        ));
    }
    let held = held_covered_in_txn(vault, txn, &adopted)?;
    Ok(Ok((adopted, held)))
}

/// The archives whose custody proofs still stand for `image` in `txn`: each
/// recorded against `image`, its custodian proved here on the same key (live
/// and answered), not this install's machine, and not an execution node (a
/// durable copy never stands on rented compute).
fn standing_archives_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    image: &[u8; 32],
) -> Result<BTreeSet<[u8; 32]>> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let this_machine = crate::identity::read_machine_id_in_txn(vault, txn)?;
    Ok(archive_custody_proofs_in_txn(&vault.store, txn)?
        .into_iter()
        .filter(|proof| {
            proof.checkpoint == *image
                && fold.machine_proof_key(proof.custodian) == Some(proof.custodian_key)
                && this_machine != Some(proof.custodian)
                && fold
                    .machine_proof_role(proof.custodian)
                    .is_some_and(|role| role != MachineRole::ExecutionNode)
        })
        .map(|proof| proof.archive)
        .collect())
}

impl Vault {
    /// Drops the covered authority rows this vault holds under `image`, its
    /// adopted head, once a custody proof stands for each (census L5-22
    /// PR 3). In one writer: the owner's `authority.history.offload` row is
    /// on; this install is not the vault's elected home; `image` is both the
    /// adopted image and the kept head, and covers no sealed row; each held
    /// covered row is listed by an archive manifest
    /// of `image` whose custody proof was recorded against `image` and still
    /// stands, its custodian proved here on the same key, live, not this
    /// install's machine and not an execution node. Then the rows go, the
    /// store order is resequenced, the fold generation advances and the
    /// offload is recorded: a second offload under the same image adds its
    /// archives and rows to the first. `None` when this vault holds no row
    /// `image` covers: nothing is dropped and nothing is written.
    ///
    /// # Errors
    /// Refuses, and writes nothing: the switch off; this install the
    /// vault's elected home; no adopted image, or `image` not the adopted
    /// head; an image that covers a sealed row; a held covered row no
    /// standing proof keeps. Storage faults.
    pub fn offload_authority_history(
        &self,
        image: &[u8; 32],
    ) -> Result<Option<AuthorityHistoryOffload>> {
        let offload = self.with_write_txn_grouped(|txn| {
            let (adopted, held) = offload_scope_in_txn(self, txn)?.map_err(refused)?;
            if adopted.id() != *image {
                return Err(refused(
                    "authority history offload names an image that is not the adopted head",
                ));
            }
            if held.is_empty() {
                return Ok(None);
            }
            let proved = standing_archives_in_txn(self, txn, image)?;
            let mut kept = BTreeSet::new();
            let mut archives = BTreeSet::new();
            for manifest in &adopted.image().archive_manifests {
                if proved.contains(&manifest.archive)
                    && manifest.rows.iter().any(|row| held.contains_key(row))
                {
                    archives.insert(manifest.archive);
                    kept.extend(manifest.rows.iter().copied());
                }
            }
            if !held.keys().all(|hash| kept.contains(hash)) {
                return Err(refused("a covered row no standing custody proof keeps"));
            }
            for (hash, (id, header)) in &held {
                evict_covered_row_in_txn(&self.store, txn, id, hash, header)?;
            }
            super::store_order::resequence_in_txn(&self.store, txn)?;
            let mut stored = OFFLOAD
                .get(&self.store, txn, image)?
                .unwrap_or(StoredOffload {
                    archives: Vec::new(),
                    evicted: 0,
                    at: 0,
                });
            archives.extend(stored.archives);
            stored.archives = archives.into_iter().collect();
            stored.evicted = stored
                .evicted
                .saturating_add(u64::try_from(held.len()).unwrap_or(u64::MAX));
            stored.at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            OFFLOAD.put(&self.store, txn, image, &stored)?;
            Ok(Some(history_offload(*image, stored)))
        })?;
        Ok(offload)
    }

    /// The offload the client's authority catch-up owes now (census L5-22
    /// PR 3): `None` when the door would refuse or find nothing (the switch
    /// off, the elected home, no adopted head, a sealed-cover image, no
    /// covered row held), else the head and the archives of it whose custody
    /// to prove first.
    /// Read-only: the door judges every proof again in its own writer.
    #[cfg(feature = "sync")]
    pub(crate) fn authority_offload_due(&self) -> Result<Option<AuthorityOffloadDue>> {
        let txn = self.store.env.read_txn()?;
        let Ok((adopted, held)) = offload_scope_in_txn(self, &txn)? else {
            return Ok(None);
        };
        if held.is_empty() {
            return Ok(None);
        }
        let image = adopted.id();
        let proved = standing_archives_in_txn(self, &txn, &image)?;
        let unproved = adopted
            .image()
            .archive_manifests
            .iter()
            .filter(|manifest| {
                !proved.contains(&manifest.archive)
                    && manifest.rows.iter().any(|row| held.contains_key(row))
            })
            .map(|manifest| manifest.archive)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Some(AuthorityOffloadDue {
            image,
            vault_id: adopted.image().vault_id,
            unproved,
        }))
    }

    /// Every offload this machine made ([`Self::offload_authority_history`]),
    /// by image id.
    ///
    /// # Errors
    /// Storage faults; an offload row that does not decode.
    pub fn authority_history_offloads(&self) -> Result<Vec<AuthorityHistoryOffload>> {
        let txn = self.store.env.read_txn()?;
        Ok(OFFLOAD
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(image, stored)| history_offload(image, stored))
            .collect())
    }
}
