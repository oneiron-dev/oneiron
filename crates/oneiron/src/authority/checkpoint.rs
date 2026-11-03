//! The checkpoint v2 images this vault built and keeps (OF-469): each image's
//! canonical bytes keyed by its id, and the head of the local chain. A kept
//! image is decoded and checked on every read, never trusted: trust is a
//! quorum attestation and an adoption. Raw history is retained.
//!
//! The host writes an image and then attests it with its own root, in two
//! phases: the image is kept even when attesting fails, and the attested head
//! moves only once the stored attestations reach the policy's quorum.
//!
//! The upkeep runs on every lifecycle tick and writes a new image when the
//! authority log grew past what the head accounts for and a cutoff is
//! reached (identity.md, the 2026-09-26 owner ruling): no head was kept here
//! yet, the head is 24 hours old, or the growth reached 50,000 rows or 64 MiB
//! of canonical signed row bytes. The put path keeps this install's
//! cumulative totals of rows first stored here; an image accounts for the
//! totals its build snapshot read, so rows landing while it builds stay
//! growth. A row the adopted image covers that arrives later is hydration,
//! never growth. A head this install built and its host root has not
//! attested is attested again on a later tick, growth or not, without
//! writing the image again. These rows are this install's own bookkeeping:
//! no image carries them.
//!
//! A head built under another root policy than the one the vault counts now
//! gives way to a new image on the next tick, growth or not, so the roots the
//! owner chose have one to attest (FIX 4882). A host whose root that policy
//! does not name writes the image and leaves it awaiting those roots
//! (`checkpoint_root_status`): it never attests in their place.
//!
//! A write whose image is the head's in every byte but the parent link is a
//! no-op (FIX 2795): it keeps no new image and adds no chain link, reuses
//! the head's id, and attests the head only where an attestation is still
//! owed. Nothing here prunes a kept image.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::checkpoint_image::{AuthorityCheckpointV2, checkpoint_image_id};
use super::*;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};

/// The age at which a head image gives way to a new one once the authority
/// log grew past it (the canon's default cutoff).
pub const AUTHORITY_CHECKPOINT_MAX_AGE_SECS: u64 = 24 * 60 * 60;
/// The new authority rows since the head's build snapshot at which a new
/// image is written at once (the canon's default cutoff).
pub const AUTHORITY_CHECKPOINT_NEW_ENTRIES: u64 = 50_000;
/// The canonical signed body bytes of those new rows at which a new image is
/// written at once (the canon's default 64 MiB cutoff).
pub const AUTHORITY_CHECKPOINT_NEW_BYTES: u64 = 64 * 1024 * 1024;
/// The local second a no-op write records a reused head as kept at when no
/// progress row of this install names it (a restored vault): its age is
/// unknown, so the next growth is due at once, as it is today for a head
/// with no progress row (FIX 2795).
const REUSED_HEAD_UNKNOWN_KEPT_AT_SECS: u64 = 0;

/// The id of the newest image of this vault's local checkpoint chain. Key: ().
const CHECKPOINT_HEAD: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_V2_HEAD);
/// One checkpoint v2 image's canonical bytes. Key: the image id.
const CHECKPOINT_IMAGE: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_V2_IMAGE);
/// What the head this install kept accounts for, and when it kept it. Key: ().
const CHECKPOINT_PROGRESS: SideTable<(), CheckpointProgress, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_PROGRESS);
/// This install's cumulative totals of authority rows first stored here.
/// Key: ().
const HISTORY_TOTALS: SideTable<(), AuthorityHistoryTotals, Named> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_TOTALS);
/// Each row the adopted image covers that this vault did not hold when it
/// adopted the image, until it arrives. Key: the row's hash.
const ADOPTED_UNHELD: SideTable<AuthorityEntryHash, (), Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_UNHELD);

/// Authority rows first stored here, and their canonical signed body bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityHistoryTotals {
    rows: u64,
    bytes: u64,
}

impl AuthorityHistoryTotals {
    /// What these totals hold past `accounted`.
    fn since(self, accounted: Self) -> Self {
        Self {
            rows: self.rows.saturating_sub(accounted.rows),
            bytes: self.bytes.saturating_sub(accounted.bytes),
        }
    }
}

/// The head this install kept, the totals it accounts for and the local
/// second it was kept at.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointProgress {
    head: [u8; 32],
    accounted: AuthorityHistoryTotals,
    kept_at_secs: u64,
    /// The digest of the root policy this install built the head under;
    /// None for an adopted head, which another install built.
    built_under: Option<[u8; 32]>,
}

/// What one checkpoint write did: kept a new image as the head, or built
/// the head's own image again and reused the head (FIX 2795).
enum CheckpointWrite {
    Written([u8; 32]),
    /// `attested` when this host's root attested the reused head now.
    Reused {
        id: [u8; 32],
        attested: bool,
    },
}

/// What one checkpoint upkeep did ([`Vault::upkeep_authority_checkpoint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityCheckpointUpkeep {
    /// No cutoff was due and no attestation owed, or a due write built the
    /// head's own image again and owed it nothing (FIX 2795).
    Idle,
    /// A new image was written, and its attestations reached the policy.
    Written([u8; 32]),
    /// A new image was written and awaits its policy's roots
    /// ([`Vault::authority_checkpoint_roots`], FIX 4882).
    WrittenAwaitingRoots([u8; 32]),
    /// The head, which this host's root had not attested, was attested,
    /// with no new image written.
    Attested([u8; 32]),
}

/// The id of this vault's newest kept image, unchecked.
pub(super) fn checkpoint_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<[u8; 32]>> {
    CHECKPOINT_HEAD.get(store, txn, &())
}

/// A head image's id and, when this install built it, the digest of the
/// root policy it was built under.
pub(super) type HeadBuiltUnder = ([u8; 32], Option<[u8; 32]>);

/// The id of this vault's newest kept image and, when this install built it,
/// the digest of the root policy it was built under.
pub(super) fn checkpoint_head_built_under_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<HeadBuiltUnder>> {
    let Some(head) = CHECKPOINT_HEAD.get(store, txn, &())? else {
        return Ok(None);
    };
    let progress = CHECKPOINT_PROGRESS.get(store, txn, &())?;
    Ok(Some((
        head,
        progress
            .filter(|progress| progress.head == head)
            .and_then(|progress| progress.built_under),
    )))
}

/// Keeps `bytes` at `id` and makes it the head, in the caller's transaction.
/// The caller has checked that `id` is the id of `bytes`.
pub(super) fn keep_checkpoint_head_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    bytes: Vec<u8>,
) -> Result<()> {
    CHECKPOINT_IMAGE.put(store, wtxn, id, &bytes)?;
    CHECKPOINT_HEAD.put(store, wtxn, &(), id)
}

/// The put path's checkpoint accounting (OF-469 cutoffs), in the put's own
/// transaction, for an authority row whose hash this vault stores for the
/// first time: adds the row and its canonical signed body bytes to the
/// totals the cutoffs read. A row the adopted image covers and this vault
/// did not hold is hydration of covered history and adds nothing.
pub(crate) fn note_new_authority_row_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    hash: &AuthorityEntryHash,
    signed_bytes: usize,
) -> Result<()> {
    if ADOPTED_UNHELD.delete(store, wtxn, hash)? {
        return Ok(());
    }
    let mut totals = HISTORY_TOTALS.get(store, wtxn, &())?.unwrap_or_default();
    totals.rows = totals.rows.saturating_add(1);
    totals.bytes = totals.bytes.saturating_add(signed_bytes as u64);
    HISTORY_TOTALS.put(store, wtxn, &(), &totals)
}

/// Adoption's checkpoint accounting (OF-469 cutoffs), in the adoption's own
/// transaction: this install kept the adopted image `id` as its head now, and
/// it accounts for every held row it covers but no held row past it. Each
/// row it covers that this vault does not hold is hydration when it arrives,
/// never growth. The adopted pin stays the trust baseline: this moves none.
pub(super) fn note_adopted_checkpoint_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    image: &AuthorityCheckpointV2,
) -> Result<()> {
    // The store id is the row's content hash: a held covered row is known
    // by its id alone.
    let covered_ids: BTreeMap<EntityId, AuthorityEntryHash> = image
        .covered
        .iter()
        .filter_map(|hash| Some((authority_log_entity_id_from_hash(hash).ok()?, *hash)))
        .collect();
    let mut held = BTreeSet::new();
    let mut past = AuthorityHistoryTotals::default();
    for (row, body) in super::readonly_fold::authority_log_rows_in_txn(store, wtxn)? {
        if let Some(hash) = covered_ids.get(&row) {
            held.insert(*hash);
            continue;
        }
        let hash = authority_entry_hash(&decode_authority_log_entry_body(&body)?)?;
        if image.rows.contains_key(&hash) {
            held.insert(hash);
        } else {
            past.rows = past.rows.saturating_add(1);
            past.bytes = past.bytes.saturating_add(body.len() as u64);
        }
    }
    ADOPTED_UNHELD.delete_from(store, wtxn, &[])?;
    for hash in image.covered.iter().filter(|hash| !held.contains(*hash)) {
        ADOPTED_UNHELD.put(store, wtxn, hash, &())?;
    }
    let totals = HISTORY_TOTALS.get(store, wtxn, &())?.unwrap_or_default();
    CHECKPOINT_PROGRESS.put(
        store,
        wtxn,
        &(),
        &CheckpointProgress {
            head: *id,
            accounted: totals.since(past),
            kept_at_secs: crate::unix_seconds_now(),
            built_under: None,
        },
    )
}

/// Whether a cutoff is due at `now_secs`: the log grew past what the head
/// accounts for, and no head was kept here, or the head is
/// [`AUTHORITY_CHECKPOINT_MAX_AGE_SECS`] old, or the growth reached
/// [`AUTHORITY_CHECKPOINT_NEW_ENTRIES`] rows or
/// [`AUTHORITY_CHECKPOINT_NEW_BYTES`] bytes. `progress` names the current
/// head or is None; a head with no progress row here (a restored vault) was
/// not kept here.
fn checkpoint_due_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    progress: Option<&CheckpointProgress>,
    now_secs: u64,
) -> Result<bool> {
    let totals = HISTORY_TOTALS.get(store, txn, &())?.unwrap_or_default();
    let Some(progress) = progress else {
        return Ok(totals != AuthorityHistoryTotals::default());
    };
    let grown = totals.since(progress.accounted);
    Ok(grown != AuthorityHistoryTotals::default()
        && (now_secs.saturating_sub(progress.kept_at_secs) >= AUTHORITY_CHECKPOINT_MAX_AGE_SECS
            || grown.rows >= AUTHORITY_CHECKPOINT_NEW_ENTRIES
            || grown.bytes >= AUTHORITY_CHECKPOINT_NEW_BYTES))
}

/// One kept image's canonical bytes, unchecked.
pub(super) fn checkpoint_image_bytes_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    CHECKPOINT_IMAGE.get(store, txn, id)
}

/// The full `vault_meta` key one kept image's bytes are stored under: what a
/// read of a vault off its disk, with no `Store`, reads them by (FIX 11823).
pub(super) fn checkpoint_image_row_key(id: &[u8; 32]) -> Vec<u8> {
    CHECKPOINT_IMAGE.key_bytes(id)
}

/// The local checkpoint head and the rows its image covers, read without
/// trusting it: naming a hash as covered history to fetch is not trust.
pub(super) fn checkpoint_head_coverage_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<([u8; 32], Vec<AuthorityEntryHash>)>> {
    let Some(head) = CHECKPOINT_HEAD.get(store, txn, &())? else {
        return Ok(None);
    };
    let covered = match CHECKPOINT_IMAGE.get(store, txn, &head)? {
        Some(bytes) => super::checkpoint_image::covered_of(&bytes)?,
        None => Vec::new(),
    };
    Ok(Some((head, covered)))
}

/// Whether writing `image` after the kept head `kept`, whose canonical bytes
/// are `kept_bytes`, is a no-op (FIX 2795): linked as the head is, `image`
/// encodes to the head's exact bytes. Leaves `image` so linked. Equal
/// coverage alone is no no-op: a moved policy, posture, peer set, building
/// pin, archive or unresolved closure makes a new image.
fn no_op_write(
    image: &mut AuthorityCheckpointV2,
    kept: &AuthorityCheckpointV2,
    kept_bytes: &[u8],
) -> Result<bool> {
    image.parent = kept.parent;
    Ok(image.encode()? == kept_bytes)
}

impl Vault {
    /// Builds this vault's checkpoint v2 image, links it after the current
    /// head and keeps it as the new head, then attests it with `issuer`'s host
    /// root; returns its id. A vault that adopted an image builds from its
    /// adopted baseline and the rows it holds past it (`adopted_build`);
    /// any other builds from the rows it holds. The write compares the head again: a
    /// moved head refuses, and the caller builds again. A chain never forgets
    /// coverage: an image covering less than the head refuses. The head's
    /// progress row records the totals the build snapshot read and the local
    /// second the head was kept.
    ///
    /// A no-op write keeps nothing new (FIX 2795): when the image built is
    /// the head's in every byte but the parent link, no image and no link is
    /// added and the head's id is returned. The head compare still holds;
    /// the progress row takes the build snapshot's totals and keeps the age
    /// it records for the head; `issuer`'s root attests the head only when
    /// it still owes it an attestation.
    ///
    /// Two phases: the image is kept once its transaction commits, and an
    /// attesting failure after that returns the error with the image kept
    /// unattested; a later upkeep attests it again. The attested head moves
    /// only when the stored attestations reach the policy's quorum
    /// ([`Vault::host_attest_authority_checkpoint`]). A host root the policy
    /// in force does not name attests nothing.
    pub fn write_authority_checkpoint_v2(&self, issuer: &HostSlipIssuer) -> Result<[u8; 32]> {
        Ok(match self.write_or_reuse_authority_checkpoint(issuer)? {
            CheckpointWrite::Written(id) | CheckpointWrite::Reused { id, .. } => id,
        })
    }

    /// [`Vault::write_authority_checkpoint_v2`], saying whether it kept a new
    /// image or reused the head.
    fn write_or_reuse_authority_checkpoint(
        &self,
        issuer: &HostSlipIssuer,
    ) -> Result<CheckpointWrite> {
        let (image, head, accounted, reused) = {
            let txn = self.store.env.read_txn()?;
            let mut image = match super::checkpoint_adopt::adopted_authority_checkpoint_in_txn(
                &self.store,
                &txn,
            )? {
                Some(adopted) => {
                    self.build_authority_checkpoint_from_adopted_in_txn(&txn, &adopted)?
                }
                None => self.build_authority_checkpoint_v2_in_txn(&txn)?,
            };
            let accounted = HISTORY_TOTALS
                .get(&self.store, &txn, &())?
                .unwrap_or_default();
            let head = CHECKPOINT_HEAD.get(&self.store, &txn, &())?;
            let mut reused = false;
            if let Some(head) = head {
                let bytes = CHECKPOINT_IMAGE
                    .get(&self.store, &txn, &head)?
                    .ok_or_else(invalid_authority)?;
                let parent = AuthorityCheckpointV2::decode(&bytes)?;
                if checkpoint_image_id(&bytes) != head
                    || parent.vault_id != image.vault_id
                    || parent
                        .covered
                        .iter()
                        .any(|hash| image.covered.binary_search(hash).is_err())
                {
                    return Err(invalid_authority());
                }
                reused = no_op_write(&mut image, &parent, &bytes)?;
            }
            if !reused {
                image.parent = head;
            }
            (image, head, accounted, reused)
        };
        let built_under = image.root_policy.digest()?;
        let bytes = image.encode()?;
        let id = checkpoint_image_id(&bytes);
        let mut txn = self.store.env.write_txn()?;
        if CHECKPOINT_HEAD.get(&self.store, &txn, &())? != head {
            return Err(Error::ConcurrentWrite("authority checkpoint head moved"));
        }
        let kept_at_secs = if reused {
            // The head stays as kept: no image is put, and its age is the
            // one this install recorded for it.
            CHECKPOINT_PROGRESS
                .get(&self.store, &txn, &())?
                .filter(|progress| progress.head == id)
                .map_or(REUSED_HEAD_UNKNOWN_KEPT_AT_SECS, |progress| {
                    progress.kept_at_secs
                })
        } else {
            keep_checkpoint_head_in_txn(&self.store, &mut txn, &id, bytes)?;
            crate::unix_seconds_now()
        };
        CHECKPOINT_PROGRESS.put(
            &self.store,
            &mut txn,
            &(),
            &CheckpointProgress {
                head: id,
                accounted,
                kept_at_secs,
                built_under: Some(built_under),
            },
        )?;
        txn.commit()?;
        if reused {
            // A repeated no-op write signs nothing again: only an
            // attestation still owed is made.
            let owed = {
                let txn = self.store.env.read_txn()?;
                self.checkpoint_attestation_owed_in_txn(
                    &txn,
                    &issuer.public_key(),
                    id,
                    &built_under,
                )?
            };
            if owed {
                self.host_attest_authority_checkpoint(issuer, id)?;
            }
            return Ok(CheckpointWrite::Reused { id, attested: owed });
        }
        // The owner's selected policy may name no host root (mesh PR2c): the
        // image then waits for the roots he named, and checkpointing goes on.
        if self.checkpoint_root_eligible(&issuer.public_key())? {
            self.host_attest_authority_checkpoint(issuer, id)?;
        }
        Ok(CheckpointWrite::Written(id))
    }

    /// The host's checkpoint upkeep (OF-469), run on every lifecycle tick:
    /// when a cutoff is due, or the root policy moved past the head's (FIX
    /// 4882), writes and host-attests a new image
    /// ([`Vault::write_authority_checkpoint_v2`]), or, when the build is the
    /// head's own image, reuses the head and reports it idle or attested
    /// (FIX 2795); otherwise, when this
    /// install built the head under the vault's current root policy and
    /// `issuer`'s root, eligible under it, has not attested it, attests it
    /// again without writing the image again
    /// ([`Vault::host_attest_authority_checkpoint`]).
    pub fn upkeep_authority_checkpoint(
        &self,
        issuer: &HostSlipIssuer,
    ) -> Result<AuthorityCheckpointUpkeep> {
        let (due, owed) = {
            let txn = self.store.env.read_txn()?;
            let head = CHECKPOINT_HEAD.get(&self.store, &txn, &())?;
            let progress = CHECKPOINT_PROGRESS
                .get(&self.store, &txn, &())?
                .filter(|progress| Some(progress.head) == head);
            if checkpoint_due_in_txn(
                &self.store,
                &txn,
                progress.as_ref(),
                crate::unix_seconds_now(),
            )? || self.checkpoint_policy_moved_in_txn(
                &txn,
                head,
                progress.as_ref().and_then(|progress| progress.built_under),
            )? {
                (true, None)
            } else {
                let built =
                    progress.and_then(|progress| Some((progress.head, progress.built_under?)));
                let owed = match built {
                    Some((head, policy))
                        if self.checkpoint_attestation_owed_in_txn(
                            &txn,
                            &issuer.public_key(),
                            head,
                            &policy,
                        )? =>
                    {
                        Some(head)
                    }
                    _ => None,
                };
                (false, owed)
            }
        };
        if due {
            return Ok(match self.write_or_reuse_authority_checkpoint(issuer)? {
                CheckpointWrite::Written(id) => {
                    if self.checkpoint_image_reached_policy(id)? {
                        AuthorityCheckpointUpkeep::Written(id)
                    } else {
                        AuthorityCheckpointUpkeep::WrittenAwaitingRoots(id)
                    }
                }
                CheckpointWrite::Reused { id, attested: true } => {
                    AuthorityCheckpointUpkeep::Attested(id)
                }
                CheckpointWrite::Reused {
                    attested: false, ..
                } => AuthorityCheckpointUpkeep::Idle,
            });
        }
        let Some(head) = owed else {
            return Ok(AuthorityCheckpointUpkeep::Idle);
        };
        self.host_attest_authority_checkpoint(issuer, head)?;
        Ok(AuthorityCheckpointUpkeep::Attested(head))
    }

    /// The kept image `id` names, decoded and checked against its id. Not
    /// trusted: an attestation and an adoption decide trust.
    pub fn authority_checkpoint_v2(&self, id: &[u8; 32]) -> Result<Option<AuthorityCheckpointV2>> {
        let txn = self.store.env.read_txn()?;
        let Some(bytes) = CHECKPOINT_IMAGE.get(&self.store, &txn, id)? else {
            return Ok(None);
        };
        let image = AuthorityCheckpointV2::decode(&bytes)?;
        if checkpoint_image_id(&bytes) != *id {
            return Err(invalid_authority());
        }
        Ok(Some(image))
    }

    /// The id of this vault's newest kept image.
    pub fn authority_checkpoint_v2_head(&self) -> Result<Option<[u8; 32]>> {
        let txn = self.store.env.read_txn()?;
        CHECKPOINT_HEAD.get(&self.store, &txn, &())
    }
}
