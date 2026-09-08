//! Proposal accept/reject lane plus the archived query and restore door.

use super::person_provenance;
use super::{
    ArchivedEntity, CleanupAcceptOutcome, CleanupDecision, CleanupDigest, CleanupProposal,
    PROPOSAL_PREFIX, apply_archives_in_txn, cleanup_posture_in_txn, decode_proposal, fresh_row_id,
    proposal_key, put_digest_in_txn,
};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::deletion::{
    ARCHIVE_TOMBSTONE_PREFIX, TombstoneReason, entity_id_from_archive_tombstone_key,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Propose lane
// ---------------------------------------------------------------------------

/// Every open cleanup proposal, oldest first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_proposals(vault: &Vault) -> Result<Vec<CleanupProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, PROPOSAL_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_proposal(&key, &raw)?);
    }
    Ok(out)
}

/// One open proposal by id.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<Option<CleanupProposal>> {
    let rtxn = vault.store.env.read_txn()?;
    let key = proposal_key(proposal);
    let Some(raw) = vault.store.vault_meta.get(&rtxn, &key)? else {
        return Ok(None);
    };
    decode_proposal(&key, &raw).map(Some)
}

/// Accepts an archive proposal: re-runs the tripwire per candidate, archives
/// the ones still empty, skips the rest, and records ONE digest.
///
/// The proposal row is consumed whichever way each candidate went — an
/// accepted proposal is answered, and a skipped candidate is a fact about
/// THIS accept, recorded on the digest, not a proposal left half-open.
///
/// # Errors
///
/// [`Error::VaultCleanupProposalNotFound`] when no such proposal is open;
/// storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn accept_cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<CleanupAcceptOutcome> {
    vault.with_write_txn(|wtxn| accept_cleanup_proposal_in_txn(vault, wtxn, proposal))
}

pub(super) fn accept_cleanup_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
) -> Result<CleanupAcceptOutcome> {
    let key = proposal_key(proposal);
    let Some(raw) = vault.store.vault_meta.get(wtxn, &key)? else {
        return Err(Error::VaultCleanupProposalNotFound {
            proposal: proposal.to_hex(),
        });
    };
    let row = decode_proposal(&key, &raw)?;
    let applied = apply_archives_in_txn(vault, wtxn, &row.candidates)?;
    let digest = CleanupDigest {
        id: fresh_row_id()?,
        attempt: Some(row.attempt),
        proposal: Some(row.id),
        decision: CleanupDecision::ProposalAccepted,
        posture: cleanup_posture_in_txn(vault, wtxn)?,
        at: crate::unix_seconds_now(),
        archived: applied.archived.clone(),
        skipped: applied.skipped.clone(),
    };
    put_digest_in_txn(vault, wtxn, &digest)?;
    vault.store.vault_meta.delete(wtxn, &key)?;
    Ok(CleanupAcceptOutcome {
        proposal: row.id,
        archived: applied.archived,
        skipped: applied.skipped,
        digest: digest.id,
    })
}

/// Rejects an archive proposal. Nothing is archived and NO digest is written:
/// a refusal is not a decision anyone needs a receipt for, and the ratified
/// row's `receipt: false` is not a licence to receipt the refusal instead.
///
/// # Errors
///
/// [`Error::VaultCleanupProposalNotFound`] when no such proposal is open;
/// storage errors.
pub fn reject_cleanup_proposal(vault: &Vault, proposal: &EntityId) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        if !vault
            .store
            .vault_meta
            .delete(wtxn, &proposal_key(proposal))?
        {
            return Err(Error::VaultCleanupProposalNotFound {
                proposal: proposal.to_hex(),
            });
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Archive query + restore door
// ---------------------------------------------------------------------------

impl Vault {
    /// Every row this vault has archived, flagged as archived.
    ///
    /// ARCH-0024 :87 conformance, scoped to what exists: "resolver-visible"
    /// means the archived data is REACHABLE, not hidden. Archived rows still
    /// answer [`Vault::entities_by_type`] — this query is how a caller tells
    /// which of them are archived, and it is what a future resolver reads
    /// before deciding to restore.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_entities(&self) -> Result<Vec<ArchivedEntity>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in self
            .store
            .sync_state
            .prefix_iter(&rtxn, ARCHIVE_TOMBSTONE_PREFIX)?
        {
            let (key, raw) = row?;
            let Some(entity) = entity_id_from_archive_tombstone_key(&key) else {
                continue;
            };
            let decoded = crate::deletion::decode_tombstone_value(&raw);
            if decoded.reason != Some(TombstoneReason::ArchivedByCleanup) {
                continue;
            }
            out.push(ArchivedEntity {
                entity,
                archived_at: decoded.deleted_at,
                request_id: decoded
                    .request_id
                    .map(|bytes| Uuid::from_bytes(bytes).to_string()),
            });
        }
        Ok(out)
    }

    /// Whether — and when — `entity` is archived.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn archived_entity(&self, entity: &EntityId) -> Result<Option<ArchivedEntity>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(decoded) = self.archive_tombstone_in_txn(&rtxn, entity)? else {
            return Ok(None);
        };
        if decoded.reason != Some(TombstoneReason::ArchivedByCleanup) {
            return Ok(None);
        }
        Ok(Some(ArchivedEntity {
            entity: *entity,
            archived_at: decoded.deleted_at,
            request_id: decoded
                .request_id
                .map(|bytes| Uuid::from_bytes(bytes).to_string()),
        }))
    }

    /// Restores an archived row: clears its `archived_by_cleanup` marker and
    /// the shell is live again.
    ///
    /// # Scope: cleanup archives ONLY
    ///
    /// This is not an un-delete. An entity with no archive marker — a
    /// `user_delete` shell, a hard-purged id, a live row — is refused with
    /// [`Error::VaultCleanupRestoreNotArchived`], and a marker whose bytes do
    /// not read as an archive is refused with
    /// [`Error::VaultCleanupArchiveMarkerUndecodable`]. There is no path
    /// through this door to a tombstone the owner or a regulator asked for.
    ///
    /// It restores rather than withdraws because the archive published
    /// nothing: no peer ever saw the archive tombstone (see
    /// `DeleteReason::publishes_crdt_tombstone`), so reviving the shell takes
    /// nothing back from anyone. That is the whole reason the archive is
    /// local.
    ///
    /// # The contract this door carries (ARCH-0024 :87)
    ///
    /// **Re-mention restores, never duplicates.** When the ARCH-0024
    /// resolver lands, a re-mention that matches an archived row must call
    /// THIS door and get that row back — it must never mint a second entity
    /// for the same subject. This function is written so it cannot do
    /// otherwise: it creates nothing and mints no id, it only deletes a
    /// marker, so the restored entity is necessarily the same
    /// [`EntityId`] the archive kept. The resolver-side matching hook is that
    /// program's ticket, not this one; the contract is recorded here because
    /// this is the door it binds.
    ///
    /// Idempotent in effect but not in answer: restoring twice refuses the
    /// second time, because by then there is no archive to undo.
    ///
    /// # Errors
    ///
    /// [`Error::VaultCleanupRestoreNotArchived`],
    /// [`Error::VaultCleanupArchiveMarkerUndecodable`], storage errors.
    pub fn restore_archived(&self, entity: &EntityId) -> Result<()> {
        self.with_write_txn(|wtxn| {
            let Some(decoded) = self.archive_tombstone_in_txn(wtxn, entity)? else {
                return Err(Error::VaultCleanupRestoreNotArchived {
                    entity: entity.to_hex(),
                });
            };
            match decoded.reason {
                Some(TombstoneReason::ArchivedByCleanup) => {}
                Some(_) => {
                    return Err(Error::VaultCleanupArchiveMarkerUndecodable {
                        entity: entity.to_hex(),
                        reason: "marker carries a non-archive tombstone reason",
                    });
                }
                None => {
                    return Err(Error::VaultCleanupArchiveMarkerUndecodable {
                        entity: entity.to_hex(),
                        reason: "marker is legacy, reserved, unknown or malformed",
                    });
                }
            }
            self.clear_archive_tombstone_in_txn(wtxn, entity)?;
            let raw = self
                .store
                .entities
                .get(wtxn, entity.as_bytes())?
                .ok_or_else(|| Error::VaultCleanupRestoreNotArchived {
                    entity: entity.to_hex(),
                })?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("archived entity header"))?;
            if self.local_hard_delete_marker_exists_in_txn(wtxn, entity)?
                || self
                    .store
                    .entity_deletion_present_in_txn(wtxn, entity, header.learned_at)?
            {
                // The failed transaction restores the archive marker too.
                return Err(Error::VaultCleanupRestoreNotArchived {
                    entity: entity.to_hex(),
                });
            }
            person_provenance::clear_mint_evidence_in_txn(self, wtxn, entity)?;
            Ok(())
        })
    }
}
