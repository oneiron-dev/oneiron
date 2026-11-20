//! Mint-time evidence for the extraction-only PERSON cleanup arm.
//!
//! Ordinary PERSON bodies have no minting-source field. Do not infer one from
//! missing claims, a display name, or claims that happened to mention the row.
//! The trusted Core extraction writer opts in through the mint-only door below.
//! Its local evidence is bound to the exact stored revision. A replacement,
//! an absent marker, or unreadable evidence leaves the PERSON off the list.
//!
//! An attempt mints its people before the claims about them land, in a
//! separate write, and a try that stops in between is tried again. So a mint
//! an attempt makes also records the first try of that attempt's retry
//! lineage, and the PERSON stays off the list while a try of that lineage is
//! pending (FIX CLEANUP-ARCHIVES-MINTED-PERSON-BETWEEN-TRIES). A mint with no
//! such record is judged on its evidence and its claims alone.

use super::claim_source_is_machine_minted;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::ClaimSubject;
use crate::deletion::TombstoneReason;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::temporal::TimeRange;
use oneiron_contracts::claim::ClaimSource;

/// Mint-time extraction evidence: a 32-byte revision hash then the source tag
/// bytes. Key: id16 (PERSON id).
pub(super) const EXTRACTION_PERSON: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_EXTRACTION_PERSON);
const REVISION_HASH_LEN: usize = 32;

/// The first try of the retry lineage whose attempt minted the PERSON,
/// recorded with the mint. Key: id16 (PERSON id).
pub(super) const EXTRACTION_LINEAGE: SideTable<EntityId, AttemptId, Named> =
    SideTable::new(&side_table::VAULT_CLEANUP_EXTRACTION_LINEAGE);

impl Vault {
    /// Mints an extraction-produced PERSON and records its source atomically.
    ///
    /// This is a trusted Core writer door, not a source inferred by cleanup.
    /// Only the machine-minted source classes are accepted. It cannot label an
    /// existing PERSON as extraction-minted or change its provenance later.
    /// Ordinary `put_entity` PERSON rows never acquire cleanup eligibility.
    ///
    /// Returns `false` without writing if the source is outside that class or
    /// the id already exists, has deletion metadata, or has prior extraction evidence.
    /// A later replacement revision conservatively loses cleanup eligibility.
    ///
    /// # Errors
    ///
    /// The ordinary entity writer's validation errors and storage errors.
    pub fn put_extraction_minted_person(
        &self,
        id: &EntityId,
        source: ClaimSource,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            self.put_extraction_minted_person_in_txn(txn, id, source, occurred, learned_at, data)
        })
    }

    pub(crate) fn put_extraction_minted_person_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        source: ClaimSource,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Result<bool> {
        if !claim_source_is_machine_minted(source) {
            return Ok(false);
        }
        if self.store.port_entity_record(wtxn, id)?.is_some()
            || EXTRACTION_PERSON.contains(&self.store, wtxn, id)?
            || self.local_hard_delete_marker_exists_in_txn(wtxn, id)?
            || self
                .store
                .entity_deletion_present_in_txn(wtxn, id, learned_at)?
        {
            return Ok(false);
        }
        self.batch_in()
            .put(id, ENTITY_TYPE_PERSON, occurred, learned_at, data)
            .apply(wtxn)?;
        let raw = self
            .store
            .port_entity_record(wtxn, id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex("extraction person mint"))?;
        let mut evidence = blake3::hash(&raw).as_bytes().to_vec();
        evidence.extend_from_slice(source.as_str().as_bytes());
        EXTRACTION_PERSON.put(&self.store, wtxn, id, &evidence)?;
        Ok(true)
    }

    /// Mints the PERSON `id` that an attempt's extraction found, as
    /// [`Self::put_extraction_minted_person_in_txn`] does: `Generated`,
    /// occurred and learned at `at`. With the mint it records `lineage`, the
    /// first try of that attempt's retry lineage, so the cleanup spares the
    /// PERSON while a try of that lineage is pending.
    ///
    /// Returns `false` without writing where that door does.
    ///
    /// # Errors
    ///
    /// That door's.
    pub(crate) fn put_attempt_minted_person_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        at: u64,
        data: &[u8],
        lineage: AttemptId,
    ) -> Result<bool> {
        let occurred = TimeRange { start: at, end: at };
        if !self.put_extraction_minted_person_in_txn(
            wtxn,
            id,
            ClaimSource::Generated,
            occurred,
            at,
            data,
        )? {
            return Ok(false);
        }
        EXTRACTION_LINEAGE.put(&self.store, wtxn, id, &lineage)?;
        Ok(true)
    }

    /// Restores the PERSON `id` for the Dreamer's new mention of it, when it
    /// bears a cleanup-archive marker: the same record through the cleanup's
    /// restore door ([`Self::restore_archived_in_txn`]), never a second one
    /// (ARCH-0073 §6, ARCH-0055 §10; FIX
    /// NATIVE-CLAIM-LANDS-ON-ARCHIVED-PERSON). Its callers are all the
    /// Dreamer's: its person mint, when
    /// [`Self::put_attempt_minted_person_in_txn`] wrote nothing for the id a
    /// declaration derives, and each of its claim writers, for the entity
    /// subject of a claim it writes, through
    /// [`Self::restore_mentioned_subject_in_txn`]. A derivation's person item
    /// never calls it: that item stays refused for an archived id.
    ///
    /// Returns `false` without writing when `id` bears no marker with the
    /// cleanup-archive reason, when no row is stored for it, when the stored
    /// row is not a PERSON, or when anything but the archive removes it: a
    /// delete or an erase, applied, pending or published (a delete keeps the
    /// marker of an archived row, and the door would fail the caller's
    /// transaction there). Otherwise it calls the door and returns `true`.
    /// It asks who archived the PERSON no more than the door does.
    ///
    /// # Errors
    ///
    /// Storage errors, a stored row whose header does not parse, and the
    /// restore door's.
    pub(crate) fn restore_mentioned_person_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let archived = self
            .archive_tombstone_in_txn(wtxn, id)?
            .is_some_and(|marker| marker.reason == Some(TombstoneReason::ArchivedByCleanup));
        if !archived {
            return Ok(false);
        }
        let Some(row) = self.store.port_entity_record(wtxn, id)? else {
            return Ok(false);
        };
        // The door refuses a record a delete removes (its row fence, a
        // hard-delete marker, a pending or published tombstone), and its
        // refusal would fail the caller's transaction: the same checks here
        // answer `false` first.
        if row.entity_type != ENTITY_TYPE_PERSON
            || crate::ports::removed_in_txn(&self.store, wtxn, id)?
            || self.local_hard_delete_marker_exists_in_txn(wtxn, id)?
            || self
                .store
                .entity_tombstone_present_in_txn(wtxn, id, row.learned_at)?
        {
            return Ok(false);
        }
        self.restore_archived_in_txn(wtxn, id)?;
        Ok(true)
    }

    /// Restores the PERSON a claim the Dreamer writes is about, as
    /// [`Self::restore_mentioned_person_in_txn`] does, when the claim's
    /// `subject` is an entity; an edge subject restores nothing. A claim
    /// about a PERSON under a cleanup archive is a new mention of that
    /// person, so every claim writer of the Dreamer calls this in the
    /// claim's own transaction, after the claim is written: the promotion
    /// writer, the open-conflict marker, a recipe's output, a settlement's
    /// answer and the alternative it keeps, a revert's copy, the nightly
    /// merge, the curator's stand-copy, a tournament's winner, a maintenance
    /// finding (a stewardship reach-out) and a durable step's `dreamer.step`
    /// claim (FIX DREAMER-DIRECT-CLAIM-WRITERS-LAND-ON-ARCHIVED-PERSON).
    ///
    /// # Errors
    ///
    /// [`Self::restore_mentioned_person_in_txn`]'s.
    pub(crate) fn restore_mentioned_subject_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        subject: ClaimSubject,
    ) -> Result<bool> {
        match subject {
            ClaimSubject::Entity(id) => self.restore_mentioned_person_in_txn(wtxn, &id),
            ClaimSubject::Edge { .. } => Ok(false),
        }
    }
}

/// Drops what the mint recorded for `id`: its evidence, and the lineage of
/// the attempt that minted it.
pub(super) fn clear_mint_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    EXTRACTION_PERSON.delete(&vault.store, txn, id)?;
    EXTRACTION_LINEAGE.delete(&vault.store, txn, id)?;
    Ok(())
}

/// Whether the attempt that minted `person` may still land a claim about it:
/// a try of the retry lineage its mint recorded is pending. `false` for a
/// mint that recorded no lineage. A record that does not decode reads as
/// pending, so the PERSON stays off the list.
///
/// # Errors
///
/// Storage errors, and the queue's read errors.
pub(super) fn minting_lineage_pending_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<bool> {
    let Some(stored) = EXTRACTION_LINEAGE.get_bytes(&vault.store, rtxn, person)? else {
        return Ok(false);
    };
    let Ok(first) = EXTRACTION_LINEAGE.decode_value(&stored) else {
        return Ok(true);
    };
    AttemptQueue::new(vault).retry_lineage_pending_in_txn(rtxn, first)
}

pub(super) fn is_extraction_minted_person_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<bool> {
    let Some(evidence) = EXTRACTION_PERSON.get(&vault.store, rtxn, person)? else {
        return Ok(false);
    };
    let Some(source_bytes) = evidence.get(REVISION_HASH_LEN..) else {
        return Ok(false);
    };
    let source = std::str::from_utf8(source_bytes)
        .ok()
        .and_then(ClaimSource::parse);
    if !source.is_some_and(claim_source_is_machine_minted) {
        return Ok(false);
    }
    let Some(raw) = vault
        .store
        .port_entity_record(rtxn, person)?
        .map(|row| row.encode())
    else {
        return Ok(false);
    };
    Ok(evidence[..REVISION_HASH_LEN] == blake3::hash(&raw).as_bytes()[..])
}
