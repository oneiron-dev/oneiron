//! Mint-time evidence for the extraction-only PERSON cleanup arm.
//!
//! Ordinary PERSON bodies have no minting-source field. Do not infer one from
//! missing claims, a display name, or claims that happened to mention the row.
//! The trusted Core extraction writer opts in through the mint-only door below.
//! Its local evidence is bound to the exact stored revision. A replacement,
//! an absent marker, or unreadable evidence leaves the PERSON off the list.

use super::claim_source_is_machine_minted;
use crate::Vault;
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;

/// Mint-time extraction evidence: a 32-byte revision hash then the source tag
/// bytes. Key: id16 (PERSON id).
pub(super) const EXTRACTION_PERSON: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::VAULT_CLEANUP_EXTRACTION_PERSON);
const REVISION_HASH_LEN: usize = 32;

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
        self.with_write_txn(|txn| {
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
}

pub(super) fn clear_mint_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    EXTRACTION_PERSON.delete(&vault.store, txn, id)?;
    Ok(())
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
