//! Mint-time evidence for the extraction-only PERSON cleanup arm.
//!
//! Ordinary PERSON bodies have no minting-source field. Do not infer one from
//! missing claims, a display name, or claims that happened to mention the row.
//! The trusted Core extraction writer opts in through the mint-only door below.
//! Its local evidence is bound to the exact stored revision. A replacement,
//! an absent marker, or unreadable evidence leaves the PERSON off the list.

use super::{claim_source_is_machine_minted, prefixed_key};
use crate::Vault;
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;

const EXTRACTION_PERSON_PREFIX: &[u8] = b"vault_cleanup.extraction_person.v1:";
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
        if !claim_source_is_machine_minted(source) {
            return Ok(false);
        }
        self.with_write_txn(|wtxn| {
            let key = prefixed_key(EXTRACTION_PERSON_PREFIX, id);
            if self.store.entities.get(wtxn, id.as_bytes())?.is_some()
                || self.store.vault_meta.get(wtxn, &key)?.is_some()
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
                .entities
                .get(wtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("extraction person mint"))?;
            let mut evidence = blake3::hash(&raw).as_bytes().to_vec();
            evidence.extend_from_slice(source.as_str().as_bytes());
            self.store.vault_meta.put(wtxn, &key, &evidence)?;
            Ok(true)
        })
    }
}

pub(super) fn is_extraction_minted_person_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    person: &EntityId,
) -> Result<bool> {
    let key = prefixed_key(EXTRACTION_PERSON_PREFIX, person);
    let Some(evidence) = vault.store.vault_meta.get(rtxn, &key)? else {
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
    let Some(raw) = vault.store.entities.get(rtxn, person.as_bytes())? else {
        return Ok(false);
    };
    Ok(evidence[..REVISION_HASH_LEN] == blake3::hash(&raw).as_bytes()[..])
}
