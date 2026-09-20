//! Durable actor-scoped state for admitted Context Board plugin blocks.
//! State is a vault projection, not an ephemeral stream subscription or NOTE.

use super::admission::{AdmittedPluginSection, PluginSectionRegistry};
use super::claim::{PREDICATE_PLUGIN_SECTION_INSTALL, PluginInstallClaimPayload};
use super::manifest::SectionId;
use super::render::{PluginSectionRow, PluginSectionSnapshot};
use super::validate::provenance_matches_record;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

const BLOCK_PREFIX: &[u8] = b"context_board.block.v1:";
const BLOCK_SCAN_LIMIT: usize = 1024;

/// The implemented durable block kinds. Scratchpad is board state, not a NOTE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardBlockKind {
    Scratchpad,
}

/// A block belongs to one actor. There is no implicit vault-wide fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoardBlockScope {
    ActorPrivate { owner_ref: EntityId },
}

/// Typed input to the board state writer. The facade stamps the author.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoardBlockWriteEnvelope {
    pub section_id: SectionId,
    pub kind: BoardBlockKind,
    pub scope: BoardBlockScope,
    pub source_revision_ref: [u8; 16],
    pub markdown: String,
}

/// Stored revision of an actor-owned block, returned after commit and on read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoardBlockRecord {
    pub schema_version: u16,
    pub block_ref: [u8; 16],
    pub section_id: SectionId,
    pub kind: BoardBlockKind,
    pub author_ref: [u8; 16],
    pub source_revision_ref: [u8; 16],
    pub markdown: String,
}

fn invalid_block() -> MemoryError {
    MemoryError::bad_request("invalid Context Board block state")
}

fn refused_block() -> MemoryError {
    MemoryError {
        code: MEMORY_CODE_FORBIDDEN.to_owned(),
        message: "Context Board block scope or admission does not match".to_owned(),
        suggestions: vec!["Use the bound actor and a live registered board section.".to_owned()],
        successor_short_id: None,
        gate_denial: None,
    }
}

fn validate_block(row: &BoardBlockRecord) -> MemoryResult<()> {
    if row.schema_version != 1
        || row.markdown.trim().is_empty()
        || row.markdown.len() > super::super::frame::MAX_BOARD_ROW_BYTES / 4
        || row.section_id.0.is_empty()
        || row.section_id.0.len() > 128
        || EntityId::from_bytes(row.block_ref).is_err()
        || EntityId::from_bytes(row.author_ref).is_err()
    {
        return Err(invalid_block());
    }
    Ok(())
}

fn encode_block(row: &BoardBlockRecord) -> MemoryResult<Vec<u8>> {
    validate_block(row)?;
    serde_json::to_vec(row).map_err(|_| invalid_block())
}

fn decode_block(bytes: &[u8]) -> MemoryResult<BoardBlockRecord> {
    // Derived struct decoding rejects unknown and duplicate fields; fixed-size
    // revision/identity arrays reject truncated and overlong revisions.
    let row = serde_json::from_slice(bytes).map_err(|_| invalid_block())?;
    validate_block(&row)?;
    Ok(row)
}

fn block_prefix(actor: EntityId, section: &SectionId) -> Vec<u8> {
    let mut prefix = BLOCK_PREFIX.to_vec();
    prefix.extend_from_slice(actor.as_bytes());
    // Prefix-safe even when two admitted section names share a prefix.
    prefix.extend_from_slice(&(section.0.len() as u64).to_be_bytes());
    prefix.extend_from_slice(section.0.as_bytes());
    prefix
}

fn block_key(row: &BoardBlockRecord) -> MemoryResult<Vec<u8>> {
    let actor = EntityId::from_bytes(row.author_ref)?;
    let mut key = block_prefix(actor, &row.section_id);
    key.extend_from_slice(&row.block_ref);
    Ok(key)
}

/// Recheck the actual approved install and exact Active skill in the same
/// snapshot as the block operation. A cached registry is never authority.
fn require_live_section(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    registry: &PluginSectionRegistry,
    section_id: &SectionId,
) -> MemoryResult<()> {
    let AdmittedPluginSection {
        install_claim_id,
        manifest,
    } = registry.get(section_id).ok_or_else(refused_block)?;
    let family = &manifest.manifest().state_family;
    if family.family != "scratchpad"
        || family.version != 1
        || manifest.manifest().authority_lane.0 != "actor.private"
    {
        return Err(refused_block());
    }
    let claim = vault
        .get_claim_in_txn(txn, install_claim_id)?
        .ok_or_else(refused_block)?;
    if claim.predicate != PREDICATE_PLUGIN_SECTION_INSTALL
        || claim.approval != ClaimApprovalStatus::Approved
        || claim.lifecycle != ClaimLifecycleStatus::Active
        || claim.stale
    {
        return Err(refused_block());
    }
    let payload =
        PluginInstallClaimPayload::from_value(&claim.value).map_err(|_| refused_block())?;
    if payload.manifest().map_err(|_| refused_block())? != *manifest.envelope() {
        return Err(refused_block());
    }
    let raw = vault
        .store
        .entities
        .get(txn, payload.target.target_skill_ref().as_bytes())?
        .ok_or_else(refused_block)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(refused_block)?;
    if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
        return Err(refused_block());
    }
    let skill = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if !skill.lifecycle_status.loads_as_canon()
        || provenance_matches_record(manifest.provenance(), &skill).is_err()
    {
        return Err(refused_block());
    }
    Ok(())
}

impl Memory<'_> {
    /// Appends one versioned block to an already registered board section.
    /// Admission and actor binding are checked in the write transaction.
    pub fn put_board_block(
        &self,
        registry: &PluginSectionRegistry,
        envelope: &BoardBlockWriteEnvelope,
    ) -> MemoryResult<BoardBlockRecord> {
        let BoardBlockScope::ActorPrivate { owner_ref } = envelope.scope;
        if owner_ref != self.actor() {
            return Err(refused_block());
        }
        let row = BoardBlockRecord {
            schema_version: 1,
            block_ref: *EntityId::now().as_bytes(),
            section_id: envelope.section_id.clone(),
            kind: envelope.kind,
            author_ref: *self.actor().as_bytes(),
            source_revision_ref: envelope.source_revision_ref,
            markdown: envelope.markdown.clone(),
        };
        let bytes = encode_block(&row)?;
        let key = block_key(&row)?;
        self.with_verified_actor_write_txn(|txn| {
            require_live_section(self.vault(), txn, registry, &row.section_id)?;
            self.vault().store.vault_meta.put(txn, &key, &bytes)?;
            Ok(())
        })?;
        Ok(row)
    }

    /// Reads this actor's durable blocks under a live section registration.
    /// No caller-chosen owner is accepted and corrupt rows fail closed.
    pub fn board_blocks(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        limit: usize,
    ) -> MemoryResult<Vec<BoardBlockRecord>> {
        if limit == 0 || limit > BLOCK_SCAN_LIMIT {
            return Err(invalid_block());
        }
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        // Actor binding and the private rows share one read snapshot.
        let actor_raw = self
            .vault()
            .store
            .entities
            .get(&txn, self.actor().as_bytes())?
            .ok_or_else(refused_block)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw).ok_or_else(refused_block)?;
        if crate::provenance::validate_actor_class(actor_header.entity_type, self.actor_class())
            .is_err()
        {
            return Err(refused_block());
        }
        require_live_section(self.vault(), &txn, registry, section_id)?;
        let prefix = block_prefix(self.actor(), section_id);
        let mut rows = Vec::new();
        for entry in self.vault().store.vault_meta.prefix_iter(&txn, &prefix)? {
            let (key, bytes) = entry?;
            let row = decode_block(&bytes)?;
            if row.author_ref != *self.actor().as_bytes()
                || row.section_id != *section_id
                || block_key(&row)?.as_slice() != key.as_ref()
            {
                return Err(invalid_block());
            }
            rows.push(row);
            if rows.len() == limit {
                break;
            }
        }
        Ok(rows)
    }

    /// Projects stored block rows into the existing typed plugin renderer.
    /// Content and revision tokens stay quoted data, never board syntax.
    pub fn board_block_snapshot(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        limit: usize,
    ) -> MemoryResult<PluginSectionSnapshot> {
        let rows = self
            .board_blocks(registry, section_id, limit)?
            .into_iter()
            .map(|row| PluginSectionRow {
                row_id: row
                    .block_ref
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                cells: vec![
                    row.markdown,
                    row.source_revision_ref
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                ],
            })
            .collect();
        Ok(PluginSectionSnapshot {
            section_id: section_id.clone(),
            rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_codec_fails_closed_on_kind_revision_scope_and_unknown_fields() {
        let row = BoardBlockRecord {
            schema_version: 1,
            block_ref: [0x41; 16],
            section_id: SectionId("actor_scratchpad".to_owned()),
            kind: BoardBlockKind::Scratchpad,
            author_ref: [0x42; 16],
            source_revision_ref: [0x43; 16],
            markdown: "working state".to_owned(),
        };
        assert_eq!(
            decode_block(&encode_block(&row).expect("encode")).expect("decode"),
            row
        );
        for (field, value) in [
            ("kind", serde_json::json!("diary")),
            ("schema_version", serde_json::json!(2)),
            ("source_revision_ref", serde_json::json!([1, 2])),
            ("owner_ref", serde_json::json!("forged")),
            ("markdown", serde_json::json!("  ")),
        ] {
            let mut encoded = serde_json::to_value(&row).expect("json");
            encoded[field] = value;
            assert_eq!(
                decode_block(&serde_json::to_vec(&encoded).expect("bytes"))
                    .expect_err("invalid row")
                    .code,
                crate::memory::MEMORY_CODE_BAD_REQUEST
            );
        }
        let bytes = encode_block(&row).expect("encode");
        let text =
            std::str::from_utf8(&bytes)
                .expect("utf8")
                .replacen("{", "{\"schema_version\":1,", 1);
        assert!(decode_block(text.as_bytes()).is_err());
    }
}
