//! Durable actor-scoped state for admitted Context Board plugin blocks.
//! State is a vault projection, not an ephemeral stream subscription or NOTE.
//! The session scratchpad itself is the `scratchpad` NOTE (`context_board::scratchpad`);
//! no production path writes a scratchpad block here.

use super::super::paging::{BoardPageCursor, decode_page_cursor, encode_page_cursor, page_binding};
use super::admission::{AdmittedPluginSection, PluginSectionRegistry};
use super::claim::PluginInstallClaimPayload;
use super::fit_install::section_install_authorized;
use super::manifest::SectionId;
use super::pages::{BoardBlockPage, PluginSectionSnapshotPage};
use super::render::{PluginSectionRow, PluginSectionSnapshot};
use super::validate::provenance_matches_record;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::side_table::{self, LegacyJson, SideKey, SideTable};
use serde::{Deserialize, Serialize};
use std::ops::Bound;

/// Block rows one read snapshot serves: a work-page size, not a cap. A larger
/// positive request continues through further pages to the end.
const BLOCK_WORK_PAGE: usize = 1_000;

/// The page kind block cursors bind to, with the actor and section.
const BLOCK_PAGE_KIND: &str = "context_board.plugin_blocks";

/// Durable actor-scoped plugin block rows. Key: actor id ‖ `section_id.len()`
/// (u64 big-endian) ‖ `section_id` bytes ‖ block id — length-prefixed so two
/// admitted section names sharing a prefix can never collide.
const PLUGIN_BLOCK: SideTable<BlockKey, BoardBlockRecord, LegacyJson> =
    SideTable::new(&side_table::CONTEXT_BOARD_PLUGIN_BLOCK);

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockKey {
    actor: EntityId,
    section_id: SectionId,
    block_ref: [u8; 16],
}

impl SideKey for BlockKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.actor.as_bytes());
        out.extend_from_slice(&(self.section_id.0.len() as u64).to_be_bytes());
        out.extend_from_slice(self.section_id.0.as_bytes());
        out.extend_from_slice(&self.block_ref);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (actor, rest) = bytes.split_at_checked(16)?;
        let actor = EntityId::from_bytes(actor.try_into().ok()?).ok()?;
        let (len, rest) = rest.split_at_checked(8)?;
        let len = u64::from_be_bytes(len.try_into().ok()?);
        let len = usize::try_from(len).ok()?;
        let (section, rest) = rest.split_at_checked(len)?;
        let section_id = SectionId(std::str::from_utf8(section).ok()?.to_owned());
        let block_ref = rest.try_into().ok()?;
        Some(Self {
            actor,
            section_id,
            block_ref,
        })
    }
}

/// The implemented durable block kinds: plugin board state, not the session pad.
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
        read_receipt: None,
        policy_denial: None,
        wrong_root: None,
        hook: None,
        retry_after: None,
        resets_at: Vec::new(),
        reason_codes: Vec::new(),
        legal_hold: None,
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

/// Test-only: exercises the exact JSON shape [`PLUGIN_BLOCK`]'s codec
/// enforces (`deny_unknown_fields` included) plus [`validate_block`], the way
/// [`Memory::put_board_block`] and [`Memory::board_blocks`] together do.
#[cfg(test)]
fn encode_block(row: &BoardBlockRecord) -> MemoryResult<Vec<u8>> {
    validate_block(row)?;
    serde_json::to_vec(row).map_err(|_| invalid_block())
}

#[cfg(test)]
fn decode_block(bytes: &[u8]) -> MemoryResult<BoardBlockRecord> {
    // Derived struct decoding rejects unknown and duplicate fields; fixed-size
    // revision/identity arrays reject truncated and overlong revisions.
    let row = serde_json::from_slice(bytes).map_err(|_| invalid_block())?;
    validate_block(&row)?;
    Ok(row)
}

/// The scan prefix (everything but the trailing block id) for one actor's
/// rows under one admitted section.
fn block_prefix(actor: EntityId, section: &SectionId) -> Vec<u8> {
    let mut prefix = actor.as_bytes().to_vec();
    // Prefix-safe even when two admitted section names share a prefix.
    prefix.extend_from_slice(&(section.0.len() as u64).to_be_bytes());
    prefix.extend_from_slice(section.0.as_bytes());
    prefix
}

fn invalid_block_cursor() -> MemoryError {
    MemoryError::bad_request_with(
        "cursor is not one an earlier page of this section returned",
        &["Pass the next_cursor of the previous page, or no cursor to start over."],
    )
}

/// Projects one stored block into the renderer's typed row.
fn block_snapshot_row(row: BoardBlockRecord) -> PluginSectionRow {
    PluginSectionRow {
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
    }
}

fn block_key(row: &BoardBlockRecord) -> MemoryResult<BlockKey> {
    let actor = EntityId::from_bytes(row.author_ref)?;
    Ok(BlockKey {
        actor,
        section_id: row.section_id.clone(),
        block_ref: row.block_ref,
    })
}

/// Recheck the actual authorized install and exact Active skill in the same
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
    // The owner's consent or a ready fit's receipt (FIX 9752), in this same
    // snapshot.
    if !section_install_authorized(vault, txn, install_claim_id, &claim)
        .map_err(|_| refused_block())?
    {
        return Err(refused_block());
    }
    let payload =
        PluginInstallClaimPayload::from_value(&claim.value).map_err(|_| refused_block())?;
    if payload.manifest().map_err(|_| refused_block())? != *manifest.envelope() {
        return Err(refused_block());
    }
    let raw = crate::ports::EntityStoreRead::port_entity_raw(
        &vault.store,
        txn,
        &payload.target.target_skill_ref(),
    )?
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
        validate_block(&row)?;
        let key = block_key(&row)?;
        self.with_verified_actor_write_txn(|txn| {
            require_live_section(self.vault(), txn, registry, &row.section_id)?;
            PLUGIN_BLOCK.put(self.vault(), txn, &key, &row)?;
            Ok(())
        })?;
        Ok(row)
    }

    /// Reads this actor's durable blocks under a live section registration:
    /// the first `limit` rows, or all of them when fewer exist. Each 1,000-row
    /// work page is its own read snapshot with its own actor and admission
    /// recheck. No caller-chosen owner is accepted and corrupt rows fail
    /// closed.
    pub fn board_blocks(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        limit: usize,
    ) -> MemoryResult<Vec<BoardBlockRecord>> {
        if limit == 0 {
            return Err(invalid_block());
        }
        let mut rows = Vec::new();
        let mut after = None;
        loop {
            let take = (limit - rows.len()).min(BLOCK_WORK_PAGE);
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            self.check_block_reader(&txn, registry, section_id)?;
            let page = self.block_rows_in_txn(&txn, section_id, after, take)?;
            drop(txn);
            let full = page.len() == take;
            after = page.last().map(|row| row.block_ref);
            rows.extend(page);
            if !full || rows.len() == limit {
                return Ok(rows);
            }
        }
    }

    /// One page of this actor's durable blocks after `cursor`: at most
    /// `limit` rows and at most one 1,000-row work page, with the truthful
    /// total and remaining counts of this read snapshot. The last page has
    /// `end` set and no cursor.
    pub fn board_blocks_page(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        cursor: Option<&str>,
        limit: usize,
    ) -> MemoryResult<BoardBlockPage> {
        if limit == 0 {
            return Err(invalid_block());
        }
        let binding = page_binding(
            BLOCK_PAGE_KIND,
            &[self.actor().as_bytes(), section_id.0.as_bytes()],
        );
        let after = cursor
            .map(|token| {
                decode_page_cursor(&binding, token)
                    .and_then(|cursor| <[u8; 16]>::try_from(cursor.after.as_slice()).ok())
                    .ok_or_else(invalid_block_cursor)
            })
            .transpose()?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        self.check_block_reader(&txn, registry, section_id)?;
        let rows = self.block_rows_in_txn(&txn, section_id, after, limit.min(BLOCK_WORK_PAGE))?;
        let keys = PLUGIN_BLOCK.scan_keys(
            &self.vault().store,
            &txn,
            &block_prefix(self.actor(), section_id),
        )?;
        drop(txn);
        let last = rows.last().map(|row| row.block_ref).or(after);
        let remaining = keys
            .iter()
            .filter(|key| last.is_none_or(|last| key.block_ref > last))
            .count();
        let next_cursor = last.filter(|_| remaining > 0).map(|last| {
            encode_page_cursor(
                &binding,
                &BoardPageCursor {
                    fence: None,
                    after: last.to_vec(),
                },
            )
        });
        Ok(BoardBlockPage {
            rows,
            total: u64::try_from(keys.len()).unwrap_or(u64::MAX),
            remaining: u64::try_from(remaining).unwrap_or(u64::MAX),
            end: next_cursor.is_none(),
            next_cursor,
        })
    }

    /// Actor binding and the live section registration, in the read snapshot
    /// the block rows are read from.
    fn check_block_reader(
        &self,
        txn: &heed::RoTxn<'_>,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
    ) -> MemoryResult<()> {
        let actor_raw = crate::ports::EntityStoreRead::port_entity_raw(
            &self.vault().store,
            txn,
            &self.actor(),
        )?
        .ok_or_else(refused_block)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw).ok_or_else(refused_block)?;
        if crate::provenance::validate_actor_class(actor_header.entity_type, self.actor_class())
            .is_err()
        {
            return Err(refused_block());
        }
        require_live_section(self.vault(), txn, registry, section_id)
    }

    /// Up to `take` of this actor's rows under `section_id`, in block order,
    /// strictly after `after` when it is set.
    fn block_rows_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        section_id: &SectionId,
        after: Option<[u8; 16]>,
        take: usize,
    ) -> MemoryResult<Vec<BoardBlockRecord>> {
        let actor = self.actor();
        let low = BlockKey {
            actor,
            section_id: section_id.clone(),
            block_ref: after.unwrap_or([0; 16]),
        };
        let high = BlockKey {
            actor,
            section_id: section_id.clone(),
            block_ref: [0xff; 16],
        };
        let start = if after.is_some() {
            Bound::Excluded(&low)
        } else {
            Bound::Included(&low)
        };
        let mut rows = Vec::new();
        for entry in
            PLUGIN_BLOCK.iter_range(&self.vault().store, txn, start, Bound::Included(&high))?
        {
            let (key, row) = entry.map_err(|_| invalid_block())?;
            validate_block(&row)?;
            if row.author_ref != *actor.as_bytes()
                || row.section_id != *section_id
                || block_key(&row)? != key
            {
                return Err(invalid_block());
            }
            rows.push(row);
            if rows.len() == take {
                break;
            }
        }
        Ok(rows)
    }

    /// Projects stored block rows into the existing typed plugin renderer:
    /// the first `limit` rows, or all of them when fewer exist. Content and
    /// revision tokens stay quoted data, never board syntax.
    pub fn board_block_snapshot(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        limit: usize,
    ) -> MemoryResult<PluginSectionSnapshot> {
        let rows = self
            .board_blocks(registry, section_id, limit)?
            .into_iter()
            .map(block_snapshot_row)
            .collect();
        Ok(PluginSectionSnapshot {
            section_id: section_id.clone(),
            rows,
        })
    }

    /// [`Self::board_blocks_page`] projected for the renderer, carrying the
    /// page's truthful total and remaining counts and its end.
    pub fn board_block_snapshot_page(
        &self,
        registry: &PluginSectionRegistry,
        section_id: &SectionId,
        cursor: Option<&str>,
        limit: usize,
    ) -> MemoryResult<PluginSectionSnapshotPage> {
        let page = self.board_blocks_page(registry, section_id, cursor, limit)?;
        Ok(PluginSectionSnapshotPage {
            snapshot: PluginSectionSnapshot {
                section_id: section_id.clone(),
                rows: page.rows.into_iter().map(block_snapshot_row).collect(),
            },
            total: page.total,
            remaining: page.remaining,
            next_cursor: page.next_cursor,
            end: page.end,
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
