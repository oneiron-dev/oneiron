//! The served archive delete (ARCH-0073 §7, OF-449 L4):
//! `vault.archive.delete.preview` and `vault.archive.delete.confirm` over
//! explicit records the cleanup archived.
//!
//! Emptying the archive is the ladder's delete, never an erase: every
//! confirmed record is a user hard delete, and backups keep it under their
//! own retention. The preview is UX, not policy: it holds no token and no
//! expiry, and a caller may confirm without one. A confirm item may bind the
//! record hash and archive marker a preview read; a record that no longer
//! matches is refused. Every canonical distinct target answers one ordered
//! entry, its receipt or its typed error, and no failure hides another
//! record's receipt.
//!
//! These types carry no authority. The vault's owner on an unnarrowed
//! credential is served by the owner door (`preview_archive_purge`,
//! `confirm_archive_purge`); every other caller, an owner on a narrowed
//! credential included, by its checked siblings under the caller's own
//! archive-delete authority (`federation::require_archive_delete_in_txn`).

use serde::{Deserialize, Serialize};

use super::archive_purge::{ArchiveDeleteResults, ArchiveExpectation};
use super::support::verify_deletion_authority_in_txn;
use super::{
    ArchivePurgeEntry, DeleteReceipt, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_OWNER_BINDING_REQUIRED, Memory, MemoryError, MemoryResult,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::federation::Scope;

/// Explicit archived records to preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeletePreviewRequest {
    /// 32-hex entity ids of records the cleanup archived.
    pub targets: Vec<String>,
}

/// What a preview read of one archived record, which a confirm item may
/// bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteExpectation {
    /// 64-hex BLAKE3 hash of the record's retained bytes.
    pub record_hash: String,
    /// Hex of the record's exact archive marker bytes.
    pub archive_marker: String,
}

/// One archived record to delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteItem {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// The record as a preview read it; absent, the current record is
    /// deleted while it is still a cleanup archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<ArchiveDeleteExpectation>,
}

/// Explicit archived records to delete, each once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArchiveDeleteConfirmRequest {
    /// The records; an id named twice is deleted once, under its first item.
    pub items: Vec<ArchiveDeleteItem>,
}

/// One record's typed refusal or failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteError {
    /// One of the `MEMORY_CODE_*` strings.
    pub code: String,
    /// What refused or failed; a refusal's own code leads it.
    pub message: String,
    /// Remediation hints.
    pub suggestions: Vec<String>,
}

/// What deleting one previewed record would remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewRow {
    /// The record's retained bytes, not a filesystem-space estimate.
    pub record_bytes: u64,
    /// What a confirm item may bind.
    pub expected: ArchiveDeleteExpectation,
}

/// One target's preview: its row, or why it may not be deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ArchiveDeletePreviewOutcome {
    /// The record is a cleanup archive this caller may delete.
    Previewed(ArchiveDeletePreviewRow),
    /// The record is refused, alone.
    Refused {
        /// Why, typed.
        error: ArchiveDeleteError,
    },
}

/// One target's preview entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewEntry {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// Its row or its refusal.
    pub result: ArchiveDeletePreviewOutcome,
}

/// The impact preview: one entry per distinct target, in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeletePreviewView {
    /// Every distinct target's entry.
    pub entries: Vec<ArchiveDeletePreviewEntry>,
    /// The retained bytes of every previewed record.
    pub record_bytes: u64,
}

/// One deleted record's receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteReceiptView {
    /// Whether the record existed before the delete.
    pub existed: bool,
    /// Always `user_hard_delete`.
    pub reason: String,
    /// The redaction audit receipt (`redaction:<hex>`), when one was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// The role the delete was admitted under: owner, admin, member or
    /// agent.
    pub role: String,
    /// The membership grant or agent Grant that admitted it, as evidence;
    /// absent for an owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
}

/// One target's delete: its receipt, or why it was not deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ArchiveDeleteConfirmOutcome {
    /// The record was deleted.
    Deleted(ArchiveDeleteReceiptView),
    /// The record was refused or its delete failed, alone.
    Refused {
        /// Why, typed.
        error: ArchiveDeleteError,
    },
}

/// One target's confirm entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteConfirmEntry {
    /// The record's 32-hex entity id.
    pub entity: String,
    /// Its receipt or its error.
    pub result: ArchiveDeleteConfirmOutcome,
}

/// The confirm's answer: one entry per distinct target, in id order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArchiveDeleteBatchResult {
    /// Every distinct target's entry.
    pub entries: Vec<ArchiveDeleteConfirmEntry>,
}

/// Previews each distinct target under the caller's delete authority.
///
/// # Errors
/// `BAD_REQUEST` for a target that is no 32-hex entity id; a store or
/// decode failure of the read. Every refusal is its target's entry.
pub fn preview_archive_delete_wire(
    memory: &Memory<'_>,
    request: &ArchiveDeletePreviewRequest,
) -> MemoryResult<ArchiveDeletePreviewView> {
    let mut ids = request
        .targets
        .iter()
        .map(|target| entity_ref(target))
        .collect::<MemoryResult<Vec<_>>>()?;
    ids.sort_unstable();
    ids.dedup();
    let rows: ArchiveDeleteResults<ArchivePurgeEntry> = if owner_door_serves(memory)? {
        ids.iter()
            .map(|id| {
                let entry = memory.preview_archive_purge(&[*id]).and_then(|preview| {
                    preview
                        .entries()
                        .first()
                        .cloned()
                        .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))
                });
                (*id, entry)
            })
            .collect()
    } else {
        memory.preview_archive_delete(&ids)?
    };
    let mut view = ArchiveDeletePreviewView {
        entries: Vec::with_capacity(rows.len()),
        record_bytes: 0,
    };
    for (id, row) in rows {
        let result = match row {
            Ok(entry) => {
                view.record_bytes = view.record_bytes.saturating_add(entry.record_bytes);
                ArchiveDeletePreviewOutcome::Previewed(preview_row(&entry))
            }
            Err(error) if error.code == MEMORY_CODE_INTERNAL => return Err(error),
            Err(error) => ArchiveDeletePreviewOutcome::Refused {
                error: error_view(error),
            },
        };
        view.entries.push(ArchiveDeletePreviewEntry {
            entity: id.to_hex(),
            result,
        });
    }
    Ok(view)
}

/// Deletes each distinct target under the caller's current delete authority.
///
/// # Errors
/// `BAD_REQUEST` for an item whose entity is no 32-hex id or whose
/// expectation is no hex, and a failure to judge which door serves the
/// caller; every other refusal or failure is its target's entry.
pub fn confirm_archive_delete_wire(
    memory: &Memory<'_>,
    request: &ArchiveDeleteConfirmRequest,
) -> MemoryResult<ArchiveDeleteBatchResult> {
    let mut items = request
        .items
        .iter()
        .map(
            |item| -> MemoryResult<(EntityId, Option<ArchiveExpectation>)> {
                Ok((
                    entity_ref(&item.entity)?,
                    item.expected.as_ref().map(expectation).transpose()?,
                ))
            },
        )
        .collect::<MemoryResult<Vec<_>>>()?;
    items.sort_by_key(|(id, _)| *id);
    items.dedup_by_key(|(id, _)| *id);
    let rows: ArchiveDeleteResults<ArchiveDeleteReceiptView> = if owner_door_serves(memory)? {
        items
            .iter()
            .map(|(id, expected)| (*id, owner_confirm(memory, *id, expected.as_ref())))
            .collect()
    } else {
        memory
            .confirm_archive_delete(&items)
            .into_iter()
            .map(|(id, result)| {
                let receipt = result.map(|(receipt, authority)| {
                    receipt_view(
                        receipt,
                        authority.role().as_str(),
                        authority.grant().map(|grant| grant.to_hex()),
                    )
                });
                (id, receipt)
            })
            .collect()
    };
    Ok(ArchiveDeleteBatchResult {
        entries: rows
            .into_iter()
            .map(|(id, row)| ArchiveDeleteConfirmEntry {
                entity: id.to_hex(),
                result: match row {
                    Ok(receipt) => ArchiveDeleteConfirmOutcome::Deleted(receipt),
                    Err(error) => ArchiveDeleteConfirmOutcome::Refused {
                        error: error_view(error),
                    },
                },
            })
            .collect(),
    })
}

/// Whether the owner door serves this caller: the vault's owner by the
/// owner predicate the door itself checks, on no credential or one that
/// narrows no record axis (facets never bind the owner). A caller the
/// predicate refuses takes the checked siblings; any other failure of it
/// is the door's own error.
fn owner_door_serves(memory: &Memory<'_>) -> MemoryResult<bool> {
    if let Some(proof) = memory.presented_credential() {
        let claims = proof.claims();
        let mut whole = Scope::top();
        whole.verbs = proof.scope().verbs.clone();
        whole.facets = proof.scope().facets.clone();
        if !claims.records.is_empty()
            || !claims.channels.is_empty()
            || !whole.is_narrowing_of(proof.scope())
        {
            return Ok(false);
        }
    }
    let txn = memory
        .vault
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    match verify_deletion_authority_in_txn(memory.vault, &txn, memory.actor, memory.actor_class) {
        Ok(()) => Ok(true),
        Err(error)
            if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED
                || error.code == MEMORY_CODE_FORBIDDEN =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The owner door's delete of one record: a fresh preview, held to the
/// item's expectation when it names one, then its confirm, which rechecks
/// that preview in the delete's own writes.
fn owner_confirm(
    memory: &Memory<'_>,
    id: EntityId,
    expected: Option<&ArchiveExpectation>,
) -> MemoryResult<ArchiveDeleteReceiptView> {
    let preview = memory.preview_archive_purge(&[id])?;
    if let Some((hash, marker)) = expected
        && preview
            .entries()
            .iter()
            .any(|entry| entry.record_hash() != *hash || entry.marker() != marker.as_slice())
    {
        return Err(MemoryError::bad_request(
            "archive preview no longer matches; preview again",
        ));
    }
    let (_, result) = memory
        .confirm_archive_purge(&preview)
        .into_iter()
        .next()
        .ok_or_else(|| MemoryError::from(crate::Error::EntityNotFound))?;
    Ok(receipt_view(result?, "owner", None))
}

fn entity_ref(text: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(text).map_err(|_| {
        MemoryError::bad_request("an archived record is named by its 32-hex entity id")
    })
}

fn expectation(expected: &ArchiveDeleteExpectation) -> MemoryResult<ArchiveExpectation> {
    let invalid = || MemoryError::bad_request("expected names the hex a preview returned");
    let hash = decode_hex(&expected.record_hash)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(invalid)?;
    let marker = decode_hex(&expected.archive_marker).ok_or_else(invalid)?;
    Ok((hash, marker))
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn preview_row(entry: &ArchivePurgeEntry) -> ArchiveDeletePreviewRow {
    ArchiveDeletePreviewRow {
        record_bytes: entry.record_bytes,
        expected: ArchiveDeleteExpectation {
            record_hash: bytes_to_hex_lower(&entry.record_hash()),
            archive_marker: bytes_to_hex_lower(entry.marker()),
        },
    }
}

fn receipt_view(
    receipt: DeleteReceipt,
    role: &str,
    grant_ref: Option<String>,
) -> ArchiveDeleteReceiptView {
    ArchiveDeleteReceiptView {
        existed: receipt.existed,
        reason: receipt.reason,
        receipt_ref: receipt.receipt_ref,
        role: role.to_owned(),
        grant_ref,
    }
}

fn error_view(error: MemoryError) -> ArchiveDeleteError {
    ArchiveDeleteError {
        code: error.code,
        message: error.message,
        suggestions: error.suggestions,
    }
}
