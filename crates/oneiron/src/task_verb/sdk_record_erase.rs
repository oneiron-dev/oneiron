//! The served erase of one record (OF-150 / OF-163): `vault.records.erase_preview`
//! shows what an erase would take (the brief grants it revokes, the records
//! holding the same bytes, the LFS chunks it shares), and
//! `vault.records.erase_confirm` erases it under the caller's own proof once
//! they confirm that same preview by its digest. In a shared vault a record
//! another owner wrote, and the confirmed record itself where two or more
//! Owners hold the vault, starts its own `erase` act instead, which
//! `vault.shared.execute` carries out once its veto window has run out.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteEntityPreview;
use crate::memory::{
    DeleteReceipt, EraseOptions, EraseReason, MEMORY_CODE_INVALID_STATE, Memory, MemoryError,
    MemoryResult, SameBytesHold, SameBytesOutcome,
};
use crate::{EntityId, entity_id::bytes_to_hex_lower};

/// `vault.records.erase_preview`'s input: the record to erase.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseRequest {
    pub record: EntityId,
}

/// `vault.records.erase_confirm`'s input: the record, the digest of the
/// preview the caller confirms, and whether every other record holding the
/// same bytes goes too.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseConfirmRequest {
    pub record: EntityId,
    pub preview_digest: String,
    #[serde(default)]
    pub also_same_bytes: bool,
}

/// One live brief grant the erase revokes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseShare {
    pub grant: String,
    pub recipient: String,
}

/// One content hash the record holds, and the other records holding it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseHeldBytes {
    pub content_hash: String,
    pub other_holders: Vec<String>,
}

/// One LFS chunk the record's object shares, and the other owners of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseLfsChunk {
    pub chunk_hash: String,
    pub other_owners: Vec<String>,
}

/// `vault.records.erase_preview`'s answer. `preview_digest` is the BLAKE3 of
/// the rest of it; `erase_confirm` takes it back, so a record whose shares or
/// same-bytes holders changed since is refused, not erased.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordErasePreview {
    pub record: String,
    pub shared_with: Vec<EraseShare>,
    pub held_bytes: Vec<EraseHeldBytes>,
    pub lfs_chunks: Vec<EraseLfsChunk>,
    /// What `also_same_bytes` would also take.
    pub same_bytes: Vec<String>,
    /// Federation recipients may keep copies after a local erase.
    pub remote_copies_may_remain: bool,
    pub preview_digest: String,
}

/// What became of one other record holding the same bytes: `erased`,
/// `held` (with its reason code, and the `erase` act it started, if any) or
/// `failed` (with the error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseSameBytesRow {
    pub record: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DeleteReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `vault.records.erase_confirm`'s answer: the confirmed record's receipt,
/// its own `erase` act when it waits on a veto window, and one row per other
/// record holding its bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordEraseOutcome {
    pub first: DeleteReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_act: Option<String>,
    pub same_bytes: Vec<EraseSameBytesRow>,
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes_to_hex_lower(bytes)
}

fn preview_view(preview: &DeleteEntityPreview) -> MemoryResult<RecordErasePreview> {
    let mut view = RecordErasePreview {
        record: preview.entity().to_hex(),
        shared_with: preview
            .shared_with()
            .iter()
            .map(|(grant, recipient)| EraseShare {
                grant: grant.to_hex(),
                recipient: recipient.to_hex(),
            })
            .collect(),
        held_bytes: preview
            .held_bytes()
            .iter()
            .map(|row| EraseHeldBytes {
                content_hash: hex(&row.content_hash()),
                other_holders: row.other_holders().iter().map(EntityId::to_hex).collect(),
            })
            .collect(),
        lfs_chunks: preview
            .lfs_chunks()
            .iter()
            .map(|row| EraseLfsChunk {
                chunk_hash: hex(&row.chunk_hash()),
                other_owners: row.other_owners().iter().map(EntityId::to_hex).collect(),
            })
            .collect(),
        same_bytes: preview
            .same_bytes_matches()
            .iter()
            .map(EntityId::to_hex)
            .collect(),
        remote_copies_may_remain: preview.remote_copies_may_remain(),
        preview_digest: String::new(),
    };
    let canonical = serde_json::to_vec(&view)
        .map_err(|_| MemoryError::bad_request("the erase preview does not encode"))?;
    view.preview_digest = blake3::hash(&canonical).to_hex().to_string();
    Ok(view)
}

const fn hold_code(hold: SameBytesHold) -> &'static str {
    match hold {
        SameBytesHold::AnotherOwnersRecord => "another_owners_record",
        SameBytesHold::LegalHold => "privacy_erase_kept",
        SameBytesHold::CompletionPending => "completion_pending",
        SameBytesHold::VetoWindow => "veto_window",
    }
}

/// `vault.records.erase_preview`: what erasing `record` would take, read
/// under the caller's own deletion authority.
pub fn preview_record_erase(
    memory: &Memory<'_>,
    input: RecordEraseRequest,
) -> MemoryResult<RecordErasePreview> {
    preview_view(&memory.preview_entity_delete(&input.record)?)
}

/// `vault.records.erase_confirm`: erases the record the caller previewed,
/// under a user hard delete, once the preview it takes again still has the
/// digest they confirmed. `owner` is the caller's own proof: with it a held
/// record starts its own `erase` act.
pub fn confirm_record_erase(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RecordEraseConfirmRequest,
) -> MemoryResult<RecordEraseOutcome> {
    let preview = memory.preview_entity_delete(&input.record)?;
    if preview_view(&preview)?.preview_digest != input.preview_digest {
        return Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            "the record's erase preview changed since it was shown",
            &["Preview the erase again and confirm what it shows now."],
        ));
    }
    let outcome = memory.confirm_entity_erase(
        &preview,
        EraseOptions {
            reason: EraseReason::UserHardDelete,
            also_same_bytes: input.also_same_bytes,
            veto_starter: Some(owner),
        },
    )?;
    Ok(RecordEraseOutcome {
        first: outcome.first,
        first_act: outcome.first_act,
        same_bytes: outcome
            .same_bytes
            .into_iter()
            .map(|(record, row)| {
                let record = record.to_hex();
                match row {
                    SameBytesOutcome::Erased(receipt) => EraseSameBytesRow {
                        record,
                        outcome: "erased".to_owned(),
                        receipt: Some(receipt),
                        reason: None,
                        act_id: None,
                        error: None,
                    },
                    SameBytesOutcome::Held { reason, act_id } => EraseSameBytesRow {
                        record,
                        outcome: "held".to_owned(),
                        receipt: None,
                        reason: Some(hold_code(reason).to_owned()),
                        act_id,
                        error: None,
                    },
                    SameBytesOutcome::Failed(error) => EraseSameBytesRow {
                        record,
                        outcome: "failed".to_owned(),
                        receipt: None,
                        reason: None,
                        act_id: None,
                        error: Some(error.to_string()),
                    },
                }
            })
            .collect(),
    })
}

/// `vault.records.erase_confirm` on an embedded handle: the embedded owner's
/// own erase.
pub fn confirm_record_erase_embedded(
    memory: &Memory<'_>,
    input: RecordEraseConfirmRequest,
) -> MemoryResult<RecordEraseOutcome> {
    let owner = memory.embedded_owner("vault.records.erase_confirm")?;
    confirm_record_erase(memory, &owner, input)
}
