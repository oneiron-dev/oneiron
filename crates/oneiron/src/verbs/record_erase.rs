//! The served erase of one record (OF-150 / OF-163): the shared preview
//! `vault.owner_confirm.preview` shows what an erase would take (the brief
//! grants it revokes, the records holding the same bytes, the LFS chunks it
//! shares), and `vault.records.erase_confirm` erases it under the caller's
//! own proof once they confirm that same preview. In a shared vault a record
//! another owner wrote, and the confirmed record itself where two or more
//! Owners hold the vault, starts its own `erase` act instead, which
//! `vault.shared.execute` carries out once its veto window has run out.
use serde::{Deserialize, Serialize};

use super::owner_confirm;
use crate::consent::AuthenticatedOwner;
use crate::deletion::DeleteEntityPreview;
use crate::memory::{
    DeleteReceipt, EraseOptions, EraseReason, Memory, MemoryResult, SameBytesHold, SameBytesOutcome,
};
use crate::{EntityId, entity_id::bytes_to_hex_lower};

/// `vault.records.erase_confirm`'s input: the record, the confirm the shared
/// preview returned for this call, and whether every other record holding
/// the same bytes goes too.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordEraseConfirmRequest {
    pub record: EntityId,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
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

/// What erasing the record would take, as the shared preview shows it: the
/// record, the brief grants the erase revokes, the records holding the same
/// bytes, the LFS chunks it shares, and what `also_same_bytes` would also
/// take. The shared confirm binds it, so a record whose shares or
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

fn preview_view(preview: &DeleteEntityPreview) -> RecordErasePreview {
    RecordErasePreview {
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
    }
}

/// The held row's reason code, as [`SameBytesHold`] logs it.
fn hold_code(hold: SameBytesHold) -> &'static str {
    match hold {
        SameBytesHold::AnotherOwnersRecord => "another_owners_record",
        SameBytesHold::LegalHold => "privacy_erase_kept",
        SameBytesHold::VetoWindow => "veto_window",
    }
}

/// The erase's view twice over: the engine preview the erase runs on, and
/// the shown view the owner confirms. [`confirm_record_erase`] and the
/// shared preview call this same fn, so a confirm binds what the preview
/// showed.
pub(crate) fn record_erase_view(
    memory: &Memory<'_>,
    record: &EntityId,
) -> MemoryResult<(DeleteEntityPreview, RecordErasePreview)> {
    let preview = memory.preview_entity_delete(record)?;
    let view = preview_view(&preview);
    Ok((preview, view))
}

/// `vault.records.erase_confirm`: erases the record the caller previewed,
/// under the owner erase reason, once the preview it takes again is still
/// what they confirmed. `owner` is the caller's own proof: with it a held
/// record starts its own `erase` act. The confirm names the caller's own
/// live retained preview of this call first (FIX 12522, kept through the
/// shared row): without it the erase is refused, even when what it names is
/// fresh.
pub fn confirm_record_erase(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: RecordEraseConfirmRequest,
) -> MemoryResult<RecordEraseOutcome> {
    let ask = owner_confirm::asked("vault.records.erase_confirm", &input)?;
    let (preview, view) = record_erase_view(memory, &input.record)?;
    owner_confirm::admit(memory.vault(), owner, ask, &view)?;
    let outcome = memory.confirm_entity_erase(
        &preview,
        EraseOptions {
            reason: EraseReason::OwnerErase,
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
