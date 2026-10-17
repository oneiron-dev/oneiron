//! Erase history (ARCH-0038, ARCH-0032 #pins): the owner drops a text's edit
//! history below its oldest pin, by hand. Disk keeps everything until then;
//! no Grant and no scheduled job reaches this. The live text and every pinned
//! version read the same afterwards; only the history between them goes.
//!
//! In a shared vault with two or more live Owners the erase waits on the
//! vault's `erase` veto window (Docs Q05): asking starts that act and erases
//! nothing, and the starter runs it once the window passes with no objection.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{PurgeReceipt, TextHistoryErase};
use oneiron::federation::PendingAuthorityAct;
use oneiron::memory::MemoryError;
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// `POST /v1/owner/history/erase`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EraseHistory {
    /// The NOTE or other text-carrying entity, as 32 hex.
    pub(crate) entity: String,
    /// Erase up to this frontier (base64 of its encoded bytes). By default,
    /// up to the oldest pin, or the head when nothing pins the text.
    #[serde(default)]
    pub(crate) through: Option<String>,
}

/// One history erase, as the engine filed it.
#[derive(Debug, Serialize)]
pub(crate) struct Erased {
    pub(crate) receipt: String,
    pub(crate) entity: String,
    pub(crate) document: String,
    /// The frontier asked for and the one applied, base64. They differ when
    /// a pin held the erase back.
    pub(crate) requested: String,
    pub(crate) applied: String,
    pub(crate) at: String,
}

impl From<PurgeReceipt> for Erased {
    fn from(receipt: PurgeReceipt) -> Self {
        Self {
            receipt: receipt.receipt,
            entity: receipt.entity,
            document: receipt.document,
            requested: STANDARD.encode(receipt.requested),
            applied: STANDARD.encode(receipt.applied),
            at: rfc3339_secs(receipt.at),
        }
    }
}

/// What asking to erase a history did, as the engine rules it for this vault.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum EraseOutcome {
    /// A personal vault, or a shared one with one live Owner: erased now.
    Erased(Erased),
    /// Two or more live Owners: nothing is erased yet. The vault's `erase`
    /// act started over exactly this range and every other Owner is told; an
    /// objection holds it. `POST /v1/owner/history/erase/execute` with its
    /// id runs it once the window passes with no objection.
    Waiting { act: PendingAuthorityAct },
}

/// `POST /v1/owner/history/erase/execute`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecuteErase {
    /// The id of the `erase` act a waiting history erase returned.
    pub(crate) act_id: String,
}

/// Asks to erase `request.entity`'s history as `owner`: erased now, or the
/// vault's `erase` act started (Docs Q05).
pub(crate) fn erase(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &EraseHistory,
) -> OwnerResult<EraseOutcome> {
    let entity = entity_id("entity", &request.entity)?;
    let through = request
        .through
        .as_deref()
        .map(|through| {
            STANDARD
                .decode(through)
                .map_err(|_| OwnerError::Invalid("through must be base64".to_owned()))
        })
        .transpose()?;
    vault
        .start_text_history_erase(owner, &entity, through.as_deref())
        .map(|outcome| match outcome {
            TextHistoryErase::Erased(receipt) => EraseOutcome::Erased(receipt.into()),
            TextHistoryErase::Waiting(act) => EraseOutcome::Waiting { act },
        })
        .map_err(|error| refused_as(vault, owner, error))
}

/// Runs the history erase a completed `erase` act names, once: the act is
/// one `owner` started here, and its window ran out with no objection. A
/// retry returns that erase's receipt.
pub(crate) fn execute(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &ExecuteErase,
) -> OwnerResult<Erased> {
    vault
        .execute_completed_text_history_erase(owner, &request.act_id)
        .map(Erased::from)
        .map_err(|error| refused_as(vault, owner, error))
}

/// A lapsed owner proof answers first; otherwise the engine's refusal.
fn refused_as(vault: &Vault, owner: &AuthenticatedOwner, error: MemoryError) -> OwnerError {
    if let Err(refusal) = vault.recheck_owner(owner) {
        return OwnerError::from(refusal);
    }
    erase_error(error)
}

/// Every history erase filed for `entity`.
pub(crate) fn receipts(vault: &Vault, entity: &str) -> OwnerResult<Vec<Erased>> {
    let entity = entity_id("entity", entity)?;
    Ok(vault
        .entity_text_purge_receipts(&entity)?
        .into_iter()
        .map(Erased::from)
        .collect())
}

fn erase_error(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_FORBIDDEN => OwnerError::Refused(error.message),
        oneiron::memory::MEMORY_CODE_NOT_FOUND => OwnerError::NotFound("text", error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => OwnerError::Host(anyhow::anyhow!("erase history: {}", error.message)),
    }
}
