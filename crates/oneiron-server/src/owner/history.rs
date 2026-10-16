//! Erase history (ARCH-0038, ARCH-0032 #pins): the owner drops a text's edit
//! history below its oldest pin, by hand. Disk keeps everything until then;
//! no Grant and no scheduled job reaches this. The live text and every pinned
//! version read the same afterwards; only the history between them goes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::PurgeReceipt;
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

/// Erases `request.entity`'s history as `owner`.
pub(crate) fn erase(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &EraseHistory,
) -> OwnerResult<Erased> {
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
        .erase_text_history_as(owner, &entity, through.as_deref())
        .map(Erased::from)
        .map_err(|error| {
            if let Err(refusal) = vault.recheck_owner(owner) {
                return OwnerError::from(refusal);
            }
            erase_error(error)
        })
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
