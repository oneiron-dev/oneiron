//! NOTE tombstone review (OF-073, FIX 2419): the tombstones the monthly NOTE
//! review proposed for archived NOTEs nothing links to and no one read since
//! they were archived. The review only asks. Accepting tombstones the NOTE
//! through the owner's `user_delete`, which is never reverted; declining
//! leaves it archived and is not asked again for that archive.

use oneiron::Vault;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::memory::MemoryError;
use serde::{Deserialize, Serialize};

use super::stamp::rfc3339_secs;
use super::{OwnerError, OwnerResult, entity_id};

/// The open NOTE tombstone proposals, oldest first.
#[derive(Debug, Serialize)]
pub(crate) struct TombstoneReview {
    pub(crate) proposals: Vec<Proposal>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Proposal {
    pub(crate) note: String,
    pub(crate) kind: String,
    /// The kind's retention in days; the NOTE has stayed archived past
    /// twice that.
    pub(crate) retention_days: u32,
    pub(crate) archived_at: String,
    pub(crate) proposed_at: String,
}

/// Which proposal the owner decides.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Decide {
    /// A `note` from `GET /v1/owner/notes/tombstones`.
    pub(crate) note: String,
}

/// What accepting a tombstone did.
#[derive(Debug, Serialize)]
pub(crate) struct Tombstoned {
    pub(crate) note: String,
    /// The deletion receipt, when the rail wrote one.
    pub(crate) receipt: Option<String>,
}

pub(crate) fn review(vault: &Vault, owner: &AuthenticatedOwner) -> OwnerResult<TombstoneReview> {
    let actor = owner.revalidate(vault)?;
    let proposals = vault
        .memory(actor, EdgeActorClass::Human)
        .note_tombstone_proposals()
        .map_err(memory_error)?;
    Ok(TombstoneReview {
        proposals: proposals
            .into_iter()
            .map(|proposal| Proposal {
                note: proposal.note.to_hex(),
                kind: proposal.kind,
                retention_days: proposal.retention_days,
                archived_at: rfc3339_secs(proposal.archived_at),
                proposed_at: rfc3339_secs(proposal.proposed_at),
            })
            .collect(),
    })
}

pub(crate) fn accept(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Decide,
) -> OwnerResult<Tombstoned> {
    let note = entity_id("note", &request.note)?;
    let actor = owner.revalidate(vault)?;
    let receipt = vault
        .memory(actor, EdgeActorClass::Human)
        .accept_note_tombstone(&note)
        .map_err(memory_error)?;
    Ok(Tombstoned {
        note: note.to_hex(),
        receipt: receipt.receipt_ref,
    })
}

pub(crate) fn decline(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: &Decide,
) -> OwnerResult<TombstoneReview> {
    let note = entity_id("note", &request.note)?;
    let actor = owner.revalidate(vault)?;
    vault
        .memory(actor, EdgeActorClass::Human)
        .decline_note_tombstone(&note)
        .map_err(memory_error)?;
    review(vault, owner)
}

fn memory_error(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_FORBIDDEN => OwnerError::Refused(error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => OwnerError::Host(anyhow::anyhow!("NOTE tombstone: {}", error.message)),
    }
}
