//! Byte-preserving signed authority history transfer for the vault owner,
//! and the owner's repair of a damaged authority clock floor (FIX 10106).
//! The engine owns signature checks, append-only storage and the local fold;
//! these DTOs only carry the original signed envelopes over JSON.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::Vault;
pub use crate::authority::{AuthorityClockRepair, AuthorityClockRepairOutcome};
use crate::consent::AuthenticatedOwner;
use crate::memory::{MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::authority_history::{
    AuthorityHistoryImported, SignedAuthorityHistory,
};

/// `vault.authority.history.export`: no local signing secret leaves.
pub fn export_authority_history_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<SignedAuthorityHistory> {
    owner.revalidate(vault)?;
    let entries = vault
        .export_signed_authority_history()?
        .into_iter()
        .map(|bytes| STANDARD.encode(bytes))
        .collect();
    Ok(SignedAuthorityHistory { entries })
}

/// `vault.authority.history.import`: the engine verifies and folds the
/// signed bytes atomically. A roster supplied by a caller is never authority.
pub fn import_authority_history_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: SignedAuthorityHistory,
) -> MemoryResult<AuthorityHistoryImported> {
    owner.revalidate(vault)?;
    let blobs = input
        .entries
        .into_iter()
        .map(|entry| {
            STANDARD.decode(entry).map_err(|_| {
                MemoryError::bad_request("entries must be base64 signed authority envelopes")
            })
        })
        .collect::<MemoryResult<Vec<_>>>()?;
    let entry_refs = vault
        .import_signed_authority_history(&blobs)?
        .into_iter()
        .map(|id| id.to_hex())
        .collect();
    Ok(AuthorityHistoryImported { entry_refs })
}

/// `vault.authority.clock.repair`: a damaged authority clock floor is
/// replaced by the highest second this vault proves it observed, judged
/// against the owner's proof in the repair's own writer; a whole floor, or
/// one nothing here proves, is left as it is and said so.
pub fn repair_authority_clock_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<AuthorityClockRepair> {
    Ok(vault.repair_authority_clock(owner)?)
}

/// `vault.authority.clock.repair` for `caller` as its ingress took it (FIX
/// 11190, FIX 11202): the caller is judged only in the repair's own writer,
/// against the floor it stages, so a damaged floor never refuses the owner
/// first.
pub fn repair_authority_clock_as(
    vault: &Vault,
    caller: crate::authority::ClockRepairCaller,
) -> MemoryResult<AuthorityClockRepair> {
    Ok(vault.repair_authority_clock_for(caller)?)
}
