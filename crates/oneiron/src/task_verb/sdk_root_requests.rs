//! The input and answer of the owner's root-request cancel row (FIX 5586):
//! `vault.roots.requests.cancel`, a host door over the one engine door
//! `POST /v1/owner/roots/requests/cancel` already reaches,
//! [`Vault::cancel_root_request`] (#3261, FIX 4739). A server hands it the
//! owner's in-request proof, as `/v1/owner` takes it, and where his say-so
//! reached this install, for the act's audit record only; an embedded
//! handle answers as its own owner, on this install. Ids only: it adds no
//! state, no gate and no rule of its own, and the route is unchanged.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::authority::{ActSurface, authority_log_entity_id_from_hash};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{MemoryError, MemoryResult};
use crate::world_keys::OwnerWorkReceipt;

/// `vault.roots.requests.cancel`'s input: the root request to cancel, as
/// the route's body names it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootRequestCancelRequest {
    /// The request's signed authority-log entry, 64 lower-case hex: its
    /// receipt's `request`.
    pub request: String,
}

/// `vault.roots.requests.cancel`: records the owner's cancel of one root
/// request through [`Vault::cancel_root_request`], from any surface he is
/// authenticated on; `surface` is audit only. It takes effect on the target
/// whenever the target syncs it, offline or not. The answer is the request's
/// receipt: cancelled, or the answer its target gave first, which stands,
/// with the cancel marked so. A cancel the fold already holds records
/// nothing again.
///
/// # Errors
///
/// `BAD_REQUEST` for a `request` that is not 64 lower-case hex; the engine's
/// refusal for a request this install folds as no root request (nothing is
/// written); a stale owner proof; an install that cannot carry the act;
/// storage errors.
pub fn cancel_root_request_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    surface: ActSurface,
    input: RootRequestCancelRequest,
) -> MemoryResult<OwnerWorkReceipt> {
    let request = request_entry(&input.request)?;
    Ok(vault.cancel_root_request(owner, surface, request)?)
}

/// The AUTHORITY_LOG rows a cancel's receipt names, which its listing
/// names: the request's own entry and each cancel's, ascending.
#[must_use]
pub fn root_request_receipt_rows(receipt: &OwnerWorkReceipt) -> Vec<EntityId> {
    let cancels = receipt.cancel.iter().flat_map(|note| note.entries.iter());
    let mut rows: Vec<EntityId> = receipt
        .request
        .iter()
        .chain(cancels)
        .filter_map(|hex| entry_hash(hex))
        .filter_map(|hash| authority_log_entity_id_from_hash(&hash).ok())
        .collect();
    rows.sort_unstable();
    rows.dedup();
    rows
}

/// A request's entry as the route takes it: 64 lower-case hex.
fn request_entry(text: &str) -> MemoryResult<[u8; 32]> {
    entry_hash(text).ok_or_else(|| MemoryError::bad_request("request must be 64 lower-case hex"))
}

/// 32 bytes from 64 lower-case ASCII hex digits.
fn entry_hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut out = [0; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
