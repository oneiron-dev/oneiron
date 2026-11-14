//! The owner's per-call erase of an outbound call's frozen request (FIX
//! 11801): evidence only. The engine writer owns the erase, its delivery
//! accounting and its retirement finishers; this door only exposes that act
//! through the typed owner surface, with the owner's proof checked in the
//! erase's own writer. The Owner may apply an asker's approved check-in for
//! the erase there (2k2; P25-SHAPE Q1 = A).

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

use super::connector_call_error;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::outbound_call_erase::{
    OutboundCallRequestEraseRequest, OutboundCallRequestErased,
};

/// `vault.outbound_calls.request.erase`: the owner's erase of one outbound
/// call's frozen request. The owner's proof is revalidated in the
/// erase's own writer; the writer keeps the row's id, attempt
/// binding, accounting, state and delivery knowledge and loses its request.
pub fn erase_outbound_call_request_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OutboundCallRequestEraseRequest,
) -> MemoryResult<OutboundCallRequestErased> {
    let attempt_id = AttemptId::from_bytes(input.attempt.as_bytes())?;
    let applied = super::shared::check_in_ref(input.check_in_ref.as_deref())?.map(|id| {
        crate::check_in::AppliedCheckIn {
            id,
            verb: "vault.outbound_calls.request.erase",
            effect_digest: crate::check_in::outbound_call_request_erase_effect_digest(
                &input.attempt,
                input.call_seq,
            ),
        }
    });
    let (erased, decision) = vault
        .erase_outbound_call_request_as_owner(owner, attempt_id, input.call_seq, applied.as_ref())
        .map_err(connector_call_error)?;
    Ok(OutboundCallRequestErased {
        erased,
        check_in: Some(decision),
    })
}
