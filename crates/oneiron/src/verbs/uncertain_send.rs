//! The input and answer of `vault.outbound.uncertain_send.answer` (FIX
//! 4747), a host door: the vault owner's answer to the inbox ask a
//! connector-send TASK raised when its send may have gone out and no
//! provider lookup could tell, the ask's one-tap actions. A server runs it
//! under the vault owner's proof; an embedded handle runs it as its embedded
//! owner. An agent never answers it.
//!
//! Resend releases the send for one more send under its engine send id,
//! which the TASK's executor makes. No resend settles the TASK
//! `owner_declined_resend`, sent no more. The first answer settles the ask;
//! a later one finds it settled.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::uncertain_send::{UncertainSendAnswer, UncertainSendAnswered};

/// `vault.outbound.uncertain_send.answer` under the owner's proof.
pub fn answer_uncertain_send_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: UncertainSendAnswer,
) -> MemoryResult<UncertainSendAnswered> {
    let outcome = vault.answer_uncertain_send(owner, input.task_ref, input.resend)?;
    Ok(UncertainSendAnswered {
        task_ref: input.task_ref,
        resend: input.resend,
        outcome,
    })
}
