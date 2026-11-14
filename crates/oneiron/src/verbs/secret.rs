//! `reveal`, `reveal.wait` and `reveal.describe`: an agent asks for a
//! secret or person's value by its handle (OF-560; ARCH-0069 #reveal-check, the code-mode
//! SDK's `reveal`). The doors are [`crate::Vault`]'s reveal doors under the
//! caller's own agent actor; the project and run come from the host's binding,
//! never from the input. `reveal` returns a pending reveal every time, and
//! `reveal.wait` collects the value once the owner's grant covers it: the first
//! answer that grants carries the value, and every later one only the receipt.
//! In code mode, `wait({reveal})` and `describe({handle})` reach the same rows.
//!
//! A value travels as `value` when it is UTF-8 text and as `value_base64`
//! otherwise. A code run's record keeps the answer without either
//! ([`kept_reveal_answer`]): the guest reads the value, and the run keeps the
//! handle. A call receipt's digest and every verb hook read the answer with
//! the handle where the value was ([`masked_reveal_reply`]).
use base64::Engine as _;

use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::secret_custody::{
    HandleReveal, SecretHandleCard, SecretRevealDecision, SecretRevealReceipt,
};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::secret::{
    RevealDecision, RevealDescribeRequest, RevealHandleCard, RevealPending, RevealProvenance,
    RevealReceipt, RevealRequest, RevealWaitAnswer, RevealWaitRequest,
};

/// `reveal` on a handle: an agent's ask for a secret's value for its model.
pub fn reveal_as_caller(memory: &Memory<'_>, input: RevealRequest) -> MemoryResult<RevealPending> {
    let asker = memory.reveal_asker()?;
    let reveal = memory
        .vault()
        .reveal_secret(&asker, &input.handle, &input.why)?;
    Ok(RevealPending {
        reveal: reveal.to_hex(),
    })
}

/// `reveal.wait` on a pending reveal: its decision, and the value the first
/// time it is granted.
pub fn wait_reveal_as_caller(
    memory: &Memory<'_>,
    input: RevealWaitRequest,
) -> MemoryResult<RevealWaitAnswer> {
    let asker = memory.reveal_asker()?;
    let reveal = EntityId::from_hex(input.reveal.trim())
        .map_err(|_| MemoryError::bad_request("reveal is not a reveal id"))?;
    let wait = memory.vault().wait_secret_reveal(&asker, &reveal)?;
    Ok(wait_answer(wait))
}

/// `reveal.wait` made again by the step that collected it, resumed after a
/// park (FIX 2360): the value its first wait delivered, read again under
/// `lease`, the lease its kept answer names (a PERSON reveal's too, FIX
/// 11683). Nothing is spent, stamped or extended; a lapsed lease answers
/// `expired`.
pub fn replay_reveal_as_caller(
    memory: &Memory<'_>,
    input: RevealWaitRequest,
    lease: EntityId,
) -> MemoryResult<RevealWaitAnswer> {
    let asker = memory.reveal_asker()?;
    let reveal = EntityId::from_hex(input.reveal.trim())
        .map_err(|_| MemoryError::bad_request("reveal is not a reveal id"))?;
    let wait = memory
        .vault()
        .replay_secret_reveal(&asker, &reveal, &lease)?;
    Ok(wait_answer(wait))
}

/// The guest's answer to a wait: the decision, the value as text or base64,
/// and the receipt.
fn wait_answer(wait: crate::secret_custody::SecretRevealWait) -> RevealWaitAnswer {
    let (value, value_base64) = match wait.value.as_deref() {
        None => (None, None),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => (Some(text.to_owned()), None),
            Err(_) => (
                None,
                Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            ),
        },
    };
    RevealWaitAnswer {
        decision: match wait.decision {
            SecretRevealDecision::Pending => RevealDecision::Pending,
            SecretRevealDecision::Granted => RevealDecision::Granted,
            SecretRevealDecision::Denied => RevealDecision::Denied,
            SecretRevealDecision::Expired => RevealDecision::Expired,
            SecretRevealDecision::Unavailable => RevealDecision::Unavailable,
        },
        value,
        value_base64,
        receipt: wait.receipt.map(reveal_receipt),
    }
}

/// `reveal.describe` on a handle, for the calling agent.
pub fn describe_secret_as_caller(
    memory: &Memory<'_>,
    input: RevealDescribeRequest,
) -> MemoryResult<RevealHandleCard> {
    let asker = memory.reveal_asker()?;
    if input.handle.trim().starts_with("pr") {
        let card = memory
            .vault()
            .describe_person_handle(&asker, &input.handle)?;
        let (reveal, grant_ref, refusal) = reveal_effect(card.reveal);
        return Ok(RevealHandleCard {
            label: card.handle.clone(),
            handle: card.handle,
            class: "names".to_owned(),
            status: "active".to_owned(),
            band: card.band.as_str().to_owned(),
            provenance: Some(RevealProvenance {
                record: card.claim.to_hex(),
                place: "claim".to_owned(),
                kind: "names".to_owned(),
                masked_at: None,
                learned_at: Some(card.learned_at),
            }),
            reveal: reveal.to_owned(),
            grant_ref,
            refusal,
        });
    }
    let card: SecretHandleCard = memory
        .vault()
        .describe_secret_handle(&input.handle, Some(&asker))?;
    let (reveal, grant_ref, refusal) = reveal_effect(card.reveal);
    Ok(RevealHandleCard {
        handle: card.handle,
        label: card.label,
        class: card.class.as_str().to_owned(),
        status: card.status.as_str().to_owned(),
        band: "restricted".to_owned(),
        provenance: card.provenance.map(|origin| RevealProvenance {
            record: origin.record.to_hex(),
            place: origin.place,
            kind: origin.kind,
            masked_at: Some(origin.masked_at),
            learned_at: None,
        }),
        reveal: reveal.to_owned(),
        grant_ref,
        refusal,
    })
}

fn reveal_effect(effect: HandleReveal) -> (&'static str, Option<String>, Option<String>) {
    match effect {
        HandleReveal::Hydrates { grant_ref } => ("hydrates", Some(grant_ref), None),
        HandleReveal::Asks => ("asks", None, None),
        HandleReveal::Refused { reason } => ("refused", None, Some(reason)),
    }
}

pub use crate::code_run::kept_reveal_answer;

pub use crate::task_verb::verb_hook_boundary::masked_reveal_reply;

/// The digest a call receipt keeps of the reply bytes a door sent for
/// `verb`: a `reveal.wait` reply's over its masked form
/// ([`masked_reveal_reply`]), any other's over its bytes.
#[must_use]
pub fn call_reply_digest(verb: &str, bytes: &[u8]) -> String {
    let Some(reply) = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|reply| masked_reveal_reply(verb, &reply))
    else {
        return crate::receipt::call_bytes_digest(bytes);
    };
    crate::receipt::call_json_digest(&reply)
}

pub use crate::task_verb::verb_hook_boundary::revealed_hook_view;

pub(crate) fn reveal_receipt(receipt: SecretRevealReceipt) -> RevealReceipt {
    RevealReceipt {
        reveal: receipt.reveal.to_hex(),
        handle: receipt.handle,
        class: receipt.class,
        why: receipt.why,
        connection: receipt.connection,
        provider: receipt.provider,
        project: receipt.project.map(|project| project.to_hex()),
        run: receipt.run,
        answered_by: receipt.answered_by,
        decision: receipt
            .decision
            .map(|decision| format!("gate:{}", decision.to_hex())),
        lease: receipt.lease.map(|lease| lease.to_hex()),
        asked_at: receipt.asked_at,
        delivered_at: receipt.delivered_at,
        cause: receipt.cause.map(|cause| cause.as_str().to_owned()),
        scope: receipt.scope.map(|scope| scope.as_str().to_owned()),
    }
}
