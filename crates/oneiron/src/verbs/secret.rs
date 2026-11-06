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
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::secret_custody::{
    HandleReveal, SecretHandleCard, SecretRevealDecision, SecretRevealReceipt, SecretSight,
};

/// `reveal`'s input: the handle, and why the agent needs the value.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealRequest {
    /// A custody or PERSON handle, such as `sc12` or `pr12`.
    pub handle: String,
    /// Why, one line of 1..=512 bytes; the owner reads it, and the receipt
    /// keeps it.
    pub why: String,
}

/// `reveal`'s answer: the pending reveal `reveal.wait` takes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealPending {
    /// The reveal's id, as 32 hex.
    pub reveal: String,
}

/// `reveal.wait`'s input: the pending reveal.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealWaitRequest {
    /// The reveal's id, as `reveal` answered it.
    pub reveal: String,
}

/// Where a reveal stands, as `reveal.wait` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevealDecision {
    /// Waiting on the owner.
    Pending,
    /// Granted: the value comes with the first such answer.
    Granted,
    /// The owner denied it.
    Denied,
    /// Its window closed; reveal again.
    Expired,
    /// Its secret was erased before its value went out; the receipt's
    /// `cause` names why (FIX 8350).
    Unavailable,
}

/// `reveal.wait`'s answer. `Debug` never prints the value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealWaitAnswer {
    pub decision: RevealDecision,
    /// The value, when it is UTF-8 text; only on the answer that delivers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The value as standard base64, when it is not UTF-8 text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_base64: Option<String>,
    /// The reveal's receipt, once it was answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<RevealReceipt>,
}

impl std::fmt::Debug for RevealWaitAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |value: &Option<String>| value.as_ref().map(|_| "<redacted>");
        f.debug_struct("RevealWaitAnswer")
            .field("decision", &self.decision)
            .field("value", &redacted(&self.value))
            .field("value_base64", &redacted(&self.value_base64))
            .field("receipt", &self.receipt)
            .finish()
    }
}

/// One reveal's receipt: the handle, never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealReceipt {
    pub reveal: String,
    pub handle: String,
    /// The disclosure class, such as `names` or `custody-portable`.
    pub class: String,
    pub why: String,
    /// The model connection the value went to.
    pub connection: Option<String>,
    pub provider: Option<String>,
    pub project: Option<String>,
    pub run: Option<String>,
    /// `standing:<grant ref>` or `owner:<hex>`.
    pub answered_by: Option<String>,
    /// The consent act's Gate receipt, `gate:<hex>`.
    pub decision: Option<String>,
    /// The lease that delivered it: a T1 lease, or a PERSON reveal's own.
    pub lease: Option<String>,
    pub asked_at: u64,
    pub delivered_at: Option<u64>,
    /// Why the reveal closed with no value, `None` otherwise (FIX 8350).
    pub cause: Option<String>,
    /// The reach of the standing grant that answered it: `project`,
    /// `every_project`, `task` or `run` (FIX 2354).
    pub scope: Option<String>,
}

/// `reveal.describe`'s input: one handle.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealDescribeRequest {
    /// A custody or PERSON handle, such as `sc12` or `pr12`.
    pub handle: String,
}

/// `reveal.describe`'s answer: what the handle names, and what a reveal of it
/// would do now. No value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealHandleCard {
    pub handle: String,
    /// The custody name.
    pub label: String,
    pub class: String,
    /// `active`, `suspended` or `revoked`.
    pub status: String,
    /// The claim band; custody is always `restricted`.
    pub band: String,
    /// Where a mask on write found it, when one did.
    pub provenance: Option<RevealProvenance>,
    /// `hydrates` (a grant covers it), `asks` or `refused`.
    pub reveal: String,
    /// The covering grant, when it hydrates.
    pub grant_ref: Option<String>,
    /// Why it would be refused.
    pub refusal: Option<String>,
}

/// The stored source of a handle: a masked secret or a PERSON claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealProvenance {
    /// The record whose text or field held it, as 32 hex.
    pub record: String,
    /// `body`, `claim`, `text:<field>` or `file`.
    pub place: String,
    /// The key's kind, such as `openai_key`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masked_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learned_at: Option<u64>,
}

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
pub(crate) use crate::code_run::kept_reveal_lease;

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
