//! `reveal`, `reveal.wait` and `reveal.describe`: an agent asks for a
//! secret's value by its handle (OF-560; ARCH-0069 #reveal-check, the code-mode
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
//! handle.
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::create_origin::task_create_origin_in_txn;
use crate::EntityId;
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, verify_actor_binding,
};
use crate::secret_custody::{
    HandleReveal, RevealAsker, SecretHandleCard, SecretRevealDecision, SecretRevealReceipt,
};

/// `reveal`'s input: the handle, and why the agent needs the value.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealRequest {
    /// The secret's handle, such as `sc12`, as the text or field holds it.
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
    /// The custody class, such as `custody-portable`.
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
    /// The T1 lease that delivered it.
    pub lease: Option<String>,
    pub asked_at: u64,
    pub delivered_at: Option<u64>,
}

/// `reveal.describe`'s input: one handle.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealDescribeRequest {
    /// The secret's handle, such as `sc12`.
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
    /// Always `restricted`: a secret sits above every model's read ceiling,
    /// and only a reveal reaches it.
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

/// Where a mask on write found a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealProvenance {
    /// The record whose text or field held it, as 32 hex.
    pub record: String,
    /// `body`, `claim`, `text:<field>` or `file`.
    pub place: String,
    /// The key's kind, such as `openai_key`.
    pub kind: String,
    pub masked_at: u64,
}

/// `reveal` on a handle: an agent's ask for a secret's value for its model.
pub fn reveal_as_caller(memory: &Memory<'_>, input: RevealRequest) -> MemoryResult<RevealPending> {
    let asker = reveal_asker(memory)?;
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
    let asker = reveal_asker(memory)?;
    let reveal = EntityId::from_hex(input.reveal.trim())
        .map_err(|_| MemoryError::bad_request("reveal is not a reveal id"))?;
    let wait = memory.vault().wait_secret_reveal(&asker, &reveal)?;
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
    Ok(RevealWaitAnswer {
        decision: match wait.decision {
            SecretRevealDecision::Pending => RevealDecision::Pending,
            SecretRevealDecision::Granted => RevealDecision::Granted,
            SecretRevealDecision::Denied => RevealDecision::Denied,
            SecretRevealDecision::Expired => RevealDecision::Expired,
        },
        value,
        value_base64,
        receipt: wait.receipt.map(reveal_receipt),
    })
}

/// `reveal.describe` on a handle, for the calling agent.
pub fn describe_secret_as_caller(
    memory: &Memory<'_>,
    input: RevealDescribeRequest,
) -> MemoryResult<RevealHandleCard> {
    let asker = reveal_asker(memory)?;
    let card: SecretHandleCard = memory
        .vault()
        .describe_secret_handle(&input.handle, Some(&asker))?;
    let (reveal, grant_ref, refusal) = match card.reveal {
        HandleReveal::Hydrates { grant_ref } => ("hydrates", Some(grant_ref), None),
        HandleReveal::Asks => ("asks", None, None),
        HandleReveal::Refused { reason } => ("refused", None, Some(reason)),
    };
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
            masked_at: origin.masked_at,
        }),
        reveal: reveal.to_owned(),
        grant_ref,
        refusal,
    })
}

/// The answer of a `reveal.wait` as a run's record keeps it: without the
/// value. The guest reads the full answer; its step row and any receipt keep
/// this one.
#[must_use]
pub fn kept_reveal_answer(output: &serde_json::Value) -> serde_json::Value {
    let mut kept = output.clone();
    if let Some(fields) = kept.as_object_mut() {
        fields.remove("value");
        fields.remove("value_base64");
    }
    kept
}

/// The asker of a reveal: the calling agent, and the project and run its
/// host bound. Only an agent reveals to a model; a reveal writes a receipt,
/// so an anonymous off-record session cannot make one.
fn reveal_asker(memory: &Memory<'_>) -> MemoryResult<RevealAsker> {
    verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "only an agent reveals a secret to its model",
            &["The owner reads a value at POST /v1/owner/secrets/reveal, with a reason."],
        ));
    }
    if memory.keeps_no_record() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a reveal writes its receipt, and an anonymous off-record session keeps none",
            &["Reveal outside the anonymous session."],
        ));
    }
    let txn = memory.vault().store.env.read_txn().map_err(Error::from)?;
    let origin = task_create_origin_in_txn(memory, &txn, memory.task_host())?;
    drop(txn);
    Ok(RevealAsker::new(
        memory.actor(),
        origin.as_ref().and_then(|origin| origin.project_ref()),
        origin.and_then(|origin| origin.run_id()),
    ))
}

fn reveal_receipt(receipt: SecretRevealReceipt) -> RevealReceipt {
    RevealReceipt {
        reveal: receipt.reveal.to_hex(),
        handle: receipt.handle,
        class: receipt.class.as_str().to_owned(),
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
    }
}
