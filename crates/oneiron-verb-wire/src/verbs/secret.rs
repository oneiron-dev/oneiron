//! Moved from `crates/oneiron/src/verbs/secret.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use serde::Deserialize;
use serde::Serialize;

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
    /// `active` or `revoked`.
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
