//! Outbound intent wire vocabulary.
//! Entry: `OutboundIntent`.
//! Defines its own items.

use serde::{Deserialize, Serialize};

pub use crate::dreamer_runner::maintenance::identity::MentionProvenance;

/// Version for the intent field contract consumed by the later dispatcher.
pub const OUTBOUND_INTENT_SCHEMA_VERSION: &str = "outbound.intent.v1";

/// Outbound intent spine shared by OF-327 dispatch and receipt projection.
///
/// `job_ref` is optional so older ad-hoc or commitment-triggered intents remain
/// valid. Brief-rooted runs stamp it to make receipt rollups an indexed lookup
/// instead of a render-time chain walk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundIntent {
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub channel: String,
    pub target: String,
    /// Every recipient of one message sent to more than one, each address
    /// once, every To before every Cc (fix list row 17645): the first is
    /// `target`, in To. Empty for a send to `target` alone, which freezes,
    /// pins and sends exactly as before. Only an email send names a list,
    /// and only a sink that delivers to every recipient sends it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<OutboundRecipient>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Vault-wide semantic identity. Producers include recipient/principal scope
    /// in this key when the same topic may be delivered to different people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
    pub intent_source: String,
    pub trigger_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    /// The saved mention the target came from, when an agent named the
    /// person (OF-123): dispatch refuses while that mention is unsettled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention: Option<MentionProvenance>,
}

impl OutboundIntent {
    /// Builds an intent from one of the three O2 trigger doors.
    #[must_use]
    pub fn from_trigger(draft: OutboundIntentDraft, trigger: OutboundIntentTrigger) -> Self {
        Self {
            actor: draft.actor,
            on_behalf_of: draft.on_behalf_of,
            verb: draft.verb,
            channel: draft.channel,
            target: draft.target,
            recipients: Vec::new(),
            content_ref: draft.content_ref,
            idempotency_key: draft.idempotency_key,
            dedupe_key: draft.dedupe_key,
            intent_source: trigger.source.as_str().to_owned(),
            trigger_ref: trigger.trigger_ref,
            job_ref: trigger.job_ref,
            mention: draft.mention,
        }
    }

    /// This intent as one message to every recipient of `recipients`, the
    /// first of which is its `target` in To (fix list row 17645). An empty
    /// list keeps the send to `target` alone.
    #[must_use]
    pub fn with_recipients(mut self, recipients: Vec<OutboundRecipient>) -> Self {
        self.recipients = recipients;
        self
    }
}

/// The header that names one recipient of a mail message (fix list row
/// 17645).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundRecipientRole {
    /// Named in `To`.
    To,
    /// Named in `Cc`.
    Cc,
}

impl OutboundRecipientRole {
    /// The role's stable name, as it freezes and hashes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::To => "to",
            Self::Cc => "cc",
        }
    }
}

/// One recipient of a message sent to more than one: the header that names
/// it and its address, one opaque recipient (a list's address is not
/// expanded into its members).
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OutboundRecipient {
    pub role: OutboundRecipientRole,
    pub address: String,
}

impl OutboundRecipient {
    #[must_use]
    pub fn new(role: OutboundRecipientRole, address: impl Into<String>) -> Self {
        Self {
            role,
            address: address.into(),
        }
    }

    /// Whether `recipients` is the whole recipient list of one message sent
    /// to `target`: empty for a send to `target` alone, or at least two
    /// recipients, each address once and none blank, every To before every
    /// Cc, the first a To naming `target`.
    ///
    /// # Errors
    ///
    /// Why the list is no such list.
    pub fn check_list(target: &str, recipients: &[Self]) -> Result<(), &'static str> {
        let Some(first) = recipients.first() else {
            return Ok(());
        };
        if recipients.len() < 2 {
            return Err("a recipient list names more than one recipient");
        }
        if first.role != OutboundRecipientRole::To || first.address != target {
            return Err("a recipient list starts with its target, in To");
        }
        let mut cc_seen = false;
        for (index, recipient) in recipients.iter().enumerate() {
            if recipient.address.trim().is_empty() {
                return Err("a recipient list names a blank address");
            }
            match recipient.role {
                OutboundRecipientRole::To if cc_seen => {
                    return Err("a recipient list names every To before every Cc");
                }
                OutboundRecipientRole::To => {}
                OutboundRecipientRole::Cc => cc_seen = true,
            }
            if recipients[..index]
                .iter()
                .any(|earlier| earlier.address == recipient.address)
            {
                return Err("a recipient list names each address once");
            }
        }
        Ok(())
    }
}

/// Intent fields shared by all trigger sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundIntentDraft {
    pub actor: String,
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub content_ref: Option<String>,
    pub idempotency_key: Option<String>,
    pub dedupe_key: Option<String>,
    pub mention: Option<MentionProvenance>,
}

impl OutboundIntentDraft {
    #[must_use]
    pub fn new(
        actor: impl Into<String>,
        verb: impl Into<String>,
        channel: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            on_behalf_of: None,
            verb: verb.into(),
            channel: channel.into(),
            target: target.into(),
            content_ref: None,
            idempotency_key: None,
            dedupe_key: None,
            mention: None,
        }
    }

    #[must_use]
    pub fn on_behalf_of(mut self, principal: impl Into<String>) -> Self {
        self.on_behalf_of = Some(principal.into());
        self
    }

    #[must_use]
    pub fn content_ref(mut self, content_ref: impl Into<String>) -> Self {
        self.content_ref = Some(content_ref.into());
        self
    }

    #[must_use]
    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    /// Use the same key for repeat attempts at one semantic action, across
    /// channels; include any recipient scope needed to distinguish actions.
    #[must_use]
    pub fn dedupe_key(mut self, dedupe_key: impl Into<String>) -> Self {
        self.dedupe_key = Some(dedupe_key.into());
        self
    }

    /// The saved mention the target came from (OF-123 act-now guard).
    #[must_use]
    pub fn mention(mut self, mention: MentionProvenance) -> Self {
        self.mention = Some(mention);
        self
    }
}

pub use crate::store::outbound_trigger::{OutboundIntentSource, OutboundIntentTrigger};
