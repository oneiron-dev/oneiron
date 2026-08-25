use serde::{Deserialize, Serialize};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
    pub intent_source: String,
    pub trigger_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
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
            content_ref: draft.content_ref,
            idempotency_key: draft.idempotency_key,
            dedupe_key: draft.dedupe_key,
            intent_source: trigger.source.as_str().to_owned(),
            trigger_ref: trigger.trigger_ref,
            job_ref: trigger.job_ref,
        }
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

    #[must_use]
    pub fn dedupe_key(mut self, dedupe_key: impl Into<String>) -> Self {
        self.dedupe_key = Some(dedupe_key.into());
        self
    }
}

/// O2 trigger source. All variants converge into [`OutboundIntent`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundIntentSource {
    /// OF-187 timer wake.
    Commitment,
    /// Dreamer gap queue.
    GapQueue,
    /// In-session agent action.
    AgentImmediate,
}

impl OutboundIntentSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commitment => "commitment",
            Self::GapQueue => "gap_queue",
            Self::AgentImmediate => "agent_immediate",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "commitment" | "commitment_timer_wake" => Some(Self::Commitment),
            "gap_queue" => Some(Self::GapQueue),
            "agent_immediate" => Some(Self::AgentImmediate),
            _ => None,
        }
    }
}

/// Source-specific trigger envelope for an outbound intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundIntentTrigger {
    pub source: OutboundIntentSource,
    pub trigger_ref: String,
    pub job_ref: Option<String>,
}

impl OutboundIntentTrigger {
    #[must_use]
    pub fn commitment_timer_wake(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::Commitment,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn gap_queue(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::GapQueue,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn agent_immediate(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::AgentImmediate,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn job_ref(mut self, job_ref: impl Into<String>) -> Self {
        self.job_ref = Some(job_ref.into());
        self
    }
}
