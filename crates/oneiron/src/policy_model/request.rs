//! What the caller asks about, and how the classifier is configured.

use serde::{Deserialize, Serialize};

use crate::llm::SafeguardModelBinding;
use crate::store::GateSystemNoticeAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyClassifySubject {
    OutboundContent,
    Action,
}

impl PolicyClassifySubject {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutboundContent => "outbound_content",
            Self::Action => "action",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyClassifyRequest {
    pub subject: PolicyClassifySubject,
    pub content: String,
    pub world_ref: Option<String>,
    pub caller_ref: Option<String>,
}

impl PolicyClassifyRequest {
    #[must_use]
    pub fn outbound_content(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::OutboundContent,
            content: content.into(),
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn action(content: impl Into<String>) -> Self {
        Self {
            subject: PolicyClassifySubject::Action,
            content: content.into(),
            world_ref: None,
            caller_ref: None,
        }
    }

    #[must_use]
    pub fn with_world_ref(mut self, world_ref: impl Into<String>) -> Self {
        self.world_ref = Some(world_ref.into());
        self
    }

    #[must_use]
    pub fn with_caller_ref(mut self, caller_ref: impl Into<String>) -> Self {
        self.caller_ref = Some(caller_ref.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyModelConfig {
    pub safeguard_binding: SafeguardModelBinding,
    /// Affordance the host attaches to owner-plane notices so the owner can
    /// jump straight to the setting that fired. `None` by default: the engine
    /// knows no product routes, so a host that wants the offer supplies both
    /// its label and its target.
    pub owner_setting_change_offer: Option<GateSystemNoticeAction>,
}
