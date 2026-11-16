//! Moved from `crates/oneiron/src/genui/consent_cards.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::genui::consent_eval::non_empty;
use oneiron_base::error::Result;
use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSendItem {
    pub send_ref: String,
    pub counterparty_ref: String,
    pub channel: String,
    pub summary: String,
}

impl BundleSendItem {
    pub fn new(
        send_ref: impl Into<String>,
        counterparty_ref: impl Into<String>,
        channel: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            send_ref: non_empty("bundle send_ref", send_ref.into())?,
            counterparty_ref: non_empty("bundle counterparty_ref", counterparty_ref.into())?,
            channel: non_empty("bundle channel", channel.into())?,
            summary: non_empty("bundle summary", summary.into())?,
        })
    }

    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "{} via {}: {}",
            self.counterparty_ref, self.channel, self.summary
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("consent.scope.escalator")]
pub enum ConsentScopeEscalator {
    JustOnce,
    AlwaysThisContact,
    AlwaysThisVerbClass,
    AlwaysThisChannel,
}

impl ConsentScopeEscalator {
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::JustOnce,
            Self::AlwaysThisContact,
            Self::AlwaysThisVerbClass,
            Self::AlwaysThisChannel,
        ]
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::JustOnce => "Just this once",
            Self::AlwaysThisContact => "Always for this contact",
            Self::AlwaysThisVerbClass => "Always for this verb class",
            Self::AlwaysThisChannel => "Always on this channel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("bundle.approval.scope")]
pub enum BundleApprovalScope {
    ExactEnumeratedSends,
    BriefVerbClass,
}

impl BundleApprovalScope {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExactEnumeratedSends => "Approve these sends",
            Self::BriefVerbClass => "Approve this brief and verb class",
        }
    }
}
