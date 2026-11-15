//! Moved from `crates/oneiron/src/genui/receipt_view.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::genui::consent_eval::non_empty;
use oneiron_base::error::Result;
use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptDeepLink {
    pub target_kind: ReceiptDeepLinkKind,
    pub target_ref: String,
    pub label: String,
    pub resolution: ViewTimeResolution,
}

impl ReceiptDeepLink {
    pub fn new(
        target_kind: ReceiptDeepLinkKind,
        target_ref: impl Into<String>,
        label: impl Into<String>,
        resolution: ViewTimeResolution,
    ) -> Result<Self> {
        Ok(Self {
            target_kind,
            target_ref: non_empty("receipt deep-link target_ref", target_ref.into())?,
            label: non_empty("receipt deep-link label", label.into())?,
            resolution,
        })
    }

    #[must_use]
    pub fn fallback_text(&self) -> String {
        format!(
            "{} -> {} ({})",
            self.label,
            self.target_ref,
            self.resolution.as_str()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDeepLinkKind {
    Commitment,
    TranscriptMoment,
    Brief,
    Share,
    AccessGrant,
    Entity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("view.time.resolution")]
pub enum ViewTimeResolution {
    Active,
    Revoked,
    Unavailable,
}
