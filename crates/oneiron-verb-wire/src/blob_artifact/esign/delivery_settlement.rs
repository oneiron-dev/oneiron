//! Moved from `crates/oneiron/src/blob_artifact/esign/delivery_settlement.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::delivery_capability::EsignDeliveryWait;
use serde::Deserialize;
use serde::Serialize;

/// Why an invitation or reminder ended unsent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EsignDeliveryEndReason {
    /// The document ended first: voided, expired or past its deadline,
    /// declined, or sealed.
    DocumentEnded,
    /// The recipient ended first: it signed or declined, or its signing
    /// window closed.
    RecipientEnded,
}

impl EsignDeliveryEndReason {
    /// The reason's code, as the settled queue row keeps it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentEnded => "document_ended",
            Self::RecipientEnded => "recipient_ended",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        [Self::DocumentEnded, Self::RecipientEnded]
            .into_iter()
            .find(|reason| reason.code() == code)
    }
}

/// One invitation or reminder that ended unsent, or that waits unexported:
/// the owner's receipt. An ended one says the delivery's last lease was never
/// exported; an earlier lease that lapsed with no ack may still have reached
/// its sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EsignDeliveryReceipt {
    /// The queued delivery, 32 lower-hex.
    pub attempt_ref: String,
    /// The lease it settled on, or its latest one.
    pub attempt_count: u32,
    /// The recipient it is for, by id.
    pub recipient: String,
    /// `invite` or `reminder`.
    pub transition: String,
    /// `state` and its typed `reason`.
    #[serde(flatten)]
    pub state: EsignDeliveryReceiptState,
    /// When it settled, or when its queue row last moved while it waits,
    /// Unix seconds.
    pub at: u64,
}

/// Where one receipt's delivery stands (FIX 6455).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum EsignDeliveryReceiptState {
    /// It settled unsent, for this reason (FIX 6363).
    Ended(EsignDeliveryEndReason),
    /// It is still queued and unexported, and waits on its own for this
    /// reason (FIX 6423, 6455).
    Waits(EsignDeliveryWait),
}
