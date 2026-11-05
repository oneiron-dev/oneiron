//! An ended delivery settles (OF-415, FIX 6363, Engine ruling 10-20). An
//! invitation or reminder whose document ended (voided, expired or past its
//! deadline, declined, or sealed) or whose recipient ended (it signed or
//! declined, or its signing window closed) before its export never waits for
//! a link forever. Its queue row fails terminally under its current lease with
//! a typed reason, `document_ended` or `recipient_ended`: nothing is sent and
//! nothing is dropped. That failed row is the owner's receipt, read back on
//! `vault.esign.get` as `delivery_receipts`, its `state` `ended`.
//!
//! Only a delivery that carries a signing link settles here. A void, expiry,
//! rejection or completion notice is sent because the document ended, and
//! goes out as before.
//!
//! The same `delivery_receipts` list each invitation or reminder still
//! queued and unexported that waits on its own (FIX 6423, 6455, 6482), its
//! `state` `waits` with its typed reason: an event of its document awaits
//! the owner's answer (`document_awaits_owner`), its document's trail does
//! not read (`document_unreadable`), the send's dispatch marker or admitted
//! call does not read (`send_unreadable`), or its recipient's signing links
//! do not read (`links_unreadable`). The view reads each one now through the
//! mint's own classifier, so it lists exactly what the next export would
//! wait on, and lists it even when the document's own trail does not read
//! (FIX 6481). A lease whose link was minted is out, and is not listed. A
//! queued notice that does not read (`notice_unreadable`) names no document
//! to list it under; the exporter logs that wait alone.

use crate::attempt_id::AttemptId;
use crate::attempt_inputs::FailAttempt;
use crate::attempt_state::AttemptState;
use crate::blob_artifact::esign::model::DocumentStatus;
use crate::blob_artifact::esign::model::SigningStatus;
use crate::blob_artifact::esign::model::invalid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

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

    pub fn from_code(code: &str) -> Option<Self> {
        [Self::DocumentEnded, Self::RecipientEnded]
            .into_iter()
            .find(|reason| reason.code() == code)
    }
}
