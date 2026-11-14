//! Moved from `crates/oneiron/src/blob_artifact/esign/delivery_capability.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Why one delivery stays unexported for now (FIX 6423, 6455, 6482). It
/// waits on its own; no other delivery waits on it. The exporter logs its
/// code, and the owner reads it on `vault.esign.get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EsignDeliveryWait {
    /// An event of the document awaits its owner's answer.
    DocumentAwaitsOwner,
    /// The document's trail no longer reads.
    DocumentUnreadable,
    /// The delivery's own queued notice does not read as an invitation or a
    /// reminder of one document: its schema, the document it names, or a
    /// notice that carries no signing link.
    NoticeUnreadable,
    /// The send's admitted call does not read: its dispatch marker, or off
    /// the outbound ledger its dispatch ref, its ledger row or its frozen
    /// payload.
    SendUnreadable,
    /// The recipient's signing links on the document do not read: their
    /// index or a link's binding does not decode, an indexed link has no
    /// binding, or a binding names another document or recipient (FIX 6482).
    LinksUnreadable,
}

impl EsignDeliveryWait {
    /// The reason's code, as the exporter logs it and the owner reads it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DocumentAwaitsOwner => "document_awaits_owner",
            Self::DocumentUnreadable => "document_unreadable",
            Self::NoticeUnreadable => "notice_unreadable",
            Self::SendUnreadable => "send_unreadable",
            Self::LinksUnreadable => "links_unreadable",
        }
    }
}
