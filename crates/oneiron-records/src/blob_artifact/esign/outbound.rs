//! Moved from `crates/oneiron/src/blob_artifact/esign/outbound.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
use crate::outbound::*;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

/// The vault owner's act an admitted e-sign act records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerSendAct {
    /// His own send, remind or void: his actor and the decision his
    /// revalidated proof carried.
    Direct { actor: String, decision_ref: String },
    /// His one-time press on an agent's send or reminder, as the gate spent
    /// it admitting this act: the ledger intent the press released and the
    /// effect digest it approved, both lower-hex (FIX 6362).
    Approved {
        intent_ref: String,
        effect_digest: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsignOutboundVerb {
    SendForSignature,
    Remind,
    Void,
}

impl EsignOutboundVerb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SendForSignature => "send_for_signature",
            Self::Remind => "remind",
            Self::Void => "void",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignOutboundCommand {
    pub document: String,
    /// Reviewed recipient count. Rechecked even on remind/resend.
    pub recipient_count: usize,
    pub verb: EsignOutboundVerb,
    pub reason: Option<String>,
}
