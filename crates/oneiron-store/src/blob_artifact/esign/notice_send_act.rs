//! The send act a signing document's staged notices go out under while no
//! caller is present (FIX 6219, Engine design B).
//!
//! When a document is sent for signature, the e-sign sink records here, in
//! the writer that appends the trail's `Sent` event, the act that authorized
//! it: the principal the send crossed the gate as, its gate class, and the
//! send's intent ref (its OF-327 ledger row and `receipt:` id). Both come off
//! the ledger row the send's admission committed, never from a caller. The
//! notices that document stages later name that principal (the trail's first
//! sender), and the housekeeping notice worker sends them as it while it
//! still stands.
//!
//! No credential is kept: no slip, token or proof. The row is engine-private
//! and is never copied into a notice or the delivery outbox. A send whose
//! admitted call cannot be read records nothing: its notices keep the
//! caller-driven door, and the send itself goes on unchanged.
use crate::blob_artifact::esign::model::invalid;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// The act that sent a document for signature, as its admission recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeSendAct {
    /// The principal the send crossed the gate as, lower-hex.
    pub principal: String,
    /// Its gate class: `human`, `agent` or `system`.
    pub class: String,
    /// The send's intent ref: its OF-327 ledger row, receipt `receipt:<ref>`.
    pub send_ref: String,
}

/// A recorded send act, read back for the notice worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordedSendAct {
    pub principal: EntityId,
    pub class: EdgeActorClass,
}

/// The class a gate class string names.
pub fn gate_class(class: &str) -> Option<EdgeActorClass> {
    [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ]
    .into_iter()
    .find(|known| known.gate_actor_class() == class)
}
