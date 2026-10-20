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
use super::ledger::events_in;
use super::model::{EsignEvent, invalid};
use super::outbound::EsignOutboundVerb;
use crate::edge::EdgeActorClass;
use crate::outbound::OutboundExecutionRequest;
use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};

/// One signing document's recorded send act. Key: id16 (document).
const SEND_ACT: SideTable<EntityId, NoticeSendAct, Named> =
    SideTable::new(&side_table::ESIGN_NOTICE_SEND_ACT);

/// The act that sent a document for signature, as its admission recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoticeSendAct {
    /// The principal the send crossed the gate as, lower-hex.
    principal: String,
    /// Its gate class: `human`, `agent` or `system`.
    class: String,
    /// The send's intent ref: its OF-327 ledger row, receipt `receipt:<ref>`.
    send_ref: String,
}

/// A recorded send act, read back for the notice worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecordedSendAct {
    pub(super) principal: EntityId,
    pub(super) class: EdgeActorClass,
}

/// Records the send `request` carries for `document`, in the e-sign sink's
/// writer right after its `Sent` event. The first act stands; a send whose
/// admitted call is not on the ledger, or does not match this act, records
/// nothing.
/// # Errors
/// A storage failure only.
pub(super) fn record_send_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    document: EntityId,
    request: &OutboundExecutionRequest<'_>,
) -> Result<()> {
    if SEND_ACT.contains(&vault.store, txn, &document)? {
        return Ok(());
    }
    let Some(act) = admitted_send_in(vault, txn, document, request)? else {
        return Ok(());
    };
    SEND_ACT.put(&vault.store, txn, &document, &act)
}

/// The send act as the ledger row its admission committed holds it: call 0
/// of the act's dispatch attempt, an e-sign send of `document` by the
/// request's own actor. `None` when there is no such row.
fn admitted_send_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
    request: &OutboundExecutionRequest<'_>,
) -> Result<Option<NoticeSendAct>> {
    #[derive(Deserialize)]
    struct Admitted {
        channel: String,
        verb: String,
        target: String,
        actor_class: String,
        #[serde(default)]
        actor_entity_ref: Option<String>,
    }
    let Ok(attempt) = crate::outbound::outbound_dispatch_attempt_id(request.intent_ref) else {
        return Ok(None);
    };
    let record = match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => record,
        Err(IntentLedgerError::Engine(error)) => return Err(error),
        Err(_) => return Ok(None),
    };
    let Some(record) = record else {
        return Ok(None);
    };
    let Ok(admitted) = serde_json::from_slice::<Admitted>(record.payload()) else {
        return Ok(None);
    };
    let send = EsignOutboundVerb::SendForSignature.as_str();
    let Ok(principal) = EntityId::from_hex(&request.intent.actor) else {
        return Ok(None);
    };
    let admitted_actor = admitted
        .actor_entity_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok());
    if record.server != "esign"
        || record.tool != send
        || admitted.channel != "esign"
        || admitted.verb != send
        || admitted.target != document.to_hex()
        || admitted_actor != Some(principal)
        || gate_class(&admitted.actor_class).is_none()
    {
        return Ok(None);
    }
    Ok(Some(NoticeSendAct {
        principal: principal.to_hex(),
        class: admitted.actor_class,
        send_ref: request.intent_ref.to_owned(),
    }))
}

/// `document`'s recorded send act, when one stands and the trail's first
/// sender, whom its notices name, is still its principal.
/// # Errors
/// A storage failure, or a row or trail that does not decode.
pub(super) fn send_act_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    document: EntityId,
) -> Result<Option<RecordedSendAct>> {
    let Some(act) = SEND_ACT.get(&vault.store, txn, &document)? else {
        return Ok(None);
    };
    let principal = EntityId::from_hex(&act.principal)?;
    let class = gate_class(&act.class).ok_or_else(|| invalid("send act class"))?;
    let first_sender = events_in(vault, txn, document)?
        .into_iter()
        .find(|row| matches!(row.event, EsignEvent::Sent))
        .and_then(|row| EntityId::from_hex(&row.actor.actor).ok());
    if first_sender != Some(principal) {
        return Ok(None);
    }
    Ok(Some(RecordedSendAct { principal, class }))
}

/// The class a gate class string names.
fn gate_class(class: &str) -> Option<EdgeActorClass> {
    [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ]
    .into_iter()
    .find(|known| known.gate_actor_class() == class)
}

/// An erased actor's recorded send acts go (FIX 3520): its documents'
/// notices then keep the caller-driven door only. A row that does not decode
/// names no one and stays.
/// # Errors
/// A storage failure.
pub(crate) fn erase_notice_send_act_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    for document in SEND_ACT.scan_keys(&vault.store, wtxn, &[])? {
        if SEND_ACT
            .get_lenient(&vault.store, wtxn, &document)?
            .is_some_and(|act| {
                EntityId::from_hex(&act.principal).is_ok_and(|named| named == *actor)
            })
        {
            SEND_ACT.delete(&vault.store, wtxn, &document)?;
        }
    }
    Ok(())
}
