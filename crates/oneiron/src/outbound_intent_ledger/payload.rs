//! A ledger row's payload at rest (FIX 9283, 9372, 2328, 2331). The row keeps
//! its frozen request in one of four stored forms, inside the same `payload`
//! field:
//!
//! - bare: the clear bytes, for an effect no actor admitted, as before;
//! - clear: an envelope naming the actor that admitted the send, then its
//!   clear bytes;
//! - sealed: an envelope naming the actor and the row's own custody ref, then
//!   the bytes sealed under that ref's ConnectorResume key, for an
//!   off-record caller (FIX 9372) or a request that carries a secret the
//!   side-row wall would refuse (FIX 2328, 2331): the whole request goes to
//!   custody and the transport opens it at use;
//! - erased: an envelope alone, once its actor is erased (FIX 9283), or the
//!   person it went to (FIX 10953).
//!
//! The clear and sealed envelopes also name the send's recipient, the
//! person its frozen counterparty resolved to at admission, so that
//! person's erase reaches the row too (FIX 10953).
//!
//! The intent id, payload hash and idempotency key stay those of the clear
//! bytes. The row's content digest covers the stored form, which is written
//! once at admission and carried unchanged by every later write until an
//! erase. Reads that hand a row to a caller open it; a sealed row opens only
//! under its own key, whose lifetime is the row's, not its caller's: no
//! PENDING_CALLS delete, acknowledgement or settlement retires it, only its
//! actor's erase does.

use heed::RwTxn;

use super::store::{get_ledger_record, ledger_rows, put_erased_record};
use super::types::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::secret_custody::{
    open_connector_resume_in_txn, retire_connector_resume_in_txn, seal_connector_resume_in_txn,
};
use crate::side_table::ErasedForm;

/// The custody generation a sealed ledger payload takes (FIX 9372).
pub(crate) const LEDGER_PAYLOAD_CUSTODY_GENERATION: u32 = 0;

/// Opens every stored envelope. Its first byte never starts a UTF-8 text, so
/// no frozen JSON request reads as one.
const ENVELOPE_TAG: &[u8] = b"\xFFoneiron:ledger-payload:v2:";

const KIND_CLEAR: u8 = 0;
const KIND_SEALED: u8 = 1;
const KIND_ERASED: u8 = 2;

/// The domain a row's own custody ref derives under, from its intent id.
const CUSTODY_REF_DOMAIN: &str = "oneiron outbound ledger payload custody v1";

/// The trusted facts admission keeps a row's payload by: the actor its Gate
/// verified, whether its caller keeps no record, and the person the
/// engine's own frozen send names as its counterparty. Never read from a
/// scoped request's own arguments or headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LedgerPayloadContext {
    pub(crate) actor: Option<EntityId>,
    pub(crate) off_record: bool,
    pub(crate) recipient: Option<EntityId>,
}

/// The frozen field the outbound dispatch pipeline names a send's
/// counterparty in: a comm party key.
const FROZEN_COUNTERPARTY_FIELD: &str = "counterparty_ref";

/// One stored payload, read.
enum StoredPayload<'a> {
    Bare(&'a [u8]),
    Clear {
        named: Named,
        payload: &'a [u8],
    },
    Sealed {
        named: Named,
        custody_ref: EntityId,
        ciphertext: &'a [u8],
    },
    Erased,
}

/// Whom a clear or sealed envelope names: the actor that admitted the send
/// and the person it went to.
#[derive(Clone, Copy, Default)]
struct Named {
    actor: Option<EntityId>,
    recipient: Option<EntityId>,
}

impl<'a> StoredPayload<'a> {
    fn parse(stored: &'a [u8]) -> IntentLedgerResult<Self> {
        let Some(rest) = stored.strip_prefix(ENVELOPE_TAG) else {
            return Ok(Self::Bare(stored));
        };
        let invalid = || IntentLedgerError::InvalidRecord("outbound intent payload envelope");
        let (&kind, rest) = rest.split_first().ok_or_else(invalid)?;
        if kind == KIND_ERASED {
            return if rest.is_empty() {
                Ok(Self::Erased)
            } else {
                Err(invalid())
            };
        }
        let (actor, rest) = take_optional_id(rest).ok_or_else(invalid)?;
        let (recipient, rest) = take_optional_id(rest).ok_or_else(invalid)?;
        let named = Named { actor, recipient };
        match kind {
            KIND_CLEAR => Ok(Self::Clear {
                named,
                payload: rest,
            }),
            KIND_SEALED => {
                let (custody_ref, ciphertext) = take_id(rest).ok_or_else(invalid)?;
                if ciphertext.is_empty() {
                    return Err(invalid());
                }
                Ok(Self::Sealed {
                    named,
                    custody_ref,
                    ciphertext,
                })
            }
            _ => Err(invalid()),
        }
    }

    fn named(&self) -> Named {
        match self {
            Self::Clear { named, .. } | Self::Sealed { named, .. } => *named,
            Self::Bare(_) | Self::Erased => Named::default(),
        }
    }
}

fn take_id(bytes: &[u8]) -> Option<(EntityId, &[u8])> {
    let (id, rest) = bytes.split_at_checked(16)?;
    let id = EntityId::from_bytes(id.try_into().ok()?).ok()?;
    Some((id, rest))
}

/// One optional id: a presence byte, then the id when present.
fn take_optional_id(bytes: &[u8]) -> Option<(Option<EntityId>, &[u8])> {
    let (&present, rest) = bytes.split_first()?;
    match present {
        0 => Some((None, rest)),
        1 => {
            let (id, rest) = take_id(rest)?;
            Some((Some(id), rest))
        }
        _ => None,
    }
}

fn push_optional_id(out: &mut Vec<u8>, id: Option<EntityId>) {
    match id {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(id.as_bytes());
        }
        None => out.push(0),
    }
}

fn envelope(kind: u8, named: Named, body: &[&[u8]]) -> Vec<u8> {
    let mut out = ENVELOPE_TAG.to_vec();
    out.push(kind);
    if kind != KIND_ERASED {
        push_optional_id(&mut out, named.actor);
        push_optional_id(&mut out, named.recipient);
    }
    for part in body {
        out.extend_from_slice(part);
    }
    out
}

/// The clear request a stored payload keeps readable as it stands: a bare or
/// clear form's bytes; `None` for a sealed form, which opens only under its
/// key, and an erased one, which keeps none.
pub(super) fn readable_payload(stored: &[u8]) -> IntentLedgerResult<Option<&[u8]>> {
    Ok(match StoredPayload::parse(stored)? {
        StoredPayload::Bare(payload) | StoredPayload::Clear { payload, .. } => Some(payload),
        StoredPayload::Sealed { .. } | StoredPayload::Erased => None,
    })
}

/// Whether a stored payload is the erased form.
pub(super) fn payload_erased(stored: &[u8]) -> IntentLedgerResult<bool> {
    Ok(matches!(
        StoredPayload::parse(stored)?,
        StoredPayload::Erased
    ))
}

/// Whether admission seals a payload whole (canon-silent policy hook): an
/// off-record caller's request (FIX 9372), and a request the side-row wall
/// would refuse for a secret it carries (FIX 2328, 2331). Every other
/// request stays readable, as before.
pub(crate) fn ledger_payload_sealed(context: &LedgerPayloadContext, payload: &[u8]) -> bool {
    context.off_record || crate::batch::secret_scan::payload_carries_secret(payload)
}

/// Row `intent_id`'s own custody ref: one per admitted row, derived from its
/// intent id, apart from every connector call's resume ref.
fn custody_ref(intent_id: &[u8; 32]) -> IntentLedgerResult<EntityId> {
    let derived = blake3::derive_key(CUSTODY_REF_DOMAIN, intent_id);
    let bytes: [u8; 16] = derived[..16]
        .try_into()
        .map_err(|_| IntentLedgerError::InvalidRecord("outbound intent custody ref"))?;
    EntityId::from_bytes(bytes)
        .map_err(|_| IntentLedgerError::InvalidRecord("outbound intent custody ref"))
}

/// `record`, an admitted row with its clear request, in the form it is
/// stored in, sealed in `wtxn` when [`ledger_payload_sealed`] says so. The
/// caller keeps `record` itself for its send.
///
/// # Errors
/// A custody fault while sealing.
pub(crate) fn stored_admission_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    record: &IntentLedgerRecord,
    context: &LedgerPayloadContext,
) -> IntentLedgerResult<IntentLedgerRecord> {
    super::store::validate_record(record)?;
    let mut stored = record.clone();
    let named = Named {
        actor: context.actor,
        recipient: context.recipient,
    };
    if ledger_payload_sealed(context, record.payload()) {
        let custody_ref = custody_ref(&record.id)?;
        let ciphertext = seal_connector_resume_in_txn(
            &vault.store,
            wtxn,
            &custody_ref,
            LEDGER_PAYLOAD_CUSTODY_GENERATION,
            record.payload(),
        )?;
        stored.payload = envelope(
            KIND_SEALED,
            named,
            &[custody_ref.as_bytes().as_slice(), ciphertext.as_slice()],
        );
    } else if named.actor.is_some() || named.recipient.is_some() {
        stored.payload = envelope(KIND_CLEAR, named, &[record.payload()]);
    }
    Ok(stored)
}

/// Opens `record`'s stored payload in place, read in `txn` (a writer, or a
/// snapshot): a clear form gives its bytes, a sealed one its bytes opened
/// under the row's own key, and both are checked against the row's payload
/// hash and approval. An erased row stays erased; a bare one is already
/// open.
///
/// # Errors
/// A sealed payload whose key does not open it; a payload that does not
/// match its row.
pub(super) fn open_payload_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &mut IntentLedgerRecord,
) -> IntentLedgerResult<()> {
    let opened = match StoredPayload::parse(record.payload())? {
        StoredPayload::Bare(_) | StoredPayload::Erased => return Ok(()),
        StoredPayload::Clear { payload, .. } => payload.to_vec(),
        StoredPayload::Sealed {
            custody_ref,
            ciphertext,
            ..
        } => open_connector_resume_in_txn(
            &vault.store,
            txn,
            &custody_ref,
            LEDGER_PAYLOAD_CUSTODY_GENERATION,
            ciphertext,
        )?
        .to_vec(),
    };
    record.payload = opened;
    super::store::validate_record(record)
}

/// Erasing `actor` from the intent ledger (FIX 9283): every row the actor
/// admitted, and every row sent to it as the person a send went to (FIX
/// 10953), keeps its id, attempt binding, accounting, state and delivery
/// knowledge, and loses its request. A sealed row's key retires with it.
/// A send still Pending or Deferred is abandoned, keeping that it may have
/// been delivered: no erased request is sent again, and its remote task
/// handle goes with the request. A Done send stays Done.
/// A send that certainly never went gives its reserved budget back (FIX
/// 7964). Runs in the erase's own transaction; housekeeping finishes the
/// staged key retirements.
///
/// # Errors
/// Storage and custody faults. A row that does not read is left to the
/// ledger's own damage report.
pub(crate) fn erase_outbound_intent_actor_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    let mut erased = Vec::new();
    for row in ledger_rows(vault, &*wtxn).map_err(erase_error)? {
        let (key, raw) = row?;
        let Ok(record) = super::codec::decode_record(&key, &raw) else {
            continue;
        };
        let Ok(stored) = StoredPayload::parse(record.payload()) else {
            continue;
        };
        let named = stored.named();
        if named.actor == Some(*actor) || named.recipient == Some(*actor) {
            let custody_ref = match stored {
                StoredPayload::Sealed { custody_ref, .. } => Some(custody_ref),
                _ => None,
            };
            erased.push((record.id, custody_ref, named.actor != Some(*actor)));
        }
    }
    for (id, custody_ref, recipient_only) in erased {
        if let Some(custody_ref) = custody_ref {
            retire_connector_resume_in_txn(&vault.store, wtxn, &custody_ref)?;
        }
        let Some(mut record) = get_ledger_record(vault, &*wtxn, &id).map_err(erase_error)? else {
            continue;
        };
        if recipient_only {
            // The send names the erased person as its recipient: it stops
            // for that, as an actor's erase stops its own sends.
            stop_for_erase(&mut record, IntentEscalationReason::RecipientErased);
        }
        put_erased_record(vault, wtxn, record)?;
        super::settlement::forget_remote_task_in_txn(vault, wtxn, &id).map_err(erase_error)?;
        if let Some(erased) = get_ledger_record(vault, &*wtxn, &id).map_err(erase_error)? {
            super::settlement::settle_reservation_in_txn(vault, wtxn, &erased)
                .map_err(erase_error)?;
        }
    }
    Ok(())
}

/// The person the engine's own frozen send names as its counterparty, as
/// the comm index resolves that party key in `txn` (FIX 10953): `None` for
/// a payload that is not the pipeline's JSON, names no counterparty, or
/// whose party has no person yet. Never fails an admission.
pub(crate) fn payload_recipient_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    payload: &[u8],
) -> Option<EntityId> {
    let frozen: serde_json::Value = serde_json::from_slice(payload).ok()?;
    let party = frozen.get(FROZEN_COUNTERPARTY_FIELD)?.as_str()?;
    crate::comm::resolve_party_ref_in_txn(vault, txn, party)
        .ok()
        .flatten()
}

/// Stops a send an erase reaches before it settled: a Pending or Deferred
/// row is abandoned for `reason`, keeping that it may have crossed the wire.
fn stop_for_erase(record: &mut IntentLedgerRecord, reason: IntentEscalationReason) {
    if matches!(record.state, IntentState::Pending | IntentState::Deferred) {
        record.delivery_uncertain |=
            record.recorded_outcome.is_none() || record.state == IntentState::Deferred;
        record.state = IntentState::Abandoned;
        record.recorded_outcome = Some(RecordedOutboundOutcome::Abandoned(reason));
    }
}

/// What an actor's erase leaves of a ledger row: its request gone, and a
/// send still Pending abandoned, keeping that it may have crossed the wire.
impl ErasedForm for IntentLedgerRecord {
    fn into_erased(mut self) -> crate::Result<Self> {
        self.payload = envelope(KIND_ERASED, Named::default(), &[]);
        stop_for_erase(&mut self, IntentEscalationReason::ActorErased);
        Ok(self)
    }
}

/// A ledger fault inside an actor's erase, as the erase reports it.
fn erase_error(error: IntentLedgerError) -> crate::Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        _ => crate::Error::CorruptedIndex("outbound intent ledger record"),
    }
}
