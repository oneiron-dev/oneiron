//! The projector's import of delivered connector send receipts as source
//! events.

use super::claims::{CommError, CommResult, KEY_PARTY_KEY};
use super::parties::resolve_or_create_party_in_txn;
use super::projector::storage_failure;
use super::records::{
    CommEventKind, CommRecord, decode_comm_record, next_event_sequence_in_txn,
    put_comm_record_in_txn, required_string, validate_channel_class, validate_key_string,
    value_map,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::ports::{EntityStoreRead, TombstoneStore};
use crate::receipt::{FIELD_TASK_REF, ReceiptRecord};
use crate::registry::{ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_PERSON};

/// One delivered message send a durable connector receipt states.
struct DeliveredSend {
    receipt_id: String,
    event_id: EntityId,
    channel: String,
    party: String,
    occurred_at: u64,
}

/// Folds durable connector receipts into this projector, at most
/// `max_imports` new ones per call; the rest wait for the next call. TASK
/// identity fixes the source event; its original PERSON subject is never
/// changed by later party merges or deletion. A new delivery without an
/// explicit counterparty is not a communication fact: transport destinations
/// can be group channels.
///
/// One read transaction finds the receipts not imported yet, so a call with
/// none opens no write. A receipt that cannot be imported is logged and
/// skipped, and the receipts after it still import; it is tried again on the
/// next call. Only a storage failure ends the call.
pub(super) fn import_delivered_send_receipts(vault: &Vault, max_imports: usize) -> CommResult<()> {
    let receipts = crate::receipt::durable_send_receipts(vault)?;
    let fresh = {
        let rtxn = vault.store.env.read_txn()?;
        let mut fresh = Vec::new();
        for receipt in &receipts {
            if fresh.len() >= max_imports {
                break;
            }
            let found = delivered_send(receipt).and_then(|send| match send {
                Some(send) => {
                    imported_in_txn(vault, &rtxn, &send).map(|imported| (!imported).then_some(send))
                }
                None => Ok(None),
            });
            match found {
                Ok(Some(send)) => fresh.push(send),
                Ok(None) => {}
                Err(error) => skip_receipt(&receipt.receipt_id, error)?,
            }
        }
        fresh
    };
    for send in fresh {
        let imported = vault.try_with_write_txn_grouped(|txn| {
            // A peer pass may have imported it since the read.
            if imported_in_txn(vault, &*txn, &send)? {
                return Ok(());
            }
            let party_ref = resolve_or_create_party_in_txn(vault, txn, &send.party)?;
            let sequence = next_event_sequence_in_txn(vault, txn)?;
            put_comm_record_in_txn(
                vault,
                txn,
                send.event_id,
                &CommRecord::Event {
                    sequence,
                    kind: CommEventKind::SendSucceeded,
                    party_ref,
                    channel_class: Some(send.channel.clone()),
                    thread_ref: None,
                    occurred_at: send.occurred_at,
                    projected: false,
                },
            )
        });
        if let Err(error) = imported {
            skip_receipt(&send.receipt_id, error)?;
        }
    }
    Ok(())
}

/// The message send `receipt` states, or `None` when it states none the
/// projector imports.
fn delivered_send(receipt: &ReceiptRecord) -> CommResult<Option<DeliveredSend>> {
    if receipt.outcome != "delivered_to_channel" {
        return Ok(None);
    }
    let channel = receipt
        .fields
        .get("channel")
        .ok_or(CommError::InvalidRecord)?;
    let verb = receipt.fields.get("verb").ok_or(CommError::InvalidRecord)?;
    if !is_delivered_message(channel, verb) {
        return Ok(None);
    }
    let Some(party) = receipt.fields.get("counterparty_ref") else {
        return Ok(None);
    };
    validate_channel_class(channel).map_err(|_| CommError::InvalidRecord)?;
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    let task_ref = EntityId::from_hex(
        receipt
            .fields
            .get(FIELD_TASK_REF)
            .ok_or(CommError::InvalidRecord)?,
    )
    .map_err(|_| CommError::InvalidRecord)?;
    let event_id = EntityId::derive(
        crate::entity_id::derived_domains::COMM_CONNECTOR_SEND_EVENT,
        &[task_ref.as_bytes()],
    )
    .map_err(|_| CommError::InvalidRecord)?;
    Ok(Some(DeliveredSend {
        receipt_id: receipt.receipt_id.clone(),
        event_id,
        channel: channel.clone(),
        party: party.clone(),
        occurred_at: receipt.occurred_at,
    }))
}

/// Whether `send`'s source event is already imported. The immutable source
/// event is checked BEFORE today's party is resolved: a merged shell keeps
/// its original body, and a deleted subject has no body at all, so neither
/// remints a PERSON or blocks STOPs. A resident row that is not this send's
/// event is an error.
fn imported_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, send: &DeliveredSend) -> CommResult<bool> {
    let Some(raw) = vault.store.port_entity_record(txn, &send.event_id)? else {
        return Ok(false);
    };
    if raw.entity_type != ENTITY_TYPE_COMM_RECORD {
        return Err(CommError::InvalidRecord);
    }
    match decode_comm_record(&raw.body)? {
        CommRecord::Event {
            kind: CommEventKind::SendSucceeded,
            party_ref: original_party,
            channel_class: Some(resident_channel),
            thread_ref: None,
            occurred_at,
            ..
        } if resident_channel == send.channel && occurred_at == send.occurred_at => {
            // A soft delete keeps a headerful PERSON shell with scrubbed body
            // bytes. It is not a live party to compare against the frozen
            // receipt; the already imported event must remain
            // replay-idempotent.
            if !vault.port_tombstone_is_deleted(txn, &original_party)?
                && let Some(original) = vault.store.port_entity_record(txn, &original_party)?
            {
                if original.entity_type != ENTITY_TYPE_PERSON {
                    return Err(CommError::InvalidRecord);
                }
                let value = rmpv::decode::read_value(&mut original.body.as_slice())
                    .map_err(|_| CommError::InvalidRecord)?;
                let key = required_string(
                    value_map(&value).map_err(|_| CommError::InvalidRecord)?,
                    KEY_PARTY_KEY,
                )
                .map_err(|_| CommError::InvalidRecord)?;
                if key != send.party {
                    return Err(CommError::InvalidRecord);
                }
            }
            Ok(true)
        }
        _ => Err(CommError::InvalidRecord),
    }
}

/// Logs a receipt the import skips; a storage failure is returned instead.
fn skip_receipt(receipt_id: &str, error: CommError) -> CommResult<()> {
    match error {
        CommError::Engine(error) if storage_failure(&error) => Err(CommError::Engine(error)),
        error => {
            tracing::warn!(
                receipt_id,
                %error,
                "communication projector skipped a delivered send receipt; it is tried again on the next pass"
            );
            Ok(())
        }
    }
}

/// A message operation projects one delivered receipt into comm history.
/// The connector manifest declares the eligible verbs; edits, reactions,
/// invitations and presence never become touches just because they delivered.
fn is_delivered_message(channel: &str, verb: &str) -> bool {
    crate::outbound::outbound_capability_manifest(channel)
        .is_some_and(|manifest| manifest.message_verbs.iter().any(|kind| kind == verb))
}
