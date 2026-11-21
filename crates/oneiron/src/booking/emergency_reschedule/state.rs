//! Emergency reschedule state and home-authority reads.
//! Entry: `verify_owner_home_in`.
//! Defines its own items.

use super::*;
use crate::ports::EntityStoreRead;

pub(super) fn verify_owner_home_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<(), BookingError> {
    crate::memory::verify_deletion_authority_in_txn(
        vault,
        txn,
        owner,
        crate::edge::EdgeActorClass::Human,
    )
    .map_err(|error| BookingError::Boundary(Box::new(error)))?;
    let local = crate::identity::read_client_id_in_txn(vault, txn)
        .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
    let home = crate::dreamer_runner::DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(txn)
        .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
    if local.is_none() || home.is_none_or(|home| Some(home.node_id) != local) {
        return Err(BookingError::InvalidConfig(
            "emergency writes require the lifecycle home node".to_owned(),
        ));
    }
    // FIX [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE]: as the lifecycle door, a node its
    // election names home is not the rows' home while it does not hold them: it froze them for
    // a home move and adopted none since, or awaits the move that carries them here. Every
    // emergency write and every outbound check of an emergency effect asks this, in its own
    // transaction.
    if !crate::booking::lifecycle::holds_booking_rows_in_txn(vault, txn)? {
        return Err(BookingError::InvalidConfig(
            "emergency writes require the lifecycle home node: this node does not hold the \
             booking rows during a home move"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Uses existing blob and claim writers inside the instruction/plan transaction.
pub(super) fn persist_content_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &EmergencyRescheduleRequest,
    name: &str,
    media_type: &str,
    bytes: &[u8],
    now: u64,
) -> Result<String, BookingError> {
    verify_instruction_in_txn(vault, txn, request)?;
    let artifact = blob_id(bytes)?;
    let occurred = TimeRange {
        start: now,
        end: now,
    };
    if vault
        .store
        .port_entity_record(txn, &artifact)
        .map(|row| row.map(|row| row.encode()))
        .map_err(storage_failure)?
        .is_none()
    {
        let body = crate::blob_artifact::encode_blob_artifact_body(
            &crate::blob_artifact::BlobArtifactBody::new(name, media_type),
        )
        .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
        vault
            .batch_in()
            .put(
                &artifact,
                crate::registry::ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                now,
                &body,
            )
            .apply(txn)
            .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
    }
    let version = vault
        .append_blob_artifact_version_in_txn(
            txn,
            &artifact,
            bytes,
            &crate::blob_artifact::BlobVersionProvenance::UserUpload,
            crate::write_envelope::WriteActor::new(
                request.owner_ref,
                crate::edge::EdgeActorClass::Human,
            ),
            occurred,
            now,
        )
        .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
    if media_type == crate::calendar::CALENDAR_INVITE_MEDIA_TYPE {
        Ok(format!("blob:{}@{}", artifact.to_hex(), version.version))
    } else {
        Ok(format!("blob:{}", artifact.to_hex()))
    }
}

pub(super) fn invite_head_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    calendar: &CalendarRevision,
) -> Result<Option<crate::calendar::CalendarPassportValue>, BookingError> {
    crate::calendar::passport::admitted_passport_for_in_txn(
        vault,
        txn,
        &calendar.event_ref,
        crate::calendar::CALENDAR_INVITE_PASSPORT_SYSTEM,
        &calendar.uid,
    )
    .map(|head| head.map(|(_, value)| value))
    .map_err(storage_failure)
}

pub(super) fn next_invite_sequence(
    prior: Option<&crate::calendar::CalendarPassportValue>,
) -> Result<u32, BookingError> {
    prior.map_or(Ok(0), |prior| {
        prior
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| refused("calendar invite sequence is exhausted"))
    })
}

/// A pending checkpoint holds its lifecycle revision until delivery completes.
/// This uses the existing lifecycle item, not a second lock or authority log.
pub(crate) fn ensure_no_pending_effect_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<(), BookingError> {
    if pending_effect_fences_in(vault, txn, event)? {
        return Err(refused(
            "pending emergency delivery fences this lifecycle revision",
        ));
    }
    Ok(())
}

/// Whether a pending emergency delivery fences `event`'s current lifecycle
/// revision: the fence [`ensure_no_pending_effect_in`] refuses, answered as a
/// fact, so a caller that holds a fenced item back (a calendar feed's move)
/// never reads it from an error's variant or text. Store failures and a
/// corrupt pending index stay errors.
pub(crate) fn pending_effect_fences_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<bool, BookingError> {
    if let Some(item) = lookup::pending_event_in(vault, txn, event)?
        && let Some(expected) = lookup::pending_revision(&item)
    {
        return Ok(
            crate::booking::lifecycle::emergency_current_revision_in(vault, txn, event)?
                == *expected,
        );
    }
    Ok(false)
}

/// The current ledger generation of `item`'s effect on `lane` (`EmergencyItem::ledger_generations`):
/// 0 until a home adopted the checkpoint back over its own earlier send of that effect.
pub(super) fn ledger_generation(item: &EmergencyItem, lane: &str) -> u32 {
    item.ledger_generations.get(lane).copied().unwrap_or(0)
}

/// The local outbound ledger identity of `item`'s effect on `lane` at ledger `generation`: its
/// idempotency key [`effect_ref`] at generation 0, else that key with the generation appended.
/// The send's attempt id, and so its ledger row, derives from it (`outbound_dispatch_attempt_id`).
/// Its provider key does not: every generation's row carries the key the generation-0 row
/// carries, the hex of the id [`effect_ref`]'s attempt derives
/// (`OutboundDispatchRequest::idempotency_identity_ref`), so a provider that drops a repeated
/// key drops a later generation's repeat of any home's send (review round 2 of #10220).
pub(super) fn effect_generation_ref(
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
    generation: u32,
) -> Result<String, BookingError> {
    let reference = effect_ref(item, lane, hash)?;
    Ok(if generation == 0 {
        reference
    } else {
        format!("{reference}:ledger-generation:{generation}")
    })
}

/// The local outbound ledger identity `item`'s next send of its effect on `lane` is admitted by:
/// its current generation's ([`effect_generation_ref`]).
pub(super) fn effect_ledger_ref(
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<String, BookingError> {
    effect_generation_ref(item, lane, hash, ledger_generation(item, lane))
}

/// This node's outbound ledger row of `item`'s effect on `lane` at ledger `generation`
/// ([`effect_generation_ref`]), read in `txn`. A row that does not read as a ledger row is none,
/// as the move's reads hold (`home_rows::item`): only a store failure is an error.
pub(super) fn ledger_record_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
    generation: u32,
) -> Result<Option<crate::outbound_intent_ledger::IntentLedgerRecord>, BookingError> {
    use crate::outbound_intent_ledger::{IntentLedgerError, read_intent_for_attempt_in_txn};
    let reference = effect_generation_ref(item, lane, hash, generation)?;
    let attempt =
        crate::outbound::outbound_dispatch_attempt_id(&reference).map_err(storage_failure)?;
    match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => Ok(record),
        Err(IntentLedgerError::Engine(error)) => Err(storage_failure(error)),
        Err(_) => Ok(None),
    }
}

/// Whether this node's outbound ledger, read in `txn`, holds `item`'s effect on `lane` delivered
/// under a ledger generation before its current one: a send this home's earlier generation made,
/// whose remote task completed after the home took a fresh attempt (review round 1 of #10220).
/// Such an effect is delivered, and its fresh attempt is never sent: the owner's resume asks
/// before it admits one ([`earlier_generation_delivered`]), and every outbound check of the
/// fresh attempt's send asks again in its own transaction, the admission writer's and the last
/// one before the transport ([`verify_frozen_effect_in`]; review round 2 of #10220).
fn earlier_generation_delivered_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<bool, BookingError> {
    use crate::outbound_intent_ledger::IntentResolution;
    for generation in 0..ledger_generation(item, lane) {
        if ledger_record_in(vault, txn, item, lane, hash, generation)?.is_some_and(|record| {
            matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Delivered)
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// [`earlier_generation_delivered_in`] on a snapshot of this node's store.
pub(super) fn earlier_generation_delivered(
    vault: &Vault,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<bool, BookingError> {
    if ledger_generation(item, lane) == 0 {
        return Ok(false);
    }
    let txn = vault.store.custody_snapshot().map_err(storage_failure)?;
    earlier_generation_delivered_in(vault, &txn, item, lane, hash)
}

/// Whether the owner's resume on a home that adopted `item`'s checkpoint back takes the
/// effect's next ledger generation over `record`, the home's own row of the generation it
/// adopted over (`readopted`), as that row reads now (FIX
/// [BK-EMERGENCY-DEFERRED-SEND-STRANDED-ON-FORMER-HOME]). It does where the row's replay never
/// sends the effect again while any other new home sends it (Engine ANSWER
/// BK-EMERGENCY-PENDING-ITEM-MOVE = A), and the fresh send repeats no delivery the owner is not
/// told of:
/// - the row stopped as a failed delivery: its send was ambiguous at a provider with no key, or
///   its remote task failed (FIX 7960). A stop the owner, an erase or the gate made stays, as on
///   a home that never moved, and so does a pending row: its replay sends it again or reads it
///   back first (FIX 9379);
/// - a send with a provider-native key, stopped so: every generation reaches the provider under
///   the effect's first key ([`effect_generation_ref`]), which a provider that drops a repeated
///   key drops. Deferred, its own remote task settles it first, as on a home that never moved;
/// - a send with none, stopped so or deferred: where no send of its row can have delivered, or
///   its row's only possible delivery came before this home adopted the checkpoint
///   (`!readopted.replayed`). The move that took the checkpoint away marked that send uncertain,
///   so the run that delivers the effect tells the owner it may repeat (`super::uncertain_send`).
pub(super) fn readopted_send_takes_fresh_attempt(
    record: &crate::outbound_intent_ledger::IntentLedgerRecord,
    readopted: super::planning::ReadoptedSend,
) -> bool {
    use crate::outbound_intent_ledger::{
        IntentEscalationReason, IntentResolution, UnconfirmedDelivery,
    };
    let keyed = record.idempotency_supported;
    match IntentResolution::from_record(record) {
        Ok(IntentResolution::Stopped { delivery, reason }) => {
            matches!(
                reason,
                IntentEscalationReason::NonIdempotentAmbiguous
                    | IntentEscalationReason::NonIdempotentPending
                    | IntentEscalationReason::RemoteTaskFailed
            ) && (keyed
                || !readopted.replayed
                || matches!(delivery, UnconfirmedDelivery::DefiniteNonDelivery))
        }
        Ok(IntentResolution::Deferred) => !keyed && !readopted.replayed,
        Ok(IntentResolution::Pending { .. } | IntentResolution::Delivered) | Err(_) => false,
    }
}

pub(super) fn effect_ref(
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<String, BookingError> {
    Ok(format!(
        "intent:booking_emergency:{}:{lane}",
        hex_lower(&content_hash(
            purposes::booking::EMERGENCY_EFFECT_REF,
            &(item_key(&item.plan.request, item.calendar.event_ref)?, hash),
        )?)
    ))
}

fn verify_content_head_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reference: &str,
) -> Result<(), BookingError> {
    let artifact = EntityId::from_hex(
        reference
            .strip_prefix("blob:")
            .ok_or_else(|| refused("invalid emergency blob reference"))?,
    )
    .map_err(storage_failure)?;
    let head = crate::blob_artifact::read_blob_artifact_head_in_txn(&vault.store, txn, &artifact)
        .map_err(|error| BookingError::Boundary(Box::new(error.into())))?
        .ok_or_else(|| refused("emergency content head is missing"))?;
    if head.content_hash[..16] != artifact.as_bytes()[..] {
        return Err(refused("emergency content-addressed blob has changed"));
    }
    Ok(())
}

/// Read by outbound's actual gate transaction AND last verified transport door,
/// including ledger recovery. Frozen bytes identify the existing item only;
/// they never substitute for its current owner or lifecycle revision.
pub(crate) fn verify_frozen_effect_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: crate::attempt_queue::AttemptId,
    bytes: &[u8],
) -> Result<(), BookingError> {
    // Classification comes from the existing ledger identity, not from JSON
    // that may be malformed or have lost its emergency idempotency key.
    let item = lookup::effect_item_in(vault, txn, attempt)?;
    let value = serde_json::from_slice::<serde_json::Value>(bytes);
    let Some(item) = item else {
        if value.as_ref().ok().is_some_and(|value| {
            value["idempotency_key"]
                .as_str()
                .is_some_and(|key| key.starts_with("intent:booking_emergency:"))
        }) {
            return Err(refused(
                "frozen emergency effect has no lifecycle checkpoint",
            ));
        }
        // Ordinary connectors may use arbitrary non-JSON bytes.
        return Ok(());
    };
    let value = value.map_err(|_| refused("malformed frozen emergency effect"))?;
    let key = value["idempotency_key"]
        .as_str()
        .ok_or_else(|| refused("frozen emergency effect has no idempotency key"))?;
    let lane = key.rsplit(':').next().unwrap_or_default();
    let (hash, expected, payload) = if lane == "pick" {
        let picked = item
            .picked
            .as_ref()
            .ok_or_else(|| refused("frozen emergency effect has no pick checkpoint"))?;
        (picked.content_hash, &picked.calendar, Some(&picked.payload))
    } else {
        (
            item.plan.content_hash,
            &item.calendar,
            item.plan.payload.as_ref(),
        )
    };
    if effect_ref(&item, lane, hash)? != key
        || crate::outbound::outbound_dispatch_attempt_id(&effect_ledger_ref(&item, lane, hash)?)
            .map_err(storage_failure)?
            != attempt
    {
        return Err(refused(
            "frozen emergency effect conflicts with its checkpoint",
        ));
    }
    // A fresh ledger attempt goes only while no earlier generation's send delivered the effect,
    // asked here under this transaction (review round 2 of #10220).
    if earlier_generation_delivered_in(vault, txn, &item, lane, hash)? {
        return Err(refused(
            "emergency effect is delivered under an earlier ledger attempt",
        ));
    }
    verify_plan_in(vault, txn, &item.plan)?;
    // Recovery has no caller-supplied verified actor. The frozen gate principal
    // must still be the human owner; the intent's display actor alone is not it.
    let owner = item.plan.request.owner_ref.to_hex();
    if value["actor_class"].as_str() != Some(crate::edge::EdgeActorClass::Human.gate_actor_class())
        || value["actor_ref"].as_str() != Some(owner.as_str())
        || value["actor_entity_ref"].as_str() != Some(owner.as_str())
        || value["counterparty_ref"].as_str() != Some(item.plan.recipient.as_str())
    {
        return Err(refused(
            "frozen emergency effect has a different gate binding",
        ));
    }
    if crate::booking::lifecycle::emergency_current_revision_in(
        vault,
        txn,
        item.calendar.event_ref,
    )? != *expected
        || (lane != "pick" && item.picked.is_some())
        || value["actor"].as_str() != Some(owner.as_str())
        || value["target"].as_str() != Some(item.plan.recipient.as_str())
    {
        return Err(refused("emergency effect is superseded or misbound"));
    }
    match lane {
        "calendar" | "pick" => {
            let payload =
                payload.ok_or_else(|| refused("no calendar effect for an unsent cancellation"))?;
            if value["calendar_invite"] != serde_json::to_value(payload).map_err(storage_failure)?
                || value["verb"] != crate::calendar::CALENDAR_INVITE_VERB
                || value["channel"] != "calendar"
            {
                return Err(refused(
                    "frozen calendar content differs from its checkpoint",
                ));
            }
            let bytes =
                crate::calendar::invite::read_calendar_invite_ics_in_txn(vault, txn, payload)
                    .map_err(storage_failure)?;
            if payload.blob_version_ref().map_err(storage_failure)?.0 != blob_id(&bytes)? {
                return Err(refused(
                    "calendar effect content differs from its pinned version",
                ));
            }
            // Before first publication the checkpoint still has the previous
            // invite head. Pending publication advances it atomically; retries
            // then see exactly the frozen revision, never a newer one.
            let head = invite_head_in(vault, txn, expected)?;
            let sequence = head.as_ref().map(|head| head.last_sequence);
            let prior = if lane == "pick" {
                super::pick::committed_invite_sequence(&item)
            } else {
                item.plan
                    .invite_before
                    .as_ref()
                    .map(|head| head.last_sequence)
            };
            if sequence != Some(payload.sequence) && sequence != prior {
                return Err(refused("calendar effect has a superseded invite sequence"));
            }
        }
        "apology" => {
            // FIX [BK-EMERGENCY-APOLOGY-BLOB-HOLDS-RAW-PICK-TOKENS]: the owner's copy, whose head
            // this home wrote, or the raw body a send an earlier build froze, whose blob is
            // released: the booker's text comes from the checkpoint at send time either way.
            let content = value["content_ref"].as_str().unwrap_or_default();
            match super::apology::apology_content_of(&item, content)? {
                super::apology::ApologyContent::OwnerCopy => {
                    verify_content_head_in(vault, txn, content)?;
                }
                super::apology::ApologyContent::FrozenRawBody => {}
                super::apology::ApologyContent::Other => {
                    return Err(refused("frozen apology differs from its checkpoint"));
                }
            }
            if value["verb"] != "send" || value["channel"] != "email" {
                return Err(refused("frozen apology differs from its checkpoint"));
            }
        }
        _ => return Err(refused("unknown emergency effect lane")),
    }
    Ok(())
}
