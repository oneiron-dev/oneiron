use super::*;

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
        .entities
        .get(txn, artifact.as_bytes())
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
    vault
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
    Ok(format!("blob:{}", artifact.to_hex()))
}

pub(super) fn invite_head_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    calendar: &CalendarRevision,
) -> Result<Option<crate::calendar::CalendarPassportValue>, BookingError> {
    crate::calendar::passport::live_passport_for_in_txn(
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
    if let Some(item) = lookup::pending_event_in(vault, txn, event)?
        && let Some(expected) = lookup::pending_revision(&item)
        && crate::booking::lifecycle::emergency_current_revision_in(vault, txn, event)? == *expected
    {
        return Err(refused(
            "pending emergency delivery fences this lifecycle revision",
        ));
    }
    Ok(())
}

pub(super) fn effect_ref(
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<String, BookingError> {
    Ok(format!(
        "intent:booking_emergency:{}:{lane}",
        hex_lower(&content_hash(&(
            item_key(&item.plan.request, item.calendar.event_ref)?,
            hash,
        ))?)
    ))
}

pub(super) fn apology_bytes(item: &EmergencyItem) -> Result<Vec<u8>, BookingError> {
    serde_json::to_vec(&serde_json::json!({ "reason": item.plan.request.reason,
        "actions": item.actions.iter().zip(&item.plan.proposals).map(|(token, slot)| serde_json::json!({
            "action": format!("booking:emergency-pick:{}", token.0), "proposal": slot
        })).collect::<Vec<_>>() })).map_err(storage_failure)
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
        || crate::outbound::outbound_dispatch_attempt_id(key).map_err(storage_failure)? != attempt
    {
        return Err(refused(
            "frozen emergency effect conflicts with its checkpoint",
        ));
    }
    verify_plan_in(vault, txn, &item.plan)?;
    if crate::booking::lifecycle::emergency_current_revision_in(
        vault,
        txn,
        item.calendar.event_ref,
    )? != *expected
        || (lane != "pick" && item.picked.is_some())
        || value["actor"].as_str() != Some(item.plan.request.owner_ref.to_hex().as_str())
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
            verify_content_head_in(vault, txn, &payload.ics_blob_ref)?;
            let head = invite_head_in(vault, txn, expected)?
                .ok_or_else(|| refused("calendar effect has no admitted passport"))?;
            if head.last_sequence != payload.sequence {
                return Err(refused("calendar effect has a superseded invite sequence"));
            }
        }
        "apology" => {
            let content = format!("blob:{}", blob_id(&apology_bytes(&item)?)?.to_hex());
            verify_content_head_in(vault, txn, &content)?;
            if value["content_ref"].as_str() != Some(content.as_str())
                || value["verb"] != "send"
                || value["channel"] != "email"
            {
                return Err(refused("frozen apology differs from its checkpoint"));
            }
        }
        _ => return Err(refused("unknown emergency effect lane")),
    }
    Ok(())
}
