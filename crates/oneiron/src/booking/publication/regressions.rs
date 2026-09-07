use super::*;
use crate::booking::{ActiveHoldSource, HoldLeaseSpec, HoldSpec, SessionKey, VaultActiveHoldSource};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_copied_owner_evidence_cannot_use_raw_batch_or_replay_doors() {
        let (_dir, vault) = open();
        let receipt = vault.memory(id(2), EdgeActorClass::Human).claim_upsert(&input(publication())).expect("owner");
        let claim = crate::memory::resolve_entity_ref(&vault, &receipt.claim_short_id).expect("id");
        let body = vault.get_claim(&claim).expect("read").expect("body");
        let bytes = crate::claim::encode_claim_body(&body).expect("bytes");
        let time = TimeRange { start: 1, end: 1 };
        assert!(vault.put_claim(&id(8), &body, time, 1).is_err());
        assert!(vault.put_claim(&claim, &body, time, 1).is_err());
        assert!(vault.batch().put(&id(8), crate::registry::ENTITY_TYPE_CLAIM, time, 1, &bytes).commit().is_err());
        assert!(vault.batch().put_replicated(&id(8), crate::registry::ENTITY_TYPE_CLAIM, time, 1, &bytes).commit().is_err());
        let candidate = ClaimCandidate::new(BOOKING_PUBLIC_PAGE_PREDICATE, body.subject, body.value.clone(), 1.0)
            .with_validity(body.valid_from, body.valid_to);
        let envelope = WriteEnvelope::new(WriteActor::new(id(2), EdgeActorClass::Human), ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("copied owner")).expect("provenance"), ClaimApprovalStatus::Auto);
        assert!(vault.batch().claim_candidate(&id(8), candidate, &envelope, time, 1).commit().is_err());
        assert_eq!(load_public_booking_page(&vault, id(1), 150).expect("unchanged"), Some(publication()));
        let txn = vault.store.env.read_txn().expect("txn");
        assert!(vault.store.vault_meta.get(&txn, &crate::memory::booking_publication::publication_write_key(claim)).expect("permit read").is_none());
    }
}

#[test]
fn publication_token_lookup_is_durable_and_misses_do_not_scan_claims() {
    let (dir, vault) = open();
    let token = crate::booking::PublicBookingPageToken::for_page(id(1)).0;
    assert_eq!(resolve_public_booking_token(&vault, &token).expect("private address"), None);
    vault.memory(id(2), EdgeActorClass::Human).claim_upsert(&input(publication())).expect("owner");
    // A malformed unrelated claim would make a scan fail. The fixed-key miss
    // and hit must not inspect it.
    vault.with_write_txn(|txn| {
        let raw = vault.store.entities.get(txn, id(5).as_bytes())?.expect("config");
        let mut corrupt = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
        corrupt.push(0xc1);
        vault.store.entities.put(txn, id(9).as_bytes(), &corrupt)?;
        Ok(())
    }).expect("hostile fixture");
    for byte in 10..30 {
        let unknown = crate::booking::PublicBookingPageToken::for_page(id(byte)).0;
        assert_eq!(resolve_public_booking_token(&vault, &unknown).expect("fixed-key miss"), None);
    }
    assert_eq!(resolve_public_booking_token(&vault, &token).expect("hit"), Some(id(1)));
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("reopen");
    assert_eq!(resolve_public_booking_token(&vault, &token).expect("durable"), Some(id(1)));
}

#[test]
fn publication_exact_config_hash_rejects_same_duration_host_or_buffer_substitution() {
    let (_dir, vault) = open();
    vault.memory(id(2), EdgeActorClass::Human).claim_upsert(&input(publication())).expect("owner");
    let original = vault.get_claim(&id(5)).expect("read").expect("config");
    let mut replacement = original;
    let mut config = fixture_config();
    config.pre_buffer_min = 15;
    config.hosts[0].host_ref = id(9);
    replacement.value = encode_event_type_claim_value(&BookingEventTypeClaimValue {
        schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION, page_ref: id(1), config,
    }).expect("replacement");
    // A lower-id claim wins the existing shared resolver but cannot inherit
    // the owner's publication approval merely by retaining duration and key.
    vault.put_claim(&id(3), &replacement, TimeRange { start: 1, end: 1 }, 1).expect("ordinary config");
    assert!(load_public_booking_page(&vault, id(1), 150).expect("hash mismatch").is_none());
}

#[test]
fn publication_read_still_rejects_corrupt_surfaceability_states() {
    let (_dir, vault) = open();
    let receipt = vault.memory(id(2), EdgeActorClass::Human).claim_upsert(&input(publication())).expect("owner");
    let claim = crate::memory::resolve_entity_ref(&vault, &receipt.claim_short_id).expect("id");
    let original = vault.get_claim(&claim).expect("read").expect("body");
    for (approval, lifecycle, stale) in [
        (ClaimApprovalStatus::Proposed, ClaimLifecycleStatus::Active, false),
        (ClaimApprovalStatus::Rejected, ClaimLifecycleStatus::Active, false),
        (ClaimApprovalStatus::Auto, ClaimLifecycleStatus::Retracted, false),
        (ClaimApprovalStatus::Auto, ClaimLifecycleStatus::Active, true),
    ] {
        let mut body = original.clone();
        body.approval = approval; body.lifecycle = lifecycle; body.stale = stale;
        // Deliberate internal corruption fixture, not a supported write door.
        vault.with_write_txn(|txn| {
            let raw = vault.store.entities.get(txn, claim.as_bytes())?.expect("row");
            let mut changed = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
            changed.extend_from_slice(&crate::claim::encode_claim_body(&body)?);
            vault.store.entities.put(txn, claim.as_bytes(), &changed)?;
            Ok(())
        }).expect("fixture");
        assert!(load_public_booking_page(&vault, id(1), 150).expect("read clamp").is_none());
    }
}

#[test]
fn public_hold_writer_rechecks_retraction_expiry_and_exact_configuration() {
    for change in ["retract", "expire", "config", "unpublish"] {
        let (_dir, vault) = open();
        let now = crate::unix_seconds_now();
        let mut claim_input = input(publication());
        claim_input.valid_from = Some(now - 1);
        claim_input.valid_to = Some(now + 100);
        let owner = vault.memory(id(2), EdgeActorClass::Human);
        let receipt = owner.claim_upsert(&claim_input).expect("publish");
        let authority = PublicBookingAuthority { page_ref: id(1), publication: load_public_booking_page(&vault, id(1), now).expect("load").expect("public") };
        let mut write_now = now;
        match change {
            "retract" => { owner.claim_retract(&receipt.claim_short_id).expect("retract"); }
            "expire" => { write_now = now + 100; }
            "unpublish" => { claim_input.value["published"] = json!(false); owner.claim_upsert(&claim_input).expect("withdraw"); }
            _ => {
                let mut config_body = vault.get_claim(&id(5)).expect("config").expect("body");
                let mut value = crate::booking::decode_event_type_claim_value(&config_body.value).expect("value");
                value.config.post_buffer_min += 1;
                config_body.value = encode_event_type_claim_value(&value).expect("changed config");
                vault.put_claim(&id(5), &config_body, TimeRange { start: 1, end: 1 }, 1).expect("config write");
            }
        }
        let spec = HoldSpec { page_ref: id(1), event_type: EventTypeKey("event".to_owned()),
            slot: TimeRange { start: now + 3_600, end: now + 5_400 }, session_key: SessionKey::derive(b"public transaction"),
            visitor_tz: "UTC".to_owned(), constraint: None, lease: HoldLeaseSpec::Ordinary, idempotency_key: None };
        assert!(crate::booking::lifecycle::execute_hold(&vault, &spec, write_now, Some(&authority)).is_err(), "{change}");
        assert!(VaultActiveHoldSource::new(&vault).active_holds(id(1), spec.slot, now, None).expect("holds").is_empty());
    }
}

#[test]
fn public_attempt_dedupe_cannot_alias_a_literal_non_public_key() {
    use crate::attempt_queue::AttemptQueue;
    use crate::booking::lifecycle::{enqueue_booking_verb, enqueue_booking_verb_with_publication};
    use crate::booking::{BookingLifecycleAttempt, BookingVerbRequest};

    let (_dir, vault) = open();
    let now = crate::unix_seconds_now();
    let mut claim_input = input(publication());
    claim_input.valid_from = Some(now - 1);
    claim_input.valid_to = Some(now + 100);
    vault.memory(id(2), EdgeActorClass::Human)
        .claim_upsert(&claim_input).expect("publish");
    let authority = PublicBookingAuthority {
        page_ref: id(1),
        publication: load_public_booking_page(&vault, id(1), now)
            .expect("read").expect("public"),
    };
    let spec = HoldSpec {
        page_ref: id(1), event_type: EventTypeKey("event".to_owned()),
        slot: TimeRange { start: now + 3_600, end: now + 5_400 },
        session_key: SessionKey::derive(b"public dedupe"), visitor_tz: "UTC".to_owned(),
        constraint: None, lease: HoldLeaseSpec::Ordinary,
        idempotency_key: Some("same-key".to_owned()),
    };
    let public_id = enqueue_booking_verb_with_publication(
        &vault, BookingVerbRequest::Hold(spec.clone()), now, Some(authority.clone()),
    ).expect("public enqueue");
    let queue = AttemptQueue::new(&vault);
    let public_row = queue.get(public_id).expect("read").expect("public row");
    let mut private_spec = spec.clone();
    // This literal fit the ordinary input bound and used to hit the public
    // queue row, despite carrying no publication restriction of its own.
    private_spec.idempotency_key = public_row.dedupe_key.clone();
    let private_id = enqueue_booking_verb(
        &vault, BookingVerbRequest::Hold(private_spec.clone()), now,
    ).expect("non-public enqueue");
    assert_ne!(private_id, public_id);
    // The dangerous order is the reverse: public admission must not reuse
    // an earlier unrestricted attempt and lose its writer-side recheck.
    let (_other_dir, other_vault) = open();
    let private_first = enqueue_booking_verb(
        &other_vault, BookingVerbRequest::Hold(private_spec), now,
    ).expect("non-public first");
    let public_later = enqueue_booking_verb_with_publication(
        &other_vault, BookingVerbRequest::Hold(spec.clone()), now, Some(authority.clone()),
    ).expect("public after non-public");
    assert_ne!(private_first, public_later);
    assert_eq!(enqueue_booking_verb_with_publication(
        &vault, BookingVerbRequest::Hold(spec), now, Some(authority.clone()),
    ).expect("public retry"), public_id);
    // Lifecycle queue payloads have the existing one-byte version envelope.
    let public_attempt: BookingLifecycleAttempt = rmp_serde::from_slice(&public_row.payload[1..])
        .expect("public payload");
    assert_eq!(public_attempt.public_authority, Some(authority));
    let private_row = queue.get(private_id).expect("read").expect("non-public row");
    let private_attempt: BookingLifecycleAttempt = rmp_serde::from_slice(&private_row.payload[1..])
        .expect("non-public payload");
    assert!(private_attempt.public_authority.is_none());
}

#[test]
fn publication_rejects_escaped_oversized_owner_fields_before_acceptance() {
    for field in ["owner_display", "theme", "constraint_field", "event_types"] {
        let mut value = publication();
        let huge = "\"".repeat(9_000); // JSON escaping, not character count, sets the bound.
        match field {
            "owner_display" => value.owner_display = huge,
            "theme" => value.theme = ThemeTokens(json!(huge)),
            "constraint_field" => value.constraint_field.placeholder = huge,
            _ => value.event_types[0].description = huge,
        }
        assert!(encode_public_booking_page_value(&value).is_err(), "{field}");
    }
}
