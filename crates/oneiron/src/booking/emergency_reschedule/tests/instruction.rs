use super::*;

#[test]
fn batch_requires_logged_owner_instruction_with_matching_request_hash() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let req = request();
    let before = (meta(&vault), entities(&vault));
    assert!(enumerate_affected_bookings(&vault, &req, NOW).is_err());
    assert_eq!((meta(&vault), entities(&vault)), before);
    let req = logged(&vault);
    assert!(
        enumerate_affected_bookings(&vault, &req, NOW)
            .unwrap()
            .is_empty()
    );
    let before = (meta(&vault), entities(&vault));
    let mut changes = Vec::new();
    let mut changed = req.clone();
    changed.owner_ref = id(0x61);
    changes.push(changed);
    let mut changed = req.clone();
    changed.authority.owner_ref = id(0x61);
    changes.push(changed);
    let mut changed = req.clone();
    changed.authority.recorded_at += 1;
    changes.push(changed);
    let mut bad_hash = req.clone();
    bad_hash.authority.request_hash[0] ^= 1;
    assert!(enumerate_affected_bookings(&vault, &bad_hash, NOW).is_err());
    let mut changed = req.clone();
    changed.affected_window.end += 1;
    changes.push(changed);
    let mut changed = req.clone();
    changed.reason.push('!');
    changes.push(changed);
    let mut changed = req;
    changed.action_policy = EmergencyActionPolicy::RequestUpdate;
    changes.push(changed);
    for mut changed in changes {
        assert!(enumerate_affected_bookings(&vault, &changed, NOW).is_err());
        // Recomputing the public hash does not log a changed request.
        changed.authority.request_hash = canonical_emergency_request_hash(
            changed.affected_window,
            &changed.reason,
            changed.action_policy,
        )
        .unwrap();
        assert!(enumerate_affected_bookings(&vault, &changed, NOW).is_err());
        assert_eq!((meta(&vault), entities(&vault)), before);
    }
}

#[test]
fn owner_instruction_row_is_lane_owned_and_content_keyed() {
    let (dir, vault) = open_test_vault_with(VaultConfig::default());
    let before = meta(&vault);
    let req = logged(&vault);
    let key = instruction_key(
        req.owner_ref,
        req.affected_window,
        &req.reason,
        req.action_policy,
        req.authority.recorded_at,
    )
    .unwrap();
    assert!(key.starts_with(EMERGENCY_INSTRUCTION_META_PREFIX));
    assert_eq!(key.len(), EMERGENCY_INSTRUCTION_META_PREFIX.len() + 64);
    let rows = meta(&vault);
    let added: Vec<_> = rows.iter().filter(|row| !before.contains(row)).collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].0, key);
    let body: serde_json::Value = serde_json::from_slice(&added[0].1).unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3);
    assert_ne!(
        &key[EMERGENCY_INSTRUCTION_META_PREFIX.len()..],
        hex_lower(&req.authority.request_hash).as_bytes()
    );
    assert_eq!(logged(&vault), req);
    assert_eq!(meta(&vault), rows);
    let other = append_owner_instruction(
        &vault,
        id(0x61),
        req.affected_window,
        &req.reason,
        req.action_policy,
        NOW,
    )
    .unwrap();
    assert_eq!(other.request_hash, req.authority.request_hash);
    assert_ne!(
        key,
        instruction_key(
            other.owner_ref,
            req.affected_window,
            &req.reason,
            req.action_policy,
            NOW
        )
        .unwrap()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    verify_logged_owner_instruction(&reopened, &req).unwrap();
}

#[test]
fn no_credential_or_device_ceremony_is_minted() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let before_meta = meta(&vault);
    let before_entities = entities(&vault);
    logged(&vault);
    assert_eq!(entities(&vault), before_entities);
    let after = meta(&vault);
    assert_eq!(after.len(), before_meta.len() + 1);
    for row in before_meta {
        assert!(after.contains(&row), "no pre-existing metadata changed");
    }
    assert_eq!(
        after
            .iter()
            .filter(|(key, _)| key.starts_with(EMERGENCY_INSTRUCTION_META_PREFIX))
            .count(),
        1
    );
}

#[test]
fn corrupted_instruction_body_and_conflicting_append_fail_closed() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let req = logged(&vault);
    let key = instruction_key(
        req.owner_ref,
        req.affected_window,
        &req.reason,
        req.action_policy,
        NOW,
    )
    .unwrap();
    for mutation in 0..3 {
        let mut forged = req.authority.clone();
        match mutation {
            0 => forged.owner_ref = id(0x61),
            1 => forged.request_hash[0] ^= 1,
            _ => forged.recorded_at += 1,
        }
        booking_writer(&vault, |wtxn| {
            put_meta(&vault, wtxn, &key, &serde_json::to_vec(&forged).unwrap())
        })
        .unwrap();
        let before = meta(&vault);
        assert!(verify_logged_owner_instruction(&vault, &req).is_err());
        assert!(
            append_owner_instruction(
                &vault,
                req.owner_ref,
                req.affected_window,
                &req.reason,
                req.action_policy,
                NOW
            )
            .is_err()
        );
        assert_eq!(
            meta(&vault),
            before,
            "append must not repair conflicting evidence"
        );
    }
}

#[test]
fn enumeration_is_owner_scoped_future_overlap_filtered_and_deterministically_sorted() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    page(&vault, 0x62, 0x61);
    let late = book(&vault, PAGE, NOW + 7_200);
    let early = book(&vault, PAGE, NOW + 3_600);
    let tie = book(&vault, PAGE, NOW + 3_600);
    book_as(&vault, 0x62, NOW + 3_600, 0x61); // different owner, same time
    book(&vault, PAGE, NOW); // already started
    book(&vault, PAGE, NOW - 3_600); // past
    book(&vault, PAGE, NOW + 10_800); // just beyond inclusive window
    book(&vault, PAGE, NOW + 1_800); // ends exactly where window starts
    let cancelled = book(&vault, PAGE, NOW + 5_400);
    run(
        &vault,
        BookingVerbRequest::Cancel(CancelSpec {
            token: cancelled.cancel_token,
            idempotency_key: None,
        }),
        TimeRange {
            start: NOW,
            end: NOW + 1,
        },
    );
    let req = logged(&vault);
    let before = (meta(&vault), entities(&vault));
    let rows = enumerate_affected_bookings(&vault, &req, NOW).unwrap();
    let mut first = vec![early.calendar.event_ref, tie.calendar.event_ref];
    first.sort();
    first.push(late.calendar.event_ref);
    assert_eq!(
        rows.iter()
            .map(|r| r.calendar.event_ref)
            .collect::<Vec<_>>(),
        first
    );
    assert!(
        rows.iter()
            .all(|row| row.calendar.sequence == 0 && row.page_ref == id(PAGE))
    );
    assert_eq!(
        rows,
        enumerate_affected_bookings(&vault, &req, NOW).unwrap()
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
    let later = enumerate_affected_bookings(&vault, &req, NOW + 3_600).unwrap();
    assert_eq!(later.len(), 1, "start == now is not future");
    assert_eq!(later[0].calendar.event_ref, late.calendar.event_ref);
}

#[test]
fn silence_never_becomes_held() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    let confirmed = book(&vault, PAGE, NOW + 3_600);
    let req = logged(&vault);
    for now in [NOW, NOW + 3_600, NOW + 86_400] {
        enumerate_affected_bookings(&vault, &req, now).unwrap();
        assert_eq!(
            project_event_outcome(
                read_event_outcome(&vault, confirmed.calendar.event_ref).unwrap()
            ),
            EventOutcome::Unknown
        );
    }
}

#[test]
fn verification_precedes_even_a_failing_booking_read() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    // A lifecycle booking with an absent page configuration is readable as
    // an EVENT, but discovery cannot infer its host. This makes the later
    // read observably fail, rather than relying on a source-order assertion.
    let unknown_page = 0x72;
    vault
        .put_entity(
            &id(unknown_page),
            ENTITY_TYPE_ASSET,
            TimeRange { start: 1, end: 1 },
            1,
            b"unconfigured page",
        )
        .unwrap();
    let broken = book(&vault, unknown_page, NOW + 3_600);
    let body =
        rmp_serde::to_vec_named(&serde_json::json!({ "name": "intro", "booking_context": false }))
            .unwrap();
    vault
        .put_entity(
            &broken.calendar.event_ref,
            crate::registry::ENTITY_TYPE_EVENT,
            TimeRange {
                start: NOW + 3_600,
                end: NOW + 5_399,
            },
            NOW,
            &body,
        )
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    let error = enumerate_affected_bookings(&vault, &request(), NOW).unwrap_err();
    assert!(error.to_string().contains("has not been logged"));
    assert_eq!((meta(&vault), entities(&vault)), before);
    let req = logged(&vault);
    let before = (meta(&vault), entities(&vault));
    let rows = enumerate_affected_bookings(&vault, &req, NOW).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].calendar.event_ref, broken.calendar.event_ref);
    assert_eq!((meta(&vault), entities(&vault)), before);
}

#[test]
fn separate_recording_times_have_separate_content_addresses() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    let first = logged(&vault);
    let mut second = first.clone();
    second.authority = append_owner_instruction(
        &vault,
        first.owner_ref,
        first.affected_window,
        &first.reason,
        first.action_policy,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(first.authority.request_hash, second.authority.request_hash);
    verify_logged_owner_instruction(&vault, &first).unwrap();
    verify_logged_owner_instruction(&vault, &second).unwrap();
    assert_eq!(
        meta(&vault)
            .iter()
            .filter(|(key, _)| key.starts_with(EMERGENCY_INSTRUCTION_META_PREFIX))
            .count(),
        2
    );
    let expected_request = serde_json::json!({
        "window": { "start": first.affected_window.start, "end": first.affected_window.end },
        "reason": first.reason,
        "action_policy": "cancel",
    });
    let encoded = serde_json::to_value(
        request_fields(first.affected_window, &first.reason, first.action_policy).unwrap(),
    )
    .unwrap();
    assert_eq!(
        encoded, expected_request,
        "the authority hash has exactly three fields"
    );
    let row_fields = serde_json::to_value(InstructionFields {
        owner_ref: first.owner_ref.to_hex(),
        request: request_fields(first.affected_window, &first.reason, first.action_policy).unwrap(),
        recorded_at: NOW,
    })
    .unwrap();
    assert_eq!(row_fields.as_object().unwrap().len(), 5);
}

fn existing_authority_root(
    seed: u8,
) -> (
    crate::authority::AuthorityLogEntry,
    ed25519_dalek::SigningKey,
) {
    use crate::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    (sign_existing_authority(entry, &signing), signing)
}

fn sign_existing_authority(
    mut entry: crate::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> crate::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

#[test]
fn a_named_person_without_an_existing_owner_binding_cannot_log_an_instruction() {
    let (_dir, vault) = open_test_vault_with(VaultConfig::default());
    page(&vault, PAGE, OWNER);
    let (genesis, _) = existing_authority_root(0x74);
    vault
        .put_authority_log_entries(&[(genesis, TimeRange { start: 1, end: 1 }, 1)])
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    let error = vault
        .memory(id(OWNER), crate::edge::EdgeActorClass::Human)
        .record_emergency_instruction(&crate::memory::EmergencyInstructionInput {
            affected_window: crate::calendar::query::CalendarRangeDto {
                start: NOW + 3_600,
                end: NOW + 10_799,
            },
            reason: "unavailable".to_owned(),
            action_policy: EmergencyActionPolicy::Cancel,
            recorded_at: NOW,
        })
        .unwrap_err();
    assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
    assert_eq!((meta(&vault), entities(&vault)), before);
}
