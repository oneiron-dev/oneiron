use super::*;
use crate::booking::{
    BOOKING_EVENT_TYPE_PREDICATE, BOOKING_EVENT_TYPE_SCHEMA_VERSION, BookingEventTypeClaimValue,
    EventTypeConfig, HostAvailabilityConfig, RoutingMode, WeeklyWallWindow,
    encode_event_type_claim_value,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::memory::{ClaimInput, MEMORY_CODE_FORBIDDEN};
use serde_json::json;

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("id")
}

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("directory");
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    for (entity, kind) in [
        (id(1), crate::registry::ENTITY_TYPE_ASSET),
        (id(2), crate::registry::ENTITY_TYPE_PERSON),
    ] {
        vault
            .put_entity(&entity, kind, TimeRange { start: 1, end: 1 }, 1, b"fixture")
            .expect("entity");
    }
    let config = EventTypeConfig {
        key: EventTypeKey("event".to_owned()),
        duration_min: 30,
        slot_step_min: 30,
        pre_buffer_min: 0,
        post_buffer_min: 0,
        min_notice_secs: 0,
        booking_window_secs: 7 * 86_400,
        daily_cap: None,
        weekly_cap: None,
        routing: RoutingMode::Either,
        hosts: vec![HostAvailabilityConfig {
            host_ref: id(3),
            calendar_refs: vec![id(4)],
            host_tz: "UTC".to_owned(),
            working_hours: vec![WeeklyWallWindow {
                weekday: 0,
                start_minute: 0,
                end_minute: 1_440,
            }],
            preferred_hours: Vec::new(),
        }],
        flex_windows: Vec::new(),
    };
    vault
        .put_claim(
            &id(5),
            &ClaimBody::new(
                BOOKING_EVENT_TYPE_PREDICATE,
                ClaimSubject::Entity(id(1)),
                encode_event_type_claim_value(&BookingEventTypeClaimValue {
                    schema_version: BOOKING_EVENT_TYPE_SCHEMA_VERSION,
                    page_ref: id(1),
                    config,
                })
                .expect("configuration"),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            ),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("config claim");
    (dir, vault)
}

fn publication() -> BookingPagePublication {
    BookingPagePublication {
        schema_version: BOOKING_PUBLIC_PAGE_SCHEMA_VERSION,
        published: true,
        owner_display: "Owner supplied display".to_owned(),
        event_types: vec![EventTypeCard {
            key: EventTypeKey("event".to_owned()),
            title: "Owner supplied title".to_owned(),
            duration_min: 30,
            description: "Owner supplied description".to_owned(),
        }],
        constraint_field: ConstraintFieldConfig {
            enabled: false,
            placeholder: String::new(),
        },
        theme: ThemeTokens(json!({"arbitrary": [false, null, {"nested": "</script>"}]})),
        initial_availability: PublicBookingAvailability {
            event_type: EventTypeKey("event".to_owned()),
            start_after_secs: 10,
            window_secs: 3_600,
            visitor_tz: "UTC".to_owned(),
        },
    }
}

fn input(value: BookingPagePublication) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: BOOKING_PUBLIC_PAGE_PREDICATE.to_owned(),
        subject_ref: id(1).to_hex(),
        value: serde_json::to_value(value).expect("JSON"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        world_ref: None,
        scope: None,
        valid_from: Some(100),
        valid_to: Some(200),
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

#[test]
fn public_booking_publication_round_trips_opaque_presentation_and_bounds_window() {
    let value = publication();
    let encoded = encode_public_booking_page_value(&value).expect("encode");
    assert_eq!(
        decode_public_booking_page_value(&encoded).expect("decode"),
        value
    );
    let request = value
        .initial_availability
        .request(100, "render".to_owned())
        .expect("window");
    assert_eq!(
        request.window,
        TimeRange {
            start: 110,
            end: 3_709
        }
    );
    assert!(
        value
            .initial_availability
            .request(u64::MAX, "render".to_owned())
            .is_err()
    );
    for bag in [
        json!(null),
        json!([1, {"never-interpreted": true}]),
        json!("opaque"),
    ] {
        let mut value = value.clone();
        value.theme = ThemeTokens(bag);
        let encoded = encode_public_booking_page_value(&value).expect("opaque bag");
        assert_eq!(
            decode_public_booking_page_value(&encoded).expect("opaque roundtrip"),
            value
        );
    }
}

#[test]
fn public_booking_publication_uses_normal_owner_write_and_half_open_claim_lifetime() {
    let (_dir, vault) = open();
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("unpublished")
            .is_none()
    );
    let receipt = vault
        .memory(id(2), EdgeActorClass::Human)
        .claim_upsert(&input(publication()))
        .expect("publish");
    assert_eq!(receipt.approval, "auto");
    for now in [100, 199] {
        assert_eq!(
            load_public_booking_page(&vault, id(1), now).expect("live"),
            Some(publication())
        );
    }
    for now in [99, 200, u64::MAX] {
        assert!(
            load_public_booking_page(&vault, id(1), now)
                .expect("not live")
                .is_none()
        );
    }
    let mut withdrawn = publication();
    withdrawn.published = false;
    vault
        .memory(id(2), EdgeActorClass::Human)
        .claim_upsert(&input(withdrawn))
        .expect("withdraw");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("revoked")
            .is_none()
    );
}

#[test]
fn public_booking_publication_is_durable_and_retraction_does_not_revive_old_allow() {
    let (dir, vault) = open();
    let owner = vault.memory(id(2), EdgeActorClass::Human);
    owner.claim_upsert(&input(publication())).expect("publish");
    let mut updated = publication();
    updated.owner_display = "Updated owner".to_owned();
    let receipt = owner.claim_upsert(&input(updated.clone())).expect("update");
    assert!(receipt.superseded_short_id.is_some());
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("reopen");
    assert_eq!(
        load_public_booking_page(&vault, id(1), 150).expect("persisted"),
        Some(updated)
    );
    vault
        .memory(id(2), EdgeActorClass::Human)
        .claim_retract(&receipt.claim_short_id)
        .expect("retract");
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::default()).expect("reopen revoked");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("persisted revocation")
            .is_none()
    );
}

#[test]
fn public_booking_publication_rejects_agent_and_invalid_claim_shapes_at_write_door() {
    let (_dir, vault) = open();
    let value = input(publication());
    let agent = vault.memory(id(2), EdgeActorClass::Agent);
    assert_eq!(
        agent.claim_upsert(&value).expect_err("agent").code,
        MEMORY_CODE_FORBIDDEN
    );
    let owner = vault.memory(id(2), EdgeActorClass::Human);
    let mut cases = Vec::new();
    let mut malformed = value.clone();
    malformed.valid_to = None;
    cases.push(malformed);
    let mut malformed = value.clone();
    malformed.valid_from = malformed.valid_to;
    cases.push(malformed);
    let mut malformed = value.clone();
    malformed.scope = Some(json!({}));
    cases.push(malformed);
    let mut malformed = value.clone();
    malformed.source = "observed".to_owned();
    cases.push(malformed);
    for (field, content) in [
        ("owner_display", json!(" ")),
        ("event_types", json!([])),
        ("schema_version", json!(2)),
    ] {
        let mut malformed = value.clone();
        malformed.value[field] = content;
        cases.push(malformed);
    }
    let mut malformed = value.clone();
    malformed.value["initial_availability"]["window_secs"] = json!(MAX_BOOKING_WINDOW_SECS + 1);
    cases.push(malformed);
    let mut malformed = value.clone();
    malformed.value["initial_availability"]["visitor_tz"] = json!("not/a/zone");
    cases.push(malformed);
    let mut malformed = value.clone();
    malformed.value["event_types"]
        .as_array_mut()
        .expect("cards")
        .push(value.value["event_types"][0].clone());
    cases.push(malformed);
    for case in cases {
        assert!(
            owner.claim_upsert(&case).is_err(),
            "invalid publication: {:?}",
            case.value
        );
    }
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("still private")
            .is_none()
    );
    // An unstamped low-level claim is not a substitute for the owner write door.
    let mut raw = ClaimBody::new(
        BOOKING_PUBLIC_PAGE_PREDICATE,
        ClaimSubject::Entity(id(1)),
        encode_public_booking_page_value(&publication()).expect("value"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    raw.source = Some(ClaimSource::UserStated);
    raw.valid_from = Some(100);
    raw.valid_to = Some(200);
    assert!(
        vault
            .put_claim(&id(6), &raw, TimeRange { start: 1, end: 1 }, 1)
            .is_err()
    );
}

#[test]
fn public_booking_publication_rechecks_configuration_and_ambiguous_heads() {
    let (_dir, vault) = open();
    let owner = vault.memory(id(2), EdgeActorClass::Human);
    let receipt = owner.claim_upsert(&input(publication())).expect("publish");
    let publication_id =
        crate::memory::resolve_entity_ref(&vault, &receipt.claim_short_id).expect("claim id");
    let body = vault
        .get_claim(&publication_id)
        .expect("claim")
        .expect("body");
    // Two independent replicated heads cannot pick an allow around a deny.
    let mut denial = body;
    let mut value = publication();
    value.published = false;
    denial.value = encode_public_booking_page_value(&value).expect("deny");
    vault
        .put_claim(&id(6), &denial, TimeRange { start: 1, end: 1 }, 1)
        .expect("concurrent owner head");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("ambiguous")
            .is_none()
    );
    owner
        .claim_retract(&id(6).to_hex())
        .expect("resolve conflict");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("one head")
            .is_some()
    );
    let mut config = vault.get_claim(&id(5)).expect("config").expect("body");
    config.approval = ClaimApprovalStatus::Proposed;
    vault
        .put_claim(&id(5), &config, TimeRange { start: 1, end: 1 }, 1)
        .expect("configuration pending");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("not live config")
            .is_none()
    );
    config.approval = ClaimApprovalStatus::Auto;
    config.stale = true;
    vault
        .put_claim(&id(5), &config, TimeRange { start: 1, end: 1 }, 1)
        .expect("configuration stale");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("stale config")
            .is_none()
    );
}

#[test]
fn public_booking_publication_requires_current_rooted_owner_authority() {
    use crate::authority::{
        AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
        AuthorityOp, AuthoritySignature, AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
        authority_entry_hash, authority_transcript, genesis_vault_id,
    };
    use ed25519_dalek::Signer;
    let (_dir, vault) = open();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x21; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let sign = |mut entry: AuthorityLogEntry| {
        entry.signer.signature = signing
            .sign(&authority_transcript(&entry).expect("transcript"))
            .to_bytes()
            .to_vec();
        entry
    };
    let signature = || AuthoritySignature {
        suite: key.suite(),
        public_key: key.clone(),
        signature: vec![0; 64],
    };
    let genesis = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
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
            genesis_nonce: [0x31; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: signature(),
        cosigns: Vec::new(),
        ts: 100,
    });
    let vault_id = genesis_vault_id(&genesis).expect("vault id");
    let bind = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq: 1,
        parent_hashes: vec![authority_entry_hash(&genesis).expect("genesis hash")],
        op: AuthorityOp::BindActor {
            authority_key: key.clone(),
            actor_ref: id(2),
            actor_class: "human".to_owned(),
            epoch: 1,
        },
        signer: signature(),
        cosigns: Vec::new(),
        ts: 101,
    });
    let bind_hash = authority_entry_hash(&bind).expect("bind hash");
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
        ])
        .expect("atomic owner ceremony");
    vault
        .put_entity(
            &id(7),
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"not the owner",
        )
        .expect("other human");
    assert_eq!(
        vault
            .memory(id(7), EdgeActorClass::Human)
            .claim_upsert(&input(publication()))
            .expect_err("a human is not necessarily the owner")
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    let owner = vault.memory(id(2), EdgeActorClass::Human);
    let receipt = owner
        .claim_upsert(&input(publication()))
        .expect("bound owner publishes");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("live")
            .is_some()
    );
    let revoke = sign(AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq: 2,
        parent_hashes: vec![bind_hash],
        op: AuthorityOp::RevokeActor {
            authority_key: key.clone(),
            epoch: 1,
        },
        signer: signature(),
        cosigns: Vec::new(),
        ts: 102,
    });
    vault
        .put_authority_log_entries(&[(revoke, TimeRange { start: 3, end: 3 }, 3)])
        .expect("revoke owner binding");
    assert!(
        load_public_booking_page(&vault, id(1), 150)
            .expect("binding no longer live")
            .is_none()
    );
    assert_eq!(
        owner
            .claim_upsert(&input(publication()))
            .expect_err("revoked owner")
            .code,
        MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(
        owner
            .claim_retract(&receipt.claim_short_id)
            .expect_err("revoked owner retract")
            .code,
        MEMORY_CODE_FORBIDDEN
    );
}
