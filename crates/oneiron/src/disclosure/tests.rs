use super::*;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use crate::interlocutor::Interlocutor;
use crate::off_record::OffRecordBackendClass;
use crate::registry::ENTITY_TYPE_TURN;

use crate::test_util::entity as test_id;

fn temp_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::config::VaultConfig::default())
}

fn put_turn(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "txt": "turn" })).expect("body"),
        )
        .expect("put turn");
}

fn seed_contact(vault: &Vault, contact_id: EntityId, counterparty: &str) {
    let record = CounterpartyContactRecord::user_introduction(test_id(0xA0), counterparty, 10)
        .expect("record");
    vault
        .create_counterparty_contact(&contact_id, &record)
        .expect("create contact");
}

fn known(contact_id: EntityId, label: &str) -> Interlocutor {
    Interlocutor::known_contact(contact_id, label, CounterpartyFirstTouch::UserIntroduction)
}

fn claim_with_scope(predicate: &str, scope: Option<Value>) -> ClaimBody {
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(test_id(0x77)),
        Value::from("value"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.scope = scope;
    body
}

fn sensitivity_scope(band: &str) -> Value {
    Value::Map(vec![(Value::from("sensitivity"), Value::from(band))])
}

// ─── Mode table (design §6) ─────────────────────────────────────────────────

#[test]
fn mode_table_is_exact() {
    assert_eq!(
        DisclosureMode::from_set(&InterlocutorSet::owner_alone()),
        DisclosureMode::OwnerAlone
    );
    assert_eq!(
        DisclosureMode::from_set(&InterlocutorSet::with_session_owner(vec![
            Interlocutor::unknown("guest", false)
        ])),
        DisclosureMode::Supervised
    );
    assert_eq!(
        DisclosureMode::from_set(&InterlocutorSet::without_owner(vec![
            Interlocutor::unknown("guest", true)
        ])),
        DisclosureMode::AbsenceClamp
    );
    assert_eq!(
        DisclosureMode::from_set(&InterlocutorSet::without_owner(Vec::new())),
        DisclosureMode::AbsenceClamp
    );
    assert_eq!(DisclosureMode::OwnerAlone.as_str(), "owner_alone");
    assert_eq!(DisclosureMode::Supervised.as_str(), "supervised");
    assert_eq!(DisclosureMode::AbsenceClamp.as_str(), "absence_clamp");
}

// ─── Tier truth table (design §7 rules 1–5) ─────────────────────────────────

#[test]
fn tier_rule_1_live_overlay_membership_is_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let fenced = test_id(0x60);
    let session = vault
        .off_record_session_vault()
        .enter("room-1", OffRecordBackendClass::Local)?;
    let overlay = session.overlay();
    let mut wtxn = vault.store.env.write_txn()?;
    let segment = overlay.install_txn_segment()?;
    let view = session.read_view()?;
    view.entities
        .put(&mut wtxn, fenced.as_bytes(), b"overlay")?;
    drop(view);
    wtxn.commit()?;
    segment.commit()?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &fenced, ENTITY_TYPE_TURN, None)?,
        DisclosureTier::TierA
    );
    // Control: an unfenced turn with no marks is Tier B.
    let plain = test_id(0x12);
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &plain, ENTITY_TYPE_TURN, None)?,
        DisclosureTier::TierB
    );
    Ok(())
}

#[test]
fn tier_rule_1_durable_fence_backstop_is_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let fenced = test_id(0x15);
    put_turn(&vault, &fenced);
    vault.enter_off_record_session("room-durable-fence", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("room-durable-fence", &fenced)?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &fenced, ENTITY_TYPE_TURN, None)?,
        DisclosureTier::TierA
    );
    Ok(())
}

#[test]
fn tier_rule_2_governance_type_bytes_are_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x13);
    assert_eq!(
        DISCLOSURE_TIER_A_ENTITY_TYPES,
        [120, 122, 123, 124, 128, 129, 131, 132, 133, 134]
    );
    for entity_type in DISCLOSURE_TIER_A_ENTITY_TYPES {
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, entity_type, None)?,
            DisclosureTier::TierA,
            "type byte {entity_type} must be Tier A"
        );
    }
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_TURN, None)?,
        DisclosureTier::TierB
    );
    Ok(())
}

#[test]
fn tier_rule_3_sensitivity_band_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x14);

    for band in ["sensitive", "restricted"] {
        let body = claim_with_scope("profile.health_note", Some(sensitivity_scope(band)));
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?,
            DisclosureTier::TierA,
            "band {band} must be Tier A"
        );
    }
    // Ambiguous duplicate sensitivity key -> fail closed.
    let ambiguous = claim_with_scope(
        "profile.hobby",
        Some(Value::Map(vec![
            (Value::from("sensitivity"), Value::from("public")),
            (Value::from("sensitivity"), Value::from("restricted")),
        ])),
    );
    assert_eq!(
        disclosure_tier(
            &vault.store,
            &rtxn,
            &id,
            ENTITY_TYPE_CLAIM,
            Some(&ambiguous)
        )?,
        DisclosureTier::TierA
    );
    // A missing/undecodable type-0 body is ambiguous -> fail closed.
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, None)?,
        DisclosureTier::TierA
    );
    // Controls: bands 0/1 stay Tier B.
    for band in ["public", "internal"] {
        let body = claim_with_scope("profile.hobby", Some(sensitivity_scope(band)));
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?,
            DisclosureTier::TierB,
            "band {band} control must stay Tier B"
        );
    }
    Ok(())
}

/// ONE-1645: the unstamped floor reaches the tier boundary. A claim with no
/// recorded provenance fails closed to Tier A — never disclosed to a
/// non-owner party — while a claim carrying a positive public stamp still
/// reaches Tier B. Proves the floor narrows absence without swallowing
/// legitimately-public claims.
#[test]
fn tier_rule_3_unstamped_claim_fails_closed_to_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x16);

    let table: [(&str, Option<Value>, DisclosureTier); 4] = [
        ("no scope map", None, DisclosureTier::TierA),
        (
            "empty scope map",
            Some(Value::Map(vec![])),
            DisclosureTier::TierA,
        ),
        (
            "scope map without a sensitivity key",
            Some(Value::Map(vec![(
                Value::from("federated_original_source"),
                Value::from("imported"),
            )])),
            DisclosureTier::TierA,
        ),
        (
            "explicit public stamp",
            Some(sensitivity_scope("public")),
            DisclosureTier::TierB,
        ),
    ];
    for (label, scope, expected) in table {
        // A non-Tier-A predicate, so rule 3 is the only rule in play.
        let body = claim_with_scope("profile.hobby", scope);
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?,
            expected,
            "{label} must resolve to {expected:?}"
        );
    }
    Ok(())
}

#[test]
fn tier_rule_4_predicate_prefixes_are_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x15);

    for predicate in [
        "affect.trigger",
        "disclosure.topic",
        "counterparty_contact.status",
        "channel_identity.state",
        "voice_print.status",
    ] {
        let body = claim_with_scope(predicate, None);
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?,
            DisclosureTier::TierA,
            "predicate {predicate} must be Tier A"
        );
    }
    // The control carries an explicit public stamp so this test isolates rule
    // 4: without one it would fail closed at rule 3 on the ONE-1645 unstamped
    // floor before ever reaching the predicate check.
    let control = claim_with_scope("profile.hobby", Some(sensitivity_scope("public")));
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&control))?,
        DisclosureTier::TierB
    );
    Ok(())
}

#[test]
fn tier_rule_5_owner_mark_round_trips_through_vault_methods() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let marked = test_id(0x16);
    put_turn(&vault, &marked);

    assert!(!vault.disclosure_tier_a_marked(&marked)?);
    vault.set_disclosure_tier_a(&marked, 100)?;
    assert!(vault.disclosure_tier_a_marked(&marked)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &marked, ENTITY_TYPE_TURN, None)?,
            DisclosureTier::TierA
        );
    }
    // The owner-visible claim mirror exists and is Active.
    let claim_id = disclosure_tier_claim_id(&marked)?;
    let claim = vault.get_claim(&claim_id)?.expect("tier claim mirror");
    assert_eq!(claim.predicate, PREDICATE_DISCLOSURE_TIER);
    assert_eq!(claim.value.as_str(), Some("tier_a"));
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);

    vault.clear_disclosure_tier_a(&marked, 200)?;
    assert!(!vault.disclosure_tier_a_marked(&marked)?);
    {
        let rtxn = vault.store.env.read_txn()?;
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &marked, ENTITY_TYPE_TURN, None)?,
            DisclosureTier::TierB
        );
    }
    let claim = vault.get_claim(&claim_id)?.expect("superseded tier claim");
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Superseded);
    assert_eq!(claim.valid_to, Some(200));

    // Marks require an existing entity.
    let missing = test_id(0x17);
    assert_eq!(
        vault
            .set_disclosure_tier_a(&missing, 100)
            .expect_err("missing entity rejected")
            .kind(),
        crate::error::ErrorKind::EntityNotFound
    );
    Ok(())
}

// ─── Scope codec + validation (design §8) ───────────────────────────────────

#[test]
fn scope_codec_round_trips_and_rejects_malformed_bodies() -> Result<()> {
    let scope = DisclosureScope::task_scoped(
        "hanami party planning",
        vec![test_id(0x22), test_id(0x21), test_id(0x22)],
        100,
    )?;
    // task_scoped sorted and deduped.
    assert_eq!(scope.entities, vec![test_id(0x21), test_id(0x22)]);

    let encoded = encode_disclosure_scope_body(&scope)?;
    assert_eq!(decode_disclosure_scope_body(&encoded)?, scope);

    // Trailing bytes rejected.
    let mut trailing = encoded;
    trailing.push(0x00);
    assert!(decode_disclosure_scope_body(&trailing).is_err());

    // Extra key rejected.
    let mut extra = disclosure_scope_body_value(&scope);
    if let Value::Map(entries) = &mut extra {
        entries.push((Value::from("widen"), Value::from(true)));
    }
    let mut extra_bytes = Vec::new();
    rmpv::encode::write_value(&mut extra_bytes, &extra).expect("encode");
    assert!(decode_disclosure_scope_body(&extra_bytes).is_err());

    // Duplicate key rejected.
    let mut duplicate = disclosure_scope_body_value(&scope);
    if let Value::Map(entries) = &mut duplicate {
        entries.push((Value::from("purpose"), Value::from("second")));
    }
    let mut duplicate_bytes = Vec::new();
    rmpv::encode::write_value(&mut duplicate_bytes, &duplicate).expect("encode");
    assert!(decode_disclosure_scope_body(&duplicate_bytes).is_err());

    // Missing key rejected.
    let mut missing = disclosure_scope_body_value(&scope);
    if let Value::Map(entries) = &mut missing {
        entries.retain(|(key, _)| key.as_str() != Some("topics"));
    }
    let mut missing_bytes = Vec::new();
    rmpv::encode::write_value(&mut missing_bytes, &missing).expect("encode");
    assert!(decode_disclosure_scope_body(&missing_bytes).is_err());

    // Bad schema version rejected.
    let mut versioned = disclosure_scope_body_value(&scope);
    if let Value::Map(entries) = &mut versioned {
        for (key, value) in entries.iter_mut() {
            if key.as_str() == Some("schema_version") {
                *value = Value::from(2_u64);
            }
        }
    }
    let mut versioned_bytes = Vec::new();
    rmpv::encode::write_value(&mut versioned_bytes, &versioned).expect("encode");
    assert!(decode_disclosure_scope_body(&versioned_bytes).is_err());
    Ok(())
}

#[test]
fn scope_validation_enforces_pinned_bounds() {
    let mut scope = DisclosureScope::deny_all(100);
    assert!(scope.validate().is_ok());

    scope.entities = vec![test_id(0x22), test_id(0x21)];
    assert!(scope.validate().is_err(), "unsorted entities rejected");
    scope.entities = vec![test_id(0x21), test_id(0x21)];
    assert!(scope.validate().is_err(), "duplicate entities rejected");
    scope.entities.clear();

    scope.purpose = String::new();
    assert!(scope.validate().is_err(), "empty purpose rejected");
    scope.purpose = " padded ".to_owned();
    assert!(scope.validate().is_err(), "untrimmed purpose rejected");
    scope.purpose = "x".repeat(513);
    assert!(scope.validate().is_err(), "oversize purpose rejected");
    scope.purpose = "deny_all".to_owned();

    scope.topics = vec!["x".repeat(129)];
    assert!(scope.validate().is_err(), "oversize topic rejected");
    scope.topics = vec![String::new()];
    assert!(scope.validate().is_err(), "empty topic rejected");
    scope.topics.clear();

    scope.updated_at = 99;
    assert!(scope.validate().is_err(), "updated_at before created_at");
    scope.updated_at = 100;
    assert!(scope.validate().is_ok());

    let too_many: Vec<EntityId> = (0..257_u16)
        .map(|index| {
            let mut bytes = [0x60_u8; 16];
            bytes[14..].copy_from_slice(&index.to_be_bytes());
            EntityId::from_bytes(bytes).expect("distinct test id")
        })
        .collect();
    assert!(
        DisclosureScope::task_scoped("p", too_many, 1).is_err(),
        "entity allowlist cap enforced"
    );
}

// ─── Intersection algebra (DEC-0005) ────────────────────────────────────────

#[test]
fn intersection_algebra_is_commutative_empty_absorbing_and_revoked_propagating() -> Result<()> {
    let a = DisclosureScope::task_scoped("alpha", vec![test_id(1), test_id(2)], 100)?;
    let b = DisclosureScope::task_scoped("beta", vec![test_id(2), test_id(3)], 50)?;

    let ab = a.intersect(&b);
    let ba = b.intersect(&a);
    assert_eq!(ab.entities, vec![test_id(2)], "most-restrictive-wins");
    assert_eq!(ab.entities, ba.entities, "commutative on entity sets");
    assert_eq!(ab.created_at, 50, "earliest created_at");
    assert_eq!(ab.updated_at, 100, "latest updated_at");
    assert_eq!(ab.purpose, "alpha ∩ beta");
    assert_eq!(ab.status, DisclosureScopeStatus::Active);

    // Empty scope is the absorbing element.
    let deny = DisclosureScope::deny_all(10);
    assert!(a.intersect(&deny).entities.is_empty());
    assert!(deny.intersect(&a).entities.is_empty());

    // Revoked propagates.
    let mut revoked = b;
    revoked.status = DisclosureScopeStatus::Revoked;
    assert_eq!(a.intersect(&revoked).status, DisclosureScopeStatus::Revoked);

    // Purpose join truncates at a char boundary within 512 bytes.
    let long_a = DisclosureScope::task_scoped("あ".repeat(170), vec![], 1)?;
    let long_b = DisclosureScope::task_scoped("い".repeat(170), vec![], 1)?;
    let joined = long_a.intersect(&long_b);
    assert!(joined.purpose.len() <= 512);
    assert!(joined.purpose.is_char_boundary(joined.purpose.len()));
    Ok(())
}

// ─── Vault scope storage (dual write) ───────────────────────────────────────

#[test]
fn scope_dual_write_requires_contact_and_supersedes_prior_claim() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_id = test_id(0x31);
    seed_contact(&vault, contact_id, "kenji@example.com");

    // Non-132 entity rejected.
    let turn = test_id(0x32);
    put_turn(&vault, &turn);
    let scope = DisclosureScope::task_scoped("party", vec![test_id(0x41)], 100)?;
    assert_eq!(
        vault
            .set_counterparty_disclosure_scope(&turn, &scope)
            .expect_err("non-contact rejected")
            .kind(),
        crate::error::ErrorKind::InvalidEntityType
    );
    // Missing entity rejected.
    assert_eq!(
        vault
            .set_counterparty_disclosure_scope(&test_id(0x33), &scope)
            .expect_err("missing contact rejected")
            .kind(),
        crate::error::ErrorKind::EntityNotFound
    );

    // Missing row reads None.
    assert_eq!(vault.counterparty_disclosure_scope(&contact_id)?, None);

    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    assert_eq!(
        vault.counterparty_disclosure_scope(&contact_id)?,
        Some(scope.clone())
    );

    // Owner-visible claim mirror exists.
    let claim_id = disclosure_scope_claim_id(&contact_id)?;
    let claim = vault.get_claim(&claim_id)?.expect("scope claim mirror");
    assert_eq!(claim.predicate, PREDICATE_DISCLOSURE_SCOPE);
    assert_eq!(claim.subject, ClaimSubject::Entity(contact_id));
    assert_eq!(claim.value, disclosure_scope_body_value(&scope));
    validate_disclosure_claim_structure(&claim)?;

    // Re-set (dial-not-wall) replaces the row AND supersedes the prior claim
    // value — exactly one owner-visible scope claim, carrying the new value.
    let mut wider =
        DisclosureScope::task_scoped("party and travel", vec![test_id(0x41), test_id(0x53)], 100)?;
    wider.updated_at = 200;
    vault.set_counterparty_disclosure_scope(&contact_id, &wider)?;
    assert_eq!(
        vault.counterparty_disclosure_scope(&contact_id)?,
        Some(wider.clone())
    );
    let claim = vault.get_claim(&claim_id)?.expect("rewritten scope claim");
    assert_eq!(claim.value, disclosure_scope_body_value(&wider));
    assert_eq!(claim.lifecycle, ClaimLifecycleStatus::Active);
    Ok(())
}

// ─── Claim family validation ────────────────────────────────────────────────

#[test]
fn disclosure_claim_family_dispatch_and_structure() {
    for predicate in DISCLOSURE_CLAIM_PREDICATES {
        assert!(is_disclosure_claim_predicate(predicate));
    }
    assert!(!is_disclosure_claim_predicate("disclosure.other"));
    assert!(!is_disclosure_claim_predicate("profile.hobby"));

    // disclosure.tier accepts only "tier_a".
    let tier = ClaimBody::new(
        PREDICATE_DISCLOSURE_TIER,
        ClaimSubject::Entity(test_id(1)),
        Value::from("tier_a"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    assert!(validate_disclosure_claim_structure(&tier).is_ok());
    let mut bad_tier = tier.clone();
    bad_tier.value = Value::from("tier_b");
    assert!(validate_disclosure_claim_structure(&bad_tier).is_err());

    // disclosure.topic bounds.
    let mut topic = tier.clone();
    topic.predicate = PREDICATE_DISCLOSURE_TOPIC.to_owned();
    topic.value = Value::from("travel");
    assert!(validate_disclosure_claim_structure(&topic).is_ok());
    topic.value = Value::from("x".repeat(129));
    assert!(validate_disclosure_claim_structure(&topic).is_err());
    topic.value = Value::from("  ");
    assert!(validate_disclosure_claim_structure(&topic).is_err());

    // disclosure.scope value must decode as a scope body.
    let mut scope_claim = tier.clone();
    scope_claim.predicate = PREDICATE_DISCLOSURE_SCOPE.to_owned();
    scope_claim.value = disclosure_scope_body_value(&DisclosureScope::deny_all(1));
    assert!(validate_disclosure_claim_structure(&scope_claim).is_ok());
    scope_claim.value = Value::from("not a scope");
    assert!(validate_disclosure_claim_structure(&scope_claim).is_err());

    // Subject must be an entity.
    let mut edge_subject = tier;
    edge_subject.subject = ClaimSubject::Edge {
        source: test_id(1),
        target: test_id(2),
        kind: EdgeKind::Mentions,
    };
    assert!(validate_disclosure_claim_structure(&edge_subject).is_err());

    // The disclosure family is wired into the claim-dispatch chain: a
    // malformed disclosure claim is rejected at the write chokepoint.
    let encoded = encode_claim_body(&bad_tier).expect("encode");
    assert!(validate_claim_body_bytes(&encoded, false).is_err());
}

// ─── DisclosureContext resolution + admission ───────────────────────────────

#[test]
fn resolve_folds_scopes_fail_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_a = test_id(0x51);
    let contact_b = test_id(0x52);
    seed_contact(&vault, contact_a, "a@example.com");
    seed_contact(&vault, contact_b, "b@example.com");

    // OwnerAlone / Supervised carry no scope.
    let ctx = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    assert_eq!(ctx.mode(), DisclosureMode::OwnerAlone);
    assert!(ctx.scope.is_none());
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::Supervised);
    assert!(ctx.scope.is_none());

    // Unknown party -> deny-all.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", true)]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::AbsenceClamp);
    assert!(
        ctx.scope
            .as_ref()
            .expect("deny-all scope")
            .entities
            .is_empty()
    );

    // Contact without a scope row -> deny-all.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    assert!(ctx.scope.as_ref().expect("scope").entities.is_empty());

    // Active scope loads; a second party with a disjoint scope intersects.
    let scope_a = DisclosureScope::task_scoped("alpha", vec![test_id(0x61), test_id(0x62)], 100)?;
    let scope_b = DisclosureScope::task_scoped("beta", vec![test_id(0x62), test_id(0x63)], 100)?;
    vault.set_counterparty_disclosure_scope(&contact_a, &scope_a)?;
    vault.set_counterparty_disclosure_scope(&contact_b, &scope_b)?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    assert_eq!(
        ctx.scope.as_ref().expect("scope").entities,
        vec![test_id(0x61), test_id(0x62)]
    );
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![
            known(contact_a, "a@example.com"),
            known(contact_b, "b@example.com"),
        ]),
    )?;
    assert_eq!(
        ctx.scope.as_ref().expect("intersected scope").entities,
        vec![test_id(0x62)],
        "DEC-0005 most-restrictive-wins"
    );

    // A revoked scope contributes deny-all.
    let mut revoked = scope_b;
    revoked.status = DisclosureScopeStatus::Revoked;
    revoked.updated_at = 200;
    vault.set_counterparty_disclosure_scope(&contact_b, &revoked)?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_b, "b@example.com")]),
    )?;
    assert!(ctx.scope.as_ref().expect("deny-all").entities.is_empty());
    Ok(())
}

#[test]
fn admits_truth_table_checks_tier_before_scope() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_id = test_id(0x71);
    seed_contact(&vault, contact_id, "kenji@example.com");
    let party = test_id(0x72);
    let diary = test_id(0x73);
    put_turn(&vault, &party);
    put_turn(&vault, &diary);
    // The party turn is IN scope but owner-marked Tier A: scope can never
    // override tier (I2 never-widen).
    let scope = DisclosureScope::task_scoped("party", vec![party], 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    vault.set_disclosure_tier_a(&party, 100)?;

    let owner_alone = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    let supervised = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;
    let clamped = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;

    let rtxn = vault.store.env.read_txn()?;
    // OwnerAlone admits everything, Tier A included.
    assert!(owner_alone.admits(&vault.store, &rtxn, &party, ENTITY_TYPE_TURN, None)?);
    // Supervised and AbsenceClamp never admit Tier A — even in-scope.
    assert!(!supervised.admits(&vault.store, &rtxn, &party, ENTITY_TYPE_TURN, None)?);
    assert!(!clamped.admits(&vault.store, &rtxn, &party, ENTITY_TYPE_TURN, None)?);
    // Supervised admits Tier B without a scope check.
    assert!(supervised.admits(&vault.store, &rtxn, &diary, ENTITY_TYPE_TURN, None)?);
    // AbsenceClamp requires scope membership: the diary is out of scope.
    assert!(!clamped.admits(&vault.store, &rtxn, &diary, ENTITY_TYPE_TURN, None)?);
    // A PSYCH_PROFILE id is never admitted in either non-owner mode (rule 2).
    let psych = test_id(0x74);
    assert!(!supervised.admits(
        &vault.store,
        &rtxn,
        &psych,
        crate::registry::ENTITY_TYPE_PSYCH_PROFILE,
        None
    )?);
    assert!(!clamped.admits(
        &vault.store,
        &rtxn,
        &psych,
        crate::registry::ENTITY_TYPE_PSYCH_PROFILE,
        None
    )?);
    Ok(())
}

#[test]
fn admits_accepts_claims_about_allowlisted_entities() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_id = test_id(0x81);
    seed_contact(&vault, contact_id, "kenji@example.com");
    let party = test_id(0x82);
    let diary = test_id(0x83);
    put_turn(&vault, &party);
    put_turn(&vault, &diary);
    let scope = DisclosureScope::task_scoped("party", vec![party], 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;

    let party_fact = test_id(0x84);
    let mut fact = ClaimBody::new(
        "event.headcount",
        ClaimSubject::Entity(party),
        Value::from("12"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    fact.scope = Some(sensitivity_scope("public"));
    vault.put_claim(&party_fact, &fact, TimeRange { start: 1, end: 1 }, 1)?;
    let diary_fact = test_id(0x85);
    let about_diary = ClaimBody::new(
        "event.note",
        ClaimSubject::Entity(diary),
        Value::from("private"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&diary_fact, &about_diary, TimeRange { start: 1, end: 1 }, 1)?;

    let clamped = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    // Claims ABOUT an allowlisted entity are the payload.
    assert!(clamped.admits(&vault.store, &rtxn, &party_fact, ENTITY_TYPE_CLAIM, None)?);
    // Claims about out-of-scope entities are not.
    assert!(!clamped.admits(&vault.store, &rtxn, &diary_fact, ENTITY_TYPE_CLAIM, None)?);
    Ok(())
}

// ─── Notice, assembly, receipt stamp (design §10) ───────────────────────────

#[test]
fn presence_discretion_notice_matches_pinned_template() {
    let set = InterlocutorSet::with_session_owner(vec![
        known(test_id(0x91), "Kenji"),
        Interlocutor::unknown("unknown speaker 2", true),
    ]);
    let notice = presence_discretion_notice(&set);
    assert_eq!(
        notice,
        "Others present: Kenji (known_contact, first contact: user_introduction), \
         unknown speaker 2 (unknown). Don't volunteer personal or sensitive information; \
         if asked about private matters, defer to the owner."
    );
    assert!(
        !notice.contains("owner (owner)"),
        "the Owner entry never appears under Others present"
    );
}

#[test]
fn assembly_and_receipt_stamp_are_mode_keyed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_id = test_id(0x92);
    seed_contact(&vault, contact_id, "kenji@example.com");

    let supervised = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;
    let assembly = supervised.assembly(3);
    assert_eq!(assembly.mode, "supervised");
    assert!(assembly.notice.as_deref().is_some_and(|notice| {
        notice.starts_with("Others present: kenji@example.com (known_contact")
    }));
    assert_eq!(assembly.clamped_out, 3);
    assert_eq!(assembly.interlocutors.len(), 2);
    assert_eq!(
        supervised.receipt_stamp(),
        "mode=supervised;interlocutors=owner:owner,known_contact:kenji@example.com"
    );

    let clamped = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    let assembly = clamped.assembly(0);
    assert_eq!(assembly.mode, "absence_clamp");
    assert!(assembly.notice.is_none(), "notice is Some iff Supervised");
    assert_eq!(
        clamped.receipt_stamp(),
        "mode=absence_clamp;interlocutors=unknown:guest"
    );

    let owner = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    assert!(owner.assembly(0).notice.is_none());
    Ok(())
}

// ─── F2 (codex, keystone review): mirror-write door containment ─────────────
//
// The door skips the write gate (`allow_reserved_predicate: true`). Its
// safety must be STRUCTURAL, not a call-site convention: no body carrying a
// caller-chosen predicate may ride it.

#[test]
fn mirror_write_door_refuses_predicates_outside_the_disclosure_family() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x21);
    put_turn(&vault, &subject);
    let claim_id = disclosure_tier_claim_id(&subject)?;

    for predicate in ["profile.hobby", "event.headcount", "voice_print.status"] {
        let body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from("smuggled"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let mut wtxn = vault.store.env.write_txn()?;
        let err = vault
            .put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &body, 100)
            .expect_err("gate-exempt door refuses non-disclosure predicates");
        assert_eq!(err.kind(), crate::error::ErrorKind::InvalidClaimBody);
        drop(wtxn);
    }

    // The family's own predicates still ride it (the door stays usable).
    let body = ClaimBody::new(
        PREDICATE_DISCLOSURE_TIER,
        ClaimSubject::Entity(subject),
        Value::from(DISCLOSURE_TIER_VALUE_TIER_A),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    let mut wtxn = vault.store.env.write_txn()?;
    vault.put_disclosure_claim_in_txn(&mut wtxn, &claim_id, &body, 100)?;
    wtxn.commit()?;
    Ok(())
}

#[test]
fn clear_tier_a_leaves_a_foreign_claim_squatting_the_mirror_id_untouched() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let marked = test_id(0x22);
    put_turn(&vault, &marked);

    // The mirror id is a public sha256 derivation: any caller can compute it
    // and write a foreign claim there through the NORMAL gated put_claim
    // door. clear_disclosure_tier_a must never forward that body into the
    // gate-exempt door.
    let claim_id = disclosure_tier_claim_id(&marked)?;
    let squatter = ClaimBody::new(
        "profile.hobby",
        ClaimSubject::Entity(marked),
        Value::from("smuggled through the mirror id"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&claim_id, &squatter, TimeRange { start: 1, end: 1 }, 1)?;

    vault.clear_disclosure_tier_a(&marked, 200)?;

    let stored = vault.get_claim(&claim_id)?.expect("squatter survives");
    assert_eq!(stored, squatter, "foreign claim is left exactly as written");
    assert_eq!(stored.lifecycle, ClaimLifecycleStatus::Active);
    assert_eq!(stored.valid_to, None);
    Ok(())
}

// ─── Qodo keystone round 2: corrupt-row fail-closed + stamp injection ───────

#[test]
fn corrupt_scope_row_fails_closed_to_absence_clamp_not_error() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact_id = test_id(0x25);
    seed_contact(&vault, contact_id, "kenji@example.com");
    let party = test_id(0x26);
    vault
        .batch()
        .put(
            &party,
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "txt": "party corrupt needle" }))
                .expect("body"),
        )
        .text(&party, &[("body", "party corrupt needle")])
        .commit()?;
    // A valid scope allowlists the party...
    let scope = DisclosureScope::task_scoped("party", vec![party], 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    // ...then the enforcement row is corrupted in place (adversarial or
    // bit-rotted vault_meta bytes).
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &disclosure_scope_meta_key(&contact_id),
            b"not a msgpack scope body",
        )?;
        wtxn.commit()?;
    }

    // The owner-facing read stays LOUD so corruption is visible.
    assert_eq!(
        vault
            .counterparty_disclosure_scope(&contact_id)
            .expect_err("owner read surfaces the corruption")
            .kind(),
        crate::error::ErrorKind::InvalidDisclosureScope
    );

    // Resolution fails CLOSED: no error, deny-all scope for that contact.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::AbsenceClamp);
    assert!(
        ctx.scope
            .as_ref()
            .expect("deny-all scope")
            .entities
            .is_empty(),
        "corrupt row narrows to the empty scope"
    );

    // Full assembly: empty pack, not an error and not a wider pack — the
    // previously-allowlisted party is no longer admitted.
    let pack = vault
        .context_pack()
        .search_text("corrupt needle", 10)
        .disclosure_context(ctx)
        .run()?;
    assert!(pack.results.is_empty() && pack.neighbors.is_empty());
    assert!(
        pack.empty.is_some(),
        "empty-context envelope: {:?}",
        pack.empty
    );
    Ok(())
}

#[test]
fn receipt_stamp_escapes_delimiters_and_round_trips_the_exact_labels() -> Result<()> {
    fn percent_decode(encoded: &str) -> String {
        let bytes = encoded.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("hex pair");
                out.push(u8::from_str_radix(hex, 16).expect("hex byte"));
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }
        String::from_utf8(out).expect("decoded label utf8")
    }

    let (_tmp, vault) = temp_vault();
    let hostile = "gu,est:x=y;z%";
    let control = "line\nbreak";
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![
            Interlocutor::unknown(hostile, false),
            Interlocutor::unknown(control, true),
        ]),
    )?;

    let stamp = ctx.receipt_stamp();
    assert_eq!(
        stamp,
        "mode=absence_clamp;interlocutors=\
         unknown:gu%2Cest%3Ax%3Dy%3Bz%25,unknown:line%0Abreak"
    );
    assert!(
        !stamp.chars().any(char::is_control),
        "no raw control bytes reach the audit record"
    );

    // A delimiter-grammar parse recovers the EXACT interlocutor set.
    let (mode_part, interlocutors_part) = stamp.split_once(';').expect("one mode separator");
    assert_eq!(mode_part, "mode=absence_clamp");
    let entries: Vec<(&str, String)> = interlocutors_part
        .strip_prefix("interlocutors=")
        .expect("interlocutors key")
        .split(',')
        .map(|entry| {
            let (class, label) = entry.split_once(':').expect("class separator");
            (class, percent_decode(label))
        })
        .collect();
    assert_eq!(
        entries,
        vec![
            ("unknown", hostile.to_owned()),
            ("unknown", control.to_owned()),
        ]
    );
    Ok(())
}
