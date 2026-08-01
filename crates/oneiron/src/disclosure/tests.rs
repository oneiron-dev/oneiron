use super::*;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use crate::interlocutor::Interlocutor;
use crate::off_record::OffRecordBackendClass;
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};

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

fn put_facet(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(
            id,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({ "name": "facet" })).expect("body"),
        )
        .expect("put facet");
}

/// A CLAIM carrying an explicit public sensitivity band, so the Tier-A
/// conjunct passes and the FACET conjunct is the rule under test. The subject
/// entity is seeded too — `put_claim` writes a `ClaimOf` edge to it.
fn put_public_claim(vault: &Vault, id: &EntityId, subject: EntityId) {
    put_turn(vault, &subject);
    let mut body = ClaimBody::new(
        "event.note",
        ClaimSubject::Entity(subject),
        Value::from("value"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.scope = Some(sensitivity_scope("public"));
    vault
        .put_claim(id, &body, TimeRange { start: 1, end: 1 }, 1)
        .expect("put claim");
}

fn stamp_facet_of(vault: &Vault, claim_id: &EntityId, facet_id: &EntityId) {
    vault
        .batch()
        .edge(claim_id, EdgeKind::FacetOf, facet_id, 1.0)
        .commit()
        .expect("stamp FacetOf");
}

fn grant_clearance(vault: &Vault, contact_id: &EntityId, facets: Vec<EntityId>) {
    let clearance = FacetClearance::granted(facets, 100).expect("clearance");
    vault
        .set_contact_facet_clearance(contact_id, &clearance)
        .expect("set clearance");
}

fn disclosable_facets(ctx: &DisclosureContext) -> Vec<EntityId> {
    match ctx.disclosable() {
        DisclosableSet::All => panic!("expected a resolved facet set, got All"),
        DisclosableSet::Facets(facets) => facets.clone(),
    }
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

// ─── S-DISC2: the F2(d) disclosable-set conjunct (ONE-1646) ─────────────────

/// T1 (P1 pin, RATIFY-mandated): the intersection over the EMPTY family of
/// non-owner interlocutors is ALL facets. The owner alone is never locked out
/// of their own private facets.
#[test]
fn disclosable_set_owner_alone_is_all() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xC1);
    let claim = test_id(0xC2);
    put_facet(&vault, &facet);
    put_public_claim(&vault, &claim, test_id(0xC3));
    stamp_facet_of(&vault, &claim, &facet);

    let ctx = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    assert_eq!(ctx.disclosable(), &DisclosableSet::All);
    assert!(ctx.disclosable().contains(&facet), "All contains anything");

    // The private-faceted claim and the facet entity itself are both admitted.
    let rtxn = vault.store.env.read_txn()?;
    assert!(ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?);
    assert!(ctx.admits(&vault.store, &rtxn, &facet, ENTITY_TYPE_FACET, None)?);
    Ok(())
}

/// T2 (V3 fold matrix): `public ∪ (∩ clearances of all non-owner present)`.
#[test]
fn disclosable_set_multi_party_folds() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet_a = test_id(0xD1);
    let facet_b = test_id(0xD2);
    let facet_pub = test_id(0xD3);
    put_facet(&vault, &facet_a);
    put_facet(&vault, &facet_b);
    put_facet(&vault, &facet_pub);
    vault.set_facet_exposure(&facet_pub, FacetExposure::Public, 100)?;

    let contact_a = test_id(0xD4);
    let contact_b = test_id(0xD5);
    let contact_c = test_id(0xD6);
    seed_contact(&vault, contact_a, "a@example.com");
    seed_contact(&vault, contact_b, "b@example.com");
    seed_contact(&vault, contact_c, "c@example.com");
    grant_clearance(&vault, &contact_a, vec![facet_a]);
    grant_clearance(&vault, &contact_b, vec![facet_b]);
    grant_clearance(&vault, &contact_c, vec![facet_a]);

    let resolve = |entries: Vec<Interlocutor>| -> Result<Vec<EntityId>> {
        let ctx = DisclosureContext::resolve(&vault, InterlocutorSet::without_owner(entries))?;
        Ok(disclosable_facets(&ctx))
    };

    // (e) single contact cleared for A -> {public ∪ A}, NOT All: the identity
    // element belongs to the EMPTY family only.
    let mut expected_single = vec![facet_a, facet_pub];
    expected_single.sort_unstable();
    assert_eq!(
        resolve(vec![known(contact_a, "a@example.com")])?,
        expected_single
    );

    // (a) disjoint clearances {A} ∩ {B} = ∅ -> public only.
    assert_eq!(
        resolve(vec![
            known(contact_a, "a@example.com"),
            known(contact_b, "b@example.com"),
        ])?,
        vec![facet_pub]
    );

    // (b) cleared + uncleared contact -> public only.
    let contact_none = test_id(0xD8);
    seed_contact(&vault, contact_none, "n@example.com");
    assert_eq!(
        resolve(vec![
            known(contact_a, "a@example.com"),
            known(contact_none, "n@example.com"),
        ])?,
        vec![facet_pub]
    );

    // (c) an UNKNOWN party (no contact_ref) is an ∅-clearance MEMBER of the
    // intersection, never an absence from it.
    assert_eq!(
        resolve(vec![
            known(contact_a, "a@example.com"),
            Interlocutor::unknown("guest", true),
        ])?,
        vec![facet_pub]
    );

    // (d) two contacts SHARING clearance {A} -> {public ∪ A}.
    assert_eq!(
        resolve(vec![
            known(contact_a, "a@example.com"),
            known(contact_c, "c@example.com"),
        ])?,
        expected_single
    );
    Ok(())
}

/// T3 (state defaults): born-private, and the exposure dial round-trips.
#[test]
fn facet_exposure_defaults_private() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xE3);
    put_facet(&vault, &facet);
    let contact = test_id(0xE4);
    seed_contact(&vault, contact, "a@example.com");

    let unknown_room = || InterlocutorSet::without_owner(vec![Interlocutor::unknown("g", true)]);
    let contact_room = || InterlocutorSet::without_owner(vec![known(contact, "a@example.com")]);

    // No exposure row at all: the engine default is PRIVATE.
    assert_eq!(vault.facet_exposure(&facet)?, None);
    let ctx = DisclosureContext::resolve(&vault, unknown_room())?;
    assert!(!ctx.disclosable().contains(&facet));

    // Public: in EVERY non-owner room, unknown-only included.
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    assert_eq!(
        vault.facet_exposure(&facet)?,
        Some(FacetExposureState {
            exposure: FacetExposure::Public,
            updated_at: 100,
        })
    );
    for set in [unknown_room(), contact_room()] {
        let ctx = DisclosureContext::resolve(&vault, set)?;
        assert!(ctx.disclosable().contains(&facet));
    }

    // Back to private: out again. Dial, not wall — one door both ways.
    vault.set_facet_exposure(&facet, FacetExposure::Private, 200)?;
    let ctx = DisclosureContext::resolve(&vault, unknown_room())?;
    assert!(!ctx.disclosable().contains(&facet));
    Ok(())
}

/// T4 (clearance lifecycle): Revoked and corrupt rows both narrow QUIETLY on
/// the enforcement path while the owner-facing read stays LOUD.
#[test]
fn clearance_revoked_and_corrupt_narrow() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xF1);
    put_facet(&vault, &facet);
    let contact = test_id(0xF2);
    seed_contact(&vault, contact, "a@example.com");
    let room = || InterlocutorSet::without_owner(vec![known(contact, "a@example.com")]);

    grant_clearance(&vault, &contact, vec![facet]);
    let ctx = DisclosureContext::resolve(&vault, room())?;
    assert_eq!(disclosable_facets(&ctx), vec![facet], "active grant holds");

    // Revoked contributes ∅ — the record is preserved, the grant is not.
    let mut revoked = FacetClearance::granted(vec![facet], 100)?;
    revoked.status = DisclosureScopeStatus::Revoked;
    revoked.updated_at = 200;
    vault.set_contact_facet_clearance(&contact, &revoked)?;
    assert_eq!(
        vault
            .contact_facet_clearance(&contact)?
            .expect("row")
            .status,
        DisclosureScopeStatus::Revoked
    );
    assert!(disclosable_facets(&DisclosureContext::resolve(&vault, room())?).is_empty());

    // A corrupt clearance row: quiet ∅ on resolve, LOUD on the owner read.
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &facet_clearance_meta_key(&contact),
            b"not a msgpack clearance body",
        )?;
        wtxn.commit()?;
    }
    assert_eq!(
        vault
            .contact_facet_clearance(&contact)
            .expect_err("owner read surfaces the corruption")
            .kind(),
        ErrorKind::InvalidFacetClearance
    );
    assert!(disclosable_facets(&DisclosureContext::resolve(&vault, room())?).is_empty());

    // Same pair for a corrupt EXPOSURE row: quiet not-public / loud read.
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    assert!(
        disclosable_facets(&DisclosureContext::resolve(&vault, room())?).contains(&facet),
        "public exposure reaches every room"
    );
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &facet_exposure_meta_key(&facet),
            b"not a msgpack exposure body",
        )?;
        wtxn.commit()?;
    }
    assert_eq!(
        vault
            .facet_exposure(&facet)
            .expect_err("owner read surfaces the corruption")
            .kind(),
        ErrorKind::InvalidFacetExposure
    );
    assert!(disclosable_facets(&DisclosureContext::resolve(&vault, room())?).is_empty());
    Ok(())
}

/// T5 (conjunct truth table): the facet rule composes as an AND with the
/// shipped tier and presence-scope conjuncts, in BOTH non-owner modes.
#[test]
fn admits_facet_conjunct_composes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let private_facet = test_id(0x31);
    put_facet(&vault, &private_facet);
    let contact = test_id(0x32);
    seed_contact(&vault, contact, "a@example.com");
    let faceted = test_id(0x33);
    let unfaceted = test_id(0x34);
    put_public_claim(&vault, &faceted, test_id(0x35));
    put_public_claim(&vault, &unfaceted, test_id(0x35));
    stamp_facet_of(&vault, &faceted, &private_facet);

    // BOTH claims are on the presence-scope allowlist, so the facet conjunct
    // is the only thing that can differ between them.
    let scope = DisclosureScope::task_scoped("room", vec![faceted, unfaceted, private_facet], 100)?;
    vault.set_counterparty_disclosure_scope(&contact, &scope)?;

    // Presence-scope also allowlists a claim that the room will NOT be able
    // to see, to prove the facet conjunct still binds after clearance lands.
    let off_scope = test_id(0x36);
    put_public_claim(&vault, &off_scope, test_id(0x37));
    stamp_facet_of(&vault, &off_scope, &private_facet);

    let both_rooms = |vault: &Vault| -> Result<Vec<DisclosureContext>> {
        Ok(vec![
            DisclosureContext::resolve(
                vault,
                InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
            )?,
            DisclosureContext::resolve(
                vault,
                InterlocutorSet::without_owner(vec![known(contact, "a@example.com")]),
            )?,
        ])
    };

    {
        let rooms = both_rooms(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        for ctx in &rooms {
            // Faceted claim: rejected even though it IS allowlisted — ∧, not ∨.
            assert!(!ctx.admits(&vault.store, &rtxn, &faceted, ENTITY_TYPE_CLAIM, None)?);
            // The FACET entity's own existence is non-disclosable.
            assert!(!ctx.admits(&vault.store, &rtxn, &private_facet, ENTITY_TYPE_FACET, None)?);
            // Unfaceted material behaves exactly as before the conjunct.
            assert!(ctx.admits(&vault.store, &rtxn, &unfaceted, ENTITY_TYPE_CLAIM, None)?);
        }
    }

    // Clear the facet for the only present party: both now pass the conjunct.
    grant_clearance(&vault, &contact, vec![private_facet]);
    let rooms = both_rooms(&vault)?;
    let rtxn = vault.store.env.read_txn()?;
    for ctx in &rooms {
        assert!(ctx.admits(&vault.store, &rtxn, &faceted, ENTITY_TYPE_CLAIM, None)?);
        assert!(ctx.admits(&vault.store, &rtxn, &private_facet, ENTITY_TYPE_FACET, None)?);
    }

    // Presence-scope still binds AFTER the facet conjunct passes: a cleared
    // facet does not widen the AbsenceClamp allowlist.
    let clamped = &rooms[1];
    assert_eq!(clamped.mode(), DisclosureMode::AbsenceClamp);
    assert!(!clamped.admits(&vault.store, &rtxn, &off_scope, ENTITY_TYPE_CLAIM, None)?);
    Ok(())
}

/// T6 (tier-first ordering): clearance can NEVER resurface Tier-A material.
#[test]
fn tier_a_wins_over_cleared_facet() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x41);
    put_facet(&vault, &facet);
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let contact = test_id(0x4A);
    seed_contact(&vault, contact, "a@example.com");
    grant_clearance(&vault, &contact, vec![facet]);

    let claim = test_id(0x43);
    put_public_claim(&vault, &claim, test_id(0x44));
    stamp_facet_of(&vault, &claim, &facet);
    vault.set_disclosure_tier_a(&claim, 100)?;
    let scope = DisclosureScope::task_scoped("room", vec![claim], 100)?;
    vault.set_counterparty_disclosure_scope(&contact, &scope)?;

    let rooms = [
        DisclosureContext::resolve(
            &vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )?,
        DisclosureContext::resolve(
            &vault,
            InterlocutorSet::without_owner(vec![known(contact, "a@example.com")]),
        )?,
    ];
    let rtxn = vault.store.env.read_txn()?;
    for ctx in &rooms {
        assert!(
            ctx.disclosable().contains(&facet),
            "the facet IS disclosable — only the tier rule rejects"
        );
        assert!(!ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?);
    }
    Ok(())
}

/// T7 (multi-stamp subset semantics): a claim stamped into {A, B} belongs to
/// BOTH masks; a room cleared only for A must not see it.
#[test]
fn multi_facet_stamp_requires_all_cleared() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet_a = test_id(0x51);
    let facet_b = test_id(0x52);
    put_facet(&vault, &facet_a);
    put_facet(&vault, &facet_b);
    let contact = test_id(0x53);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0x54);
    put_public_claim(&vault, &claim, test_id(0x55));
    stamp_facet_of(&vault, &claim, &facet_a);
    stamp_facet_of(&vault, &claim, &facet_b);

    let supervised = |vault: &Vault| {
        DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )
    };

    grant_clearance(&vault, &contact, vec![facet_a]);
    {
        let ctx = supervised(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "A-only clearance must not disclose B-linked material"
        );
    }

    grant_clearance(&vault, &contact, vec![facet_a, facet_b]);
    let ctx = supervised(&vault)?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?);
    Ok(())
}

/// T8 (dual-write): each owner write op produces the `vault_meta` enforcement
/// row AND the owner-visible claim mirror at the derived id, Tier-A
/// classified, CID-7 overwriting on re-set; validation failures write nothing.
#[test]
fn facet_exposure_and_clearance_dual_write() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x61);
    let other_facet = test_id(0x62);
    put_facet(&vault, &facet);
    put_facet(&vault, &other_facet);
    let contact = test_id(0x63);
    seed_contact(&vault, contact, "a@example.com");

    // ── exposure mirror ──
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let exposure_claim = facet_exposure_claim_id(&facet)?;
    let stored = vault
        .get_claim(&exposure_claim)?
        .expect("exposure claim mirror");
    assert_eq!(stored.predicate, PREDICATE_DISCLOSURE_FACET_EXPOSURE);
    assert_eq!(stored.subject, ClaimSubject::Entity(facet));
    assert_eq!(stored.value.as_str(), Some("public"));

    // ── clearance mirror ──
    grant_clearance(&vault, &contact, vec![facet]);
    let clearance_claim = facet_clearance_claim_id(&contact)?;
    let stored = vault
        .get_claim(&clearance_claim)?
        .expect("clearance claim mirror");
    assert_eq!(stored.predicate, PREDICATE_DISCLOSURE_CLEARANCE);
    assert_eq!(stored.subject, ClaimSubject::Entity(contact));
    assert_eq!(
        decode_facet_clearance_value(&stored.value)?.facets,
        vec![facet]
    );

    // Both mirrors are Tier A by predicate prefix — the facet-privacy
    // METADATA can never itself surface to a third party.
    {
        let rtxn = vault.store.env.read_txn()?;
        for id in [exposure_claim, clearance_claim] {
            assert_eq!(
                disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, None)?,
                DisclosureTier::TierA
            );
        }
    }

    // CID-7 overwrite: a re-set rewrites the SAME claim id, no second record.
    vault.set_facet_exposure(&facet, FacetExposure::Private, 200)?;
    assert_eq!(facet_exposure_claim_id(&facet)?, exposure_claim);
    assert_eq!(
        vault
            .get_claim(&exposure_claim)?
            .expect("mirror")
            .value
            .as_str(),
        Some("private")
    );

    // ── validation failures write NOTHING ──
    let turn = test_id(0x64);
    put_turn(&vault, &turn);
    let missing = test_id(0x65);

    // exposure: non-FACET target / absent target.
    assert_eq!(
        vault
            .set_facet_exposure(&turn, FacetExposure::Public, 1)
            .expect_err("non-FACET target")
            .kind(),
        ErrorKind::InvalidEntityType
    );
    assert_eq!(
        vault
            .set_facet_exposure(&missing, FacetExposure::Public, 1)
            .expect_err("absent target")
            .kind(),
        ErrorKind::EntityNotFound
    );
    assert_eq!(vault.facet_exposure(&turn)?, None, "nothing written");

    // clearance: non-contact subject, dangling facet, cap breach.
    let grant = FacetClearance::granted(vec![facet], 100)?;
    assert_eq!(
        vault
            .set_contact_facet_clearance(&turn, &grant)
            .expect_err("non-contact subject")
            .kind(),
        ErrorKind::InvalidEntityType
    );
    let dangling = FacetClearance::granted(vec![facet, missing], 100)?;
    assert_eq!(
        vault
            .set_contact_facet_clearance(&contact, &dangling)
            .expect_err("dangling facet")
            .kind(),
        ErrorKind::EntityNotFound
    );
    assert_eq!(
        vault
            .contact_facet_clearance(&contact)?
            .expect("prior grant survives the failed write")
            .facets,
        vec![facet]
    );
    // Cap breach: 257 distinct ids built directly (the sorted/deduped
    // invariant must hold so the CAP is the rule under test).
    let over_cap = FacetClearance {
        facets: (0..=u16::try_from(MAX_FACET_CLEARANCE_ENTRIES).expect("cap fits"))
            .map(|i| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&i.to_be_bytes());
                bytes[15] = 1;
                EntityId::from_bytes(bytes).expect("id")
            })
            .collect(),
        status: DisclosureScopeStatus::Active,
        created_at: 1,
        updated_at: 1,
    };
    assert_eq!(
        vault
            .set_contact_facet_clearance(&contact, &over_cap)
            .expect_err("cap breach")
            .kind(),
        ErrorKind::InvalidFacetClearance
    );
    assert_eq!(
        FacetClearance {
            facets: vec![facet],
            status: DisclosureScopeStatus::Active,
            created_at: 200,
            updated_at: 100,
        }
        .validate()
        .expect_err("updated_at before created_at")
        .kind(),
        ErrorKind::InvalidFacetClearance
    );
    Ok(())
}

/// The three new predicates join the containment door and the codecs
/// round-trip.
#[test]
fn facet_state_codecs_and_predicate_family() -> Result<()> {
    assert_eq!(DISCLOSURE_CLAIM_PREDICATES.len(), 6);
    for predicate in [
        PREDICATE_DISCLOSURE_FACET_EXPOSURE,
        PREDICATE_DISCLOSURE_CLEARANCE,
        PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION,
    ] {
        assert!(is_disclosure_claim_predicate(predicate));
        // Rule 4 already classifies every `disclosure.*` predicate Tier A.
        assert!(
            DISCLOSURE_TIER_A_PREDICATE_PREFIXES
                .iter()
                .any(|prefix| predicate.starts_with(prefix))
        );
    }

    let state = FacetExposureState {
        exposure: FacetExposure::Public,
        updated_at: 7,
    };
    let encoded = encode_facet_exposure_body(&state)?;
    assert_eq!(decode_facet_exposure_body(&encoded)?, state);
    let clearance = FacetClearance::granted(vec![test_id(0x02), test_id(0x01)], 3)?;
    assert_eq!(clearance.facets, vec![test_id(0x01), test_id(0x02)]);
    let encoded = encode_facet_clearance_body(&clearance)?;
    assert_eq!(decode_facet_clearance_body(&encoded)?, clearance);

    // Strict codecs: trailing bytes, unknown keys, and bad enum strings all
    // reject with the family's own variant.
    let mut trailing = encode_facet_exposure_body(&state)?;
    trailing.push(0x00);
    assert_eq!(
        decode_facet_exposure_body(&trailing)
            .expect_err("trailing bytes")
            .kind(),
        ErrorKind::InvalidFacetExposure
    );
    let mut clearance_trailing = encode_facet_clearance_body(&clearance)?;
    clearance_trailing.push(0x00);
    assert_eq!(
        decode_facet_clearance_body(&clearance_trailing)
            .expect_err("trailing bytes")
            .kind(),
        ErrorKind::InvalidFacetClearance
    );
    let consent = FacetReclassificationConsent {
        record: test_id(0x03),
        facet: test_id(0x04),
        consented_at: 11,
    };
    let encoded = encode_facet_reclassification_body(&consent)?;
    assert_eq!(decode_facet_reclassification_body(&encoded)?, consent);
    let mut consent_trailing = encode_facet_reclassification_body(&consent)?;
    consent_trailing.push(0x00);
    assert_eq!(
        decode_facet_reclassification_body(&consent_trailing)
            .expect_err("trailing bytes")
            .kind(),
        ErrorKind::InvalidFacetClearance
    );
    assert_eq!(FacetExposure::parse("public"), Some(FacetExposure::Public));
    assert_eq!(FacetExposure::parse("PUBLIC"), None);
    Ok(())
}

// ─── ONE-1646 reclassification-consent gate on FacetOf unstamping ───────────

/// P1 REGRESSION — privacy must not launder through DELETION.
///
/// `facet_conjunct_admits` admits a claim with NO `FacetOf` stamp as the
/// `{invariant}` (unfaceted) term, so tearing off a claim's last stamp MOVES IT
/// BETWEEN CLAMP CLASSES with no body edit. This pins the full sequence on the
/// real admission door: private-stamped claim is clamped → both generic delete
/// doors REFUSE with nothing written and the clamp intact → the dedicated
/// consent-bearing op performs the same removal AND the claim is admitted,
/// because the reclassification is on record rather than laundered.
#[test]
fn facet_of_delete_cannot_launder_a_private_claim_unfaceted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x81);
    put_facet(&vault, &facet);
    let contact = test_id(0x82);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0x83);
    put_public_claim(&vault, &claim, test_id(0x84));
    stamp_facet_of(&vault, &claim, &facet);

    let room = |vault: &Vault| {
        DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )
    };

    // Baseline: the stamp is doing real work — the claim is clamped out.
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "a claim stamped into a private facet must be clamped"
        );
    }

    // THE ATTACK: delete the stamp with no consent record. Both generic
    // edge-delete doors refuse, and neither leaves a torn row behind.
    let refusal = vault
        .delete_edge(&claim, EdgeKind::FacetOf, &facet)
        .expect_err("delete_edge must refuse the unstamp");
    assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    let batch_refusal = vault
        .batch()
        .delete_edge(&claim, EdgeKind::FacetOf, &facet)
        .commit()
        .expect_err("BatchOp::DeleteEdge must refuse the unstamp");
    assert_eq!(batch_refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "a refused unstamp writes nothing"
    );
    assert_eq!(
        vault.facet_reclassification_consent(&claim, &facet)?,
        None,
        "a refused unstamp mints no consent record either"
    );
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "the clamp still holds after the refused delete"
        );
    }

    // THE DOOR: the dedicated op removes the stamp and records the consent in
    // ONE commit. The facet is still PRIVATE — no public window was needed.
    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    assert!(!vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?);
    assert_eq!(vault.facet_exposure(&facet)?, None, "facet stayed private");
    let consent = vault
        .facet_reclassification_consent(&claim, &facet)?
        .expect("the unstamp recorded its consent");
    assert_eq!(
        consent,
        FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 200,
        }
    );
    // The owner-visible ledger mirror rides with it.
    assert!(
        vault
            .get_claim(&facet_reclassification_claim_id(&claim, &facet)?)?
            .is_some(),
        "the reclassification is on the owner's consent surface"
    );
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "post-consent the claim is admitted through the ledgered door, not laundered"
        );
    }
    Ok(())
}

/// P1 REGRESSION (fix-2) — a REVERSIBLE Public window must not authorize the
/// IRREVERSIBLE unstamp.
///
/// Fix-1 keyed this gate on the facet's CURRENT exposure, which the owner may
/// flip in both directions at will. That let the whole reclassification be
/// laundered through a window: widen the facet, tear the claim's last stamp,
/// narrow it back. The claim ends up unfaceted — admitted as the P7 invariant
/// term — under a FINAL policy that says the facet is private, and no surviving
/// state records that anything was reclassified.
///
/// The pin walks that exact three-step sequence and requires the unstamp to be
/// REFUSED mid-window; the claim stays clamped after the facet is narrowed
/// again. Then the consent-bearing door does it properly, and the same
/// narrow-again leaves an admitted claim WITH a consent record standing.
#[test]
fn public_window_cannot_launder_an_unstamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xC1);
    put_facet(&vault, &facet);
    let contact = test_id(0xC2);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0xC3);
    put_public_claim(&vault, &claim, test_id(0xC4));
    stamp_facet_of(&vault, &claim, &facet);

    let room = |vault: &Vault| {
        DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )
    };

    // ── THE WINDOW ATTACK, step by step ──
    // 1. Widen. This much is a legitimate, ledgered owner act.
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    // 2. Unstamp through a generic door while the window is open. REFUSED:
    //    exposure is reversible and authorizes nothing.
    for refusal in [
        vault
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .expect_err("delete_edge must refuse a public-window unstamp"),
        vault
            .batch()
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .commit()
            .expect_err("BatchOp::DeleteEdge must refuse a public-window unstamp"),
        vault
            .batch()
            .delete(&facet)
            .commit()
            .expect_err("the FACET hard delete must refuse it too"),
    ] {
        assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    }
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the stamp survived the whole window"
    );
    // 3. Narrow again — the step that would have completed the laundering.
    vault.set_facet_exposure(&facet, FacetExposure::Private, 300)?;
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "the claim is STILL clamped: the window laundered nothing"
        );
    }

    // ── The honest path: consent, on a facet that is private the whole time ──
    assert!(vault.unstamp_facet_of(&claim, &facet, 400)?);
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "the consented reclassification takes effect"
        );
    }
    assert!(
        vault
            .facet_reclassification_consent(&claim, &facet)?
            .is_some(),
        "and unlike the window, it leaves a record that cannot be wound back"
    );
    Ok(())
}

/// The consent record is APPEND-ONLY: re-consenting the same pair keeps the
/// FIRST `consented_at`, so a later call cannot restate when the owner
/// reclassified. A no-op unstamp (no such stamp) mints NO record at all —
/// otherwise it would be a free, pre-purchased authorization for a real unstamp
/// of the same pair later.
#[test]
fn reclassification_consent_is_append_only_and_never_pre_minted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xC6);
    put_facet(&vault, &facet);
    let claim = test_id(0xC7);
    put_public_claim(&vault, &claim, test_id(0xC8));

    // No stamp yet: the no-op unstamp must not leave an authorization behind.
    assert!(!vault.unstamp_facet_of(&claim, &facet, 100)?);
    assert_eq!(vault.facet_reclassification_consent(&claim, &facet)?, None);

    // A real stamp is therefore still gated afterwards.
    stamp_facet_of(&vault, &claim, &facet);
    assert_eq!(
        vault
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .expect_err("no pre-minted consent may exist")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );

    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    // Re-stamp and re-consent: the ORIGINAL timestamp stands.
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 900)?);
    assert_eq!(
        vault
            .facet_reclassification_consent(&claim, &facet)?
            .expect("consent")
            .consented_at,
        200,
        "re-consent must not restate when the owner first reclassified"
    );
    Ok(())
}

/// The FACET-entity hard delete is the same laundering path at its widest: the
/// deindex cascade tears EVERY inbound stamp at once. Each stamp needs its OWN
/// consent, and an unstamped facet stays freely deletable (nothing moves
/// between clamp classes, so there is nothing to consent to).
#[test]
fn facet_entity_hard_delete_requires_consent_for_every_stamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let stamped = test_id(0x86);
    let bare = test_id(0x87);
    put_facet(&vault, &stamped);
    put_facet(&vault, &bare);
    let first = test_id(0x88);
    let second = test_id(0x8D);
    put_public_claim(&vault, &first, test_id(0x89));
    put_public_claim(&vault, &second, test_id(0x8E));
    stamp_facet_of(&vault, &first, &stamped);
    stamp_facet_of(&vault, &second, &stamped);

    let refusal = vault
        .batch()
        .delete(&stamped)
        .commit()
        .expect_err("hard-deleting a stamped facet must refuse");
    assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    assert!(
        vault.edge_exists(&first, EdgeKind::FacetOf, &stamped)?,
        "the refusal is atomic — no stamp was torn"
    );
    assert!(
        vault.get_entity_type(&stamped)?.is_some(),
        "facet still exists"
    );

    // A facet NOTHING is stamped into carries no reclassification at all.
    vault.batch().delete(&bare).commit()?;
    assert!(vault.get_entity_type(&bare)?.is_none());

    // PARTIAL consent is not enough — the cascade would still reclassify the
    // second record without authorization.
    assert!(vault.unstamp_facet_of(&first, &stamped, 300)?);
    stamp_facet_of(&vault, &first, &stamped);
    assert_eq!(
        vault
            .batch()
            .delete(&stamped)
            .commit()
            .expect_err("one consent does not cover the other stamp")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );

    // With EVERY stamp consented, the facet goes.
    assert!(vault.unstamp_facet_of(&second, &stamped, 400)?);
    stamp_facet_of(&vault, &second, &stamped);
    vault.batch().delete(&stamped).commit()?;
    assert!(vault.get_entity_type(&stamped)?.is_none());
    assert!(!vault.edge_exists(&first, EdgeKind::FacetOf, &stamped)?);
    Ok(())
}

/// The gate is NARROW: it fires on `FacetOf` unstamps of PRIVATE facets and
/// nothing else. Other edge kinds between the same endpoints, and unstamps of
/// rows that do not exist, both pass — a gate that converted an idempotent
/// no-op into an error would be a wall, not a dial.
#[test]
fn unstamp_gate_ignores_other_kinds_and_absent_rows() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x8A);
    put_facet(&vault, &facet);
    let claim = test_id(0x8B);
    put_public_claim(&vault, &claim, test_id(0x8C));

    // No FacetOf row exists: deleting one removes nothing, so it widens
    // nothing. Both doors stay quiet.
    assert!(!vault.delete_edge(&claim, EdgeKind::FacetOf, &facet)?);
    vault
        .batch()
        .delete_edge(&claim, EdgeKind::FacetOf, &facet)
        .commit()?;

    // A DIFFERENT kind between the same endpoints is not a facet stamp and is
    // not read by the facet conjunct — deleting it is untouched by the gate.
    vault
        .batch()
        .edge(&claim, EdgeKind::HasFacet, &facet, 1.0)
        .commit()?;
    assert!(vault.delete_edge(&claim, EdgeKind::HasFacet, &facet)?);
    Ok(())
}

// ─── ONE-1646 fix leg 1: one snapshot per resolve, facet state erased ───────

/// P2-a REGRESSION — the resolver reads EVERY conjunct from the caller's
/// snapshot, never from transactions it opens itself.
///
/// The two halves of the disclosable set used to read from DIFFERENT
/// transactions: each clearance lookup opened its own, and the exposure scan
/// another. A write committing between them yielded a set that was never the
/// vault's state at any instant — the pre-write clearance mixed with the
/// post-write exposure (TOCTOU).
///
/// The pin makes that interleaving deterministic instead of racy. A snapshot is
/// taken, then BOTH families are rewritten and committed, then the resolver is
/// evaluated ON THE OLD SNAPSHOT. The two halves are wired to disagree under
/// the defect: `public_facet` is disclosable ONLY via exposure and
/// `cleared_facet` ONLY via clearance, and each is revoked by the commit. A
/// resolver honoring the snapshot returns BOTH; one that re-read either family
/// through a fresh transaction would drop that family's facet and return a mix
/// that never existed.
#[test]
fn resolve_reads_every_conjunct_from_one_snapshot() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let public_facet = test_id(0x91);
    let cleared_facet = test_id(0x93);
    put_facet(&vault, &public_facet);
    put_facet(&vault, &cleared_facet);
    let contact = test_id(0x92);
    seed_contact(&vault, contact, "a@example.com");
    // Disjoint sources: exposure carries one facet, clearance the other.
    vault.set_facet_exposure(&public_facet, FacetExposure::Public, 100)?;
    grant_clearance(&vault, &contact, vec![cleared_facet]);

    let set = InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]);
    let expected = {
        let mut both = vec![public_facet, cleared_facet];
        both.sort_unstable();
        both
    };
    match resolve_disclosable_set(&vault.store, &vault.store.env.read_txn()?, &set)? {
        DisclosableSet::Facets(facets) => assert_eq!(facets, expected),
        DisclosableSet::All => panic!("expected a resolved facet set"),
    }

    // The snapshot the resolve will run against, taken BEFORE the writes.
    let snapshot = vault.store.env.read_txn()?;

    // Both families change and COMMIT while that snapshot is held.
    vault.set_facet_exposure(&public_facet, FacetExposure::Private, 200)?;
    vault.set_contact_facet_clearance(
        &contact,
        &FacetClearance {
            facets: vec![cleared_facet],
            status: DisclosureScopeStatus::Revoked,
            created_at: 100,
            updated_at: 400,
        },
    )?;

    // Evaluated on the OLD snapshot, both halves report the OLD state. Losing
    // either one would mean that family had been re-read outside the snapshot.
    match resolve_disclosable_set(&vault.store, &snapshot, &set)? {
        DisclosableSet::Facets(facets) => assert_eq!(
            facets, expected,
            "every conjunct must come from the caller's snapshot, whole"
        ),
        DisclosableSet::All => panic!("expected a resolved facet set"),
    }
    drop(snapshot);

    // A resolve started AFTER the commits sees the new state, equally whole.
    assert!(
        disclosable_facets(&DisclosureContext::resolve(&vault, set)?).is_empty(),
        "a later resolve reports the post-commit state in full"
    );
    Ok(())
}

/// P2-b REGRESSION — facet-state rows are ERASED WITH THEIR ENTITY.
///
/// Hard-deleting a contact used to leave `contact.clearance.v1:<contact>` and
/// its `disclosure.clearance` mirror standing: a record naming a person who no
/// longer exists, still holding the facet ids they were cleared for. Symmetric
/// for a deleted facet's exposure row. Both families now go with the entity —
/// row AND mirror — and the resolver stops counting them.
#[test]
fn hard_delete_erases_contact_clearance_and_facet_exposure() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xB1);
    put_facet(&vault, &facet);
    let contact = test_id(0xB2);
    seed_contact(&vault, contact, "a@example.com");
    grant_clearance(&vault, &contact, vec![facet]);
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let clearance_mirror = facet_clearance_claim_id(&contact)?;
    let exposure_mirror = facet_exposure_claim_id(&facet)?;
    assert!(vault.get_claim(&clearance_mirror)?.is_some());
    assert!(vault.get_claim(&exposure_mirror)?.is_some());

    // ── contact erased: clearance row AND mirror go with it ──
    vault.batch().delete(&contact).commit()?;
    assert_eq!(
        vault.contact_facet_clearance(&contact)?,
        None,
        "the clearance row must not outlive the contact"
    );
    assert!(
        vault.get_claim(&clearance_mirror)?.is_none(),
        "the disclosure.clearance mirror must not outlive the contact"
    );

    // ── facet erased: exposure row AND mirror go with it ──
    vault.batch().delete(&facet).commit()?;
    assert_eq!(vault.facet_exposure(&facet)?, None);
    assert!(vault.get_claim(&exposure_mirror)?.is_none());

    // And the resolver no longer counts the dead facet as public: a room with
    // an unknown party present sees an empty disclosable set.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    assert!(
        disclosable_facets(&ctx).is_empty(),
        "an erased facet stops voting public in every future resolve"
    );
    Ok(())
}

/// Deleting the STAMPED RECORD is not laundering and is not gated: a claim
/// that no longer exists cannot be admitted to any room, so tearing its own
/// stamps on the way out moves nothing between clamp classes. Only unstamping
/// a SURVIVING record widens.
#[test]
fn hard_deleting_a_stamped_claim_is_not_gated() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xB4);
    put_facet(&vault, &facet);
    let claim = test_id(0xB5);
    put_public_claim(&vault, &claim, test_id(0xB6));
    stamp_facet_of(&vault, &claim, &facet);

    // The facet stays PRIVATE throughout — the gate would fire if it keyed on
    // the stamp rather than on who survives it.
    vault.batch().delete(&claim).commit()?;
    assert!(vault.get_claim(&claim)?.is_none());
    assert!(!vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?);
    assert_eq!(vault.facet_exposure(&facet)?, None, "facet still private");
    Ok(())
}

// ─── ONE-1646 fix leg 2: facet-id reuse must not resurrect old grants ───────

/// P2 REGRESSION — a deleted facet's id is REUSABLE, so no clearance may
/// outlive the facet it names.
///
/// Facet deletion removes only the facet's OWN exposure row and mirror;
/// `contact.clearance.v1` rows are keyed by CONTACT and merely CONTAIN facet
/// ids, so they survive untouched. Since entity ids are caller-chosen, the
/// attack is: delete facet F → mint a brand-new, unrelated FACET at the same id
/// F → stamp a fresh claim into it → every contact ever cleared for the OLD F
/// silently reads the new one. The contact is never deleted, so fix-1's
/// deletion test (which deleted the contact first) could not see this.
///
/// The gate blocks the delete while any clearance still names the facet, and
/// the pin proves the property that matters: after the delete is done the
/// LEGITIMATE way, a recreated facet at the same id inherits NOTHING.
#[test]
fn deleted_facet_id_cannot_resurrect_a_stale_clearance() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xD1);
    put_facet(&vault, &facet);
    let contact = test_id(0xD2);
    seed_contact(&vault, contact, "a@example.com");
    grant_clearance(&vault, &contact, vec![facet]);

    let room = |vault: &Vault| {
        DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )
    };

    // THE ATTACK, step 1: delete the facet while the grant stands. REFUSED,
    // and the error names the contact standing in the way.
    let refusal = vault
        .batch()
        .delete(&facet)
        .commit()
        .expect_err("a facet with a live clearance must not be deletable");
    assert_eq!(refusal.kind(), ErrorKind::FacetDeleteWithLiveClearance);
    assert!(
        matches!(
            refusal,
            Error::FacetDeleteWithLiveClearance { contact: named, .. } if named == contact
        ),
        "the refusal names the contact to narrow"
    );
    assert!(
        vault.get_entity_type(&facet)?.is_some(),
        "the refusal is atomic — the facet still exists"
    );

    // THE LEGITIMATE PATH: narrow the grant through its own owner door first.
    // (Revocation preserves the record but must ALSO stop blocking, because a
    // revoked grant contributes nothing to resolve either.)
    vault.set_contact_facet_clearance(&contact, &FacetClearance::granted(Vec::new(), 500)?)?;
    vault.batch().delete(&facet).commit()?;
    assert!(vault.get_entity_type(&facet)?.is_none());

    // THE PAYOFF: a brand-new facet minted at the SAME id, with a fresh claim
    // stamped into it, inherits NOTHING from the dead grant.
    put_facet(&vault, &facet);
    let claim = test_id(0xD3);
    put_public_claim(&vault, &claim, test_id(0xD4));
    stamp_facet_of(&vault, &claim, &facet);
    assert!(
        disclosable_facets(&room(&vault)?).is_empty(),
        "the recreated facet is disclosable to nobody"
    );
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "a claim in the RECREATED facet must not inherit the old contact's clearance"
        );
    }
    Ok(())
}

/// The clearance gate is keyed on the FACET ID appearing in a row, not on the
/// row existing: a clearance naming OTHER facets never blocks, and a row whose
/// body will not decode blocks everything (it cannot be proven to exclude the
/// id, and its bytes stay just as resurrectable as a valid row's).
#[test]
fn facet_delete_gate_is_keyed_on_the_named_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let cleared = test_id(0xD6);
    let unrelated = test_id(0xE2);
    put_facet(&vault, &cleared);
    put_facet(&vault, &unrelated);
    let contact = test_id(0xD8);
    seed_contact(&vault, contact, "a@example.com");
    grant_clearance(&vault, &contact, vec![cleared]);

    // A facet no clearance names is deletable with the grant still live.
    vault.batch().delete(&unrelated).commit()?;
    assert!(vault.get_entity_type(&unrelated)?.is_none());

    // Corrupt the clearance row: it can no longer be proven to exclude the
    // facet, so the delete fails CLOSED.
    vault.with_write_txn(|wtxn| {
        let mut key = b"contact.clearance.v1:".to_vec();
        key.extend_from_slice(contact.as_bytes());
        vault.store.vault_meta.put(wtxn, &key, b"\xc1garbage")?;
        Ok(())
    })?;
    assert_eq!(
        vault
            .batch()
            .delete(&cleared)
            .commit()
            .expect_err("an undecodable clearance row must not open the gate")
            .kind(),
        ErrorKind::FacetDeleteWithLiveClearance
    );
    Ok(())
}

/// Consent records are erased WITH EITHER named entity, on both sides of the
/// pair. A row outliving its record or its facet is a spendable authorization
/// waiting for a caller-chosen id to be reused: recreate the entity, re-stamp,
/// and the stale row would let the stamp come off with no fresh consent.
#[test]
fn reclassification_consent_is_erased_with_either_named_entity() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xDA);
    let other_facet = test_id(0xDB);
    put_facet(&vault, &facet);
    put_facet(&vault, &other_facet);
    let claim = test_id(0xDC);
    put_public_claim(&vault, &claim, test_id(0xDD));

    // ── record side: delete the stamped record ──
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 100)?);
    let mirror = facet_reclassification_claim_id(&claim, &facet)?;
    assert!(vault.get_claim(&mirror)?.is_some());
    vault.batch().delete(&claim).commit()?;
    assert_eq!(
        vault.facet_reclassification_consent(&claim, &facet)?,
        None,
        "the consent must not outlive the record it reclassified"
    );
    assert!(
        vault.get_claim(&mirror)?.is_none(),
        "its ledger mirror goes too"
    );

    // A record re-minted at the same id is gated afresh.
    put_public_claim(&vault, &claim, test_id(0xDE));
    stamp_facet_of(&vault, &claim, &facet);
    assert_eq!(
        vault
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .expect_err("the stale consent must not be spendable")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );

    // ── facet side: delete the facet the consent names ──
    assert!(!vault.unstamp_facet_of(&claim, &other_facet, 200)?);
    stamp_facet_of(&vault, &claim, &other_facet);
    assert!(vault.unstamp_facet_of(&claim, &other_facet, 300)?);
    vault.batch().delete(&other_facet).commit()?;
    assert_eq!(
        vault.facet_reclassification_consent(&claim, &other_facet)?,
        None,
        "the consent must not outlive the facet it named"
    );
    Ok(())
}
