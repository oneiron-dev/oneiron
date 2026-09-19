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
fn tier_rule_2_governance_type_bytes_are_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x13);
    assert_eq!(
        DISCLOSURE_TIER_A_ENTITY_TYPES,
        [64, 66, 67, 68, 73, 71, 79, 80, 81, 82]
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
    for band in ["public", "private"] {
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
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::unknown("guest", true)]),
    )?;
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x15);

    for predicate in [
        "affect.trigger",
        "disclosure.topic",
        "counterparty_contact.status",
        "channel_identity.state",
        "voice_print.status",
    ] {
        let body = claim_with_scope(predicate, Some(sensitivity_scope("public")));
        assert_eq!(
            disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?,
            DisclosureTier::TierA,
            "predicate {predicate} must be Tier A"
        );
        assert!(!ctx.admits(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&body))?);
    }
    // Public sensitivity isolates rule 4 from the unstamped rule-3 floor.
    let control = claim_with_scope("profile.hobby", Some(sensitivity_scope("public")));
    // Admission needs stored exposure, not a caller-supplied body for an absent id.
    drop(rtxn);
    vault.put_entity(
        &id,
        ENTITY_TYPE_CLAIM,
        TimeRange { start: 1, end: 1 },
        1,
        &encode_claim_body(&control)?,
    )?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&control))?,
        DisclosureTier::TierB
    );
    assert!(ctx.admits(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&control))?);
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

    test_support::clear_tier(&vault, &marked, 200)?;
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
    for scope in [
        ScopeCeiling::top(),
        ScopeCeiling::bottom(),
        ScopeCeiling::public(),
        test_support::projects(vec![test_id(1), test_id(2)]),
    ] {
        let bytes = encode_scope_ceiling_body(&scope)?;
        assert_eq!(decode_scope_ceiling_body(&bytes)?, scope);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_scope_ceiling_body(&trailing).is_err());
        for key in SCOPE_BODY_KEYS {
            let Value::Map(entries) = scope_ceiling_body_value(&scope) else {
                unreachable!()
            };
            let missing = Value::Map(
                entries
                    .iter()
                    .filter(|(name, _)| name.as_str() != Some(key))
                    .cloned()
                    .collect(),
            );
            let mut duplicate = entries.clone();
            duplicate.push(
                entries
                    .iter()
                    .find(|(name, _)| name.as_str() == Some(key))
                    .unwrap()
                    .clone(),
            );
            for bad in [missing, Value::Map(duplicate)] {
                let mut bytes = Vec::new();
                rmpv::encode::write_value(&mut bytes, &bad).unwrap();
                assert!(decode_scope_ceiling_body(&bytes).is_err());
            }
        }
    }
    let position = ScopePosition {
        worlds: ScopeIdAxis::Some(vec![EntityId::scope_base_world()]),
        facets: ScopeIdAxis::Bottom,
        kinds: ScopeKindAxis::Some(vec![ENTITY_TYPE_TURN]),
        projects: ScopeIdAxis::All,
        sensitivity: 1,
    };
    assert_eq!(
        decode_scope_position_body(&encode_scope_position_body(&position)?)?,
        position
    );
    Ok(())
}

#[test]
fn scope_validation_enforces_pinned_bounds() {
    for axis in [
        ScopeIdAxis::Some(vec![]),
        ScopeIdAxis::Some(vec![test_id(1), test_id(1)]),
        ScopeIdAxis::Some(vec![test_id(2), test_id(1)]),
    ] {
        assert!(
            encode_scope_ceiling_body(&ScopeCeiling {
                worlds: axis,
                ..ScopeCeiling::top()
            })
            .is_err()
        );
    }
    for kinds in [vec![], vec![3, 3], vec![4, 3]] {
        assert!(
            encode_scope_ceiling_body(&ScopeCeiling {
                kinds: ScopeKindAxis::Some(kinds),
                ..ScopeCeiling::top()
            })
            .is_err()
        );
    }
    assert!(
        encode_scope_ceiling_body(&ScopeCeiling {
            sensitivity: 4,
            ..ScopeCeiling::top()
        })
        .is_err()
    );
    assert!(decode_scope_ceiling_body(b"").is_err());
}

#[test]
fn scope_meet_keeps_disjoint_worlds_bottom_and_kind_sets_open_ended() {
    let a = ScopeCeiling {
        worlds: ScopeIdAxis::Some(vec![test_id(1)]),
        kinds: ScopeKindAxis::Some(vec![0, 107, 200]),
        ..ScopeCeiling::top()
    };
    let b = ScopeCeiling {
        worlds: ScopeIdAxis::Some(vec![test_id(2)]),
        kinds: ScopeKindAxis::Some(vec![107, 200, 250]),
        ..ScopeCeiling::top()
    };
    assert_eq!(a.meet(&b), b.meet(&a));
    assert_eq!(a.meet(&ScopeCeiling::top()), a);
    assert_eq!(a.meet(&ScopeCeiling::bottom()), ScopeCeiling::bottom());
    assert_eq!(a.meet(&b).worlds, ScopeIdAxis::Bottom);
    assert_eq!(a.meet(&b).kinds, ScopeKindAxis::Some(vec![107, 200]));
}

#[test]
fn scope_dual_write_requires_signed_intent_and_preserves_atomic_mirror() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x31);
    seed_contact(&vault, contact, "contact");
    let scope = test_support::projects(vec![test_id(0x41)]);
    assert!(
        vault
            .set_counterparty_disclosure_scope(&contact, &scope)
            .is_err()
    );
    let authorization = test_support::authorization(&vault, &contact, &scope)?;
    let mut forged = authorization.clone();
    forged.epoch += 1;
    assert!(
        vault
            .authorize_counterparty_disclosure_scope(&contact, &scope, &forged)
            .is_err()
    );
    let wrong_scope = ScopeCeiling::top();
    assert!(
        vault
            .authorize_counterparty_disclosure_scope(&contact, &wrong_scope, &authorization)
            .is_err()
    );
    assert_eq!(vault.counterparty_disclosure_scope(&contact)?, None);
    vault.authorize_counterparty_disclosure_scope(&contact, &scope, &authorization)?;
    assert_eq!(
        vault.counterparty_disclosure_scope(&contact)?,
        Some(scope.clone())
    );
    assert_eq!(
        vault
            .get_claim(&disclosure_scope_claim_id(&contact)?)?
            .unwrap()
            .value,
        scope_ceiling_body_value(&scope)
    );
    assert!(
        vault
            .authorize_counterparty_disclosure_scope(&contact, &scope, &authorization)
            .is_err()
    );
    vault.set_counterparty_disclosure_scope(&contact, &ScopeCeiling::bottom())?;
    assert!(
        vault
            .authorize_counterparty_disclosure_scope(&contact, &scope, &authorization)
            .is_err()
    );
    assert_eq!(
        vault.counterparty_disclosure_scope(&contact)?,
        Some(ScopeCeiling::bottom())
    );
    test_support::authorize(&vault, &contact, &ScopeCeiling::top())?;
    assert_eq!(
        vault
            .get_claim(&disclosure_scope_claim_id(&contact)?)?
            .unwrap()
            .value,
        scope_ceiling_body_value(&ScopeCeiling::top())
    );
    Ok(())
}

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
    scope_claim.value = scope_ceiling_body_value(&ScopeCeiling::bottom());
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
    let a = test_id(0x31);
    let b = test_id(0x32);
    seed_contact(&vault, a, "a");
    seed_contact(&vault, b, "b");
    assert_eq!(
        DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?.disclosable_set(),
        &ScopeCeiling::top()
    );
    assert_eq!(
        DisclosureContext::resolve(&vault, InterlocutorSet::without_owner(vec![]))?
            .disclosable_set(),
        &ScopeCeiling::top()
    );
    test_support::authorize(&vault, &a, &test_support::projects(vec![test_id(1)]))?;
    test_support::authorize(&vault, &b, &test_support::projects(vec![test_id(2)]))?;
    let disjoint = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(a, "a"), known(b, "b")]),
    )?;
    assert_eq!(disjoint.disclosable_set().projects, ScopeIdAxis::Bottom);
    for roster in [
        vec![known(a, "a"), Interlocutor::unknown("unidentified", false)],
        vec![known(test_id(0x33), "missing")],
    ] {
        assert_eq!(
            DisclosureContext::resolve(&vault, InterlocutorSet::without_owner(roster))?
                .disclosable_set(),
            &ScopeCeiling::bottom()
        );
    }
    vault.clear_counterparty_disclosure_scope(&a, 100)?;
    assert_eq!(
        DisclosureContext::resolve(&vault, InterlocutorSet::without_owner(vec![known(a, "a")]))?
            .disclosable_set(),
        &ScopeCeiling::bottom()
    );
    Ok(())
}

#[test]
fn admits_truth_table_checks_tier_before_scope() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x31);
    seed_contact(&vault, contact, "a");
    test_support::authorize(&vault, &contact, &ScopeCeiling::top())?;
    let id = test_id(0x32);
    put_turn(&vault, &id);
    vault.set_disclosure_tier_a(&id, 1)?;
    for set in [
        InterlocutorSet::without_owner(vec![known(contact, "a")]),
        InterlocutorSet::with_session_owner(vec![known(contact, "a")]),
    ] {
        let ctx = DisclosureContext::resolve(&vault, set)?;
        let txn = vault.store.env.read_txn()?;
        assert!(!ctx.admits(&vault.store, &txn, &id, ENTITY_TYPE_TURN, None)?);
    }
    let owner = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    let txn = vault.store.env.read_txn()?;
    assert!(owner.admits(&vault.store, &txn, &id, ENTITY_TYPE_TURN, None)?);
    Ok(())
}

#[test]
fn missing_position_axes_are_unknown_not_public_or_bottom() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0x40);
    put_turn(&vault, &id);
    let txn = vault.store.env.read_txn()?;
    let position = record_scope_position(&vault.store, &txn, &id, ENTITY_TYPE_TURN, None)?;
    assert!(!ScopeCeiling::public().admits(&position));
    assert!(!ScopeCeiling::bottom().admits(&position));
    assert!(!test_support::projects(vec![test_id(0x41)]).admits(&position));
    assert_eq!(position.sensitivity, 2);
    Ok(())
}

#[test]
fn presence_discretion_notice_matches_pinned_template() {
    let set = InterlocutorSet::with_session_owner(vec![
        known(test_id(0x91), "Kenji"),
        Interlocutor::unknown("unknown speaker 2", true),
    ]);
    let notice = presence_discretion_notice(&set);
    assert!(notice.contains("Kenji (known_contact"));
    assert!(notice.contains("unknown speaker 2 (unknown)"));
    assert!(
        !notice.contains("owner (owner)"),
        "the Owner entry never appears under Others present"
    );

    // Verify discretion through admission, not the wording of the instruction.
    let (_tmp, vault) = temp_vault();
    let ctx = DisclosureContext::resolve(&vault, set).expect("resolve supervised context");
    assert_eq!(ctx.mode(), DisclosureMode::Supervised);
    assert!(ctx.assembly(0).notice.is_some());
    let id = test_id(0x15);
    let public = claim_with_scope("profile.hobby", Some(sensitivity_scope("public")));
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_claim_body(&public).expect("body"),
        )
        .expect("stored public claim");
    let rtxn = vault.store.env.read_txn().expect("read transaction");
    let protected = claim_with_scope("affect.trigger", Some(sensitivity_scope("public")));
    assert!(
        !ctx.admits(
            &vault.store,
            &rtxn,
            &id,
            ENTITY_TYPE_CLAIM,
            Some(&protected)
        )
        .expect("protected admission")
    );
    let public = claim_with_scope("profile.hobby", Some(sensitivity_scope("public")));
    assert!(
        ctx.admits(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&public))
            .expect("public admission")
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
    let notice = assembly
        .notice
        .as_deref()
        .expect("supervised presence notice");
    assert!(notice.contains("kenji@example.com (known_contact"));
    assert!(!notice.contains("owner (owner)"));
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

    test_support::clear_tier(&vault, &marked, 200)?;

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
    let scope = test_support::projects(vec![party]);
    test_support::authorize(&vault, &contact_id, &scope)?;
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

    // Resolution fails CLOSED without propagating the corruption error.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_id, "kenji@example.com")]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::AbsenceClamp);

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

fn put_positioned_claim(
    vault: &Vault,
    id: EntityId,
    ceiling_axes: &ScopeCeiling,
    evidence: Option<Value>,
    invariant: bool,
) -> Result<()> {
    if vault.get_entity_type(&test_id(0x77))?.is_none() {
        put_turn(vault, &test_id(0x77));
    }
    let mut body = claim_with_scope(
        "profile.scope_test",
        Some(Value::Map(vec![
            (
                Value::from(RECORD_SCOPE_POSITION_KEY),
                scope_ceiling_body_value(ceiling_axes),
            ),
            (
                Value::from("sensitivity"),
                Value::from(ceiling_axes.sensitivity),
            ),
        ])),
    );
    if invariant && let Some(Value::Map(ref mut entries)) = body.scope {
        entries.push((
            Value::from(CLAIM_SCOPE_INVARIANT_KEY),
            Value::from("invariant"),
        ));
    }
    body.evidence = evidence;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_claim_body(&body)?,
        )
        .text(&id, &[("body", "scopeprobe")])
        .commit()?;
    Ok(())
}

#[test]
fn assembled_scope_union_keeps_public_floor_separate_from_private_axes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let a = test_id(0x31);
    let b = test_id(0x32);
    seed_contact(&vault, a, "a");
    seed_contact(&vault, b, "b");
    let allowed = ScopeCeiling {
        worlds: ScopeIdAxis::Some(vec![EntityId::scope_base_world()]),
        facets: ScopeIdAxis::Some(vec![test_id(0x60)]),
        kinds: ScopeKindAxis::Some(vec![ENTITY_TYPE_CLAIM]),
        projects: ScopeIdAxis::Some(vec![test_id(0x61)]),
        sensitivity: 1,
    };
    test_support::authorize(&vault, &a, &allowed)?;
    let private_ok = test_id(0x40);
    put_positioned_claim(&vault, private_ok, &allowed, None, false)?;
    let outside = ScopeCeiling {
        worlds: ScopeIdAxis::Some(vec![test_id(0x62)]),
        facets: ScopeIdAxis::Some(vec![test_id(0x63)]),
        projects: ScopeIdAxis::Some(vec![test_id(0x64)]),
        ..allowed
    };
    let private_outside = test_id(0x41);
    put_positioned_claim(&vault, private_outside, &outside, None, false)?;
    let public_outside = test_id(0x44);
    put_positioned_claim(
        &vault,
        public_outside,
        &ScopeCeiling {
            sensitivity: 0,
            ..outside.clone()
        },
        None,
        false,
    )?;
    let unstamped = test_id(0x43);
    let body = claim_with_scope("profile.scope_test", None);
    vault
        .batch()
        .put(
            &unstamped,
            ENTITY_TYPE_CLAIM,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_claim_body(&body)?,
        )
        .text(&unstamped, &[("body", "scopeprobe")])
        .commit()?;
    for owner_present in [false, true] {
        let parties = vec![known(a, "a")];
        let roster = if owner_present {
            InterlocutorSet::with_session_owner(parties)
        } else {
            InterlocutorSet::without_owner(parties)
        };
        let pack = vault
            .context_pack()
            .search_text("scopeprobe", 20)
            .disclosure_context(DisclosureContext::resolve(&vault, roster)?)
            .run()?;
        let ids: Vec<_> = pack.results.iter().map(|row| row.id).collect();
        assert!(ids.contains(&private_ok));
        assert!(ids.contains(&public_outside));
        assert!(!ids.contains(&private_outside));
        assert!(!ids.contains(&unstamped));
    }
    test_support::authorize(&vault, &b, &outside)?;
    for parties in [
        vec![known(a, "a"), known(b, "b")],
        vec![known(a, "a"), Interlocutor::unknown("unknown", false)],
        vec![known(test_id(0x33), "missing")],
    ] {
        let ctx = DisclosureContext::resolve(&vault, InterlocutorSet::without_owner(parties))?;
        let pack = vault
            .context_pack()
            .search_text("scopeprobe", 20)
            .disclosure_context(ctx)
            .run()?;
        assert_eq!(
            pack.results.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![public_outside]
        );
    }
    let owner = vault
        .context_pack()
        .search_text("scopeprobe", 20)
        .disclosure_context(DisclosureContext::resolve(
            &vault,
            InterlocutorSet::owner_alone(),
        )?)
        .run()?;
    for id in [private_ok, private_outside, public_outside, unstamped] {
        assert!(owner.results.iter().any(|row| row.id == id));
    }
    Ok(())
}

#[test]
fn private_source_and_missing_links_cannot_become_invariant() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let source = test_id(0x50);
    put_turn(&vault, &source);
    let claim = test_id(0x51);
    let public = ScopeCeiling::public();
    let evidence = Value::Map(vec![(
        Value::from("refs"),
        Value::Array(vec![Value::Binary(source.as_bytes().to_vec())]),
    )]);
    put_positioned_claim(&vault, claim, &public, Some(evidence), true)?;
    let no_source = test_id(0x52);
    put_positioned_claim(&vault, no_source, &public, None, true)?;
    let txn = vault.store.env.read_txn()?;
    assert!(!claim_is_invariant(
        &vault.store,
        &txn,
        &claim,
        ENTITY_TYPE_CLAIM,
        None
    )?);
    assert!(!claim_is_invariant(
        &vault.store,
        &txn,
        &no_source,
        ENTITY_TYPE_CLAIM,
        None
    )?);
    assert!(!scope_admits_record(
        &vault.store,
        &txn,
        &ScopeCeiling::bottom(),
        &claim,
        ENTITY_TYPE_CLAIM,
        None
    )?);
    drop(txn);
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    let pack = vault
        .context_pack()
        .search_text("scopeprobe", 20)
        .disclosure_context(ctx)
        .run()?;
    assert!(!pack.results.iter().any(|row| row.id == claim));
    // An explicit public source is positive evidence, not absence.
    let public_source = test_id(0x53);
    let public_claim = test_id(0x54);
    vault.put_entity(
        &public_source,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(
            &serde_json::json!({"txt":"public source","sensitivity":"public"}),
        )
        .unwrap(),
    )?;
    let public_evidence = Value::Map(vec![(
        Value::from("refs"),
        Value::Array(vec![Value::Binary(public_source.as_bytes().to_vec())]),
    )]);
    put_positioned_claim(&vault, public_claim, &public, Some(public_evidence), true)?;
    let txn = vault.store.env.read_txn()?;
    assert!(claim_is_invariant(
        &vault.store,
        &txn,
        &public_claim,
        ENTITY_TYPE_CLAIM,
        None
    )?);
    Ok(())
}

#[test]
fn roster_widening_aborts_inflight_generation_and_redacts_transcript_turns() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let private = test_id(0x50);
    put_turn(&vault, &private);
    let public = test_id(0x51);
    vault.put_entity(
        &public,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &rmp_serde::to_vec_named(&serde_json::json!({"txt":"public turn","sensitivity":"public"}))
            .unwrap(),
    )?;
    let session = DisclosureSession::new(&vault, InterlocutorSet::owner_alone())?;
    let old = session.begin_generation()?;
    assert_eq!(
        old.transcript_records(&vault, &[private, public])?,
        vec![private, public]
    );
    session.update_roster(
        &vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::unknown("arrival", false)]),
    )?;
    let mut released = false;
    assert!(old.publish(&vault, || released = true).is_err());
    assert!(!released);
    assert!(old.transcript_records(&vault, &[private, public]).is_err());
    assert!(
        vault
            .context_pack()
            .search_text("missing", 10)
            .disclosure_context(old.context().clone())
            .run()
            .is_err()
    );
    let current = session.begin_generation()?;
    assert_eq!(
        current.transcript_records(&vault, &[private, public])?,
        vec![public]
    );
    current.publish(&vault, || released = true)?;
    assert!(released);
    Ok(())
}

#[test]
fn public_restamp_requires_exact_owner_intent_not_a_raw_rewrite() -> Result<()> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    let (_tmp, vault) = temp_vault();
    let turn = test_id(0x55);
    put_turn(&vault, &turn);
    let body =
        rmp_serde::to_vec_named(&serde_json::json!({"txt":"changed turn","sensitivity":"public"}))
            .unwrap();
    vault.put_entity(
        &turn,
        ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    let session = DisclosureSession::new(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    assert!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[turn])?
            .is_empty()
    );
    let position = ScopePosition {
        worlds: ScopeIdAxis::All,
        facets: ScopeIdAxis::All,
        projects: ScopeIdAxis::All,
        kinds: ScopeKindAxis::Some(vec![ENTITY_TYPE_TURN]),
        sensitivity: 0,
    };
    let mut authorization = test_support::authorization(&vault, &turn, &ScopeCeiling::public())?;
    assert!(
        vault
            .restamp_disclosure_position(&turn, &position, &authorization)
            .is_err()
    );
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    authorization.signature.signature = signing
        .sign(&authorization.restamp_transcript(&turn, &position, Sha256::digest(&body).into())?)
        .to_bytes()
        .to_vec();
    vault.restamp_disclosure_position(&turn, &position, &authorization)?;
    assert_eq!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[turn])?,
        vec![turn]
    );
    assert!(
        vault
            .restamp_disclosure_position(&turn, &position, &authorization)
            .is_err()
    );
    Ok(())
}

#[test]
fn unconfirmed_departure_never_widens_the_next_generation() -> Result<()> {
    use ed25519_dalek::Signer;
    let (_tmp, vault) = temp_vault();
    let private = test_id(0x56);
    put_turn(&vault, &private);
    let session = DisclosureSession::new(
        &vault,
        InterlocutorSet::with_session_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    session.update_roster(&vault, InterlocutorSet::owner_alone())?;
    assert!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[private])?
            .is_empty()
    );
    let roster = InterlocutorSet::owner_alone();
    let mut authorization = test_support::authorization(&vault, &private, &ScopeCeiling::top())?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    authorization.signature.signature = signing
        .sign(&session.roster_change_transcript(&roster, &authorization)?)
        .to_bytes()
        .to_vec();
    session.confirm_roster(&vault, roster, &authorization)?;
    assert_eq!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[private])?,
        vec![private]
    );
    Ok(())
}

#[test]
fn generation_publish_rechecks_clearance_revocation_without_host_refresh() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x31);
    seed_contact(&vault, contact, "a");
    test_support::authorize(&vault, &contact, &ScopeCeiling::top())?;
    let private = test_id(0x57);
    put_turn(&vault, &private);
    let session = DisclosureSession::new(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact, "a")]),
    )?;
    let generation = session.begin_generation()?;
    assert_eq!(
        generation.transcript_records(&vault, &[private])?,
        vec![private]
    );
    vault.clear_counterparty_disclosure_scope(&contact, 100)?;
    let mut released = false;
    assert!(generation.publish(&vault, || released = true).is_err());
    assert!(!released);
    Ok(())
}

#[test]
fn transcript_messages_inherit_their_live_turn_position() -> Result<()> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0x65);
    let room = test_id(0x66);
    let turn = test_id(0x67);
    let message = test_id(0x68);
    vault.put_entity(
        &actor,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &[0x80],
    )?;
    vault
        .memory(actor, crate::EdgeActorClass::Human)
        .witness(&crate::WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            occurred_at: 1,
            messages: vec![crate::WitnessMessage {
                id: Some(message.to_hex()),
                author: crate::WitnessAuthor::User,
                message_type: "dialogue".into(),
                content: "a witnessed message".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .expect("witnessed transcript");
    let session = DisclosureSession::new(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", false)]),
    )?;
    assert!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[turn, message])?
            .is_empty()
    );
    let position = ScopePosition {
        worlds: ScopeIdAxis::All,
        facets: ScopeIdAxis::All,
        projects: ScopeIdAxis::All,
        kinds: ScopeKindAxis::Some(vec![ENTITY_TYPE_TURN]),
        sensitivity: 0,
    };
    let raw = vault.get_raw(&turn)?.expect("turn");
    let mut authorization = test_support::authorization(&vault, &turn, &ScopeCeiling::public())?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    authorization.signature.signature = signing
        .sign(&authorization.restamp_transcript(
            &turn,
            &position,
            Sha256::digest(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]).into(),
        )?)
        .to_bytes()
        .to_vec();
    vault.restamp_disclosure_position(&turn, &position, &authorization)?;
    assert_eq!(
        session
            .begin_generation()?
            .transcript_records(&vault, &[turn, message])?,
        vec![turn, message]
    );
    Ok(())
}

#[test]
fn base_world_scope_codec_roundtrips_without_making_reserved_entity_ids_public() -> Result<()> {
    let mut ceiling = ScopeCeiling::top();
    ceiling.worlds = ScopeIdAxis::Some(vec![EntityId::scope_base_world()]);
    let encoded = encode_scope_ceiling_body(&ceiling)?;
    assert_eq!(decode_scope_ceiling_body(&encoded)?, ceiling);
    assert!(EntityId::from_hex("00000000000000000000000000000000").is_err());
    ceiling.facets = ceiling.worlds.clone();
    assert!(encode_scope_ceiling_body(&ceiling).is_err());
    let mut forged =
        rmpv::decode::read_value(&mut std::io::Cursor::new(&encoded)).expect("scope value");
    if let rmpv::Value::Map(entries) = &mut forged {
        let base = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("worlds"))
            .unwrap()
            .1
            .clone();
        entries
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some("projects"))
            .unwrap()
            .1 = base;
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &forged).expect("encode forged axis");
    assert!(decode_scope_ceiling_body(&bytes).is_err());
    Ok(())
}
