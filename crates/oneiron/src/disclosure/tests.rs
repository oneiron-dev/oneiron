use super::*;
use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
use crate::interlocutor::Interlocutor;
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
    )
    .unwrap();
    body.scope = scope;
    body
}

fn sensitivity_scope(band: &str) -> Value {
    Value::Map(vec![(Value::from("sensitivity"), Value::from(band))])
}

// ─── Tier truth table (design §7 rules 1–5) ─────────────────────────────────

#[test]
fn tier_rule_2_governance_type_bytes_are_tier_a() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let rtxn = vault.store.env.read_txn()?;
    let id = test_id(0x13);
    assert_eq!(
        DISCLOSURE_TIER_A_ENTITY_TYPES,
        [72, 64, 65, 66, 67, 94, 81, 82, 83, 85]
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
    assert_eq!(
        disclosure_tier(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&control))?,
        DisclosureTier::TierB
    );
    assert!(ctx.admits(&vault.store, &rtxn, &id, ENTITY_TYPE_CLAIM, Some(&control))?);
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
    )
    .unwrap();
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
    scope_claim.value = disclosure_scope_body_value(
        &DisclosureScope::new(crate::federation::Scope::default(), "deny", 1).expect("clearance"),
    )
    .expect("body");
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
    let entities = [test_id(0x61), test_id(0x62), test_id(0x63)];
    for id in &entities {
        put_turn(&vault, id);
    }
    let check_admission = |ctx: &DisclosureContext, expected: [bool; 3]| -> Result<()> {
        let rtxn = vault.store.env.read_txn()?;
        for (id, allowed) in entities.iter().zip(expected) {
            assert_eq!(
                ctx.admits(&vault.store, &rtxn, id, ENTITY_TYPE_TURN, None)?,
                allowed,
            );
        }
        Ok(())
    };

    // OwnerAlone and Supervised do not require a contact clearance.
    let ctx = DisclosureContext::resolve(&vault, InterlocutorSet::owner_alone())?;
    assert_eq!(ctx.mode(), DisclosureMode::OwnerAlone);
    check_admission(&ctx, [true, true, true])?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::with_session_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::Supervised);
    check_admission(&ctx, [true, true, true])?;

    // Unknown party -> Scope bottom.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![Interlocutor::unknown("guest", true)]),
    )?;
    assert_eq!(ctx.mode(), DisclosureMode::AbsenceClamp);
    check_admission(&ctx, [false, false, false])?;

    // Contact without a scope row -> bottom.
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    check_admission(&ctx, [false, false, false])?;

    // Two live clearances meet on the sensitivity axis, not on entity ids.
    let scope_a = DisclosureScope::new(crate::federation::Scope::top(), "alpha", 100)?;
    let mut public_only = crate::federation::Scope::top();
    public_only.sensitivity =
        crate::federation::SensitivityCeiling::AtMost(crate::federation::Sensitivity::Public);
    let scope_b = DisclosureScope::new(public_only, "beta", 100)?;
    vault.set_counterparty_disclosure_scope(&contact_a, &scope_a)?;
    vault.set_counterparty_disclosure_scope(&contact_b, &scope_b)?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_a, "a@example.com")]),
    )?;
    check_admission(&ctx, [true, true, true])?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![
            known(contact_a, "a@example.com"),
            known(contact_b, "b@example.com"),
        ]),
    )?;
    check_admission(&ctx, [false, false, false])?;

    // A revoked scope contributes bottom.
    let mut revoked = scope_b;
    revoked.status = DisclosureScopeStatus::Revoked;
    revoked.updated_at = 200;
    vault.set_counterparty_disclosure_scope(&contact_b, &revoked)?;
    let ctx = DisclosureContext::resolve(
        &vault,
        InterlocutorSet::without_owner(vec![known(contact_b, "b@example.com")]),
    )?;
    check_admission(&ctx, [false, false, false])?;
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
        )?;
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
    )?;
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
    )?;
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
    // A valid Scope admits the party...
    let scope = DisclosureScope::new(crate::federation::Scope::top(), "party", 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    // ...then the enforcement row is corrupted in place (adversarial or
    // bit-rotted vault_meta bytes).
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &DISCLOSURE_SCOPES.key_bytes(&contact_id),
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
    // previously-admitted party is no longer admitted.
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
