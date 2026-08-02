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

/// Presence of the permanent `dt:{entity_hex}` local hard-delete marker — the
/// delete path's own durable "this id was hard-deleted" truth.
fn hard_delete_marker_exists(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .sync_state
        .get(&rtxn, &crate::deletion::local_hard_delete_key(id))?
        .is_some())
}

/// Whether ANY `pt:{window}:{entity_hex}` crash marker names `id`. Scanned by
/// prefix rather than computed, so the check does not depend on guessing which
/// window the delete would have addressed.
fn pending_tombstone_exists(vault: &Vault, id: &EntityId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let suffix = id.to_hex();
    for row in vault
        .store
        .sync_state
        .prefix_iter(&rtxn, crate::deletion::PENDING_TOMBSTONE_PREFIX)?
    {
        let (key, _value) = row?;
        if key.ends_with(&suffix) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the CRDT window doc carries a tombstone for `id` — the truth a
/// refused delete must never publish to other devices.
#[cfg(feature = "sync")]
fn crdt_tombstone_exists(vault: &Vault, id: &EntityId, learned_at: u64) -> Result<bool> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::types::WindowKey;

    let window_key = WindowKey::from_timestamp(learned_at);
    let doc = match crate::sync::window::load_window_from_state(vault, "local", &window_key) {
        Ok(doc) => doc,
        Err(Error::WindowNotFound { .. }) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(map_contains_binary(
        &doc.get_map("tombstones"),
        id.to_hex().as_str(),
    ))
}

/// Whether ANY persisted window carries a CRDT tombstone for `id`.
///
/// [`crdt_tombstone_exists`] must be told which window to look in, and callers
/// derive that from a clock reading of their own. That derivation is only sound
/// when the reading names the same `YYYY-MM` the delete used: a call that
/// crosses a UTC month boundary publishes into the PRIOR window while a reading
/// taken afterwards names the next one, and the check then passes against an
/// empty window it was never going to find anything in — a silently vacuous
/// assertion in exactly the test that is supposed to prove nothing was
/// published. Bracketing the call narrows that to the boundary case but still
/// assumes the delete's clock and the test's agree.
///
/// So this does not guess. It ENUMERATES the persisted windows — `d:w:{key}`
/// snapshots and `u:w:{key}:{seq}` pending updates, the two row families a
/// window's state can live in — and asks each one. Independent of any
/// timestamp, so it holds on any day of any month.
///
/// Enumerating both families is only half the job: a label discovered ONLY
/// through `u:w:` rows has no snapshot to load, and `load_window_from_state`
/// answers `WindowNotFound` for it. Treating that as "nothing here" would
/// leave the scan blind to exactly the window family it went out of its way
/// to enumerate. So the WindowNotFound arm mirrors the production fresh-doc
/// fallback (`sync::manager::WindowManager::open_window`): create a bare
/// window doc and replay the pending rows onto it through the SAME
/// `apply_pending_window_updates` production uses, then ask that doc.
#[cfg(feature = "sync")]
fn crdt_tombstone_exists_in_any_window(vault: &Vault, id: &EntityId) -> Result<bool> {
    use crate::sync::loro_support::map_contains_binary;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window::apply_pending_window_updates;
    use std::collections::BTreeSet;

    let mut windows: BTreeSet<String> = BTreeSet::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for row in vault.store.sync_state.prefix_iter(&rtxn, "d:w:")? {
            let (key, _value) = row?;
            if let Some(label) = key.strip_prefix("d:w:") {
                windows.insert(label.to_string());
            }
        }
        // A window can have pending updates with no snapshot row yet, so the
        // `u:w:` family is scanned too. Key shape is `u:w:{label}:{seq}`; the
        // label never contains a colon (`YYYY-MM`), so the first one ends it.
        for row in vault.store.sync_state.prefix_iter(&rtxn, "u:w:")? {
            let (key, _value) = row?;
            if let Some(rest) = key.strip_prefix("u:w:")
                && let Some((label, _seq)) = rest.split_once(':')
            {
                windows.insert(label.to_string());
            }
        }
    }

    for label in windows {
        let Some(window_key) = WindowKey::try_new(label) else {
            continue;
        };
        let doc = match crate::sync::window::load_window_from_state(vault, "local", &window_key) {
            Ok(doc) => doc,
            // No `d:w:` snapshot — the label came from the `u:w:` family
            // alone. Production's fresh-doc fallback, verbatim: a bare doc
            // with the pending rows replayed onto it. Skipping here would
            // make the whole `u:w:` enumeration above decorative.
            Err(Error::WindowNotFound { .. }) => {
                let doc = create_window_doc("local", &window_key);
                apply_pending_window_updates(vault, &doc, &window_key)?;
                doc
            }
            Err(error) => return Err(error),
        };
        if map_contains_binary(&doc.get_map("tombstones"), id.to_hex().as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
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
    let encoded = encode_facet_reclassification_body(&consent, 7)?;
    assert_eq!(decode_facet_reclassification_body(&encoded)?, (consent, 7));
    let mut consent_trailing = encode_facet_reclassification_body(&consent, 7)?;
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
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .is_empty(),
        "a refused unstamp appends no ledger event either"
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
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        vec![FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 200,
        }],
        "the unstamp appended its own consent event"
    );
    // The owner-visible ledger mirror rides with it.
    assert!(
        vault
            .get_claim(&facet_reclassification_claim_id(&claim, &facet, 0)?)?
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
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1,
        "and unlike the window, it leaves a record that cannot be wound back"
    );
    Ok(())
}

/// The ledger is APPEND-ONLY AND PER-EVENT: an unstamp of a re-created stamp
/// appends its OWN row with its OWN timestamp rather than collapsing into the
/// first one, so the owner's consent surface shows every reclassification that
/// actually happened. A no-op unstamp (no such stamp) appends nothing — there
/// was no reclassification to record.
#[test]
fn reclassification_ledger_appends_one_event_per_unstamp() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xC6);
    put_facet(&vault, &facet);
    let claim = test_id(0xC7);
    put_public_claim(&vault, &claim, test_id(0xC8));

    // No stamp yet: nothing happened, so nothing is recorded.
    assert!(!vault.unstamp_facet_of(&claim, &facet, 100)?);
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .is_empty()
    );

    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    // Re-stamp and unstamp again: TWO events, oldest first, each with its own
    // timestamp and its own mirror.
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 900)?);
    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .iter()
            .map(|event| event.consented_at)
            .collect::<Vec<_>>(),
        vec![200, 900],
        "each unstamp is its own ledger event, oldest first"
    );
    for sequence in [0, 1] {
        assert!(
            vault
                .get_claim(&facet_reclassification_claim_id(&claim, &facet, sequence)?)?
                .is_some(),
            "event {sequence} has its own mirror — no event overwrites another"
        );
    }
    Ok(())
}

/// P2-a REGRESSION (fix-3) — CONSENT MUST NOT REPLAY ACROSS STAMP
/// INCARNATIONS.
///
/// Fix-2 made a durable per-`(record, facet)` consent record THE authorization
/// the generic doors accepted. But stamps are freely re-creatable, so that
/// record outlives the incarnation it was minted for: consent-unstamp `(C, F)`
/// once, re-stamp `C → F`, and a GENERIC `delete_edge` / `BatchOp::DeleteEdge`
/// passes on the stale record — a second, unconsented reclassification, after
/// which C is unfaceted-admitted into rooms never cleared for F.
///
/// The fix binds authorization to the ACT, not to any record: every generic
/// `FacetOf` deletion refuses unconditionally, and the dedicated door consents
/// and removes in one commit, each time. The pin walks the replay: consent,
/// re-stamp, then demand that BOTH generic doors and the facet-delete cascade
/// still refuse with the stamp intact and the clamp holding — and that the
/// fresh dedicated op succeeds and appends a SECOND event.
#[test]
fn consent_does_not_replay_across_stamp_incarnations() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xE4);
    put_facet(&vault, &facet);
    let contact = test_id(0xE5);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0xE6);
    put_public_claim(&vault, &claim, test_id(0xE7));
    stamp_facet_of(&vault, &claim, &facet);

    let room = |vault: &Vault| {
        DisclosureContext::resolve(
            vault,
            InterlocutorSet::with_session_owner(vec![known(contact, "a@example.com")]),
        )
    };

    // Step 1 — ONE legitimate, consented unstamp. This is what fix-2 recorded
    // permanently, and what the replay would have spent twice.
    assert!(vault.unstamp_facet_of(&claim, &facet, 100)?);
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1
    );

    // Step 2 — RE-STAMP. The claim is clamped again, and the consent above
    // describes an incarnation of the stamp that no longer exists.
    stamp_facet_of(&vault, &claim, &facet);
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "the re-stamped claim is clamped again"
        );
    }

    // Step 3 — THE REPLAY. Every generic removal refuses on the stale record.
    for refusal in [
        vault
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .expect_err("delete_edge must not spend the prior consent"),
        vault
            .batch()
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .commit()
            .expect_err("BatchOp::DeleteEdge must not spend the prior consent"),
        vault
            .batch()
            .delete(&facet)
            .commit()
            .expect_err("the FACET-delete cascade must not spend it either"),
    ] {
        assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);
    }
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the replay tore nothing"
    );
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1,
        "and appended nothing — the refusals are total"
    );
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            !ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "the clamp holds: the second reclassification never happened"
        );
    }

    // Step 4 — a FRESH consent-then-act does the job, and says so.
    assert!(vault.unstamp_facet_of(&claim, &facet, 500)?);
    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .iter()
            .map(|event| event.consented_at)
            .collect::<Vec<_>>(),
        vec![100, 500],
        "the second reclassification is its own consented event"
    );
    {
        let ctx = room(&vault)?;
        let rtxn = vault.store.env.read_txn()?;
        assert!(
            ctx.admits(&vault.store, &rtxn, &claim, ENTITY_TYPE_CLAIM, None)?,
            "and only now is the claim admitted"
        );
    }
    Ok(())
}

/// The FACET-entity hard delete is the same laundering path at its widest: the
/// deindex cascade tears EVERY inbound stamp at once. The cascade is a GENERIC
/// removal, so it refuses while ANY stamp stands — the owner unstamps each one
/// through the dedicated door first, and only a facet nothing points at is
/// deletable (nothing moves between clamp classes, so there is nothing to
/// consent to).
///
/// Fix-3 note: a PRIOR consent no longer opens this door either. Unstamping
/// then RE-stamping leaves the cascade refusing exactly as it did before the
/// consent, because the record on disk describes a stamp incarnation that is
/// gone.
#[test]
fn facet_entity_hard_delete_refuses_while_any_stamp_stands() -> Result<()> {
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

    // Unstamping one is not enough — the OTHER stamp still stands.
    assert!(vault.unstamp_facet_of(&first, &stamped, 300)?);
    assert_eq!(
        vault
            .batch()
            .delete(&stamped)
            .commit()
            .expect_err("the second stamp still blocks")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );

    // RE-stamping the first one re-blocks it, prior consent notwithstanding.
    stamp_facet_of(&vault, &first, &stamped);
    assert!(vault.unstamp_facet_of(&second, &stamped, 400)?);
    assert_eq!(
        vault
            .batch()
            .delete(&stamped)
            .commit()
            .expect_err("a re-created stamp blocks again despite its prior consent")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );

    // With EVERY stamp actually removed through the dedicated door, the facet
    // goes.
    assert!(vault.unstamp_facet_of(&first, &stamped, 500)?);
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
    let mirror = facet_reclassification_claim_id(&claim, &facet, 0)?;
    assert!(vault.get_claim(&mirror)?.is_some());
    vault.batch().delete(&claim).commit()?;
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .is_empty(),
        "the ledger event must not outlive the record it reclassified"
    );
    assert!(
        vault.get_claim(&mirror)?.is_none(),
        "its ledger mirror goes too"
    );

    // A record re-minted at the same id starts a fresh ledger, and its stamp
    // is removable only through the dedicated door.
    put_public_claim(&vault, &claim, test_id(0xDE));
    stamp_facet_of(&vault, &claim, &facet);
    assert_eq!(
        vault
            .delete_edge(&claim, EdgeKind::FacetOf, &facet)
            .expect_err("generic doors never remove a stamp")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );
    assert!(vault.unstamp_facet_of(&claim, &facet, 150)?);
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        vec![FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 150,
        }],
        "the erased history did not carry over into the new incarnation"
    );

    // ── facet side: delete the facet the events name ──
    assert!(!vault.unstamp_facet_of(&claim, &other_facet, 200)?);
    stamp_facet_of(&vault, &claim, &other_facet);
    assert!(vault.unstamp_facet_of(&claim, &other_facet, 300)?);
    vault.batch().delete(&other_facet).commit()?;
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &other_facet)?
            .is_empty(),
        "the ledger event must not outlive the facet it named"
    );
    Ok(())
}

// ─── ONE-1646 fix leg 3: refusals decide BEFORE the tombstone ───────────────

/// P2-b REGRESSION — A REFUSED FACET DELETE PUBLISHES NOTHING.
///
/// `delete_entity_with_reason` writes the CRDT tombstone FIRST by locked
/// ARCH-0038 ordering (it must precede the purge so sync cannot resurrect the
/// body mid-erase), and fix-2's gates only spoke inside
/// `purge_entity_active_store_in_txn`. A refused facet delete therefore
/// published hard-delete truth for a delete that never happened: the facet, its
/// stamps, its exposure row and every clearance naming it stayed whole locally,
/// while every other device was told the id was erased. The refusing device
/// cannot take a published tombstone back, so the divergence is permanent — an
/// erasure-completeness failure of its own.
///
/// The gate now runs BEFORE TXN1. This pins the whole no-op: the refusal, then
/// zero tombstone, zero `dt:`/`pt:` marker, zero receipt, and byte-identical
/// local state.
#[test]
fn refused_facet_delete_publishes_no_tombstone_and_changes_no_state() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xF1);
    put_facet(&vault, &facet);
    let contact = test_id(0xF2);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0xF3);
    put_public_claim(&vault, &claim, test_id(0xF4));
    stamp_facet_of(&vault, &claim, &facet);
    grant_clearance(&vault, &contact, vec![facet]);
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;

    for reason in [
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::GdprDelete,
        crate::DeleteReason::PolicyDelete,
    ] {
        let refusal = vault
            .delete_entity_with_reason(&facet, reason)
            .expect_err("a stamped facet must refuse on every hard reason");
        assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);

        // NOTHING was published. `dt:` is the permanent local hard-delete
        // truth and `pt:` the crash marker — a refused delete writes neither,
        // because it never reached TXN1. Both are read straight off
        // `sync_state`, the rows the delete path itself writes.
        assert!(
            !hard_delete_marker_exists(&vault, &facet)?,
            "a refused delete must not record local hard-delete truth"
        );
        assert!(
            !pending_tombstone_exists(&vault, &facet)?,
            "a refused delete must not leave a pending-tombstone marker"
        );
        // THE DEFECT ITSELF: the CRDT tombstone is the cross-device claim that
        // this id is erased. Under fix-2's ordering it was already published by
        // the time the gate spoke.
        #[cfg(feature = "sync")]
        assert!(
            !crdt_tombstone_exists(&vault, &facet, 1)?,
            "a refused delete must not publish hard-delete truth to other devices"
        );

        // And local state is EXACTLY as found — the facet, its stamp, its
        // exposure row and the clearance naming it.
        assert!(vault.get_entity_type(&facet)?.is_some(), "facet survives");
        assert!(
            vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
            "the stamp survives"
        );
        assert_eq!(
            vault.facet_exposure(&facet)?.map(|state| state.exposure),
            Some(FacetExposure::Public),
            "the exposure row survives"
        );
        assert_eq!(
            vault
                .contact_facet_clearance(&contact)?
                .expect("clearance")
                .facets,
            vec![facet],
            "the clearance survives"
        );
    }

    // The CLEARANCE arm of the gate refuses just as early: unstamp first, so
    // only the live clearance stands in the way.
    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    let refusal = vault
        .delete_entity_with_reason(&facet, crate::DeleteReason::UserHardDelete)
        .expect_err("a live clearance must refuse before the tombstone too");
    assert_eq!(refusal.kind(), ErrorKind::FacetDeleteWithLiveClearance);
    assert!(!hard_delete_marker_exists(&vault, &facet)?);
    assert!(vault.get_entity_type(&facet)?.is_some());
    Ok(())
}

/// The other half of the same rule: an ACCEPTED hard delete still removes ALL
/// facet state atomically — exposure row, ledger mirror, consent sweep, deindex
/// — so moving the gate earlier bought the refusal path without weakening the
/// accepted one.
#[test]
fn accepted_facet_hard_delete_removes_all_facet_state() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xF6);
    put_facet(&vault, &facet);
    let contact = test_id(0xF7);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0xF8);
    put_public_claim(&vault, &claim, test_id(0xF9));
    stamp_facet_of(&vault, &claim, &facet);
    grant_clearance(&vault, &contact, vec![facet]);
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let exposure_mirror = facet_exposure_claim_id(&facet)?;
    let consent_mirror = facet_reclassification_claim_id(&claim, &facet, 0)?;

    // Clear both blockers through their own owner doors, in order.
    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    assert!(vault.get_claim(&consent_mirror)?.is_some());
    vault.set_contact_facet_clearance(&contact, &FacetClearance::granted(Vec::new(), 300)?)?;

    let outcome = vault.delete_entity_with_reason(&facet, crate::DeleteReason::UserHardDelete)?;
    assert!(outcome.existed, "the accepted delete erased the facet");
    assert!(outcome.receipt_id.is_some(), "and minted its receipt");

    assert!(vault.get_entity_type(&facet)?.is_none(), "entity gone");
    assert_eq!(vault.facet_exposure(&facet)?, None, "exposure row gone");
    assert!(
        vault.get_claim(&exposure_mirror)?.is_none(),
        "exposure mirror gone"
    );
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .is_empty(),
        "the consent events naming the facet are swept"
    );
    assert!(
        vault.get_claim(&consent_mirror)?.is_none(),
        "and so are their mirrors"
    );
    assert!(
        hard_delete_marker_exists(&vault, &facet)?,
        "an ACCEPTED hard delete does record local hard-delete truth"
    );
    Ok(())
}

// ─── ONE-1646 fix leg 4: the preflight→purge window (TOCTOU) ────────────────

/// Drives a hard delete of `facet` while a `FacetOf` stamp commits INSIDE the
/// window between the pre-tombstone preflight and the destructive txn.
///
/// The ONE-1149 rendezvous seam fires after the deleter has proven its header
/// and passed the preflight, but before it takes any write lock. Staging the
/// stamp in an uncommitted write txn keeps it invisible to that preflight (LMDB
/// MVCC), and committing it on the rendezvous drops the stamp into the window
/// exactly. Deterministic — no sleeps, no thread-timing luck.
fn delete_racing_a_stamp(
    vault: &Vault,
    facet: &EntityId,
    claim: &EntityId,
    reason: crate::DeleteReason,
) -> Result<crate::DeleteEntityOutcome> {
    let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_after_header_read_signal(tx);
    std::thread::scope(|scope| -> Result<crate::DeleteEntityOutcome> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .batch_in()
            .edge(claim, EdgeKind::FacetOf, facet, 1.0)
            .apply(&mut wtxn)?;
        let deleter = scope.spawn(move || vault.delete_entity_with_reason(facet, reason));
        rx.recv()
            .expect("deleter must signal after the header read");
        wtxn.commit()?;
        deleter.join().expect("deleter thread must not panic")
    })
}

/// P2 REGRESSION — A STAMP THAT LANDS IN THE PREFLIGHT→PURGE WINDOW STILL
/// PROTECTS THE FACET.
///
/// Fix-3's preflight runs in a standalone read txn that is DROPPED before the
/// destructive transactions. A `FacetOf` stamp committing after it passes is
/// invisible to it, so the gate's protection has to be re-established INSIDE
/// each destructive txn or the delete tears the very stamp the gate exists to
/// defend. The two hard-reason shapes reach their destructive step differently
/// and both are pinned here:
///
/// * `UserHardDelete` goes straight to the purge txn, where `deindex_entity`'s
///   in-txn backstop refuses;
/// * `GdprDelete` / `PolicyDelete` run a SoftErase txn FIRST, which scrubs the
///   body before the purge is ever reached — so it carries its own in-txn
///   re-evaluation. Without it the facet's body was destroyed (truncated to
///   its 25 B shell) even though the delete was refused.
///
/// In every case the refusal must leave the facet's body and the racing stamp
/// intact. The tombstone IS published (the preflight passed on a truthful
/// snapshot, and the publish is upstream of the tearing) — that is the
/// documented, recoverable half of the trade, and it is asserted rather than
/// left implicit so a future change to it is a deliberate act.
#[test]
fn stamp_racing_into_the_purge_window_is_not_torn() -> Result<()> {
    for (reason, label) in [
        (crate::DeleteReason::UserHardDelete, "user_hard_delete"),
        (crate::DeleteReason::GdprDelete, "gdpr_delete"),
        (crate::DeleteReason::PolicyDelete, "policy_delete"),
    ] {
        let (_tmp, vault) = temp_vault();
        let facet = test_id(0xC1);
        put_facet(&vault, &facet);
        let claim = test_id(0xC3);
        put_public_claim(&vault, &claim, test_id(0xC4));
        let body_before = vault.get(&facet)?.expect("facet body before");
        assert!(!body_before.is_empty(), "{label}: fixture has a real body");

        let refusal = delete_racing_a_stamp(&vault, &facet, &claim, reason)
            .expect_err("{label}: a stamp in the window must refuse the delete");
        assert_eq!(
            refusal.kind(),
            ErrorKind::FacetUnstampWithoutConsent,
            "{label}: refused by the stamp gate"
        );

        // THE DEFECT: the racing stamp survives, and so does the facet it
        // classifies. A torn stamp here would silently unfacet the claim —
        // reclassifying it into rooms never cleared for this facet.
        assert!(
            vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
            "{label}: the racing stamp must survive the refused delete"
        );
        assert!(
            vault.get_entity_type(&facet)?.is_some(),
            "{label}: the facet entity must survive"
        );
        // The SoftErase arm's specific damage: body truncated to the shell
        // while the delete was refused.
        assert_eq!(
            vault.get(&facet)?.as_deref(),
            Some(body_before.as_slice()),
            "{label}: the facet body must be byte-identical after a refusal"
        );
        // No local hard-delete truth was recorded for a delete that did not
        // happen.
        assert!(
            !hard_delete_marker_exists(&vault, &facet)?,
            "{label}: a refused delete records no local hard-delete truth"
        );
    }
    Ok(())
}

/// The clearance arm of the same window: a clearance naming the facet that
/// commits between the preflight and the destructive txn must protect it too.
/// Distinct from the stamp arm because it refuses through
/// `gate_facet_delete_against_live_clearances` — a different predicate on a
/// different index — and only the SoftErase reasons can destroy state before
/// the purge backstop speaks.
///
/// Staged into a HELD write txn like the stamp arm, rather than granted through
/// `set_contact_facet_clearance` on the rendezvous. That door opens its own
/// write txn, so the ordering was decided by which thread won the write lock —
/// thread-timing luck, and it flipped with fix-5 (the deleter now takes one
/// commit instead of two, wins the lock, and the grant then fails outright on
/// an already-purged facet). Holding the lock removes the coin flip. The gate
/// reads the `contact.clearance.v1:` `vault_meta` row and nothing else, so
/// staging exactly the bytes the door writes is a faithful fixture.
///
/// WHICH WINDOW THIS PINS: the preflight → destructive-txn-open window, closed
/// by the fix-4 in-txn re-evaluation. It cannot reach the window BETWEEN the
/// two destructive phases, because under the pinned single-transaction shape no
/// writer can be there at all — see
/// `destructive_delete_phases_share_one_commit`, which pins that half with a
/// reader at the phase boundary.
#[test]
fn clearance_racing_into_the_purge_window_is_honored() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0xC6);
    put_facet(&vault, &facet);
    let contact = test_id(0xC7);
    seed_contact(&vault, contact, "a@example.com");
    let body_before = vault.get(&facet)?.expect("facet body before");
    let clearance_row = encode_facet_clearance_body(&FacetClearance::granted(vec![facet], 100)?)?;

    let (tx, rx) = std::sync::mpsc::sync_channel::<()>(0);
    crate::deletion::install_after_header_read_signal(tx);
    let vault = &vault;
    let refusal = std::thread::scope(|scope| -> Result<crate::Error> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.vault_meta.put(
            &mut wtxn,
            &facet_clearance_meta_key(&contact),
            &clearance_row,
        )?;
        let deleter = scope.spawn(move || {
            vault.delete_entity_with_reason(&facet, crate::DeleteReason::GdprDelete)
        });
        rx.recv()
            .expect("deleter must signal after the header read");
        wtxn.commit()?;
        Ok(deleter
            .join()
            .expect("deleter thread must not panic")
            .expect_err("a clearance in the window must refuse the delete"))
    })?;
    assert_eq!(refusal.kind(), ErrorKind::FacetDeleteWithLiveClearance);

    assert!(
        vault.get_entity_type(&facet)?.is_some(),
        "the facet entity survives a refusal"
    );
    assert_eq!(
        vault.get(&facet)?.as_deref(),
        Some(body_before.as_slice()),
        "and its body is byte-identical — the SoftErase must have rolled back"
    );
    assert_eq!(
        vault
            .contact_facet_clearance(&contact)?
            .expect("clearance")
            .facets,
        vec![facet],
        "the racing clearance stands"
    );
    assert!(
        !hard_delete_marker_exists(vault, &facet)?,
        "a refused delete records no local hard-delete truth"
    );
    Ok(())
}

// The fix-5 shape pin (`destructive_delete_phases_share_one_commit`) does not
// cross the splice: the landed fix-legs 8..10 keep soft-erase and purge as
// SEPARATE transactions (see the splice note in `deletion.rs`), and the racing
// tests above pin the no-damage-on-refusal outcome directly — the scrub txn's
// in-txn facet-state gate is what closes the window the one-commit shape closed
// by construction. The `BeforeHardPurge` rendezvous pins the boundary itself.
// ─── ONE-1646 fix leg 6: the gate's unknown-type arm + mirror custody ───────

/// P1 REGRESSION — A HEADERLESS ID STILL CANNOT BE UNSTAMPED BY DELETION.
///
/// The row-tearing gate used to be reached through
/// `if let Some(entity_type) = stored_entity_type(..)`, so an id with LIVE
/// inbound `FacetOf` stamps but no entity row skipped it entirely — and
/// `delete_related_edges`, three lines later, tore every one of those stamps.
/// The stamped records SURVIVE that tear (they are separate entities) and land
/// unfaceted, which the P7 conjunct admits as the invariant/core class: a
/// reclassification into wider rooms, with no consent event anywhere. That is
/// the laundering class this lane exists to close, reached by deleting the one
/// thing whose type nobody can vouch for.
///
/// The gate now treats an unknowable type as possibly-FACET and evaluates both
/// arms. The consent-authorized op is unaffected: `unstamp_facet_of` removes
/// the stamp with its ledger event, and the delete then proceeds.
#[test]
fn headerless_residue_cannot_tear_a_stamp_via_a_generic_delete() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x18);
    put_facet(&vault, &facet);
    let claim = test_id(0x19);
    put_public_claim(&vault, &claim, test_id(0x1A));
    stamp_facet_of(&vault, &claim, &facet);

    // Strip the ENTITY ROW only, the way a concurrent delete that lost the
    // purge race would: the stamp and every other index row stay live, so the
    // id's type is now unknowable while its edges are not.
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, facet.as_bytes())?;
        Ok(())
    })?;
    assert!(
        vault.get_entity_type(&facet)?.is_none(),
        "fixture is headerless"
    );
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "and the stamp it is standing on is live"
    );

    // Both hard-delete doors refuse, naming the stamp in the way.
    assert_eq!(
        vault
            .batch()
            .delete(&facet)
            .commit()
            .expect_err("a generic hard delete must not tear the stamp")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );
    assert_eq!(
        vault
            .delete_entity_with_reason(&facet, crate::DeleteReason::UserHardDelete)
            .expect_err("the reason-aware door refuses identically")
            .kind(),
        ErrorKind::FacetUnstampWithoutConsent
    );
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the refusals tore nothing"
    );

    // The CONSENT-AUTHORIZED op is the way through, and it still works on a
    // headerless target — the stamp is what it operates on, not the row.
    assert!(vault.unstamp_facet_of(&claim, &facet, 400)?);
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        vec![FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 400,
        }],
        "and it left the consent event the tear-via-delete never would have"
    );
    vault.batch().delete(&facet).commit()?;
    Ok(())
}

/// The other half: the fail-closed default is not a wall in front of harmless
/// deletes. A headerless id with NO incident stamp and NO clearance naming it
/// deletes exactly as it always did.
#[test]
fn headerless_residue_without_facet_state_still_deletes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let stray = test_id(0x1B);
    put_turn(&vault, &stray);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, stray.as_bytes())?;
        Ok(())
    })?;

    vault
        .batch()
        .delete(&stray)
        .commit()
        .expect("a headerless id naming no facet state is freely deletable");

    // And a headerless id blocked only by a live CLEARANCE gets the clearance
    // diagnostic, not the stamp one — both arms run without a type.
    let facet = test_id(0x1C);
    put_facet(&vault, &facet);
    let contact = test_id(0x1D);
    seed_contact(&vault, contact, "a@example.com");
    grant_clearance(&vault, &contact, vec![facet]);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, facet.as_bytes())?;
        Ok(())
    })?;
    assert_eq!(
        vault
            .batch()
            .delete(&facet)
            .commit()
            .expect_err("a live clearance still blocks a headerless facet delete")
            .kind(),
        ErrorKind::FacetDeleteWithLiveClearance
    );
    Ok(())
}

/// P2 REGRESSION — MIRROR CUSTODY: the cleanup tears OUR mirror, not whatever
/// claim happens to sit at the derived id.
///
/// Mirror ids are public sha256 derivations, and `disclosure.*` is
/// engine-reserved (item 3), so a foreign claim can no longer be minted at one
/// through `put_claim`. What CAN sit there is another disclosure mirror: the
/// derivations are independent hashes, so nothing structurally prevents one
/// family's id from being another family's — and the old check ("a CLAIM whose
/// predicate is anywhere in the disclosure family") admitted every one of them.
/// Deleting a contact would then deindex an unrelated reclassification's ledger
/// mirror.
///
/// The check is now the id's own round trip: exact predicate plus the subject
/// (and, for ledger rows, the `(record, facet, sequence)` triple) the id was
/// derived from. A mismatch leaves the row standing.
#[test]
fn mirror_cleanup_leaves_a_claim_that_is_not_the_expected_mirror() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x1E);
    seed_contact(&vault, contact, "a@example.com");
    let facet = test_id(0x1F);
    put_facet(&vault, &facet);
    grant_clearance(&vault, &contact, vec![facet]);

    // A SECOND disclosure mirror, of a different family, written through the
    // engine door — then relocated onto the contact's clearance-mirror id, the
    // way an id collision or a future derivation change would present it.
    let clearance_mirror = facet_clearance_claim_id(&contact)?;
    let exposure_mirror = facet_exposure_claim_id(&facet)?;
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let foreign = vault
        .get_claim(&exposure_mirror)?
        .expect("exposure mirror to relocate");
    vault.with_write_txn(|wtxn| {
        let raw = vault
            .store
            .entities
            .get(&*wtxn, exposure_mirror.as_bytes())?
            .expect("exposure mirror row")
            .to_vec();
        vault
            .store
            .entities
            .put(wtxn, clearance_mirror.as_bytes(), &raw)?;
        Ok(())
    })?;

    // Deleting the contact sweeps its clearance ROW, but the claim standing at
    // the clearance-mirror id is a `disclosure.facet_exposure` about a facet —
    // not this contact's clearance mirror — so it is left exactly as written.
    vault.batch().delete(&contact).commit()?;
    assert!(
        vault.contact_facet_clearance(&contact)?.is_none(),
        "the contact's own enforcement row is gone"
    );
    assert_eq!(
        vault
            .get_claim(&clearance_mirror)?
            .expect("the non-matching claim survives"),
        foreign,
        "a claim that is not the expected mirror is never torn"
    );

    // And the REAL mirror is still removed: same delete shape, matching body.
    let other_contact = test_id(0x23);
    seed_contact(&vault, other_contact, "b@example.com");
    grant_clearance(&vault, &other_contact, vec![facet]);
    let real_mirror = facet_clearance_claim_id(&other_contact)?;
    assert!(vault.get_claim(&real_mirror)?.is_some(), "fixture mirror");
    vault.batch().delete(&other_contact).commit()?;
    assert!(
        vault.get_claim(&real_mirror)?.is_none(),
        "the owned mirror is still swept"
    );
    Ok(())
}

/// P3 REGRESSION — `disclosure.*` IS RESERVED (D17), so the owner-visible
/// consent mirrors cannot be forged.
///
/// The mirror ids are public derivations and the ledger mirror is the owner's
/// audit surface for "which reclassifications did I consent to". While
/// `disclosure.*` was publicly writable, any caller could `put_claim` a
/// `disclosure.facet_reclassification` at a derived id and assert a consent
/// event that never happened — or contradict the clearance the enforcement row
/// actually holds. Audit-trail integrity is the one property an audit trail
/// exists to have.
#[test]
fn disclosure_predicates_are_reserved_from_the_public_claim_door() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let subject = test_id(0x24);
    put_turn(&vault, &subject);

    for predicate in DISCLOSURE_CLAIM_PREDICATES {
        let body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::from("forged"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        let id = EntityId::now();
        assert_eq!(
            vault
                .put_claim(&id, &body, TimeRange { start: 1, end: 1 }, 1)
                .expect_err("public put_claim must reject disclosure.*")
                .kind(),
            ErrorKind::ReservedPredicate,
            "predicate {predicate} must be reserved"
        );
        // The raw entity door is the same door underneath, and rejects too.
        assert_eq!(
            vault
                .put_entity(
                    &id,
                    ENTITY_TYPE_CLAIM,
                    TimeRange { start: 1, end: 1 },
                    1,
                    &encode_claim_body(&body)?,
                )
                .expect_err("public put_entity must reject disclosure.*")
                .kind(),
            ErrorKind::ReservedPredicate
        );
        assert!(vault.get_claim(&id)?.is_none(), "nothing was written");
    }

    // An unreserved neighbour is unaffected — the reservation is namespace
    // scoped, not a substring match.
    let ok = ClaimBody::new(
        "disclosures.note",
        ClaimSubject::Entity(subject),
        Value::from("not in the reserved namespace"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    vault.put_claim(&EntityId::now(), &ok, TimeRange { start: 1, end: 1 }, 1)?;

    // The ENGINE door still lands its mirrors: reservation closed the public
    // path without closing the lane's own writes.
    let facet = test_id(0x27);
    put_facet(&vault, &facet);
    let claim = test_id(0x28);
    put_public_claim(&vault, &claim, test_id(0x29));
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 500)?);
    let mirror = facet_reclassification_claim_id(&claim, &facet, 0)?;
    assert_eq!(
        vault
            .get_claim(&mirror)?
            .expect("the unstamp op's mirror still lands")
            .predicate,
        PREDICATE_DISCLOSURE_FACET_RECLASSIFICATION
    );
    vault.set_facet_exposure(&facet, FacetExposure::Public, 600)?;
    assert!(
        vault
            .get_claim(&facet_exposure_claim_id(&facet)?)?
            .is_some(),
        "and so does every other owner write op's mirror"
    );
    Ok(())
}

/// P4 REGRESSION — A DEEP MIRROR CHAIN COMPLETES WITHOUT STACK GROWTH.
///
/// The chain is built from ordinary public ops: a ledger MIRROR is a CLAIM, so
/// it is `FacetOf`-stampable, and unstamping it through the consent door mints
/// a ledger row whose `record` is that mirror — whose own cleanup therefore
/// reaches a further mirror. The predecessor tore each level on the stack, so a
/// chain of caller-chosen depth was a stack-overflow ABORT (process death, not
/// a refusal). The traversal is now a worklist, so depth is heap-bounded.
///
/// The chain is run on a dedicated thread with a DELIBERATELY SMALL stack: at
/// 256 KiB the old per-level frames could not survive this depth, so a pass
/// here is evidence about stack growth rather than about the machine's default
/// stack being generous.
#[test]
fn deep_mirror_chain_is_swept_without_stack_growth() -> Result<()> {
    const DEPTH: usize = 300;

    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x2A);
    put_facet(&vault, &facet);
    let root = test_id(0x2B);
    put_public_claim(&vault, &root, test_id(0x2C));

    // Build the chain: each level's unstamp mints a mirror, which becomes the
    // next level's stamped record.
    let mut level = root;
    let mut mirrors = Vec::with_capacity(DEPTH);
    for step in 0..DEPTH {
        stamp_facet_of(&vault, &level, &facet);
        assert!(
            vault.unstamp_facet_of(&level, &facet, 1000 + step as u64)?,
            "step {step} must remove the stamp it just wrote"
        );
        let mirror = facet_reclassification_claim_id(&level, &facet, 0)?;
        assert!(
            vault.get_claim(&mirror)?.is_some(),
            "step {step} must mint a ledger mirror"
        );
        mirrors.push(mirror);
        level = mirror;
    }

    // Deleting the ROOT sweeps its ledger row, which deindexes its mirror,
    // which sweeps ITS ledger row — all the way down, in one transaction.
    let vault_ref = &vault;
    std::thread::scope(|scope| -> Result<()> {
        let handle = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn_scoped(scope, move || -> Result<()> {
                vault_ref.batch().delete(&root).commit()
            })
            .expect("spawn small-stack sweeper");
        handle
            .join()
            .expect("the sweep must not overflow the stack")
    })?;

    for (step, mirror) in mirrors.iter().enumerate() {
        assert!(
            vault.get_claim(mirror)?.is_none(),
            "mirror at depth {step} must be swept with the chain"
        );
    }
    Ok(())
}

/// P5 REGRESSION — a ledger row whose BODY disagrees with its KEY is not
/// returned as that key's event.
///
/// The key is the authority on which `(record, facet, sequence)` an event
/// belongs to. Returning a body that names a DIFFERENT pair would show the
/// owner, on the consent surface, a reclassification they never consented to
/// for the facet they asked about — silent mis-attribution in the one record
/// that exists to be attributable. It errors rather than skipping: a silent
/// skip would render a damaged ledger as a shorter, plausible history.
#[test]
fn ledger_rejects_a_body_that_disagrees_with_its_row_key() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x2D);
    let other_facet = test_id(0x2E);
    put_facet(&vault, &facet);
    put_facet(&vault, &other_facet);
    let claim = test_id(0x2F);
    put_public_claim(&vault, &claim, test_id(0x38));
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 700)?);
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1
    );

    // Overwrite the row's BODY with an event naming a different facet, leaving
    // the key alone — the corrupt-row shape the read must not launder.
    let key = facet_reclassification_meta_key(&claim, &facet, 0);
    let forged = encode_facet_reclassification_body(
        &FacetReclassificationConsent {
            record: claim,
            facet: other_facet,
            consented_at: 700,
        },
        0,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &forged)?;
        Ok(())
    })?;

    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)
            .expect_err("a body disagreeing with its key is corruption")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // The SEQUENCE half of the same rule.
    let forged = encode_facet_reclassification_body(
        &FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 700,
        },
        7,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &forged)?;
        Ok(())
    })?;
    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)
            .expect_err("a sequence disagreeing with its key is corruption")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // A body that AGREES with its key reads back normally.
    let honest = encode_facet_reclassification_body(
        &FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 700,
        },
        0,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &key, &honest)?;
        Ok(())
    })?;
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        vec![FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 700,
        }]
    );
    Ok(())
}

// ─── ONE-1646 fix leg 7: the headerless door's publish gate + key length ────

/// P1 REGRESSION — THE HEADERLESS DOOR REFUSES BEFORE IT PUBLISHES.
///
/// `delete_entity_with_reason` splits on the header read: an id with an entity
/// row takes the headerful leg (whose pre-TXN1 publish gate fix-3 installed),
/// and an id WITHOUT one takes `delete_entity_without_header`. That second leg
/// reached the facet-state gate only through `deindex_entity`'s backstop inside
/// its purge txn — which runs AFTER `write_crdt_tombstone`. So a stamped or
/// clearance-blocked headerless id returned the right refusal and kept every
/// local row, while the CRDT tombstone claiming the id was hard-deleted stood
/// published on every other device, unretractable from here.
///
/// The lane's rule since fix-3 is that a refusal publishes NOTHING. This pins it
/// for the door that was missed: the typed refusal, then zero CRDT tombstone,
/// zero `dt:`, zero `pt:`, zero receipt, and untouched local state.
#[test]
fn refused_headerless_delete_publishes_no_tombstone_and_changes_no_state() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x39);
    put_facet(&vault, &facet);
    let contact = test_id(0x3A);
    seed_contact(&vault, contact, "a@example.com");
    let claim = test_id(0x3B);
    put_public_claim(&vault, &claim, test_id(0x3C));
    stamp_facet_of(&vault, &claim, &facet);
    grant_clearance(&vault, &contact, vec![facet]);
    // A non-`FacetOf` edge onto the same id, so the delete SCOPE outlives both
    // blockers: with it the accepted delete at the end still has residue to
    // erase, and its survival through each refusal is another byte of proof
    // that nothing was torn.
    let mentioner = test_id(0x3F);
    put_turn(&vault, &mentioner);
    vault
        .batch()
        .edge(&mentioner, EdgeKind::Mentions, &facet, 1.0)
        .commit()?;

    // Strip the ENTITY ROW only — every edge and clearance stays live, so the
    // delete routes through the headerless leg with real facet state incident
    // on the id. This is the shape a lost purge race leaves behind.
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, facet.as_bytes())?;
        Ok(())
    })?;
    assert!(
        vault.get_entity_type(&facet)?.is_none(),
        "fixture must take the headerless leg"
    );

    let receipts_before = vault.count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)?;

    // Every hard reason refuses on the STAMP first — and this leg has no
    // soft-erase arm, so the soft reason purges too and must gate identically.
    for reason in [
        crate::DeleteReason::UserDelete,
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::GdprDelete,
        crate::DeleteReason::PolicyDelete,
    ] {
        let refusal = vault
            .delete_entity_with_reason(&facet, reason)
            .expect_err("a stamped headerless id must refuse on every reason");
        assert_eq!(refusal.kind(), ErrorKind::FacetUnstampWithoutConsent);

        // THE DEFECT ITSELF: under fix-6's ordering the tombstone was already
        // durable by the time the purge txn's backstop spoke.
        //
        // Asked of EVERY persisted window, not of the one a clock reading taken
        // here would name. `requested_at` is "now" on this leg (there is no
        // `learned_at` to address a window with), so a guessed window is only
        // the right one while the test's clock and the delete's agree on the
        // `YYYY-MM` — which a call crossing a UTC month boundary breaks, and
        // the assertion would then pass against an empty window instead of
        // finding the tombstone in the prior one.
        #[cfg(feature = "sync")]
        assert!(
            !crdt_tombstone_exists_in_any_window(&vault, &facet)?,
            "a refused headerless delete must not publish hard-delete truth"
        );
        assert!(
            !hard_delete_marker_exists(&vault, &facet)?,
            "nor record local hard-delete truth"
        );
        assert!(
            !pending_tombstone_exists(&vault, &facet)?,
            "nor leave a pending-tombstone marker"
        );
        assert_eq!(
            vault.count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)?,
            receipts_before,
            "nor mint a redaction receipt"
        );

        // And local state is EXACTLY as found.
        assert!(
            vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
            "the stamp survives"
        );
        assert_eq!(
            vault
                .contact_facet_clearance(&contact)?
                .expect("clearance")
                .facets,
            vec![facet],
            "the clearance survives"
        );
        assert!(
            vault.edge_exists(&mentioner, EdgeKind::Mentions, &facet)?,
            "and so does the unrelated edge the purge would have torn"
        );
    }

    // The CLEARANCE arm refuses just as early: unstamp through the consent
    // door, and only the live clearance is left standing in the way.
    //
    // Driven through ALL FOUR reasons, exactly like the stamp arm above, and
    // asserting the same full no-op rather than only the CRDT/`dt:` pair. The
    // gate this leg installed is unconditional on reason (there is no
    // soft-erase arm here — every reason purges), so a later hard-reason
    // conditional slipped into it would let a headerless `UserDelete` purge a
    // clearance-blocked facet through while a `UserHardDelete`-only check
    // stayed green. This closes that hole by construction.
    assert!(vault.unstamp_facet_of(&claim, &facet, 800)?);
    for reason in [
        crate::DeleteReason::UserDelete,
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::GdprDelete,
        crate::DeleteReason::PolicyDelete,
    ] {
        let refusal = vault
            .delete_entity_with_reason(&facet, reason)
            .expect_err("a live clearance must refuse before the tombstone too");
        assert_eq!(refusal.kind(), ErrorKind::FacetDeleteWithLiveClearance);

        // Nothing published, on any reason — the same four surfaces the stamp
        // arm pins, and the same window-independent tombstone scan.
        #[cfg(feature = "sync")]
        assert!(
            !crdt_tombstone_exists_in_any_window(&vault, &facet)?,
            "a clearance refusal must not publish hard-delete truth"
        );
        assert!(
            !hard_delete_marker_exists(&vault, &facet)?,
            "nor record local hard-delete truth"
        );
        assert!(
            !pending_tombstone_exists(&vault, &facet)?,
            "nor leave a pending-tombstone marker"
        );
        assert_eq!(
            vault.count_entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)?,
            receipts_before,
            "nor mint a redaction receipt"
        );

        // And the state the refusal was protecting is EXACTLY as found: the
        // clearance itself, and the unrelated edge a purge would have torn.
        assert_eq!(
            vault
                .contact_facet_clearance(&contact)?
                .expect("clearance")
                .facets,
            vec![facet],
            "the clearance survives"
        );
        assert!(
            vault.edge_exists(&mentioner, EdgeKind::Mentions, &facet)?,
            "and so does the unrelated edge the purge would have torn"
        );
    }

    // Clear the last blocker and the SAME call goes through, so the gate is a
    // decision and not a wall: the headerless residue erases and publishes.
    vault.set_contact_facet_clearance(&contact, &FacetClearance::granted(Vec::new(), 900)?)?;
    let outcome = vault.delete_entity_with_reason(&facet, crate::DeleteReason::UserHardDelete)?;
    // `existed` reports the ENTITY ROW, which is what "headerless" means is
    // absent — the erasure is visible in the residue instead.
    assert!(
        !vault.edge_exists(&mentioner, EdgeKind::Mentions, &facet)?,
        "the accepted delete tore the residue the refusals preserved"
    );
    assert!(
        outcome.receipt_id.is_some(),
        "and minted its receipt, so the gate is a decision and not a wall"
    );
    assert!(
        hard_delete_marker_exists(&vault, &facet)?,
        "an ACCEPTED headerless delete does record hard-delete truth"
    );
    Ok(())
}

/// The other half: an id with NO facet state whose entity row is gone still
/// deletes as the strict no-op it always was. The publish gate sits AFTER the
/// scope probe, so an id with no delete scope at all never reaches it.
#[test]
fn headerless_delete_without_facet_state_is_unaffected() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let stray = test_id(0x3D);
    put_turn(&vault, &stray);
    // An incident edge keeps the id in delete SCOPE after the row is stripped,
    // so this exercises a real headerless erasure rather than the missing-id
    // short circuit below.
    let mentioner = test_id(0x49);
    put_turn(&vault, &mentioner);
    vault
        .batch()
        .edge(&mentioner, EdgeKind::Mentions, &stray, 1.0)
        .commit()?;
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, stray.as_bytes())?;
        Ok(())
    })?;

    let outcome = vault.delete_entity_with_reason(&stray, crate::DeleteReason::UserHardDelete)?;
    assert!(
        outcome.receipt_id.is_some(),
        "a headerless delete naming no facet state proceeds untouched"
    );
    assert!(
        !vault.edge_exists(&mentioner, EdgeKind::Mentions, &stray)?,
        "and tears the residue it found"
    );
    assert!(hard_delete_marker_exists(&vault, &stray)?);

    // A FULLY missing id stays the strict no-op it was: no tombstone, no
    // marker, no receipt — the probe short-circuits before the gate.
    let absent = test_id(0x3E);
    let outcome = vault.delete_entity_with_reason(&absent, crate::DeleteReason::UserHardDelete)?;
    assert_eq!(outcome, crate::DeleteEntityOutcome::missing());
    assert!(!hard_delete_marker_exists(&vault, &absent)?);
    assert!(!pending_tombstone_exists(&vault, &absent)?);
    Ok(())
}

/// P2 REGRESSION — AN OVERLONG RECLASSIFICATION KEY IS CORRUPTION, NOT AN EVENT.
///
/// `sequence_of_reclassification_key` read its 8-byte suffix at a fixed offset
/// and ignored everything after it, so `canonical_key || extra` parsed as the
/// canonical key's own `(record, facet, sequence)`. Carrying a body honest about
/// that canonical triple then satisfied fix-6's body-to-key binding (it compares
/// against these same extractors), and the ledger returned the overlong row as a
/// real consent event — a second, duplicate event for a pair, minted by writing
/// a key nothing in this module can produce.
///
/// The length is now exact, so the row reads as the corruption it is.
#[test]
fn ledger_rejects_an_overlong_row_key() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x45);
    put_facet(&vault, &facet);
    let claim = test_id(0x46);
    put_public_claim(&vault, &claim, test_id(0x48));
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 900)?);

    // An HONEST body — the same bytes the canonical row carries — under a key
    // one byte too long. Nothing about the body is forged; the key is.
    let mut overlong = facet_reclassification_meta_key(&claim, &facet, 0);
    overlong.push(0x00);
    let honest = encode_facet_reclassification_body(
        &FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 900,
        },
        0,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &overlong, &honest)?;
        Ok(())
    })?;

    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)
            .expect_err("an overlong key is a corrupt row, not a duplicate event")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // Removing the forged row restores the honest single-event history, so the
    // rejection is about the KEY and not about the pair.
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.delete(wtxn, &overlong)?;
        Ok(())
    })?;
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        vec![FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 900,
        }]
    );

    // A key one byte SHORT was already rejected and stays rejected — the exact
    // length is the rule, not a lower bound with a new upper one.
    let mut truncated = facet_reclassification_meta_key(&claim, &facet, 0);
    truncated.pop();
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &truncated, &honest)?;
        Ok(())
    })?;
    assert_eq!(
        vault
            .facet_reclassification_ledger(&claim, &facet)
            .expect_err("a short key is corrupt too")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    Ok(())
}

/// The WRITE half of the same rule: the SEQUENCE ALLOCATOR rejects a corrupt
/// key too, and rejects it ATOMICALLY — before `unstamp_facet_of` has removed
/// a live stamp or appended anything.
///
/// `ledger_rejects_an_overlong_row_key` above exercises only the READ door
/// (`facet_reclassification_ledger`). But the same key length is parsed on the
/// WRITE path, by `next_facet_reclassification_sequence_in_txn`, and that call
/// sits INSIDE `unstamp_facet_of`'s write txn alongside the edge deletes and
/// the event/mirror writes. A rejection that fired after any of those had
/// landed — or one that let them land and only then errored without unwinding
/// — would be the worse outcome of the two: a stamp torn off a record with NO
/// consent event recording it, which is precisely the laundering shape this
/// lane exists to prevent, reached this time by corrupting a row rather than
/// by calling a delete.
///
/// The whole op is one `with_write_txn`, which rolls back on `Err`, so the
/// corrupt row makes the unstamp a strict no-op. This pins that: `CorruptedIndex`
/// out, and the stamp, the canonical ledger rows, and the mirror set all
/// byte-identical to what stood before the call.
#[test]
fn overlong_key_rejects_the_unstamp_before_any_side_effect() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x4B);
    put_facet(&vault, &facet);
    let claim = test_id(0x4C);
    put_public_claim(&vault, &claim, test_id(0x4D));

    // One honest unstamp first, so sequence 0 exists as real history and the
    // corrupt row below is an ADDITION to a live pair rather than the only
    // thing under the prefix.
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 900)?);
    let honest_history = vec![FacetReclassificationConsent {
        record: claim,
        facet,
        consented_at: 900,
    }];
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        honest_history
    );
    let mirror_0 = facet_reclassification_claim_id(&claim, &facet, 0)?;
    let mirror_1 = facet_reclassification_claim_id(&claim, &facet, 1)?;
    assert!(vault.get_claim(&mirror_0)?.is_some(), "sequence 0 mirrored");
    assert!(
        vault.get_claim(&mirror_1)?.is_none(),
        "and nothing beyond it"
    );

    // The corrupt row: honest body, key one byte too long. Same fixture the
    // read-door test uses, so the two doors are pinned against one shape.
    let mut overlong = facet_reclassification_meta_key(&claim, &facet, 0);
    overlong.push(0x00);
    let honest = encode_facet_reclassification_body(
        &FacetReclassificationConsent {
            record: claim,
            facet,
            consented_at: 900,
        },
        0,
    )?;
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &overlong, &honest)?;
        Ok(())
    })?;

    // RE-STAMP, so there is a LIVE stamp for the failing unstamp to tear.
    // Without this the call would return `false` at the edge probe and never
    // reach the allocator — the rejection has to be proven on the path that
    // actually mutates.
    stamp_facet_of(&vault, &claim, &facet);
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "fixture must have a live stamp to lose"
    );

    assert_eq!(
        vault
            .unstamp_facet_of(&claim, &facet, 1000)
            .expect_err("a corrupt row must stop the unstamp, not be allocated past")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // NOTHING moved. The stamp is the one that matters — it is what a
    // successful-but-unrecorded unstamp would have torn.
    assert!(
        vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the refused unstamp must not tear the stamp"
    );
    // No event and no mirror was appended: the canonical rows still read as the
    // single honest event once the corrupt row is lifted, and the sequence-1
    // mirror that a partial write would have minted does not exist.
    assert!(
        vault.get_claim(&mirror_1)?.is_none(),
        "nor mint an event mirror for the sequence it never allocated"
    );
    assert!(
        vault.get_claim(&mirror_0)?.is_some(),
        "and the mirror that was already there is untouched"
    );
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.delete(wtxn, &overlong)?;
        Ok(())
    })?;
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?,
        honest_history,
        "the canonical ledger rows are exactly the history from before the call"
    );

    // And with the corruption gone the SAME call goes through, so the
    // rejection was the row's doing and not a wall in front of the op.
    assert!(vault.unstamp_facet_of(&claim, &facet, 1000)?);
    assert!(!vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?);
    assert!(
        vault.get_claim(&mirror_1)?.is_some(),
        "the honest unstamp allocates the sequence the corrupt one could not"
    );
    Ok(())
}

// ─── ONE-1646 fix leg 9: the any-window scan covers the `u:w:`-only family ──

/// REGRESSION — A TOMBSTONE THAT LIVES ONLY IN `u:w:` ROWS IS STILL FOUND.
///
/// `crdt_tombstone_exists_in_any_window` is the assertion three refusal tests
/// above lean on to prove a refused delete published NOTHING. Its whole claim
/// is exhaustiveness over the two row families a window's state can live in.
/// It enumerated both — but then asked `load_window_from_state`, which
/// REQUIRES a `d:w:{window}` snapshot and answers `WindowNotFound` without
/// one, and that arm was `continue`d past. So a window discovered ONLY through
/// `u:w:` rows — the exact family the second enumeration loop exists to reach —
/// was scanned into the set and then silently dropped, and the helper returned
/// `false` over a tombstone sitting in plain sight.
///
/// That is a false PASS in a fail-closed direction that matters: every caller
/// asserts `!exists`, so the blind spot turns "the refusal published a hard
/// delete to every other device" into a green test. And it is not a contrived
/// state — a window carries pending updates with no snapshot whenever remote
/// updates persist before the window is ever unloaded or compacted, which is
/// why production's own `WindowManager::open_window` has a fresh-doc fallback
/// for precisely this case.
///
/// This builds that state directly — a `u:w:` row carrying a tombstone commit,
/// with NO `d:w:` row for its window — and requires the helper to say `true`.
#[cfg(feature = "sync")]
#[test]
fn any_window_scan_finds_a_tombstone_in_a_snapshotless_window() -> Result<()> {
    use crate::deletion::{TombstoneReason, TombstoneValueV2};
    use crate::sync::loro_support::{export_updates_from, map_insert_bytes};
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;

    let (_tmp, vault) = temp_vault();
    let buried = test_id(0x4E);

    // A window doc holding one tombstone, exported as an UPDATE delta from
    // the empty version vector — the shape a `u:w:` row carries. The doc
    // itself is thrown away; only the delta is persisted.
    let window = WindowKey::new("2001-02");
    let doc = create_window_doc("local", &window);
    let base_vv = doc.oplog_vv();
    let value = TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at: 1_000,
        request_id: [0x11; 16],
    };
    map_insert_bytes(
        &doc.get_map("tombstones"),
        buried.to_hex().as_str(),
        &value.encode(),
    )?;
    doc.commit();
    let delta = export_updates_from(&doc, &base_vv)?;

    // Persist ONLY the pending-update row. No `d:w:{window}` snapshot — this
    // is the state `load_window_from_state` refuses with `WindowNotFound`.
    vault.sync_state_put(&format!("u:w:{window}:00000000"), &delta)?;
    assert!(
        vault.sync_state_get(&format!("d:w:{window}"))?.is_none(),
        "fixture must have NO snapshot row, or it proves nothing"
    );

    // THE DEFECT: with the WindowNotFound arm skipping, this reads `false`.
    assert!(
        crdt_tombstone_exists_in_any_window(&vault, &buried)?,
        "a tombstone persisted only in `u:w:` rows must still be found"
    );

    // And the helper still says `false` for an id nobody buried, so the fix
    // is a replay and not a blanket `true`.
    assert!(
        !crdt_tombstone_exists_in_any_window(&vault, &test_id(0x4F))?,
        "an unrelated id is still absent"
    );
    Ok(())
}

/// P2 REGRESSION (fix-10 item 2) — the mirror WRITE door refuses to overwrite
/// a foreign claim squatting the derived id.
///
/// Fix-6 item 2 gave the CLEANUP side custody: it will not TEAR a row that is
/// not the expected mirror. The write side had none — it overwrote whatever
/// sat at the derived id. Same hazard, same public sha256 derivation, worse
/// outcome: an overwrite destroys the foreign record AND leaves a plausible
/// disclosure record standing in its place, where a tear at least leaves the
/// id empty.
#[test]
fn mirror_write_refuses_to_overwrite_a_foreign_claim_at_the_derived_id() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x2A);
    seed_contact(&vault, contact, "a@example.com");
    let facet = test_id(0x2B);
    put_facet(&vault, &facet);

    // Relocate a DIFFERENT family's mirror onto the contact's clearance-mirror
    // id — the same collision shape the cleanup-side test models.
    let clearance_mirror = facet_clearance_claim_id(&contact)?;
    let exposure_mirror = facet_exposure_claim_id(&facet)?;
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    vault.with_write_txn(|wtxn| {
        let raw = vault
            .store
            .entities
            .get(&*wtxn, exposure_mirror.as_bytes())?
            .expect("exposure mirror row")
            .to_vec();
        vault
            .store
            .entities
            .put(wtxn, clearance_mirror.as_bytes(), &raw)?;
        Ok(())
    })?;
    let before = vault.get_claim(&clearance_mirror)?.expect("squatter");

    // Granting the contact a clearance would write its mirror at that id.
    // REFUSE — and write nothing at all, enforcement row included.
    let refusal = vault
        .set_contact_facet_clearance(&contact, &FacetClearance::granted(vec![facet], 200)?)
        .expect_err("the mirror write must refuse a foreign occupant");
    assert_eq!(refusal.kind(), ErrorKind::InvalidClaimBody);
    assert_eq!(
        vault.get_claim(&clearance_mirror)?,
        Some(before),
        "the foreign claim is byte-identical after the refusal"
    );
    assert!(
        vault.contact_facet_clearance(&contact)?.is_none(),
        "the refusal is atomic — no enforcement row either"
    );

    // The ordinary re-set (this family's own mirror) still passes: custody is
    // about foreign occupants, not about forbidding the CID-7 overwrite.
    vault.set_facet_exposure(&facet, FacetExposure::Private, 300)?;
    assert_eq!(
        vault.facet_exposure(&facet)?,
        Some(FacetExposureState {
            exposure: FacetExposure::Private,
            updated_at: 300,
        }),
        "this family's own mirror still re-sets (the CID-7 overwrite)"
    );
    Ok(())
}

/// P2 REGRESSION (fix-10 item 3) — a HEADERLESS facet deletion leaves no
/// facet-state residue.
///
/// `deindex_entity` returns early when no entity row exists, and that early
/// return skipped the facet-state cleanup entirely. Facet state is keyed by
/// ID ALONE, so it survived: the `facet.exposure.v1` row kept voting "public"
/// in every future resolve for an id with nothing behind it, and its claim
/// mirror stayed on the owner's consent surface.
#[test]
fn headerless_facet_deletion_leaves_no_facet_state_residue() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let facet = test_id(0x3A);
    put_facet(&vault, &facet);
    vault.set_facet_exposure(&facet, FacetExposure::Public, 100)?;
    let exposure_mirror = facet_exposure_claim_id(&facet)?;
    assert!(vault.get_claim(&exposure_mirror)?.is_some());

    // HEADERLESS: strip the entity row out from under the facet state, so the
    // delete takes the no-type early return.
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, facet.as_bytes())?;
        Ok(())
    })?;
    assert_eq!(
        vault.facet_exposure(&facet)?,
        Some(FacetExposureState {
            exposure: FacetExposure::Public,
            updated_at: 100,
        }),
        "the state outlives its entity row — this is the residue"
    );

    vault.batch().delete(&facet).commit()?;
    assert_eq!(
        vault.facet_exposure(&facet)?,
        None,
        "the headerless delete swept the exposure row"
    );
    assert!(
        vault.get_claim(&exposure_mirror)?.is_none(),
        "and its owner-visible mirror"
    );
    Ok(())
}

/// The CONTACT half of the same headerless sweep, plus the reclassification
/// ledger — one delete, no type byte, all three families keyed by id alone.
#[test]
fn headerless_contact_deletion_leaves_no_clearance_or_ledger_residue() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let contact = test_id(0x3B);
    seed_contact(&vault, contact, "a@example.com");
    let facet = test_id(0x3C);
    put_facet(&vault, &facet);
    grant_clearance(&vault, &contact, vec![facet]);
    let clearance_mirror = facet_clearance_claim_id(&contact)?;

    // A ledger event whose RECORD is the contact — swept by the record-side
    // prefix scan, which needs no type either.
    let claim = test_id(0x3D);
    put_public_claim(&vault, &claim, test_id(0x3E));
    stamp_facet_of(&vault, &claim, &facet);
    assert!(vault.unstamp_facet_of(&claim, &facet, 200)?);
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1
    );

    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, contact.as_bytes())?;
        vault.store.entities.delete(wtxn, claim.as_bytes())?;
        Ok(())
    })?;

    vault.batch().delete(&contact).commit()?;
    assert!(
        vault.contact_facet_clearance(&contact)?.is_none(),
        "headerless contact delete swept the clearance row"
    );
    assert!(vault.get_claim(&clearance_mirror)?.is_none());

    vault.batch().delete(&claim).commit()?;
    assert!(
        vault
            .facet_reclassification_ledger(&claim, &facet)?
            .is_empty(),
        "headerless record delete swept its ledger events"
    );
    Ok(())
}

// ─── fix-14 defect 1: the unstamp's two commits are bridged by a marker ─────

/// Builds a window doc carrying `record -FacetOf-> facet` and persists it,
/// returning the window key and the CRDT edge key — the durable shape a real
/// window has after Observer A / reverse remat published the stamp.
#[cfg(feature = "sync")]
fn publish_stamp_to_window(
    vault: &Vault,
    record: &EntityId,
    facet: &EntityId,
) -> Result<(crate::sync::WindowKey, String)> {
    use crate::sync::bridge::format_edge_key;
    use crate::sync::loro_support::doc_version_vector;
    use crate::sync::schema::create_window_doc;
    use crate::sync::window::{persist_window_doc_in_txn, write_window_svf_in_txn};

    let window_key = crate::sync::WindowKey::from_timestamp(vault.get_learned_at(record)?);
    let doc = create_window_doc("local", &window_key);
    let edge_key = format_edge_key(record, EdgeKind::FacetOf, facet);
    crate::sync::window::reverse_rematerialize(vault, &doc, &window_key)?;
    assert!(
        crate::sync::loro_support::map_get_bytes(&doc.get_map("edges"), &edge_key).is_some(),
        "fixture: reverse remat must publish the stamp into the window doc"
    );
    let snapshot = crate::sync::window::export_scrubbed_window_snapshot(vault, &window_key, &doc)?;
    let vv = doc_version_vector(&doc);
    vault.with_write_txn(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, &window_key, &snapshot, &vv)?;
        write_window_svf_in_txn(vault, wtxn, &window_key)
    })?;
    Ok((window_key, edge_key))
}

/// Whether a window's DURABLE state carries an `edges` key, read the way
/// production recovery reads it (snapshot + pending rows, or a pure rebuild).
#[cfg(feature = "sync")]
fn persisted_window_holds_edge(
    vault: &Vault,
    window_key: &crate::sync::WindowKey,
    edge_key: &str,
) -> Result<bool> {
    let doc = match crate::sync::window::load_window_from_state(vault, "local", window_key) {
        Ok(doc) => doc,
        Err(Error::WindowNotFound { .. }) => {
            crate::sync::window::rebuild_window_from_updates(vault, "local", window_key)?
        }
        Err(err) => return Err(err),
    };
    Ok(crate::sync::loro_support::map_get_bytes(&doc.get_map("edges"), edge_key).is_some())
}

/// Runs the recovery pass that used to RESTORE the stamp: load the window's
/// durable doc and forward-rematerialize it, exactly as `open_window` does.
#[cfg(feature = "sync")]
fn recover_window(vault: &Vault, window_key: &crate::sync::WindowKey) -> Result<()> {
    let doc = match crate::sync::window::load_window_from_state(vault, "local", window_key) {
        Ok(doc) => doc,
        Err(Error::WindowNotFound { .. }) => {
            crate::sync::window::rebuild_window_from_updates(vault, "local", window_key)?
        }
        Err(err) => return Err(err),
    };
    crate::sync::window::forward_rematerialize(
        vault,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        window_key,
    )?;
    // The recovered doc is what an open would go on to persist.
    let snapshot = crate::sync::window::export_scrubbed_window_snapshot(vault, window_key, &doc)?;
    let vv = crate::sync::loro_support::doc_version_vector(&doc);
    vault.with_write_txn(|wtxn| {
        crate::sync::window::persist_window_doc_in_txn(vault, wtxn, window_key, &snapshot, &vv)?;
        crate::sync::window::write_window_svf_in_txn(vault, wtxn, window_key)
    })
}

/// THE RECOVERY-ATOMICITY REGRESSION — a crash AFTER the LMDB commit.
///
/// `unstamp_facet_of` commits consent + the LMDB tear, then removes the CRDT
/// carrier in a SECOND commit (Loro and LMDB are separate durability domains —
/// there is no one-commit option). A crash in between leaves consent and the
/// LMDB deletion durable while the doc stamp survives, and retry is no escape:
/// the LMDB row is already absent, so a re-issued call answers `false` and does
/// nothing, while the next open's forward remat writes the surviving doc stamp
/// straight back into LMDB. A CONSENTED unstamp reversing itself is the worst
/// failure direction this lane has.
///
/// The crash is injected at exactly that point, so the durable state under test
/// is the real one: ledger event, torn rows and pending marker on disk, CRDT
/// carrier alive.
///
/// MUTATION PROBE: drop the `facet_unstamp_pending_key` write from
/// `unstamp_facet_of`'s txn, or the `drain_pending_facet_unstamps` call in
/// `forward_rematerialize`, and this fails — the stamp is back in LMDB.
#[cfg(feature = "sync")]
#[test]
fn a_crash_after_the_lmdb_commit_resumes_the_unstamp_on_recovery() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x71);
    let facet = test_id(0x72);
    put_facet(&vault, &facet);
    put_public_claim(&vault, &claim, test_id(0x73));
    stamp_facet_of(&vault, &claim, &facet);
    let (window_key, edge_key) = publish_stamp_to_window(&vault, &claim, &facet)?;

    // THE CRASH: the LMDB txn commits, the process dies before the doc removal.
    super::INJECT_UNSTAMP_DOC_REMOVAL_SKIP.with(|cell| cell.set(true));
    assert!(vault.unstamp_facet_of(&claim, &facet, 500)?);
    assert!(
        !vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "fixture: the LMDB tear committed"
    );
    assert_eq!(
        vault.facet_reclassification_ledger(&claim, &facet)?.len(),
        1,
        "fixture: the consent is durable"
    );
    assert!(
        persisted_window_holds_edge(&vault, &window_key, &edge_key)?,
        "fixture: the CRDT carrier survived the crash — this is the hazard"
    );
    assert_eq!(
        super::pending_unstamp_count(&vault)?,
        1,
        "the pending marker is the crash's durable signature"
    );
    assert!(
        !vault.unstamp_facet_of(&claim, &facet, 501)?,
        "a re-issued unstamp finds nothing to tear — recovery is the only path"
    );

    // RECOVERY. Forward remat runs; without the drain it writes the surviving
    // doc stamp back into LMDB.
    recover_window(&vault, &window_key)?;
    assert!(
        !vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the consented unstamp must NOT reverse itself on recovery"
    );
    assert!(
        !persisted_window_holds_edge(&vault, &window_key, &edge_key)?,
        "recovery finishes the removal instead of restoring the stamp"
    );
    assert_eq!(
        super::pending_unstamp_count(&vault)?,
        0,
        "and discharges the marker"
    );

    // A second recovery pass is a no-op.
    recover_window(&vault, &window_key)?;
    assert!(!vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?);
    assert!(!persisted_window_holds_edge(
        &vault,
        &window_key,
        &edge_key
    )?);
    Ok(())
}

/// The same crash one step later: the DOC removal committed but the process
/// died before the marker could clear. The drain must be idempotent — re-running
/// a removal that already landed removes nothing, restores nothing, and clears
/// the marker.
#[cfg(feature = "sync")]
#[test]
fn a_crash_after_the_doc_commit_leaves_nothing_to_restore() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x74);
    let facet = test_id(0x75);
    put_facet(&vault, &facet);
    put_public_claim(&vault, &claim, test_id(0x76));
    stamp_facet_of(&vault, &claim, &facet);
    let (window_key, edge_key) = publish_stamp_to_window(&vault, &claim, &facet)?;

    assert!(vault.unstamp_facet_of(&claim, &facet, 500)?);
    assert!(!persisted_window_holds_edge(
        &vault,
        &window_key,
        &edge_key
    )?);
    assert_eq!(super::pending_unstamp_count(&vault)?, 0);

    // Re-arm: "the doc removal landed, the marker clear did not".
    super::rearm_pending_unstamp(&vault, &claim, &facet)?;

    recover_window(&vault, &window_key)?;
    assert!(
        !vault.edge_exists(&claim, EdgeKind::FacetOf, &facet)?,
        "the stamp stays gone from LMDB"
    );
    assert!(
        !persisted_window_holds_edge(&vault, &window_key, &edge_key)?,
        "and from the window — the drain is idempotent"
    );
    assert_eq!(
        super::pending_unstamp_count(&vault)?,
        0,
        "the marker discharges once the removal is proven durable"
    );
    Ok(())
}

/// A malformed pending-unstamp marker key is LOUD, never a silent skip: a key
/// we cannot parse names an unstamp we cannot finish, and continuing past it
/// would let the resurrection the drain exists to stop proceed unnoticed.
/// Same stance as every other key parse in this module.
#[cfg(feature = "sync")]
#[test]
fn a_malformed_pending_unstamp_marker_fails_loud() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let claim = test_id(0x77);
    let facet = test_id(0x78);
    put_facet(&vault, &facet);
    put_public_claim(&vault, &claim, test_id(0x79));
    stamp_facet_of(&vault, &claim, &facet);
    let (window_key, _) = publish_stamp_to_window(&vault, &claim, &facet)?;

    // A truncated key: the pair prefix without the facet half. Reading a prefix
    // of it would address some OTHER pair — i.e. remove a different record's
    // stamp — so length is exact.
    let mut short = super::facet_unstamp_pending_key(&claim, &facet);
    short.truncate(short.len() - 1);
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(wtxn, &short, &[])?;
        Ok(())
    })?;

    let doc = crate::sync::window::load_window_from_state(&vault, "local", &window_key)?;
    let err = crate::sync::window::forward_rematerialize(
        &vault,
        &doc,
        &crate::sync::bridge::Materializer::new(),
        &window_key,
    )
    .expect_err("a malformed marker must abort recovery, not be skipped");
    assert_eq!(err.kind(), ErrorKind::CorruptedIndex);
    Ok(())
}
