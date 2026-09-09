use super::*;
use crate::claim::encode_claim_body;
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};

fn interval() -> TimeRange {
    TimeRange {
        start: OBSERVED_AT,
        end: OBSERVED_AT,
    }
}

fn passport_body(identity: EntityId, message: &str) -> ClaimBody {
    let passport = ThreadPassport {
        identity_ref: identity,
        message_id: mid(message),
        thread_ref: mid(message).minted_thread_ref(),
        mask: ThreadMask::new(identity, entity(0xA9)),
        observed_at: OBSERVED_AT,
    };
    let mut body = ClaimBody::new(
        PREDICATE_THREAD_PASSPORT,
        ClaimSubject::Entity(identity),
        encode_passport_value(&passport, &[], None),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(OBSERVED_AT);
    body
}

fn alias_body(identity: EntityId, from: &str, to: &str) -> ClaimBody {
    let mut body = passport_body(identity, "alias@x");
    body.predicate = PREDICATE_THREAD_ALIAS.to_owned();
    body.value = encode_alias_value(identity, from, to, OBSERVED_AT);
    body
}

fn set_value(body: &mut ClaimBody, key: &str, replacement: Value) {
    let Value::Map(entries) = &mut body.value else {
        panic!("map");
    };
    *entries
        .iter_mut()
        .find(|(field, _)| field.as_str() == Some(key))
        .unwrap() = (Value::from(key), replacement);
}

fn replicate(vault: &Vault, id: EntityId, body: &ClaimBody) -> Result<()> {
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            interval(),
            OBSERVED_AT,
            &encode_claim_body(body)?,
        )
        .commit()
}

fn family_rows(vault: &Vault) -> Vec<(EntityId, ClaimBody)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    [PREDICATE_THREAD_PASSPORT, PREDICATE_THREAD_ALIAS]
        .into_iter()
        .flat_map(|predicate| {
            vault
                .claims_with_predicate_in_txn(&rtxn, predicate)
                .unwrap()
        })
        .collect()
}

#[test]
fn malformed_thread_claims_fail_at_public_batch_and_replicated_doors() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let mut roots = [
        mid("a@x").minted_thread_ref(),
        mid("b@x").minted_thread_ref(),
    ];
    roots.sort();
    let passport = passport_body(identity, "root@x");
    let alias = alias_body(identity, &roots[1], &roots[0]);
    let mut malformed = Vec::new();
    for good in [&passport, &alias] {
        for (key, bad) in [
            (KEY_IDENTITY_REF, Value::from(entity(0x62).to_hex())),
            (KEY_SCHEMA_VERSION, Value::from(99)),
            (KEY_OBSERVED_AT, Value::from(-1)),
        ] {
            let mut body = good.clone();
            set_value(&mut body, key, bad);
            malformed.push(body);
        }
        let mut duplicate = good.clone();
        if let Value::Map(entries) = &mut duplicate.value {
            entries.push(entries[0].clone());
        }
        malformed.push(duplicate);
        let mut extra = good.clone();
        if let Value::Map(entries) = &mut extra.value {
            entries.push((Value::from("extra"), Value::Nil));
        }
        malformed.push(extra);
        let mut missing = good.clone();
        if let Value::Map(entries) = &mut missing.value {
            entries.pop();
        }
        malformed.push(missing);
        let mut body = good.clone();
        body.source = None;
        malformed.push(body);
        let mut body = good.clone();
        body.valid_from = Some(OBSERVED_AT + 1);
        malformed.push(body);
        let mut body = good.clone();
        body.stale = true;
        malformed.push(body);
        for approval in [ClaimApprovalStatus::Proposed, ClaimApprovalStatus::Rejected] {
            let mut body = good.clone();
            body.approval = approval;
            malformed.push(body);
        }
        let mut body = good.clone();
        body.valid_to = Some(OBSERVED_AT);
        malformed.push(body);
        let mut body = good.clone();
        body.lifecycle = ClaimLifecycleStatus::Retracted;
        body.valid_to = Some(OBSERVED_AT - 1);
        malformed.push(body);
        // These APIs have no world or relationship context. Scoped evidence
        // must not become global routing authority through their readers.
        let mut body = good.clone();
        body.world = Some(entity(0x63));
        malformed.push(body);
        let mut body = good.clone();
        body.rel = Some(entity(0x64));
        malformed.push(body);
        let mut body = good.clone();
        body.scope = Some(Value::Map(Vec::new()));
        malformed.push(body);
    }
    let mut body = passport.clone();
    set_value(
        &mut body,
        KEY_REFERENCES,
        Value::Array(vec![Value::from("same@x"), Value::from("same@x")]),
    );
    malformed.push(body);
    let mut body = passport.clone();
    set_value(&mut body, KEY_IN_REPLY_TO, Value::from("<wrapped@x>"));
    malformed.push(body);
    let mut body = passport;
    set_value(&mut body, KEY_THREAD_REF, Value::from("mail:v1:short"));
    malformed.push(body);
    malformed.push(alias_body(identity, &roots[0], &roots[1]));
    malformed.push(alias_body(identity, &roots[0], &roots[0]));
    for body in malformed {
        let id = EntityId::now();
        assert!(
            vault
                .put_claim(&id, &body, interval(), OBSERVED_AT)
                .is_err()
        );
        let bytes = encode_claim_body(&body).unwrap();
        assert!(
            vault
                .batch()
                .put(&id, ENTITY_TYPE_CLAIM, interval(), OBSERVED_AT, &bytes)
                .commit()
                .is_err()
        );
        assert!(replicate(&vault, id, &body).is_err());
        assert!(vault.get_claim(&id).unwrap().is_none());
    }
    assert!(family_rows(&vault).is_empty());
}

#[test]
fn generic_thread_claim_ownership_and_reference_proof_are_checked() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let person = crate::comm::resolve_or_create_comm_party(&vault, "person@x").unwrap();
    let wrong = passport_body(person, "wrong@x");
    assert!(
        vault
            .put_claim(&EntityId::now(), &wrong, interval(), OBSERVED_AT)
            .is_err()
    );
    assert!(replicate(&vault, EntityId::now(), &wrong).is_err());
    let mut forged = passport_body(identity, "new@x");
    set_value(
        &mut forged,
        KEY_THREAD_REF,
        Value::from(mid("unrelated@x").minted_thread_ref()),
    );
    assert!(
        vault
            .put_claim(&EntityId::now(), &forged, interval(), OBSERVED_AT)
            .is_err()
    );
    // Partial remote evidence is stored but cannot route reads.
    replicate(&vault, EntityId::now(), &forged).unwrap();
    assert!(
        vault
            .thread_passport(&identity, &mid("new@x"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn unknown_owner_and_alias_evidence_are_reconsidered_on_arrival() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    let body = passport_body(identity, "root@x");
    let id = EntityId::now();
    replicate(&vault, id, &body).unwrap();
    assert!(
        vault
            .thread_passport(&identity, &mid("root@x"))
            .unwrap()
            .is_none()
    );
    seed_identity(&vault, identity, "agent@example.com");
    assert!(
        vault
            .thread_passport(&identity, &mid("root@x"))
            .unwrap()
            .is_some()
    );
    // No separately replicated edge is needed: apply_put made ClaimOf.
    assert!(vault.claims_for_subject(&identity).unwrap().contains(&id));
    let other = vault
        .record_thread_passport(input(identity, "other@x", OBSERVED_AT + 1))
        .unwrap();
    let mut refs = [
        mid("root@x").minted_thread_ref(),
        other.canonical_thread_ref,
    ];
    refs.sort();
    let forged = alias_body(identity, &refs[1], &refs[0]);
    assert!(
        vault
            .put_claim(&EntityId::now(), &forged, interval(), OBSERVED_AT)
            .is_err()
    );
    replicate(&vault, EntityId::now(), &forged).unwrap();
    assert_eq!(vault.canonical_thread_ref(&refs[1]).unwrap(), refs[1]);
    vault
        .record_thread_passport(
            input(identity, "bridge@x", OBSERVED_AT + 2)
                .with_references(vec![mid("root@x"), mid("other@x")]),
        )
        .unwrap();
    assert_eq!(vault.canonical_thread_ref(&refs[1]).unwrap(), refs[0]);
}

#[test]
fn unknown_parent_arrival_and_replay_preserve_passport_and_mask() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let child = vault
        .record_thread_passport(
            input(identity, "child@x", OBSERVED_AT)
                .with_references(vec![mid("grandparent@x")])
                .with_in_reply_to(mid("parent@x")),
        )
        .unwrap();
    let parent = vault
        .record_thread_passport(input(identity, "parent@x", OBSERVED_AT + 1))
        .unwrap();
    let grandparent = vault
        .record_thread_passport(input(identity, "grandparent@x", OBSERVED_AT + 2))
        .unwrap();
    assert_eq!(parent.canonical_thread_ref, child.canonical_thread_ref);
    assert_eq!(grandparent.canonical_thread_ref, child.canonical_thread_ref);
    let original = vault
        .thread_passport(&identity, &mid("child@x"))
        .unwrap()
        .unwrap();
    let other = vault
        .record_thread_passport(input(identity, "other@x", OBSERVED_AT + 3))
        .unwrap();
    let replay = vault
        .record_thread_passport(
            ThreadPassportInput::new(identity, entity(0xB9), mid("child@x"), OBSERVED_AT + 4)
                .with_references(vec![mid("other@x"), mid("later@x")]),
        )
        .unwrap();
    assert_eq!(replay.passport, original);
    assert_eq!(
        replay.canonical_thread_ref,
        child.canonical_thread_ref.min(other.canonical_thread_ref)
    );
    let later = vault
        .record_thread_passport(input(identity, "later@x", OBSERVED_AT + 5))
        .unwrap();
    assert_eq!(later.canonical_thread_ref, replay.canonical_thread_ref);
    assert_eq!(
        vault
            .sticky_thread_mask(&later.canonical_thread_ref, None)
            .unwrap(),
        StickyMaskDecision::Keep(original.mask)
    );
    assert_eq!(active_passport_count(&vault), 5);
    let rows = family_rows(&vault);
    let stored = rows
        .iter()
        .find(|(_, body)| {
            body.predicate == PREDICATE_THREAD_PASSPORT
                && decode_passport_value(identity, &body.value).unwrap() == original
        })
        .unwrap();
    let (references, parent) = decode_relationships(&stored.1.value).unwrap();
    assert!(references.contains(&mid("grandparent@x")) || references.contains(&mid("later@x")));
    assert!(parent.is_none() || parent == Some(mid("parent@x")));
}

#[test]
fn valid_offline_alias_forks_and_duplicate_passports_converge_in_both_orders() {
    let (_a_dir, a) = test_vault();
    let (_b_dir, b) = test_vault();
    let identity = entity(0x61);
    for vault in [&a, &b] {
        seed_identity(vault, identity, "agent@example.com");
    }
    let mut messages = [mid("a@x"), mid("b@x"), mid("c@x")];
    messages.sort_by_key(CanonicalMessageId::minted_thread_ref);
    for vault in [&a, &b] {
        for message in &messages {
            vault
                .record_thread_passport(ThreadPassportInput::new(
                    identity,
                    entity(0xA9),
                    message.clone(),
                    OBSERVED_AT,
                ))
                .unwrap();
        }
    }
    a.record_thread_passport(
        input(identity, "bridge-a@x", OBSERVED_AT + 1)
            .with_references(vec![messages[2].clone(), messages[0].clone()]),
    )
    .unwrap();
    b.record_thread_passport(
        input(identity, "bridge-b@x", OBSERVED_AT + 1)
            .with_references(vec![messages[2].clone(), messages[1].clone()]),
    )
    .unwrap();
    a.record_thread_passport(
        input(identity, "duplicate@x", OBSERVED_AT + 2).with_in_reply_to(messages[0].clone()),
    )
    .unwrap();
    b.record_thread_passport(
        ThreadPassportInput::new(identity, entity(0xB9), mid("duplicate@x"), OBSERVED_AT + 3)
            .with_in_reply_to(messages[1].clone()),
    )
    .unwrap();
    let a_rows = family_rows(&a);
    let b_rows = family_rows(&b);
    for (vault, roots) in [(&a, [0, 1, 0]), (&b, [0, 1, 1])] {
        for (message, root) in messages.iter().zip(roots) {
            assert_eq!(
                vault
                    .canonical_thread_ref(&message.minted_thread_ref())
                    .unwrap(),
                messages[root].minted_thread_ref()
            );
        }
    }
    for (id, body) in b_rows.iter().rev() {
        replicate(&a, *id, body).unwrap();
    }
    for (id, body) in &a_rows {
        replicate(&b, *id, body).unwrap();
    }
    let canonical = messages[0].minted_thread_ref();
    for vault in [&a, &b] {
        for message in &messages {
            assert_eq!(
                vault
                    .canonical_thread_ref(&message.minted_thread_ref())
                    .unwrap(),
                canonical
            );
        }
        assert_eq!(active_passport_count(vault), 6);
        let singular = vault
            .thread_passport(&identity, &mid("duplicate@x"))
            .unwrap()
            .unwrap();
        assert_eq!(singular.mask.actor_ref, entity(0xA9));
        let all = vault.thread_passports(&canonical).unwrap();
        assert_eq!(
            all.iter()
                .filter(|row| row.message_id == mid("duplicate@x"))
                .collect::<Vec<_>>(),
            vec![&singular]
        );
        assert_eq!(
            vault
                .record_thread_passport(input(identity, "duplicate@x", OBSERVED_AT + 5))
                .unwrap()
                .passport,
            singular
        );
    }
    assert_eq!(
        a.thread_passports(&canonical).unwrap(),
        b.thread_passports(&canonical).unwrap()
    );
    assert_eq!(
        a.sticky_thread_mask(&canonical, None).unwrap(),
        b.sticky_thread_mask(&canonical, None).unwrap()
    );
}

#[test]
fn generic_passport_puts_maintain_the_existing_subject_index_and_delete_cleanly() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let id = EntityId::now();
    let body = passport_body(identity, "indexed@x");
    let actor = entity(0xA9);
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            interval(),
            OBSERVED_AT,
            b"actor",
        )
        .unwrap();
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Agent),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("fixture")).unwrap(),
        ClaimApprovalStatus::Auto,
    );
    let candidate = ClaimCandidate::new(body.predicate, body.subject, body.value, body.confidence)
        .with_validity(body.valid_from, body.valid_to);
    vault
        .batch()
        .claim_candidate(&id, candidate, &envelope, interval(), OBSERVED_AT)
        .commit()
        .unwrap();
    assert_eq!(
        vault
            .thread_passport(&identity, &mid("indexed@x"))
            .unwrap()
            .unwrap()
            .thread_ref,
        mid("indexed@x").minted_thread_ref()
    );
    assert!(vault.claims_for_subject(&identity).unwrap().contains(&id));
    vault.batch().delete(&id).commit().unwrap();
    assert!(
        vault
            .thread_passport(&identity, &mid("indexed@x"))
            .unwrap()
            .is_none()
    );
    assert!(!vault.claims_for_subject(&identity).unwrap().contains(&id));
}

#[test]
fn memberships_and_leave_boundaries_survive_aliasing_before_and_after_projection() {
    for project_before_bridge in [false, true] {
        let (_dir, vault) = test_vault();
        let identity = entity(0x61);
        seed_identity(&vault, identity, "agent@example.com");
        let a = vault
            .record_thread_passport(input(identity, "a@x", OBSERVED_AT))
            .unwrap();
        let b = vault
            .record_thread_passport(input(identity, "b@x", OBSERVED_AT + 1))
            .unwrap();
        let party = "party@example.com";
        let other = "other@example.com";
        vault
            .join_thread_party(&a.canonical_thread_ref, party, true, OBSERVED_AT + 10)
            .unwrap();
        vault
            .join_thread_party(&b.canonical_thread_ref, party, true, OBSERVED_AT + 11)
            .unwrap();
        vault
            .join_thread_party(&b.canonical_thread_ref, other, true, OBSERVED_AT + 12)
            .unwrap();
        if project_before_bridge {
            crate::comm::run_comm_projector(&vault).unwrap();
        }
        let bridge = vault
            .record_thread_passport(
                input(identity, "bridge@x", OBSERVED_AT + 20)
                    .with_references(vec![mid("a@x"), mid("b@x")]),
            )
            .unwrap();
        crate::comm::run_comm_projector(&vault).unwrap();
        for thread in [
            &a.canonical_thread_ref,
            &b.canonical_thread_ref,
            &bridge.canonical_thread_ref,
        ] {
            assert_eq!(
                crate::comm::count_active_thread_member_claims(&vault, thread, party).unwrap(),
                1
            );
            assert_eq!(
                crate::comm::count_active_thread_member_claims(&vault, thread, other).unwrap(),
                1
            );
        }
        let contact = crate::comm::materialize_contact_record(&vault, party).unwrap();
        let view = rmpv::decode::read_value(&mut std::io::Cursor::new(contact)).unwrap();
        let Value::Map(entries) = view else {
            panic!("contact map");
        };
        let threads = entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("threads"))
            .unwrap()
            .1
            .as_array()
            .unwrap();
        assert_eq!(
            threads,
            &vec![Value::from(bridge.canonical_thread_ref.as_str())]
        );
        vault
            .join_thread_party(&a.canonical_thread_ref, party, false, OBSERVED_AT + 30)
            .unwrap();
        crate::comm::run_comm_projector(&vault).unwrap();
        vault
            .join_thread_party(&b.canonical_thread_ref, party, true, OBSERVED_AT + 25)
            .unwrap();
        crate::comm::run_comm_projector(&vault).unwrap();
        assert_eq!(
            crate::comm::count_active_thread_member_claims(
                &vault,
                &bridge.canonical_thread_ref,
                party
            )
            .unwrap(),
            0
        );
        assert_eq!(
            crate::comm::count_active_thread_member_claims(
                &vault,
                &bridge.canonical_thread_ref,
                other
            )
            .unwrap(),
            1
        );
        vault
            .join_thread_party(&b.canonical_thread_ref, party, true, OBSERVED_AT + 31)
            .unwrap();
        crate::comm::run_comm_projector(&vault).unwrap();
        assert_eq!(
            crate::comm::count_active_thread_member_claims(
                &vault,
                &bridge.canonical_thread_ref,
                party
            )
            .unwrap(),
            1
        );
    }
}

#[test]
fn a_leave_without_a_claim_on_one_root_closes_an_older_join_after_merge() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let a = vault
        .record_thread_passport(input(identity, "a@x", OBSERVED_AT))
        .unwrap();
    let b = vault
        .record_thread_passport(input(identity, "b@x", OBSERVED_AT + 1))
        .unwrap();
    vault
        .join_thread_party(&a.canonical_thread_ref, "party@x", true, OBSERVED_AT + 10)
        .unwrap();
    vault
        .join_thread_party(&b.canonical_thread_ref, "party@x", false, OBSERVED_AT + 20)
        .unwrap();
    crate::comm::run_comm_projector(&vault).unwrap();
    assert_eq!(
        crate::comm::count_active_thread_member_claims(&vault, &a.canonical_thread_ref, "party@x")
            .unwrap(),
        1
    );
    let bridge = vault
        .record_thread_passport(
            input(identity, "bridge@x", OBSERVED_AT + 30)
                .with_references(vec![mid("a@x"), mid("b@x")]),
        )
        .unwrap();
    assert_eq!(
        crate::comm::count_active_thread_member_claims(
            &vault,
            &bridge.canonical_thread_ref,
            "party@x"
        )
        .unwrap(),
        0
    );
}

#[test]
fn passport_hot_path_does_not_decode_unrelated_claim_rows() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    // Deliberately unreadable unrelated CLAIM. A complete type-0 scan would
    // fail here, while the real identity/ClaimOf indexes never visit it.
    let id = EntityId::now();
    let raw = crate::test_util::entity_record(ENTITY_TYPE_CLAIM, interval(), OBSERVED_AT, &[0xC1]);
    let mut wtxn = vault.store.env.write_txn().unwrap();
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &raw)
        .unwrap();
    vault
        .store
        .type_index
        .put(
            &mut wtxn,
            &crate::store::Store::encode_type_key(ENTITY_TYPE_CLAIM, &id),
            &[],
        )
        .unwrap();
    wtxn.commit().unwrap();
    vault
        .record_thread_passport(input(identity, "indexed@x", OBSERVED_AT))
        .unwrap();
    assert!(
        vault
            .thread_passport(&identity, &mid("indexed@x"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn unsupported_remote_passport_relationships_cannot_bridge_other_roots() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let a = vault
        .record_thread_passport(input(identity, "a@x", OBSERVED_AT))
        .unwrap();
    let b = vault
        .record_thread_passport(input(identity, "b@x", OBSERVED_AT + 1))
        .unwrap();
    let mut forged = passport_body(identity, "forged@x");
    set_value(
        &mut forged,
        KEY_REFERENCES,
        Value::Array(vec![Value::from("a@x"), Value::from("b@x")]),
    );
    set_value(
        &mut forged,
        KEY_THREAD_REF,
        Value::from(mid("absent@x").minted_thread_ref()),
    );
    replicate(&vault, EntityId::now(), &forged).unwrap();
    assert_eq!(
        vault.canonical_thread_ref(&a.canonical_thread_ref).unwrap(),
        a.canonical_thread_ref
    );
    assert_eq!(
        vault.canonical_thread_ref(&b.canonical_thread_ref).unwrap(),
        b.canonical_thread_ref
    );
}

#[cfg(feature = "sync")]
#[path = "sync_regressions.rs"]
mod sync_regressions;

#[test]
fn thread_evidence_cannot_change_subject_predicate_or_mask_on_overwrite() {
    let (_dir, vault) = test_vault();
    let identity = entity(0x61);
    seed_identity(&vault, identity, "agent@example.com");
    let id = EntityId::now();
    let body = passport_body(identity, "root@x");
    vault
        .put_claim(&id, &body, interval(), OBSERVED_AT)
        .unwrap();
    let mut changed_mask = body.clone();
    set_value(
        &mut changed_mask,
        KEY_ACTOR_REF,
        Value::from(entity(0xB9).to_hex()),
    );
    let mut changed_predicate = body.clone();
    changed_predicate.predicate = "profile.note".to_owned();
    let mut edge_subject = body.clone();
    edge_subject.subject = ClaimSubject::Edge {
        source: identity,
        kind: crate::edge::EdgeKind::Mentions,
        target: entity(0x62),
    };
    for changed in [changed_mask, changed_predicate, edge_subject] {
        assert!(
            vault
                .put_claim(&id, &changed, interval(), OBSERVED_AT)
                .is_err()
        );
        assert!(replicate(&vault, id, &changed).is_err());
        assert_eq!(vault.get_claim(&id).unwrap(), Some(body.clone()));
    }
}
