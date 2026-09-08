//! Actor bind, rebind and revoke fold, qualification and DAG merge.

use super::support::*;
use super::*;

#[test]
fn bind_rebind_revoke_ops_roundtrip_and_golden_vectors() {
    let fixture = bind_fixture(200);
    let key = fixture.owner_key.clone();
    let actor = fixture.actor;
    for op in [
        bind_op(&key, actor, "human", 1),
        rebind_op(&key, actor, "agent", 2),
        revoke_actor_op(&key, 3),
    ] {
        let decoded = decode_op(&op_value_with_genesis_delay(&op, true)).unwrap();
        assert_eq!(
            decoded, op,
            "op must survive a canonical encode/decode cycle"
        );
    }

    // GOLDEN BYTE VECTORS — literal MessagePack captured from the reviewed
    // encoder, NOT re-derived from it. Comparing structure against the current
    // encoder passes vacuously under any encoding change; these bytes do not.
    //
    // Pinned wire contract, decodable straight out of the hex below:
    //   bind/rebind: fixmap(5) {kind, authority_key, actor_ref, actor_class, epoch}
    //   revoke:      fixmap(3) {kind, authority_key, epoch}
    //   kind:          "bind_actor" | "rebind_actor" | "revoke_actor"
    //   authority_key: fixmap(2) {suite: "ed25519", public_key: bin8(32)}
    //   actor_ref:     str8, 32 lowercase hex chars (the grant_ref precedent)
    //   actor_class:   str, EXACT ("human"/"agent"/"system" — never normalized)
    //   epoch:         positive fixint
    // Changing ANY of field order, key spelling, map arity, or a value's
    // MessagePack type breaks these vectors, which is the entire point.
    //
    // Fixture inputs the vectors were captured against; pinned so a fixture
    // drift reports itself here instead of as an opaque byte mismatch.
    assert_eq!(
        key,
        AuthorityKey::Ed25519(
            <[u8; 32]>::try_from(
                hex_bytes("97ffc883c80bee7237ef95d9b9b703d4ad63e60a21e605867682b75b8b3f4303")
                    .as_slice()
            )
            .unwrap()
        )
    );
    assert_eq!(actor.to_hex(), "c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8");
    for (label, op, golden) in [
        (
            "bind_actor",
            bind_op(&key, actor, "human", 1),
            concat!(
                "85a46b696e64aa62696e645f6163746f72ad617574686f726974795f6b657982",
                "a57375697465a765643235353139aa7075626c69635f6b6579c42097ffc883c8",
                "0bee7237ef95d9b9b703d4ad63e60a21e605867682b75b8b3f4303a96163746f",
                "725f726566d92063386338633863386338633863386338633863386338633863",
                "38633863386338ab6163746f725f636c617373a568756d616ea565706f636801",
            ),
        ),
        (
            "rebind_actor",
            rebind_op(&key, actor, "agent", 2),
            concat!(
                "85a46b696e64ac726562696e645f6163746f72ad617574686f726974795f6b65",
                "7982a57375697465a765643235353139aa7075626c69635f6b6579c42097ffc8",
                "83c80bee7237ef95d9b9b703d4ad63e60a21e605867682b75b8b3f4303a96163",
                "746f725f726566d9206338633863386338633863386338633863386338633863",
                "386338633863386338ab6163746f725f636c617373a56167656e74a565706f63",
                "6802",
            ),
        ),
        (
            "revoke_actor",
            revoke_actor_op(&key, 3),
            concat!(
                "83a46b696e64ac7265766f6b655f6163746f72ad617574686f726974795f6b65",
                "7982a57375697465a765643235353139aa7075626c69635f6b6579c42097ffc8",
                "83c80bee7237ef95d9b9b703d4ad63e60a21e605867682b75b8b3f4303a56570",
                "6f636803",
            ),
        ),
    ] {
        let encoded = encode_value(&op_value_with_genesis_delay(&op, true)).unwrap();
        assert_eq!(
            hex(&encoded),
            golden,
            "{label} encoding drifted from its golden vector"
        );
        // The vector is also a DECODE fixture: these exact bytes must still
        // parse back to the op, so a decoder that only understands the new
        // encoding cannot pass by changing both sides together.
        assert_eq!(
            decode_op(
                &rmpv::decode::read_value(&mut Cursor::new(hex_bytes(golden).as_slice())).unwrap()
            )
            .unwrap(),
            op,
            "{label} golden bytes must decode back to the op"
        );
    }

    // Unknown discriminants still fail closed: a pre-1633 binary rejecting a
    // bind body is the correct pre-release behavior, and the reverse (this
    // binary meeting a future kind) must stay a hard error, never a silent
    // default.
    let mut unknown = op_value_with_genesis_delay(&bind_op(&key, actor, "human", 1), true)
        .as_map()
        .unwrap()
        .clone();
    unknown[0].1 = Value::from("bind_actor_v2");
    assert_eq!(
        decode_op(&Value::Map(unknown)).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidAuthorityLogBody
    );

    // Signed-entry hash stability: the bind entry round-trips through the
    // canonical body encoder with an unchanged content hash.
    let entry = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&fixture.enroll).unwrap()],
        2,
        bind_op(&key, actor, "human", 1),
        102,
    );
    let bytes = encode_authority_log_entry_body(&entry).unwrap();
    let round_tripped = decode_authority_log_entry_body(&bytes).unwrap();
    assert_eq!(round_tripped, entry);
    assert_eq!(
        authority_entry_hash(&round_tripped).unwrap(),
        authority_entry_hash(&entry).unwrap()
    );
}

#[test]
fn bind_op_validate_rows() {
    let fixture = bind_fixture(201);
    let key = fixture.owner_key.clone();
    let actor = fixture.actor;

    // EXACT class vocabulary. "Human" and "owner" are the plausible
    // near-misses; admitting either would reintroduce ESB-C through a
    // spelling.
    for class in ["human", "agent", "system"] {
        validate_op(&bind_op(&key, actor, class, 1)).expect("vocabulary class must validate");
        validate_op(&rebind_op(&key, actor, class, 1)).expect("vocabulary class must validate");
    }
    for class in ["Human", "owner", "", "human ", "HUMAN", "person"] {
        assert_eq!(
            validate_op(&bind_op(&key, actor, class, 1))
                .unwrap_err()
                .kind(),
            crate::error::ErrorKind::InvalidAuthorityLogBody,
            "non-vocabulary class {class:?} must fail closed"
        );
        assert_eq!(
            validate_op(&rebind_op(&key, actor, class, 1))
                .unwrap_err()
                .kind(),
            crate::error::ErrorKind::InvalidAuthorityLogBody
        );
    }

    // Epoch 0 is the revocation watermark's zero value: a binding at epoch 0
    // could never out-rank a watermark, so it is refused at the door.
    for op in [
        bind_op(&key, actor, "human", 0),
        rebind_op(&key, actor, "human", 0),
        revoke_actor_op(&key, 0),
    ] {
        assert_eq!(
            validate_op(&op).unwrap_err().kind(),
            crate::error::ErrorKind::InvalidAuthorityLogBody
        );
    }

    // Key validation still runs on every arm.
    let bad_key = AuthorityKey::P256(vec![9; 33]);
    for op in [
        bind_op(&bad_key, actor, "human", 1),
        rebind_op(&bad_key, actor, "human", 1),
        revoke_actor_op(&bad_key, 1),
    ] {
        assert!(
            validate_op(&op).is_err(),
            "invalid key must fail validate_op"
        );
    }

    // Reserved-sentinel actor_ref fails DECODE (from_hex routes from_bytes).
    let mut fields = op_value_with_genesis_delay(&bind_op(&key, actor, "human", 1), true)
        .as_map()
        .unwrap()
        .clone();
    fields[2].1 = Value::from(hex(&[0; 16]));
    assert_eq!(
        decode_op(&Value::Map(fields.clone())).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidAuthorityLogBody,
        "reserved sentinel actor_ref must fail closed at decode"
    );
    // Non-canonical hex is refused by the round-trip check.
    fields[2].1 = Value::from(actor.to_hex().to_uppercase());
    assert_eq!(
        decode_op(&Value::Map(fields)).unwrap_err().kind(),
        crate::error::ErrorKind::InvalidAuthorityLogBody
    );
}

#[test]
fn actor_binding_fold_transition_table() {
    let fixture = bind_fixture(202);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();
    let other_actor = scope_entity(0x5a);

    // bind -> Active
    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let base = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        bind.clone(),
    ];
    let fold = fold_authority_log_without_seen_time_delay(&base);
    assert!(
        fold.issues.is_empty(),
        "clean bind must fold without issues"
    );
    assert_eq!(folded_status(&fold, &key), Some(ActorBindingStatus::Active));
    assert!(actor_binding_is_active(&fold, &fixture.actor, "human"));

    // rebind bumps the epoch and retargets the actor
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let rebind = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        rebind_op(&key, other_actor, "human", 2),
        103,
    );
    let mut with_rebind = base.clone();
    with_rebind.push(rebind);
    let fold = fold_authority_log_without_seen_time_delay(&with_rebind);
    assert!(fold.issues.is_empty());
    let binding = &fold.actor_bindings[&key];
    assert_eq!(binding.actor_ref, other_actor);
    assert_eq!(binding.epoch, 2);
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));
    assert!(actor_binding_is_active(&fold, &other_actor, "human"));

    // revoke watermark kills every binding at epoch <= watermark
    let revoke = cosigned_entry(&fixture, vec![bind_hash], 3, revoke_actor_op(&key, 1), 104);
    let mut with_revoke = base;
    with_revoke.push(revoke.clone());
    let fold = fold_authority_log_without_seen_time_delay(&with_revoke);
    assert!(fold.issues.is_empty());
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked)
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // A revoke that folds on a branch which never saw the bind is VALID and
    // still suppresses the bind once the branches merge. This is the reason
    // watermarks live in their own map: order must not matter.
    let orphan_revoke = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        revoke_actor_op(&key, 1),
        105,
    );
    let merged = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        orphan_revoke.clone(),
        bind,
    ];
    let fold = fold_authority_log_without_seen_time_delay(&merged);
    assert!(binding_rejection(&fold, &orphan_revoke).is_none());
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // Re-binding ABOVE the watermark re-activates.
    let revoke_hash = authority_entry_hash(&revoke).unwrap();
    let rebind_above = cosigned_entry(
        &fixture,
        vec![revoke_hash],
        4,
        bind_op(&key, fixture.actor, "human", 2),
        106,
    );
    let mut revived = with_revoke.clone();
    revived.push(rebind_above);
    let fold = fold_authority_log_without_seen_time_delay(&revived);
    assert!(fold.issues.is_empty());
    assert_eq!(folded_status(&fold, &key), Some(ActorBindingStatus::Active));
    assert!(actor_binding_is_active(&fold, &fixture.actor, "human"));
}

#[test]
fn actor_binding_rejection_rows_leave_state_untouched() {
    let fixture = bind_fixture(203);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();
    let other_actor = scope_entity(0x5b);

    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let base = vec![fixture.genesis.clone(), fixture.enroll.clone(), bind];

    // BindingExists: a second bind on a live binding must not silently
    // overwrite it — a stolen key must not be able to re-point an existing
    // identity without going through rebind's epoch discipline.
    let double_bind = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        bind_op(&key, other_actor, "human", 5),
        103,
    );
    let mut entries = base.clone();
    entries.push(double_bind.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        binding_rejection(&fold, &double_bind),
        Some(ActorBindingRejection::BindingExists)
    );
    assert_eq!(
        fold.actor_bindings[&key].actor_ref, fixture.actor,
        "rejected bind must leave the live binding untouched"
    );
    assert_eq!(fold.actor_bindings[&key].epoch, 1);

    // BindingMissing: rebind with nothing live.
    let orphan_rebind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        rebind_op(&key, fixture.actor, "human", 1),
        104,
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        orphan_rebind.clone(),
    ]);
    assert_eq!(
        binding_rejection(&fold, &orphan_rebind),
        Some(ActorBindingRejection::BindingMissing)
    );
    assert!(fold.actor_bindings.is_empty());

    // EpochNotAdvanced: rebind at or below the live epoch is a replay.
    let stale_rebind = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        rebind_op(&key, other_actor, "human", 1),
        105,
    );
    let mut entries = base.clone();
    entries.push(stale_rebind.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        binding_rejection(&fold, &stale_rebind),
        Some(ActorBindingRejection::EpochNotAdvanced)
    );
    assert_eq!(fold.actor_bindings[&key].actor_ref, fixture.actor);

    // EpochNotAdvanced on a REVOKED key: replaying the original bind after a
    // revocation must not resurrect it.
    let revoke = cosigned_entry(&fixture, vec![bind_hash], 3, revoke_actor_op(&key, 4), 106);
    let replay = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&revoke).unwrap()],
        4,
        bind_op(&key, fixture.actor, "human", 1),
        107,
    );
    let mut entries = base;
    entries.push(revoke);
    entries.push(replay.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        binding_rejection(&fold, &replay),
        Some(ActorBindingRejection::EpochNotAdvanced)
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));
}

#[test]
fn human_class_bind_requires_owner_capable_key() {
    let fixture = bind_fixture(204);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let base = [fixture.genesis.clone(), fixture.enroll.clone()];

    // The hole this closes: binding a ROLE_AGENT key at "human" class would
    // let an agent key exercise owner verbs. Human class demands a key that
    // could itself give owner consent.
    let agent_as_human = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&fixture.agent_key, fixture.actor, "human", 1),
        102,
    );
    let mut entries = base.to_vec();
    entries.push(agent_as_human.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        binding_rejection(&fold, &agent_as_human),
        Some(ActorBindingRejection::OwnerCapabilityRequired)
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // The SAME key at "agent" class is legitimate — this is the 1634 machine
    // identity seam, and refusing it would be gold-plating.
    let agent_as_agent = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&fixture.agent_key, fixture.actor, "agent", 1),
        103,
    );
    let mut entries = base.to_vec();
    entries.push(agent_as_agent);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert!(fold.issues.is_empty());
    assert_eq!(
        folded_status(&fold, &fixture.agent_key),
        Some(ActorBindingStatus::Active)
    );
    assert!(actor_binding_is_active(&fold, &fixture.actor, "agent"));
    // EXACT class: an agent-class binding never satisfies a human-class ask.
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // KeyNotInRoster: a binding may only attach to an enrolled key.
    let stranger = authority_key_from_ed(&ed_key(240));
    let unenrolled = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&stranger, fixture.actor, "agent", 1),
        104,
    );
    let mut entries = base.to_vec();
    entries.push(unenrolled.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        binding_rejection(&fold, &unenrolled),
        Some(ActorBindingRejection::KeyNotInRoster)
    );
    assert!(fold.actor_bindings.is_empty());
}

#[test]
fn binding_dies_with_roster_key() {
    let fixture = bind_fixture(205);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();
    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let base = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        bind.clone(),
    ];
    assert!(actor_binding_is_active(
        &fold_authority_log_without_seen_time_delay(&base),
        &fixture.actor,
        "human"
    ));

    // No cascade is written into binding state: Active simply requires a live
    // roster key, so every roster-killing op takes dependent bindings with it
    // automatically and order-independently.
    let recovery = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&bind).unwrap()],
        3,
        AuthorityOp::RecoveryReboot {
            new_genesis_nonce: [231; 32],
            new_device: device(
                authority_key_from_ed(&ed_key(231)),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
            tier_floor: AuthorityTier::Software,
        },
        108,
    );
    let mut entries = base.clone();
    entries.push(recovery);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked)
    );
    assert!(
        !actor_binding_is_active(&fold, &fixture.actor, "human"),
        "recovery reboot must kill bindings on the retired key"
    );

    // A rotation does NOT migrate the binding: the new key is a NEW identity
    // claim and needs its own BindActor. Explicitness over magic.
    let rotate = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&bind).unwrap()],
        3,
        AuthorityOp::RotateKey {
            old_key: key.clone(),
            new_device: device(
                authority_key_from_ed(&ed_key(232)),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        109,
    );
    let mut entries = base.clone();
    entries.push(rotate.clone());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked)
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));
    let rotated_key = authority_key_from_ed(&ed_key(232));
    assert!(
        !fold.actor_bindings.contains_key(&rotated_key),
        "rotation must not silently carry the binding to the new key"
    );

    // A fresh bind on the rotated key restores the identity.
    let rebound = {
        let entry = unsigned_entry(
            Some(fixture.vault_id),
            4,
            vec![authority_entry_hash(&rotate).unwrap()],
            bind_op(&rotated_key, fixture.actor, "human", 1),
            rotated_key.clone(),
            109,
        );
        cosign_ed(entry, &ed_key(232), &fixture.agent)
    };
    let mut entries = base;
    entries.push(rotate);
    entries.push(rebound);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        folded_status(&fold, &rotated_key),
        Some(ActorBindingStatus::Active)
    );
    assert!(actor_binding_is_active(&fold, &fixture.actor, "human"));
}

/// P2-a: a key that FAILS the bind transition table's own key predicate after
/// the merge must not keep an Active binding. Roster presence alone was the
/// fail-open: the row survives quarantine and survives role stripping.
#[test]
fn binding_dies_when_key_loses_its_bind_qualification() {
    // ── quarantined key ──────────────────────────────────────────────────
    // AUTH-5: the owner key signs two DIFFERENT entries at the same seq. That
    // key is precisely the one an attacker is holding, so its roster row
    // outliving the equivocation must not keep it speaking for a human owner.
    let fixture = bind_fixture(214);
    let key = fixture.owner_key.clone();
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let mut clean = vec![fixture.genesis.clone(), fixture.enroll.clone(), bind];
    let fold = fold_authority_log_without_seen_time_delay(&clean);
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Active),
        "control: a clean owner key backs its binding"
    );

    // Same signer, same seq, divergent content (ts differs) -> equivocation.
    let equivocation = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        103,
    );
    clean.push(equivocation);
    let quarantined = clean;
    let fold = fold_authority_log_without_seen_time_delay(&quarantined);
    assert!(
        fold.authority_forks
            .iter()
            .any(|fork| fork.signer == key && fork.status == AuthorityForkStatus::Quarantined),
        "fixture must actually quarantine the bound key"
    );
    // fix-leg 5 item 3 STRENGTHENED this outcome. The bind is signed by the
    // forked key with only a ROLE_AGENT cosigner, so post-quarantine scrutiny
    // finds no independent owner consent and REFUSES both fork candidates —
    // the binding never enters `actor_bindings` rather than entering and being
    // marked `Revoked`. Both are fail-closed and the invariant below is the
    // load-bearing one; what must never happen is `Active`.
    assert_ne!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Active),
        "an equivocation-quarantined key must not back a binding"
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // ── role-stripped key ────────────────────────────────────────────────
    // Two concurrent branches enroll the SAME third key with different roles.
    // The merge's most-restrictive `roles &=` leaves AGENT only, so the key can
    // no longer give owner consent — exactly the state that would have REJECTED
    // the human bind with `OwnerCapabilityRequired` had it arrived first.
    let fixture = bind_fixture(216);
    let third = ed_key(216_u8.wrapping_add(2));
    let third_key = authority_key_from_ed(&third);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let wide_enroll = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        AuthorityOp::EnrollDevice {
            device: device(
                third_key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        102,
    );
    let bind = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&wide_enroll).unwrap()],
        3,
        bind_op(&third_key, fixture.actor, "human", 1),
        103,
    );
    let owner_capable = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        wide_enroll,
        bind,
    ];
    let fold = fold_authority_log_without_seen_time_delay(&owner_capable);
    assert_eq!(
        fold.roster[&third_key].roles & (ROLE_OWNER | ROLE_ADMIN),
        ROLE_OWNER | ROLE_ADMIN,
        "control fixture must leave the key owner-capable"
    );
    assert_eq!(
        folded_status(&fold, &third_key),
        Some(ActorBindingStatus::Active),
        "control: an owner-capable key backs a human binding"
    );

    // The concurrent narrow enroll is what strips the bits on merge.
    let narrow_enroll = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        4,
        AuthorityOp::EnrollDevice {
            device: device(third_key.clone(), ROLE_AGENT, AuthorityTier::Software),
        },
        104,
    );
    let mut stripped = owner_capable;
    stripped.push(narrow_enroll);
    let fold = fold_authority_log_without_seen_time_delay(&stripped);
    assert_eq!(
        fold.roster[&third_key].roles & (ROLE_OWNER | ROLE_ADMIN),
        0,
        "fixture must actually strip the owner-capable bits"
    );
    assert!(
        !fold.roster[&third_key].revoked,
        "the stripped key must stay UNREVOKED — roster presence is the fail-open"
    );
    assert_eq!(
        folded_status(&fold, &third_key),
        Some(ActorBindingStatus::Revoked),
        "a role-stripped key must not back a human binding"
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "human"));

    // ── revoked key, NON-human class ─────────────────────────────────────
    // Owner-capability is a human-class rule, so the roster-liveness leg is
    // the ONLY thing killing an agent-class binding on a revoked key. Pinned
    // separately or the human-class rows would mask its removal.
    // A third agent key is what gets revoked, so the owner+agent pair still
    // forms the surviving quorum a RevokeDevice needs.
    let fixture = bind_fixture(217);
    let spare = ed_key(217_u8.wrapping_add(2));
    let spare_key = authority_key_from_ed(&spare);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let enroll_spare = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        AuthorityOp::EnrollDevice {
            device: device(spare_key.clone(), ROLE_AGENT, AuthorityTier::Software),
        },
        102,
    );
    let bind = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&enroll_spare).unwrap()],
        3,
        bind_op(&spare_key, fixture.actor, "agent", 1),
        103,
    );
    let live = vec![
        fixture.genesis.clone(),
        fixture.enroll.clone(),
        enroll_spare,
        bind.clone(),
    ];
    assert_eq!(
        folded_status(
            &fold_authority_log_without_seen_time_delay(&live),
            &spare_key
        ),
        Some(ActorBindingStatus::Active),
        "control: a live agent key backs an agent-class binding"
    );
    let revoke_device = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&bind).unwrap()],
        4,
        AuthorityOp::RevokeDevice {
            revoked_key: spare_key.clone(),
        },
        104,
    );
    let mut revoked = live;
    revoked.push(revoke_device);
    let fold = fold_authority_log_without_seen_time_delay(&revoked);
    assert!(
        fold.issues.is_empty(),
        "revoke fixture must fold cleanly: {:?}",
        fold.issues
    );
    assert!(
        fold.roster[&spare_key].revoked,
        "fixture must actually revoke the roster key"
    );
    assert_eq!(
        folded_status(&fold, &spare_key),
        Some(ActorBindingStatus::Revoked),
        "a revoked roster key must not back an agent-class binding either"
    );
    assert!(!actor_binding_is_active(&fold, &fixture.actor, "agent"));
}

/// A rooted vault where the owner key `K1` has enrolled a SECOND owner-capable
/// key `K2`, then equivocated at one seq with two `BindActor(K2, …, "human")`
/// legs naming DIFFERENT actors. `K1` is quarantined by the fork; `K2` is
/// clean. The fork winner therefore decides which actor `K2` speaks for.
struct QuarantinedBindFixture {
    entries: Vec<AuthorityLogEntry>,
    control: Vec<AuthorityLogEntry>,
    signer_key: AuthorityKey,
    bound_key: AuthorityKey,
    actor_a: EntityId,
    actor_b: EntityId,
    /// Rebind fixtures only: the actor bound by a PREFORK entry the signer
    /// made while still clean. It must survive — the quarantine is positional.
    prefork_actor: Option<EntityId>,
}

fn quarantined_signer_bind_fixture(seed: u8, rebind: bool) -> QuarantinedBindFixture {
    let fixture = bind_fixture(seed);
    let bound = ed_key(seed.wrapping_add(2));
    let bound_key = authority_key_from_ed(&bound);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    // K2 enters the roster owner-capable, so a "human" bind onto it satisfies
    // `apply_actor_binding`'s OwnerCapabilityRequired leg.
    let enroll_bound = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        AuthorityOp::EnrollDevice {
            device: device(
                bound_key.clone(),
                ROLE_OWNER | ROLE_ADMIN,
                AuthorityTier::Software,
            ),
        },
        102,
    );
    let enroll_bound_hash = authority_entry_hash(&enroll_bound).unwrap();
    let actor_a = scope_entity(seed.wrapping_add(0x30));
    let actor_b = scope_entity(seed.wrapping_add(0x40));
    // Rebind needs a live binding to advance, so the rebind fixture lands a
    // clean epoch-1 bind on a THIRD actor first and equivocates on the epoch-2
    // REBIND. The seed actor doubles as the prefork control: an entry the
    // signer made while still clean must NOT be retracted by a later fork.
    let (base, fork_parent, fork_seq, op_a, op_b, prefork_actor) = if rebind {
        let prefork_actor = scope_entity(seed.wrapping_add(0x50));
        let seed_bind = cosigned_entry(
            &fixture,
            vec![enroll_bound_hash],
            3,
            bind_op(&bound_key, prefork_actor, "human", 1),
            103,
        );
        let seed_hash = authority_entry_hash(&seed_bind).unwrap();
        (
            vec![
                fixture.genesis.clone(),
                fixture.enroll.clone(),
                enroll_bound,
                seed_bind,
            ],
            seed_hash,
            4,
            rebind_op(&bound_key, actor_a, "human", 2),
            rebind_op(&bound_key, actor_b, "human", 2),
            Some(prefork_actor),
        )
    } else {
        (
            vec![
                fixture.genesis.clone(),
                fixture.enroll.clone(),
                enroll_bound,
            ],
            enroll_bound_hash,
            3,
            bind_op(&bound_key, actor_a, "human", 1),
            bind_op(&bound_key, actor_b, "human", 1),
            None,
        )
    };
    let leg_a = cosigned_entry(&fixture, vec![fork_parent], fork_seq, op_a, 110);
    let leg_b = cosigned_entry(&fixture, vec![fork_parent], fork_seq, op_b, 111);

    let mut control = base.clone();
    control.push(leg_a.clone());
    let mut entries = base;
    entries.push(leg_a);
    entries.push(leg_b);
    QuarantinedBindFixture {
        entries,
        control,
        signer_key: fixture.owner_key,
        bound_key,
        actor_a,
        actor_b,
        prefork_actor,
    }
}

/// fix-leg 5 item 3: a `BindActor`/`RebindActor` that WINS an equivocation
/// group must survive the same post-quarantine scrutiny `RevokeDevice` gets.
///
/// fix-1 strips a binding only when the BOUND key is quarantined. A signer that
/// equivocated is exactly the key an attacker holds — and it can spend its last
/// pre-quarantine act binding owner authority onto a DIFFERENT, clean roster
/// key, which fix-1 leaves Active. `fork_winner_post_quarantine_issue` is the
/// place the fold already re-derives quorum + consent WITHOUT the forked key;
/// the bind ops now take that same door, so a bind whose only owner-capable
/// backing was the forked key itself is refused.
#[test]
fn fork_winner_bind_by_quarantined_signer_is_refused() {
    for rebind in [false, true] {
        let fixture =
            quarantined_signer_bind_fixture(220_u8.wrapping_add(u8::from(rebind)), rebind);

        // Control: without the divergent sibling the bind folds Active. The
        // fixture is only interesting if the CLEAN path really works.
        let control = fold_authority_log_without_seen_time_delay(&fixture.control);
        assert_eq!(
            folded_status(&control, &fixture.bound_key),
            Some(ActorBindingStatus::Active),
            "rebind={rebind}: control must bind the clean owner-capable key"
        );
        assert!(
            actor_binding_is_active(&control, &fixture.actor_a, "human"),
            "rebind={rebind}: control must bind actor_a"
        );

        let fold = fold_authority_log_without_seen_time_delay(&fixture.entries);
        assert!(
            fold.authority_forks
                .iter()
                .any(|fork| fork.signer == fixture.signer_key
                    && fork.status == AuthorityForkStatus::Quarantined),
            "rebind={rebind}: fixture must actually quarantine the SIGNING key"
        );
        assert!(
            !fold.roster[&fixture.bound_key].revoked
                && fold.roster[&fixture.bound_key].roles & (ROLE_OWNER | ROLE_ADMIN) != 0,
            "rebind={rebind}: the BOUND key must stay clean and owner-capable — \
             that is the fail-open fix-1 leaves open"
        );

        // The teeth: neither actor may hold owner authority through a bind the
        // quarantined signer alone backed.
        for actor in [fixture.actor_a, fixture.actor_b] {
            assert!(
                !actor_binding_is_active(&fold, &actor, "human"),
                "rebind={rebind}: a fork-winner bind signed by a quarantined key \
                 must not mint owner authority for {}",
                actor.to_hex()
            );
        }
        assert!(
            fold.issues.iter().any(|issue| matches!(
                issue,
                AuthorityFoldIssue::MissingAuthorityConsent(_)
                    | AuthorityFoldIssue::MissingQuorum(_)
            )),
            "rebind={rebind}: the refusal must be recorded, not silent: {:?}",
            fold.issues
        );

        // Positional, not retroactive: the entry the signer made BEFORE it
        // equivocated keeps its binding. Over-stripping here would let any
        // later self-equivocation retract the vault's whole owner identity —
        // a denial-of-authority the quarantine must not hand the attacker.
        if let Some(prefork_actor) = fixture.prefork_actor {
            assert!(
                actor_binding_is_active(&fold, &prefork_actor, "human"),
                "rebind={rebind}: a PREFORK binding must survive the later fork"
            );
        }
    }
}

/// The other half of item 3, and the one that proves the gate is not just a
/// blanket refusal: the SAME quarantined-signer shape, but the bind carries TWO
/// independent owner-capable cosigners. Delete the forked key from both sides
/// and the entry still satisfies its own admission rules — consent from a clean
/// owner, quorum from a clean pair — so it must be ADMITTED.
///
/// Without this pin, "refuse every bind by a forked signer" would pass the
/// refusal test above while silently converting any self-equivocation into a
/// denial of the vault's owner identity. The fold re-derives; it does not
/// blacklist.
#[test]
fn fork_winner_bind_with_independent_quorum_still_binds() {
    let fixture = bind_fixture(240);
    let clean_a = ed_key(243);
    let clean_b = ed_key(244);
    let bound = ed_key(245);
    let (key_a, key_b, bound_key) = (
        authority_key_from_ed(&clean_a),
        authority_key_from_ed(&clean_b),
        authority_key_from_ed(&bound),
    );
    let mut parent_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let mut entries = vec![fixture.genesis.clone(), fixture.enroll.clone()];
    for (seq, key) in [(2, &key_a), (3, &key_b), (4, &bound_key)] {
        let enroll = cosigned_entry(
            &fixture,
            vec![parent_hash],
            seq,
            AuthorityOp::EnrollDevice {
                device: device(
                    key.clone(),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            100 + seq,
        );
        parent_hash = authority_entry_hash(&enroll).unwrap();
        entries.push(enroll);
    }
    // The forked owner signs both legs; the cosigners are clean and owner-capable.
    let bind_leg = |actor, ts| {
        let entry = unsigned_entry(
            Some(fixture.vault_id),
            5,
            vec![parent_hash],
            bind_op(&bound_key, actor, "human", 1),
            fixture.owner_key.clone(),
            ts,
        );
        cosign_ed_two(entry, &fixture.owner, &clean_a, &clean_b)
    };
    let actor_a = scope_entity(0x81);
    entries.push(bind_leg(actor_a, 120));
    entries.push(bind_leg(scope_entity(0x82), 121));

    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert!(
        fold.authority_forks
            .iter()
            .any(|fork| fork.signer == fixture.owner_key
                && fork.status == AuthorityForkStatus::Quarantined),
        "fixture must still quarantine the signing key"
    );
    assert_eq!(
        folded_status(&fold, &bound_key),
        Some(ActorBindingStatus::Active),
        "a bind an independent owner quorum backs must survive its signer's quarantine"
    );
    assert!(
        actor_binding_is_active(&fold, &actor_a, "human"),
        "the fork WINNER's actor keeps owner authority"
    );
}

/// Divergent branches over one key's identity: both siblings parent on the
/// enroll, bind the SAME key at the SAME epoch to DIFFERENT actors, and a
/// third branch revokes an unrelated epoch. Fold order must not decide who
/// the key speaks for.
struct BindingDag {
    entries: Vec<AuthorityLogEntry>,
    key: AuthorityKey,
    actor_a: EntityId,
    actor_b: EntityId,
    late_actor: EntityId,
}

fn binding_dag() -> BindingDag {
    let fixture = bind_fixture(206);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();
    let actor_a = scope_entity(0x12);
    let actor_b = scope_entity(0x23);
    let late_actor = scope_entity(0x34);

    // Equal-epoch divergent content on two branches. Distinct seqs keep this
    // a genuine DAG divergence rather than signer equivocation.
    let branch_a = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, actor_a, "human", 1),
        110,
    );
    let branch_b = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        3,
        bind_op(&key, actor_b, "human", 1),
        111,
    );
    // A merge entry above both branches, plus a later rebind that must beat
    // the conflicted epoch-1 state on epoch alone.
    let merge = cosigned_entry(
        &fixture,
        vec![
            authority_entry_hash(&branch_a).unwrap(),
            authority_entry_hash(&branch_b).unwrap(),
        ],
        4,
        revoke_actor_op(&key, 1),
        112,
    );
    let late = cosigned_entry(
        &fixture,
        vec![authority_entry_hash(&merge).unwrap()],
        5,
        bind_op(&key, late_actor, "human", 2),
        113,
    );
    BindingDag {
        entries: vec![
            fixture.genesis,
            fixture.enroll,
            branch_a,
            branch_b,
            merge,
            late,
        ],
        key,
        actor_a,
        actor_b,
        late_actor,
    }
}

#[test]
fn equal_epoch_divergent_bindings_fail_closed() {
    let dag = binding_dag();
    // Only the two branches: nothing resolves the divergence, so the merged
    // binding must be deterministic AND dead. A fork over identity is exactly
    // where picking a silent winner would be the bug.
    let fold = fold_authority_log_without_seen_time_delay(&dag.entries[..4]);
    let binding = &dag.key;
    assert_eq!(
        folded_status(&fold, binding),
        Some(ActorBindingStatus::Revoked),
        "conflicted binding must never authorize"
    );
    assert_eq!(
        fold.actor_bindings[binding].actor_ref,
        dag.actor_a.min(dag.actor_b),
        "conflict winner must be the byte-wise smaller tuple"
    );
    assert!(!actor_binding_is_active(&fold, &dag.actor_a, "human"));
    assert!(!actor_binding_is_active(&fold, &dag.actor_b, "human"));
}

proptest! {
    #[test]
    fn binding_fold_is_permutation_invariant(
        perm in prop::collection::vec(0_usize..6, 6),
    ) {
        let dag = binding_dag();
        let baseline = fold_authority_log_without_seen_time_delay(&dag.entries);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = dag.entries.get(index % dag.entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &dag.entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }
        let folded = fold_authority_log_without_seen_time_delay(&permuted);

        // Absolute checks, not just baseline equality: a consistently
        // order-biased merge would agree with itself under every permutation.
        prop_assert_eq!(
            folded.actor_bindings[&dag.key].actor_ref,
            dag.late_actor
        );
        prop_assert_eq!(
            folded.actor_bindings[&dag.key].status,
            ActorBindingStatus::Active
        );
        prop_assert!(actor_binding_is_active(&folded, &dag.late_actor, "human"));
        prop_assert!(!actor_binding_is_active(&folded, &dag.actor_a, "human"));
        prop_assert!(!actor_binding_is_active(&folded, &dag.actor_b, "human"));
        prop_assert_eq!(folded, baseline);
    }
}

#[test]
fn atomic_genesis_owner_binding_door() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();

    // The genesis owner-binding ceremony: a single-key roster needs no cosign,
    // so [genesis, bind] is one atomic host call.
    let genesis = genesis_entry(207, DEFAULT_PENDING_WIDEN_DELAY_SECS, 200);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner = ed_key(207);
    let owner_key = authority_key_from_ed(&owner);
    let actor = scope_entity(0x5c);
    let bind = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key.clone(),
            201,
        ),
        &owner,
    );

    let ids = vault
        .put_authority_log_entries(&[
            (genesis.clone(), TimeRange { start: 1, end: 1 }, 1),
            (bind.clone(), TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], authority_log_entity_id(&genesis).unwrap());
    assert_eq!(ids[1], authority_log_entity_id(&bind).unwrap());
    assert_eq!(
        vault.get_authority_log_entry(&ids[1]).unwrap(),
        Some(bind.clone())
    );
    let fold = vault.authority_fold().unwrap();
    assert_eq!(fold.vault_id, Some(vault_id));
    assert!(
        actor_binding_is_active(&fold, &actor, "human"),
        "the atomic ceremony must leave a live owner binding"
    );

    // All-or-nothing: a pair whose SECOND entry is invalid stores NEITHER.
    // Without this the host could end up rooted-but-unbound, which fail-closes
    // its own owner verbs.
    let other_dir = tempfile::tempdir().unwrap();
    let other = crate::Vault::open(other_dir.path(), crate::VaultConfig::device()).unwrap();
    let mut broken = bind;
    broken.signer.signature = vec![0; 64];
    other
        .put_authority_log_entries(&[
            (genesis.clone(), TimeRange { start: 1, end: 1 }, 1),
            (broken, TimeRange { start: 2, end: 2 }, 2),
        ])
        .expect_err("an invalid entry must abort the whole batch");
    assert_eq!(
        other
            .get_authority_log_entry(&authority_log_entity_id(&genesis).unwrap())
            .unwrap(),
        None,
        "nothing may be stored when any entry in the batch is invalid"
    );

    // A lone genesis is accepted: enforcement lives at the facade, not here.
    other
        .put_authority_log_entries(&[(genesis, TimeRange { start: 1, end: 1 }, 1)])
        .unwrap();
    assert_eq!(other.authority_fold().unwrap().vault_id, Some(vault_id));
}
