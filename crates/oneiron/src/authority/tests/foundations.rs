//! Genesis vectors, wall-clock clock, signature suites, roles and quorum.

use super::support::*;
use super::*;

/// The observation clock belongs to the vault that observes, so two vaults open
/// at the same time cannot move each other's reading.
///
/// The clock used to be a process-wide `BTreeMap` keyed by a minted domain id.
/// Nothing pinned the isolation that keying bought, so a later change that
/// collapsed the map to one shared anchor — or moved the clock back to a plain
/// static — would have been invisible: every existing clock test drives ONE
/// vault. A second vault open in the same process is what makes the ownership
/// observable.
///
/// MUTATION PROBE: share one `AuthorityLocalClock` across handles and this test
/// fails at the second assertion — the behind vault inherits the first's
/// far-future anchor and reports that instead of its own reading, ten days
/// ahead of anything it saw.
#[test]
fn two_open_vaults_observe_on_independent_authority_clocks() {
    let ahead_dir = tempfile::tempdir().unwrap();
    let ahead = crate::Vault::open(ahead_dir.path(), crate::VaultConfig::device()).unwrap();
    let behind_dir = tempfile::tempdir().unwrap();
    let behind = crate::Vault::open(behind_dir.path(), crate::VaultConfig::device()).unwrap();

    // Anchor the first vault ten days ahead of real Unix time.
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    assert_eq!(authority_observation_secs(&ahead.store, 0, future), future);

    // The second vault has observed nothing, so ITS first observation is its
    // own candidate — not the neighbour's anchor.
    let seeded = 1_000;
    assert_eq!(
        authority_observation_secs(&behind.store, 0, seeded),
        seeded,
        "a vault's first observation is its own candidate, whatever another \
         vault has observed"
    );

    // Neither reading moved the other. The first is still parked in the future
    // with a past candidate offered...
    assert!(
        authority_observation_secs(&ahead.store, 0, seeded) >= future,
        "an observation on another vault must not drag this anchor backwards"
    );
    // ...and the second still reports from its own origin with a future
    // candidate offered, i.e. it never inherited the anchor next door.
    assert!(
        authority_observation_secs(&behind.store, 0, future) < future,
        "an observation on another vault must not drag this anchor forwards"
    );
}

#[test]
fn authority_genesis_golden_vector_is_canonical() {
    let genesis = genesis_entry(1, 86_400, 123);
    let encoded = encode_authority_log_entry_body(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();

    assert_eq!(
        hex(&encoded),
        "88ae736368656d615f76657273696f6e01a87661756c745f6964c0a373657100ad706172656e745f68617368657390a26f7085a46b696e64a767656e65736973a664657669636585a36b657982a57375697465a765643235353139aa7075626c69635f6b6579c4208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5cb57472616e73706f72745f6b65795f62696e64696e67c4200707070707070707070707070707070707070707070707070707070707070707ab6174746573746174696f6e82a46b696e64b0536f6674776172654172676f6e326964a865766964656e6365c403010203a474696572a8736f667477617265a5726f6c657303ad67656e657369735f6e6f6e6365c4200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0baa746965725f666c6f6f72a8736f667477617265b870656e64696e675f776964656e5f64656c61795f73656373ce00015180a67369676e657283a57375697465a765643235353139aa7075626c69635f6b6579c4208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5ca97369676e6174757265c4408131cde03c78cec247140fe8fc1c3b97b4bce2f52ea4564e15a459badddbe8e0f204047d0e2dbc2cad8490ca48eb8488f842dc4b49b13fd59f5bdb6f75f45e0ba7636f7369676e7390a274737b"
    );
    assert_eq!(
        hex(&vault_id),
        "c9328f916e5290288757fc622aba9f87f7226d33590ac6652f1c7c7ad7f0dc12"
    );
    assert_eq!(decode_authority_log_entry_body(&encoded).unwrap(), genesis);
}

#[test]
fn legacy_genesis_without_pending_delay_decodes_with_default_and_old_hash() {
    let signing = ed_key(79);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        ),
        genesis_nonce: [79; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    };
    let legacy = sign_ed_legacy_genesis(unsigned_entry(None, 0, Vec::new(), op, key, 1), &signing);
    let legacy_encoded =
        encode_value(&entry_value_with_genesis_delay(&legacy, true, false)).unwrap();
    let current_encoded = encode_authority_log_entry_body(&legacy).unwrap();
    let legacy_hash = *blake3::hash(&legacy_encoded).as_bytes();

    assert_ne!(legacy_encoded, current_encoded);
    let decoded = decode_authority_log_entry_body(&legacy_encoded).unwrap();
    assert_eq!(decoded, legacy);
    assert_eq!(
        authority_entry_hash(&decoded).unwrap(),
        legacy_hash,
        "legacy genesis hash must stay tied to the legacy signed bytes"
    );
    assert_eq!(genesis_vault_id(&decoded).unwrap(), legacy_hash);
}

/// ONE-1604-D1 T5: the AUTHORITY_LOG store key is pinned to the first 16 bytes of
/// the entry's BLAKE3 hash, and survives an encode/decode round trip. The
/// genesis corollary: a genesis row's entity id is the first 16 bytes of the
/// vault id, since `genesis_vault_id == authority_entry_hash(genesis)`.
#[test]
fn authority_log_entity_id_is_first_sixteen_bytes_of_entry_hash() {
    let signing = ed_key(96);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        ),
        genesis_nonce: [96; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    };
    let genesis = sign_ed(unsigned_entry(None, 0, Vec::new(), op, key, 1), &signing);
    let hash = authority_entry_hash(&genesis).unwrap();

    let id = authority_log_entity_id(&genesis).unwrap();
    assert_eq!(id.as_bytes(), &hash[..16]);
    assert_eq!(
        id.as_bytes(),
        &genesis_vault_id(&genesis).unwrap()[..16],
        "a genesis row's store key is the first 16 bytes of the vault id"
    );

    let encoded = encode_authority_log_entry_body(&genesis).unwrap();
    let decoded = decode_authority_log_entry_body(&encoded).unwrap();
    assert_eq!(
        authority_log_entity_id(&decoded).unwrap(),
        id,
        "the derived store key must survive an encode/decode round trip"
    );
    assert_eq!(authority_log_entity_id_from_hash(&hash).unwrap(), id);
}

/// ONE-1604-D1 T5b: the derived store key is stable for a legacy-signed
/// genesis, whose hash is taken over the LEGACY signed bytes rather than the
/// current canonical encoding. Only the legacy bytes carry a verifying
/// signature, so only they decode — the current re-encoding of the same entry
/// is refused at body validation and can never reach a door under this key.
/// That is why the key==hash bind alone determines admissibility here, and
/// the append-only guard behind it stays defense-in-depth.
#[test]
fn legacy_signed_genesis_derives_a_stable_store_key_from_its_legacy_bytes() {
    let signing = ed_key(97);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        ),
        genesis_nonce: [97; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    };
    let legacy = sign_ed_legacy_genesis(unsigned_entry(None, 0, Vec::new(), op, key, 1), &signing);
    let legacy_encoded =
        encode_value(&entry_value_with_genesis_delay(&legacy, true, false)).unwrap();
    let current_encoded = encode_authority_log_entry_body(&legacy).unwrap();

    assert_ne!(
        legacy_encoded, current_encoded,
        "the two encodings must genuinely differ for this to be a divergence case"
    );
    let decoded = decode_authority_log_entry_body(&legacy_encoded).unwrap();
    assert_eq!(
        authority_log_entity_id(&decoded).unwrap(),
        authority_log_entity_id(&legacy).unwrap(),
        "the legacy bytes decode to an entry with the same derived store key"
    );
    assert!(
        decode_authority_log_entry_body(&current_encoded).is_err(),
        "the current re-encoding carries no verifying signature, so no door admits it"
    );
}

#[test]
fn genesis_rejects_pending_widen_delay_outside_ceremony_band() {
    let signing = ed_key(80);
    let key = authority_key_from_ed(&signing);
    for pending_widen_delay_secs in [
        0,
        MIN_DEFAULT_PENDING_WIDEN_DELAY_SECS - 1,
        MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS + 1,
    ] {
        let op = AuthorityOp::Genesis {
            device: device(key.clone(), ROLE_OWNER, AuthorityTier::Software),
            genesis_nonce: [80; 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs,
        };
        let entry = unsigned_entry(None, 0, Vec::new(), op, key.clone(), 1);
        assert!(
            encode_authority_log_entry_body(&entry).is_err(),
            "delay {pending_widen_delay_secs} must be rejected"
        );
    }
}

#[test]
fn persisted_seen_time_ignores_forward_wall_clock_jumps_after_first_observation() {
    let mut clock = AuthorityLocalClock::default();
    let now = Instant::now();
    let first = clock.observation_secs_at(0, 1_000, now);
    let jumped = clock.observation_secs_at(first, 1_000_000, now);

    assert_eq!(first, 1_000);
    assert_eq!(
        jumped, first,
        "wall-clock jumps after first observation must not skip the local delay"
    );
}

#[test]
fn reopened_authority_clock_advances_wall_time_past_stored_floor() {
    let mut clock = AuthorityLocalClock::default();
    let now = Instant::now();
    let observed = clock.observation_secs_at(1_000, 2_500, now);
    // Hold monotonic time fixed: rollback must not change the observation, but
    // elapsed monotonic seconds may legitimately advance it past this floor.
    let backward = clock.observation_secs_at(observed, 10, now);

    assert_eq!(observed, 2_500);
    assert_eq!(
        backward, observed,
        "wall-clock rollback after reopening must not move the floor backward"
    );
}

#[test]
fn reopened_authority_clock_rollback_does_not_freeze_elapsed_time() {
    let mut clock = AuthorityLocalClock::default();
    let now = Instant::now();
    let observed = clock.observation_secs_at(1_000, 2_500, now);
    assert_eq!(observed, 2_500);

    assert_eq!(
        clock.observation_secs_at(observed, 10, now + Duration::from_millis(999)),
        2_500,
        "rollback must not advance the observation before a whole second elapses"
    );
    assert_eq!(
        clock.observation_secs_at(observed, 10, now + Duration::from_secs(1)),
        2_501,
        "rollback must not freeze monotonic progress at the persisted floor"
    );
}

/// fix-leg 5 item 2: sub-second remainders must NOT be discarded.
///
/// `Duration::as_secs` truncates, so a per-call anchor reset banks a zero every
/// time two folds land inside the same monotonic second. A sustained >1 Hz
/// readonly fold would then freeze `now_secs` at its first observation and stall
/// every veto delay. The anchor is stable, so elapsed time crosses the boundary.
#[test]
fn sub_second_readonly_folds_still_advance_the_observed_clock() {
    let mut clock = AuthorityLocalClock::default();
    let now = Instant::now();
    let first = clock.observation_secs_at(0, 1_000, now);
    assert_eq!(first, 1_000);

    // Six sub-second calls inside one 0.6 s window: each measures a truncated
    // ZERO elapsed second and must leave the anchor alone.
    for step in 1..=6 {
        assert_eq!(
            clock.observation_secs_at(first, 1_000, now + Duration::from_millis(step * 100)),
            first,
            "a sub-second call must not advance the whole-second observation"
        );
    }
    // Total elapsed monotonic time is 1.1 s from the ORIGINAL anchor. With a
    // per-call reset every one of those 100 ms gaps truncated to zero and this
    // assert reads 1_000; with a stable anchor it reads 1_001.
    assert_eq!(
        clock.observation_secs_at(first, 1_000, now + Duration::from_millis(1_100)),
        first + 1,
        "sub-second remainders must accumulate: 1.1 s of elapsed time crosses a second boundary"
    );
}

/// The rebase half of the same anchor: a persisted floor ABOVE the
/// anchor-derived value re-origins the clock (monotone upward), and the next
/// call then advances from the NEW origin rather than from the stale one.
#[test]
fn persisted_floor_lift_rebases_the_authority_clock_anchor() {
    let mut clock = AuthorityLocalClock::default();
    let now = Instant::now();
    let first = clock.observation_secs_at(0, 1_000, now);
    assert_eq!(first, 1_000);

    // Another writer advanced the persisted floor well past this anchor.
    let lifted_at = now + Duration::from_millis(1_500);
    let lifted = clock.observation_secs_at(5_000, 1_000, lifted_at);
    assert_eq!(lifted, 5_000, "a floor above the anchor must lift it");

    // The lifted value is now the origin: a lower floor cannot pull it back,
    // and elapsed time counts from the lift, not from the original anchor.
    let held = clock.observation_secs_at(0, 1_000, lifted_at + Duration::from_millis(500));
    assert_eq!(
        held, lifted,
        "the rebased anchor is monotone: a lower floor never moves it backward"
    );
    assert_eq!(
        clock.observation_secs_at(0, 1_000, lifted_at + Duration::from_secs(1)),
        lifted + 1,
        "elapsed seconds must advance from the rebased anchor"
    );
}

#[test]
fn authority_signature_suite_verifies_ed25519_and_p256() {
    let ed = genesis_entry(2, 172_800, 1);
    assert!(verify_authority_signature(
        &ed.signer,
        &authority_transcript(&ed).unwrap()
    ));

    let p256 = p256_key(3);
    let key = authority_key_from_p256(&p256);
    let op = AuthorityOp::Genesis {
        device: device(key.clone(), ROLE_OWNER, AuthorityTier::Hardware),
        genesis_nonce: [44; 32],
        tier_floor: AuthorityTier::Hardware,
        pending_widen_delay_secs: 86_400,
    };
    let entry = sign_p256(unsigned_entry(None, 0, Vec::new(), op, key, 2), &p256);
    assert!(verify_authority_signature(
        &entry.signer,
        &authority_transcript(&entry).unwrap()
    ));
    assert!(
        decode_authority_log_entry_body(&encode_authority_log_entry_body(&entry).unwrap()).is_ok()
    );
}

#[test]
fn authority_body_validation_rejects_bad_origin_signature() {
    let mut genesis = genesis_entry(3, 86_400, 3);
    genesis.signer.signature[0] ^= 0xff;
    let encoded = encode_value(&entry_value(&genesis, true)).unwrap();
    let err = validate_authority_log_entry_body_bytes(&encoded)
        .expect_err("tampered origin signature must fail closed");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn p256_authority_identity_requires_canonical_compressed_sec1() {
    let signing = p256_key(22);
    let uncompressed = signing.verifying_key().to_encoded_point(false);
    let key = AuthorityKey::P256(uncompressed.as_bytes().to_vec());
    let op = AuthorityOp::Genesis {
        device: device(key.clone(), ROLE_OWNER, AuthorityTier::Hardware),
        genesis_nonce: [22; 32],
        tier_floor: AuthorityTier::Hardware,
        pending_widen_delay_secs: 86_400,
    };
    let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("uncompressed P-256 key must not be canonical authority identity");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn authority_transcript_binds_cosigner_key_set() {
    let owner = ed_key(23);
    let second = ed_key(24);
    let genesis = genesis_entry(23, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_entry(vault_id, &genesis, &owner, 24, 1, 2);
    let signed = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&enroll).unwrap()],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
        &second,
    );
    let mut stripped = signed.clone();
    stripped.cosigns.clear();

    assert!(
        decode_authority_log_entry_body(&encode_value(&entry_value(&stripped, true)).unwrap())
            .is_err()
    );
    assert!(
        decode_authority_log_entry_body(&encode_authority_log_entry_body(&signed).unwrap()).is_ok()
    );
}

#[test]
fn cloud_devices_cannot_hold_authority_consent_roles() {
    let signing = ed_key(25);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_ADMIN | ROLE_CLOUD,
            AuthorityTier::CloudCustodial,
        ),
        genesis_nonce: [25; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: 86_400,
    };
    let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("cloud/custodial authority roots must fail closed");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn device_authority_roles_reject_unknown_bits() {
    let signing = ed_key(31);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(key.clone(), ROLE_OWNER | 0x8000, AuthorityTier::Hardware),
        genesis_nonce: [31; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: 86_400,
    };
    let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("unknown authority role bits must fail closed");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn genesis_requires_owner_or_admin_authority_consent() {
    let signing = ed_key(37);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(key.clone(), ROLE_AGENT, AuthorityTier::Software),
        genesis_nonce: [37; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: 86_400,
    };
    let entry = unsigned_entry(None, 0, Vec::new(), op, key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("genesis must establish an owner/admin authority root");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn rotate_key_rejects_self_rotation() {
    let signing = ed_key(38);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::RotateKey {
        old_key: key.clone(),
        new_device: device(key.clone(), ROLE_ADMIN, AuthorityTier::Software),
    };
    let entry = unsigned_entry(Some([38; 32]), 1, vec![[39; 32]], op, key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("self-rotation must fail before fold application");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn invalid_signatures_do_not_poison_equivocation_detection() {
    let valid = genesis_entry(39, 86_400, 1);
    let valid_hash = authority_entry_hash(&valid).unwrap();
    let mut forged = valid.clone();
    forged.ts = 2;
    forged.signer.signature[0] ^= 0xff;
    let forged_hash = authority_entry_hash(&forged).unwrap();

    let fold = fold_authority_log(&[forged, valid]);
    assert!(fold.valid_entries.contains(&valid_hash));
    assert!(!fold.valid_entries.contains(&forged_hash));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == forged_hash
    )));
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
}

#[test]
fn zero_role_devices_do_not_count_as_quorum_participants() {
    let owner = ed_key(40);
    let zero = ed_key(41);
    let owner_key = authority_key_from_ed(&owner);
    let zero_key = authority_key_from_ed(&zero);
    let state = FoldState {
        vault_id: [40; 32],
        roster: BTreeMap::from([
            (
                owner_key.clone(),
                FoldedDevice {
                    key: owner_key.clone(),
                    tier: AuthorityTier::Software,
                    roles: ROLE_ADMIN,
                    revoked: false,
                },
            ),
            (
                zero_key.clone(),
                FoldedDevice {
                    key: zero_key,
                    tier: AuthorityTier::Software,
                    roles: 0,
                    revoked: false,
                },
            ),
        ]),
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        pending_widens: BTreeMap::new(),
        vetoed_widens: BTreeSet::new(),
        delayed_rotation_veto_revocations: BTreeMap::new(),
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        critical_write_confirms: BTreeMap::new(),
        consumed_critical_write_confirm_nonces: BTreeSet::new(),
        critical_write_confirm_nonce_provenance: BTreeMap::new(),
        conflicted_critical_write_confirms: BTreeSet::new(),
        federation_grant_bindings: BTreeMap::new(),
        actor_bindings: BTreeMap::new(),
        actor_binding_revocations: BTreeMap::new(),
        seqs: BTreeMap::from([(owner_key.clone(), 0)]),
    };
    let entry = cosign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![[41; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key,
            1,
        ),
        &owner,
        &zero,
    );

    let storage = LocalFoldContext::default();
    let context = storage.context();
    assert!(
        active_participant_keys(
            &state,
            &entry,
            authority_entry_hash(&entry).unwrap(),
            context
        )
        .is_err()
    );
}
