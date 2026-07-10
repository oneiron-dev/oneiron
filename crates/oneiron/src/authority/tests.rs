use super::*;
use ed25519_dalek::{Signer, SigningKey};
use p256::ecdsa::SigningKey as P256SigningKey;
use proptest::prelude::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::registry::TypeByteBand;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ed_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn authority_key_from_ed(key: &SigningKey) -> AuthorityKey {
    AuthorityKey::Ed25519(key.verifying_key().to_bytes())
}

fn p256_key(seed: u8) -> P256SigningKey {
    let mut rng = StdRng::from_seed([seed; 32]);
    P256SigningKey::random(&mut rng)
}

fn authority_key_from_p256(key: &P256SigningKey) -> AuthorityKey {
    let point = key.verifying_key().to_encoded_point(true);
    AuthorityKey::P256(point.as_bytes().to_vec())
}

fn attestation(kind: &str) -> AuthorityAttestation {
    AuthorityAttestation {
        kind: kind.to_owned(),
        evidence: vec![1, 2, 3],
    }
}

fn device(key: AuthorityKey, roles: u16, tier: AuthorityTier) -> DeviceAuthority {
    DeviceAuthority {
        key,
        transport_key_binding: [7; 32],
        attestation: attestation("SoftwareArgon2id"),
        tier,
        roles,
    }
}

fn unsigned_entry(
    vault_id: Option<AuthorityVaultId>,
    seq: u64,
    parent_hashes: Vec<AuthorityEntryHash>,
    op: AuthorityOp,
    signer_key: AuthorityKey,
    ts: u64,
) -> AuthorityLogEntry {
    AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id,
        seq,
        parent_hashes,
        op,
        signer: AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts,
    }
}

fn sign_ed(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

fn sign_ed_legacy_genesis(mut entry: AuthorityLogEntry, key: &SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript_with_genesis_delay(&entry, false).unwrap();
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

fn sign_p256(mut entry: AuthorityLogEntry, key: &P256SigningKey) -> AuthorityLogEntry {
    let transcript = authority_transcript(&entry).unwrap();
    let mut signature: P256Signature = key.sign(&transcript);
    if let Some(normalized) = signature.normalize_s() {
        signature = normalized;
    }
    entry.signer.signature = signature.to_bytes().to_vec();
    entry
}

fn cosign_ed(
    mut entry: AuthorityLogEntry,
    signer: &SigningKey,
    cosigner: &SigningKey,
) -> AuthorityLogEntry {
    let cosigner_key = authority_key_from_ed(cosigner);
    entry.cosigns.push(AuthoritySignature {
        suite: cosigner_key.suite(),
        public_key: cosigner_key,
        signature: vec![0; 64],
    });
    entry.cosigns.sort_by(|left, right| {
        left.public_key
            .cmp(&right.public_key)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    let cosigner_key = authority_key_from_ed(cosigner);
    for cosign in &mut entry.cosigns {
        if cosign.public_key == cosigner_key {
            cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
        }
    }
    entry
}

fn genesis_entry(seed: u8, pending_widen_delay_secs: u64, ts: u64) -> AuthorityLogEntry {
    let signing = ed_key(seed);
    let key = authority_key_from_ed(&signing);
    let op = AuthorityOp::Genesis {
        device: device(
            key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Software,
        ),
        genesis_nonce: [seed.wrapping_add(10); 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs,
    };
    sign_ed(unsigned_entry(None, 0, Vec::new(), op, key, ts), &signing)
}

struct EnrollSpec {
    seed: u8,
    roles: u16,
    tier: AuthorityTier,
    seq: u64,
    ts: u64,
}

fn enroll_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_key_seed: u8,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    enroll_device_entry(
        vault_id,
        parent,
        signer,
        EnrollSpec {
            seed: new_key_seed,
            roles: ROLE_AGENT | ROLE_CLOUD,
            tier: AuthorityTier::Software,
            seq,
            ts,
        },
    )
}

fn enroll_device_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    spec: EnrollSpec,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(spec.seed);
    let op = AuthorityOp::EnrollDevice {
        device: device(authority_key_from_ed(&new), spec.roles, spec.tier),
    };
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            spec.seq,
            vec![authority_entry_hash(parent).unwrap()],
            op,
            signer_key,
            spec.ts,
        ),
        signer,
    )
}

fn revoke_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    revoked: AuthorityKey,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RevokeDevice {
                revoked_key: revoked,
            },
            signer_key,
            777,
        ),
        signer,
    )
}

fn set_tier_floor_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    tier_floor: AuthorityTier,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SetTierFloor { tier_floor },
            signer_key,
            888,
        ),
        signer,
    )
}

fn set_ceiling_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SetCeiling {
                authority_key: signer_key.clone(),
                actor_class: "agent".to_string(),
                ceiling: 1,
            },
            signer_key,
            ts,
        ),
        signer,
    )
}

fn rotate_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    old_key: AuthorityKey,
    new_seed: u8,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(new_seed);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RotateKey {
                old_key,
                new_device: device(
                    authority_key_from_ed(&new),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            signer_key,
            889,
        ),
        signer,
    )
}

fn recovery_reboot_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    let new = ed_key(new_seed);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [new_seed; 32],
                new_device: device(
                    authority_key_from_ed(&new),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
                tier_floor: AuthorityTier::Software,
            },
            signer_key,
            890,
        ),
        signer,
    )
}

fn veto_entry(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    pending_widen_hash: AuthorityEntryHash,
    seq: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::VetoPendingWiden { pending_widen_hash },
            signer_key,
            999,
        ),
        signer,
    )
}

fn fold_entry_state_for_test(
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    states: &BTreeMap<AuthorityEntryHash, FoldState>,
) -> EntryFold {
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    fold_entry_state(
        entry,
        hash,
        states,
        FoldContext {
            first_seen_at_secs: &first_seen_at_secs,
            now_secs: None,
            enforce_seen_time_delay: false,
            vetoed_widens: &vetoed_widens,
            authority_forks: &authority_forks,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: None,
        },
    )
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
    let domain = 0x1325_0001;
    let first = authority_observation_secs_for_domain(domain, 0, 1_000);
    let jumped = authority_observation_secs_for_domain(domain, first, 1_000_000);

    assert_eq!(first, 1_000);
    assert_eq!(
        jumped, first,
        "wall-clock jumps after first observation must not skip the local delay"
    );
    release_authority_clock_domain(domain);
}

#[test]
fn reopened_authority_clock_advances_wall_time_past_stored_floor() {
    let domain = 0x1325_0002;
    let observed = authority_observation_secs_for_domain(domain, 1_000, 2_500);
    let backward = authority_observation_secs_for_domain(domain, observed, 10);

    assert_eq!(observed, 2_500);
    assert_eq!(
        backward, observed,
        "wall-clock rollback after reopening must not move the floor backward"
    );
    release_authority_clock_domain(domain);
}

#[test]
fn authority_clock_domain_release_drops_process_local_state() {
    let domain = 0x1325_0003;
    let first = authority_observation_secs_for_domain(domain, 0, 5_000);
    let clamped = authority_observation_secs_for_domain(domain, 0, 10);

    assert_eq!(first, 5_000);
    assert_eq!(
        clamped, first,
        "active clock domains must keep their monotonic local floor"
    );

    release_authority_clock_domain(domain);
    let reset = authority_observation_secs_for_domain(domain, 0, 10);

    assert_eq!(
        reset, 10,
        "released clock domains must not keep process-local state"
    );
    release_authority_clock_domain(domain);
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
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
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

    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    let context = FoldContext {
        first_seen_at_secs: &first_seen_at_secs,
        now_secs: None,
        enforce_seen_time_delay: false,
        vetoed_widens: &vetoed_widens,
        authority_forks: &authority_forks,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: None,
    };
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

fn single_owner_state(seed: u8) -> (SigningKey, AuthorityKey, AuthorityEntryHash, FoldState) {
    let owner = ed_key(seed);
    let owner_key = authority_key_from_ed(&owner);
    let parent = [seed.wrapping_add(90); 32];
    let vault_id = [seed.wrapping_add(91); 32];
    let state = FoldState {
        vault_id,
        roster: BTreeMap::from([(
            owner_key.clone(),
            FoldedDevice {
                key: owner_key.clone(),
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
                revoked: false,
            },
        )]),
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        pending_widens: BTreeMap::new(),
        vetoed_widens: BTreeSet::new(),
        delayed_rotation_veto_revocations: BTreeMap::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        seqs: BTreeMap::from([(owner_key.clone(), 0)]),
    };
    (owner, owner_key, parent, state)
}

#[test]
fn fold_rejects_duplicate_active_enroll_key_before_role_intersection() {
    let (owner, owner_key, parent, state) = single_owner_state(42);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::EnrollDevice {
                device: device(owner_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn fold_rejects_rotation_to_revoked_destination_key() {
    let (owner, owner_key, parent, mut state) = single_owner_state(43);
    let revoked = ed_key(44);
    let revoked_key = authority_key_from_ed(&revoked);
    state.roster.insert(
        revoked_key.clone(),
        FoldedDevice {
            key: revoked_key.clone(),
            tier: AuthorityTier::Software,
            roles: ROLE_ADMIN,
            revoked: true,
        },
    );
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(revoked_key, ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn fold_rejects_rotation_that_leaves_no_authority_consent() {
    let (owner, owner_key, parent, state) = single_owner_state(45);
    let agent = ed_key(46);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&agent),
                    ROLE_AGENT,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::MissingAuthorityConsent(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn delayed_rotation_that_would_leave_no_authority_consent_is_not_pending() {
    let owner = ed_key(115);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(115, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let agent_key = authority_key_from_ed(&ed_key(116));
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(agent_key.clone(), ROLE_AGENT, AuthorityTier::Software),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();
    let first_seen = BTreeMap::from([(rotate_hash, 10)]);

    let fold = fold_authority_log_with_seen_times(&[genesis, rotate], &first_seen, 10);

    assert!(!fold.pending_widens.contains_key(&rotate_hash));
    assert!(!fold.roster.contains_key(&agent_key));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingAuthorityConsent(issue_hash) if *issue_hash == rotate_hash
    )));
}

#[test]
fn recovery_reboot_requires_consenting_new_device() {
    let owner = ed_key(47);
    let agent = ed_key(48);
    let owner_key = authority_key_from_ed(&owner);
    let op = AuthorityOp::RecoveryReboot {
        new_genesis_nonce: [47; 32],
        new_device: device(
            authority_key_from_ed(&agent),
            ROLE_AGENT,
            AuthorityTier::Software,
        ),
        tier_floor: AuthorityTier::Software,
    };
    let entry = unsigned_entry(Some([47; 32]), 1, vec![[48; 32]], op, owner_key, 1);

    let err = encode_authority_log_entry_body(&entry)
        .expect_err("recovery reboot must install a consenting authority");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

#[test]
fn fold_rejects_recovery_reboot_reusing_existing_key() {
    let (owner, owner_key, parent, state) = single_owner_state(49);
    let entry = sign_ed(
        unsigned_entry(
            Some(state.vault_id),
            1,
            vec![parent],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [49; 32],
                new_device: device(owner_key.clone(), ROLE_OWNER, AuthorityTier::Software),
                tier_floor: AuthorityTier::Software,
            },
            owner_key,
            1,
        ),
        &owner,
    );
    let hash = authority_entry_hash(&entry).unwrap();

    assert!(matches!(
        fold_entry_state_for_test(&entry, hash, &BTreeMap::from([(parent, state)])),
        EntryFold::Invalid(AuthorityFoldIssue::InvalidEntry(issue_hash))
            if issue_hash == hash
    ));
}

#[test]
fn fold_equivocation_dangling_fork_does_not_block_ready_winner() {
    let owner = ed_key(50);
    let genesis = genesis_entry(50, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let ready = set_tier_floor_entry(vault_id, &genesis, &owner, 1, AuthorityTier::Hardware);
    let dangling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xDA; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::CloudCustodial,
            },
            authority_key_from_ed(&owner),
            3,
        ),
        &owner,
    );
    let ready_hash = authority_entry_hash(&ready).unwrap();
    let dangling_hash = authority_entry_hash(&dangling).unwrap();

    let fold = fold_authority_log(&[dangling, ready, genesis]);
    assert!(fold.valid_entries.contains(&ready_hash));
    assert!(!fold.valid_entries.contains(&dangling_hash));
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == dangling_hash
    )));
}

#[test]
fn fold_rejects_entries_signed_by_revoked_key() {
    let owner = ed_key(4);
    let revoked_signer = ed_key(5);
    let cosigner = ed_key(6);
    let genesis = genesis_entry(4, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_entry(vault_id, &genesis, &owner, 5, 1, 2);
    let enroll_cosigner = cosign_ed(
        enroll_entry(vault_id, &enroll, &owner, 6, 2, 3),
        &owner,
        &revoked_signer,
    );
    let revoke = cosign_ed(
        revoke_entry(
            vault_id,
            &enroll_cosigner,
            &owner,
            authority_key_from_ed(&revoked_signer),
            3,
        ),
        &owner,
        &cosigner,
    );
    let invalid_child = enroll_entry(vault_id, &revoke, &revoked_signer, 7, 1, 4);

    let fold = fold_authority_log_without_seen_time_delay(&[
        invalid_child.clone(),
        revoke,
        enroll_cosigner,
        enroll,
        genesis,
    ]);
    assert!(
        !fold
            .valid_entries
            .contains(&authority_entry_hash(&invalid_child).unwrap())
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash)
            if *hash == authority_entry_hash(&invalid_child).unwrap()
    )));
}

#[test]
fn fold_rejects_revoke_without_surviving_quorum() {
    let owner = ed_key(14);
    let revoked_signer = ed_key(15);
    let genesis = genesis_entry(14, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_entry(vault_id, &genesis, &owner, 15, 1, 2);
    let revoke = revoke_entry(
        vault_id,
        &enroll,
        &owner,
        authority_key_from_ed(&revoked_signer),
        2,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[revoke.clone(), enroll, genesis]);
    assert!(fold.issues.iter().any(|issue| matches!(
    issue,
    AuthorityFoldIssue::MissingQuorum(hash)
        if *hash == authority_entry_hash(&revoke).unwrap()
    )));
}

#[test]
fn fold_detects_equivocation_by_signer_and_seq() {
    let left = genesis_entry(16, 86_400, 1);
    let right = genesis_entry(16, 86_400, 2);
    let signer = authority_key_from_ed(&ed_key(16));
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let winner_vault_id = if winner_hash == left_hash {
        genesis_vault_id(&left).unwrap()
    } else {
        genesis_vault_id(&right).unwrap()
    };

    let fold = fold_authority_log(&[left, right]);
    assert_eq!(fold.vault_id, Some(winner_vault_id));
    assert!(fold.valid_entries.contains(&winner_hash));
    assert_eq!(fold.valid_entries.len(), 1);
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 0 }
            if *key == signer
    )));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: signer.clone(),
            seq: 0,
            first_hash: left_hash.min(right_hash),
            second_hash: left_hash.max(right_hash),
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer,
            seq: 0,
            first_hash: left_hash.min(right_hash),
            second_hash: left_hash.max(right_hash),
        }]
    );
    assert_eq!(AuthorityForkAlarm::KIND, AUTHORITY_FORK_ALARM_KIND);
}

#[test]
fn multiway_equivocation_alarm_spans_min_and_max_hashes() {
    let owner = ed_key(64);
    let second = ed_key(65);
    let signer = authority_key_from_ed(&owner);
    let genesis = genesis_entry(64, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 65, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 66, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let mut hashes = [
        authority_entry_hash(&fork_enroll).unwrap(),
        authority_entry_hash(&fork_ceiling).unwrap(),
        authority_entry_hash(&fork_tier).unwrap(),
    ];
    hashes.sort();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling,
        fork_tier,
        fork_enroll,
        enroll_second,
        genesis,
    ]);

    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: signer.clone(),
            seq: 2,
            first_hash: hashes[0],
            second_hash: hashes[2],
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer,
            seq: 2,
            first_hash: hashes[0],
            second_hash: hashes[2],
        }]
    );
}

#[test]
fn quarantined_key_cannot_widen_enroll_or_set_ceiling_but_prefix_survives() {
    let owner = ed_key(60);
    let second = ed_key(61);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(60, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 61, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 62, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_enroll_hash = authority_entry_hash(&fork_enroll).unwrap();
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling.clone(),
        fork_enroll.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold.valid_entries.contains(&fork_enroll_hash) {
        fork_enroll.clone()
    } else {
        fork_ceiling.clone()
    };
    let child_enroll = cosign_ed(
        enroll_entry(vault_id, &winner, &owner, 63, 3, 5),
        &owner,
        &second,
    );
    let child_widen = cosign_ed(
        set_tier_floor_entry(vault_id, &winner, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let child_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &winner, &owner, 3, 6),
        &owner,
        &second,
    );
    let child_enroll_hash = authority_entry_hash(&child_enroll).unwrap();
    let child_widen_hash = authority_entry_hash(&child_widen).unwrap();
    let child_ceiling_hash = authority_entry_hash(&child_ceiling).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        child_enroll,
        child_widen,
        child_ceiling,
        fork_enroll,
        fork_ceiling,
        enroll_second.clone(),
        genesis.clone(),
    ]);

    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&genesis).unwrap())
    );
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&enroll_second).unwrap())
    );
    assert!(!fold.valid_entries.contains(&child_enroll_hash));
    assert!(!fold.valid_entries.contains(&child_widen_hash));
    assert!(!fold.valid_entries.contains(&child_ceiling_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    for child_hash in [child_enroll_hash, child_widen_hash, child_ceiling_hash] {
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == child_hash
        )));
    }
}

#[test]
fn quarantined_key_cannot_bypass_with_clean_prefix_parent() {
    let owner = ed_key(66);
    let second = ed_key(67);
    let genesis = genesis_entry(66, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 67, 1, 2);
    let fork_enroll = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 68, 2, 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 4),
        &owner,
        &second,
    );
    let clean_prefix_child = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 5),
        &owner,
        &second,
    );
    let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        clean_prefix_child,
        fork_ceiling,
        fork_enroll,
        enroll_second.clone(),
        genesis.clone(),
    ]);

    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&genesis).unwrap())
    );
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&enroll_second).unwrap())
    );
    assert!(!fold.valid_entries.contains(&clean_prefix_child_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == clean_prefix_child_hash
    )));
}

#[test]
fn quorum_revoke_resolves_authority_fork() {
    let owner = ed_key(70);
    let second = ed_key(71);
    let third = ed_key(72);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(70, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 71,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 72,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let restrict_hash = authority_entry_hash(&fork_restrict).unwrap();
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold.valid_entries.contains(&restrict_hash) {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let revoke = cosign_ed(
        revoke_entry(vault_id, &winner, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let entries = vec![
        revoke.clone(),
        fork_ceiling.clone(),
        fork_restrict.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ];
    let permutations = [
        entries,
        vec![
            genesis,
            enroll_second,
            enroll_third,
            fork_restrict,
            fork_ceiling,
            revoke,
        ],
    ];

    for entries in permutations {
        let fold = fold_authority_log_without_seen_time_delay(&entries);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert!(
            fold.roster
                .get(&owner_key)
                .is_some_and(|device| device.revoked)
        );
        assert!(
            fold.valid_entries
                .contains(&authority_entry_hash(&entries[0]).unwrap())
                || fold
                    .valid_entries
                    .contains(&authority_entry_hash(&entries[5]).unwrap())
        );
    }
}

#[test]
fn quorum_revoke_on_clean_prefix_resolves_authority_fork() {
    let owner = ed_key(80);
    let second = ed_key(81);
    let third = ed_key(82);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(80, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 81,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 82,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&revoke_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn restore_prefix_divergence_suppresses_authority_fork_alarm() {
    let owner = ed_key(73);
    let second = ed_key(74);
    let genesis = genesis_entry(73, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 74,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 75, 2),
        &owner,
        &second,
    );
    let short_branch = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 3),
        &owner,
        &second,
    );
    let restored_branch = cosign_ed(
        set_tier_floor_entry(vault_id, &recovery, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );

    for entries in [
        vec![
            restored_branch.clone(),
            short_branch.clone(),
            recovery.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ],
        vec![
            genesis,
            enroll_second,
            recovery,
            short_branch,
            restored_branch,
        ],
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);
        assert!(fold.fork_alarms.is_empty());
        assert!(fold.authority_forks.is_empty());
        assert!(
            !fold
                .issues
                .iter()
                .any(|issue| { matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }) })
        );
    }
}

#[test]
fn strict_prefix_without_restore_marker_still_quarantines_and_alarms() {
    let owner = ed_key(76);
    let second = ed_key(77);
    let genesis = genesis_entry(76, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 77,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let short_branch = set_ceiling_entry(vault_id, &genesis, &owner, 2, 3);
    let longer_branch = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        longer_branch,
        short_branch,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.fork_alarms.len(), 1);
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| {
        matches!(
            issue,
            AuthorityFoldIssue::EquivocationDetected { seq: 2, .. }
        )
    }));
}

#[test]
fn shared_restore_marker_does_not_suppress_later_strict_prefix_fork() {
    let owner = ed_key(83);
    let second = ed_key(84);
    let recovered = ed_key(85);
    let recovered_key = authority_key_from_ed(&recovered);
    let genesis = genesis_entry(83, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 84,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 85, 2),
        &owner,
        &second,
    );
    let shared_after_recovery = set_ceiling_entry(vault_id, &recovery, &recovered, 0, 3);
    let short_branch =
        set_tier_floor_entry(vault_id, &recovery, &recovered, 1, AuthorityTier::Hardware);
    let longer_branch = set_ceiling_entry(vault_id, &shared_after_recovery, &recovered, 1, 4);

    let fold = fold_authority_log_without_seen_time_delay(&[
        longer_branch,
        short_branch,
        shared_after_recovery,
        recovery,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.fork_alarms.len(), 1);
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, recovered_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
}

#[test]
fn invalid_restore_marker_does_not_suppress_strict_prefix_fork_group() {
    let owner = ed_key(86);
    let second = ed_key(87);
    let genesis = genesis_entry(86, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 87,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let invalid_recovery = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&enroll_second).unwrap()],
            AuthorityOp::RecoveryReboot {
                new_genesis_nonce: [87; 32],
                new_device: device(second_key, ROLE_OWNER | ROLE_ADMIN, AuthorityTier::Software),
                tier_floor: AuthorityTier::Software,
            },
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    let short_branch = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );
    let longer_branch = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &invalid_recovery,
            &owner,
            3,
            AuthorityTier::Hardware,
        ),
        &owner,
        &second,
    );
    let by_hash = BTreeMap::from_iter([
        (authority_entry_hash(&genesis).unwrap(), genesis),
        (authority_entry_hash(&enroll_second).unwrap(), enroll_second),
        (
            authority_entry_hash(&invalid_recovery).unwrap(),
            invalid_recovery,
        ),
        (authority_entry_hash(&short_branch).unwrap(), short_branch),
        (authority_entry_hash(&longer_branch).unwrap(), longer_branch),
    ]);
    let group = BTreeSet::from_iter([
        *by_hash
            .iter()
            .find_map(|(hash, entry)| {
                matches!(entry.op, AuthorityOp::SetCeiling { .. }).then_some(hash)
            })
            .expect("short branch present"),
        *by_hash
            .iter()
            .find_map(|(hash, entry)| {
                matches!(entry.op, AuthorityOp::SetTierFloor { .. }).then_some(hash)
            })
            .expect("longer branch present"),
    ]);
    let ancestors = entry_ancestor_index(&by_hash);

    assert!(
        !restore_prefix_divergence(&group, &by_hash, &ancestors),
        "invalid recovery markers must not route an equivocation group away from fork handling"
    );
}

#[test]
fn group_internal_parent_still_records_authority_fork() {
    let owner = ed_key(88);
    let second = ed_key(89);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(88, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 89,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let first = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let second_parented_to_first = cosign_ed(
        set_tier_floor_entry(vault_id, &first, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let second_hash = authority_entry_hash(&second_parented_to_first).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        second_parented_to_first,
        first,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == second_hash
    )));
}

#[test]
fn all_invalid_same_seq_group_does_not_quarantine_later_valid_entry() {
    let owner = ed_key(96);
    let second = ed_key(97);
    let genesis = genesis_entry(96, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 97,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3);
    let invalid_tier =
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware);
    let valid_later = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );
    let valid_later_hash = authority_entry_hash(&valid_later).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        valid_later,
        invalid_tier,
        invalid_ceiling,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&valid_later_hash));
    assert!(fold.authority_forks.is_empty());
    assert!(fold.fork_alarms.is_empty());
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
}

#[test]
fn all_invalid_same_seq_group_does_not_resolve_clean_prefix_revoke() {
    let owner = ed_key(103);
    let second = ed_key(104);
    let third = ed_key(105);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(103, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 104,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 105,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let invalid_ceiling = set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4);
    let invalid_tier =
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware);
    let revoke_owner = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key, 0),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke_owner).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke_owner,
        invalid_tier,
        invalid_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&revoke_hash));
    assert!(fold.authority_forks.is_empty());
    assert!(fold.fork_alarms.is_empty());
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
}

#[test]
fn clean_prefix_entry_waits_when_unresolved_fork_key_is_cosigner() {
    let owner = ed_key(109);
    let second = ed_key(110);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(109, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 110,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let clean_prefix_child = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
        &second,
        &owner,
    );
    let fork_ceiling_hash = authority_entry_hash(&fork_ceiling).unwrap();
    let fork_tier_hash = authority_entry_hash(&fork_tier).unwrap();
    let clean_prefix_child_hash = authority_entry_hash(&clean_prefix_child).unwrap();
    let by_hash = BTreeMap::from([
        (authority_entry_hash(&genesis).unwrap(), genesis),
        (authority_entry_hash(&enroll_second).unwrap(), enroll_second),
        (fork_ceiling_hash, fork_ceiling),
        (fork_tier_hash, fork_tier),
        (clean_prefix_child_hash, clean_prefix_child.clone()),
    ]);
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let group_key = (owner_key, 2);
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let equivocation_groups = BTreeMap::from([(
        group_key.clone(),
        BTreeSet::from([fork_ceiling_hash, fork_tier_hash]),
    )]);
    let unresolved_equivocation_groups = BTreeSet::from([group_key]);
    let context = FoldContext {
        first_seen_at_secs: &first_seen_at_secs,
        now_secs: None,
        enforce_seen_time_delay: false,
        vetoed_widens: &vetoed_widens,
        authority_forks: &authority_forks,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: Some(&entry_ancestors),
    };

    assert!(entry_waits_on_unresolved_equivocation(
        &clean_prefix_child,
        clean_prefix_child_hash,
        context
    ));
}

#[test]
fn equivocation_group_waits_on_other_unresolved_equivocation() {
    let owner = ed_key(111);
    let second = ed_key(112);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(111, 86_400, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 112,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_second_hash = authority_entry_hash(&enroll_second).unwrap();
    let owner_fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let owner_fork_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let second_fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &second, 0, 4),
        &second,
        &owner,
    );
    let second_fork_tier = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &enroll_second,
            &second,
            0,
            AuthorityTier::Hardware,
        ),
        &second,
        &owner,
    );
    let owner_fork_ceiling_hash = authority_entry_hash(&owner_fork_ceiling).unwrap();
    let owner_fork_tier_hash = authority_entry_hash(&owner_fork_tier).unwrap();
    let second_fork_ceiling_hash = authority_entry_hash(&second_fork_ceiling).unwrap();
    let second_fork_tier_hash = authority_entry_hash(&second_fork_tier).unwrap();
    let by_hash = BTreeMap::from([
        (genesis_hash, genesis.clone()),
        (enroll_second_hash, enroll_second.clone()),
        (owner_fork_ceiling_hash, owner_fork_ceiling),
        (owner_fork_tier_hash, owner_fork_tier),
        (second_fork_ceiling_hash, second_fork_ceiling),
        (second_fork_tier_hash, second_fork_tier),
    ]);
    let entry_ancestors = entry_ancestor_index(&by_hash);
    let mut states = BTreeMap::new();
    let genesis_state = match fold_entry_state_for_test(&genesis, genesis_hash, &states) {
        EntryFold::Ready(state) => state,
        _ => panic!("genesis should fold"),
    };
    states.insert(genesis_hash, genesis_state);
    let enroll_state = match fold_entry_state_for_test(&enroll_second, enroll_second_hash, &states)
    {
        EntryFold::Ready(state) => state,
        _ => panic!("enrollment should fold"),
    };
    states.insert(enroll_second_hash, enroll_state);
    let owner_group_key = (owner_key, 2);
    let second_group_key = (second_key, 0);
    let owner_group = BTreeSet::from([owner_fork_ceiling_hash, owner_fork_tier_hash]);
    let second_group = BTreeSet::from([second_fork_ceiling_hash, second_fork_tier_hash]);
    let pending = BTreeSet::from([
        owner_fork_ceiling_hash,
        owner_fork_tier_hash,
        second_fork_ceiling_hash,
        second_fork_tier_hash,
    ]);
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let equivocation_groups = BTreeMap::from([
        (owner_group_key.clone(), owner_group),
        (second_group_key.clone(), second_group.clone()),
    ]);
    let unresolved_equivocation_groups =
        BTreeSet::from([owner_group_key, second_group_key.clone()]);
    let context = FoldContext {
        first_seen_at_secs: &first_seen_at_secs,
        now_secs: None,
        enforce_seen_time_delay: false,
        vetoed_widens: &vetoed_widens,
        authority_forks: &authority_forks,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: Some(&entry_ancestors),
    };

    assert!(matches!(
        resolve_equivocation_group(
            &second_group_key,
            &second_group,
            &by_hash,
            &states,
            &pending,
            context
        ),
        EquivocationResolution::Waiting
    ));
}

#[test]
fn resolved_fork_does_not_mask_unresolved_later_fork_for_same_key() {
    let (_, key, _, mut state) = single_owner_state(98);
    state.authority_forks.insert(
        (key.clone(), 1),
        AuthorityFork {
            signer: key.clone(),
            seq: 1,
            first_hash: [1; 32],
            second_hash: [2; 32],
            status: AuthorityForkStatus::Resolved,
        },
    );
    let authority_forks = BTreeMap::from([(
        (key.clone(), 2),
        AuthorityFork {
            signer: key.clone(),
            seq: 2,
            first_hash: [3; 32],
            second_hash: [4; 32],
            status: AuthorityForkStatus::Quarantined,
        },
    )]);
    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    let context = FoldContext {
        first_seen_at_secs: &first_seen_at_secs,
        now_secs: None,
        enforce_seen_time_delay: false,
        vetoed_widens: &vetoed_widens,
        authority_forks: &authority_forks,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: None,
    };

    assert!(key_is_quarantined_for_entry(&state, context, &key, [9; 32]));
}

#[test]
fn quarantined_keys_do_not_count_as_revoke_survivors() {
    let owner = ed_key(90);
    let second = ed_key(91);
    let third = ed_key(92);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(90, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 91,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &second,
            EnrollSpec {
                seed: 92,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 0,
                ts: 3,
            },
        ),
        &second,
        &owner,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 2, 4),
        &owner,
        &second,
    );
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold
        .valid_entries
        .contains(&authority_entry_hash(&fork_restrict).unwrap())
    {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let revoke_second = cosign_ed(
        revoke_entry(vault_id, &winner, &second, second_key, 1),
        &second,
        &third,
    );
    let revoke_hash = authority_entry_hash(&revoke_second).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        revoke_second,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert!(!fold.valid_entries.contains(&revoke_hash));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_hash
    )));
}

#[test]
fn fork_winner_revoke_rechecks_quorum_without_quarantined_signer() {
    let owner = ed_key(106);
    let second = ed_key(107);
    let third = ed_key(108);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(106, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 107,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 108,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let bad_revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &owner, second_key, 3),
        &owner,
        &third,
    );
    let good_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let bad_revoke_hash = authority_entry_hash(&bad_revoke).unwrap();
    let good_ceiling_hash = authority_entry_hash(&good_ceiling).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        bad_revoke,
        good_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&good_ceiling_hash));
    assert!(!fold.valid_entries.contains(&bad_revoke_hash));
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Quarantined
    );
    assert_eq!(fold.fork_alarms.len(), 1);
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == bad_revoke_hash
    )));
}

#[test]
fn winning_self_revoke_marks_authority_fork_resolved() {
    let owner = ed_key(93);
    let second = ed_key(94);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(93, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 94,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 95,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let self_revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &owner, owner_key.clone(), 3),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fork_ceiling,
        self_revoke,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn recovery_reboot_resolves_inherited_authority_fork() {
    let owner = ed_key(100);
    let second = ed_key(101);
    let third = ed_key(102);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(100, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 101,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 102,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let fork_restrict = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_third, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 4),
        &owner,
        &second,
    );
    let fork_fold = fold_authority_log_without_seen_time_delay(&[
        fork_restrict.clone(),
        fork_ceiling.clone(),
        enroll_third.clone(),
        enroll_second.clone(),
        genesis.clone(),
    ]);
    let winner = if fork_fold
        .valid_entries
        .contains(&authority_entry_hash(&fork_restrict).unwrap())
    {
        fork_restrict.clone()
    } else {
        fork_ceiling.clone()
    };
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &winner, &second, 103, 0),
        &second,
        &third,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        recovery,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn fold_equivocation_fork_rank_prefers_more_restrictive_state_before_hash() {
    let owner = ed_key(34);
    let second = ed_key(35);
    let genesis = genesis_entry(34, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_entry(vault_id, &genesis, &owner, 35, 1, 2);
    let enroll_third = cosign_ed(
        enroll_entry(vault_id, &enroll_second, &owner, 36, 2, 3),
        &owner,
        &second,
    );
    let restrict_floor = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 2, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let restrict_hash = authority_entry_hash(&restrict_floor).unwrap();
    let grant_hash = authority_entry_hash(&enroll_third).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        enroll_third,
        restrict_floor,
        enroll_second,
        genesis,
    ]);
    assert!(fold.valid_entries.contains(&restrict_hash));
    assert!(!fold.valid_entries.contains(&grant_hash));
    assert_eq!(fold.tier_floor, Some(AuthorityTier::Hardware));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 2 }
            if *key == authority_key_from_ed(&owner)
    )));
}

#[test]
fn pending_widen_equivocation_rank_uses_eventual_state() {
    let owner = ed_key(42);
    let genesis = genesis_entry(42, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let mut chosen = None;
    for seed in 43..96 {
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: u64::from(seed),
            },
        );
        let ceiling = set_ceiling_entry(vault_id, &genesis, &owner, 1, u64::from(seed) + 100);
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let ceiling_hash = authority_entry_hash(&ceiling).unwrap();
        if pending_hash < ceiling_hash {
            chosen = Some((pending, pending_hash, ceiling, ceiling_hash));
            break;
        }
    }
    let (pending, pending_hash, ceiling, ceiling_hash) =
        chosen.expect("test seeds must include a pending hash below the ceiling hash");
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(
        &[pending, ceiling, genesis],
        &first_seen,
        DEFAULT_PENDING_WIDEN_DELAY_SECS - 1,
    );

    assert!(fold.valid_entries.contains(&ceiling_hash));
    assert!(!fold.valid_entries.contains(&pending_hash));
    assert!(fold.pending_widens.is_empty());
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationDetected { signer: key, seq: 1 }
            if *key == authority_key_from_ed(&owner)
    )));
}

#[test]
fn fold_allows_newly_enrolled_signer_to_start_at_seq_zero() {
    let owner = ed_key(32);
    let new_signer = ed_key(33);
    let genesis = genesis_entry(32, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner_key = authority_key_from_ed(&owner);
    let new_key = authority_key_from_ed(&new_signer);
    let enroll_admin = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            AuthorityOp::EnrollDevice {
                device: device(new_key, ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let first_new_signer_entry = cosign_ed(
        set_tier_floor_entry(
            vault_id,
            &enroll_admin,
            &new_signer,
            0,
            AuthorityTier::Hardware,
        ),
        &new_signer,
        &owner,
    );
    let first_hash = authority_entry_hash(&first_new_signer_entry).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        first_new_signer_entry,
        enroll_admin,
        genesis,
    ]);
    assert!(fold.valid_entries.contains(&first_hash));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == first_hash
    )));
}

#[test]
fn fold_rejects_cross_vault_root_contamination() {
    let local = genesis_entry(26, 86_400, 1);
    let foreign = genesis_entry(27, 86_400, 1);

    let fold = fold_authority_log(&[local, foreign]);
    assert_eq!(fold.vault_id, None);
    assert!(fold.valid_entries.is_empty());
    assert!(fold.roster.is_empty());
    assert!(
        fold.issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
    );
}

#[test]
fn software_tier_widen_waits_for_local_seen_time_window() {
    let owner = ed_key(60);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(60, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 61,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let first_seen = BTreeMap::from([(enroll_hash, 10)]);
    let new_key = authority_key_from_ed(&ed_key(61));

    let before = fold_authority_log_with_seen_times(
        &[genesis.clone(), enroll.clone()],
        &first_seen,
        10 + delay - 1,
    );
    assert!(!before.roster.contains_key(&new_key));
    assert_eq!(
        before.pending_widens.get(&enroll_hash),
        Some(&AuthorityPendingWiden {
            entry_hash: enroll_hash,
            first_seen_at_secs: Some(10),
            eligible_at_secs: Some(10 + delay),
            delay_secs: delay,
        })
    );

    let after = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 10 + delay);
    assert!(after.roster.contains_key(&new_key));
    assert!(after.pending_widens.is_empty());
}

#[test]
fn hardware_tier_widen_is_instant() {
    let owner = ed_key(62);
    let owner_key = authority_key_from_ed(&owner);
    let op = AuthorityOp::Genesis {
        device: device(
            owner_key.clone(),
            ROLE_OWNER | ROLE_ADMIN,
            AuthorityTier::Hardware,
        ),
        genesis_nonce: [72; 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    };
    let genesis = sign_ed(
        unsigned_entry(None, 0, Vec::new(), op, owner_key, 1),
        &owner,
    );
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 63,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let first_seen = BTreeMap::from([(enroll_hash, 1)]);
    let fold = fold_authority_log_with_seen_times(&[genesis, enroll], &first_seen, 1);

    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(63)))
    );
    assert!(fold.pending_widens.is_empty());
}

#[test]
fn veto_from_owner_kills_pending_widen_in_every_arrival_order() {
    let owner = ed_key(64);
    let genesis = genesis_entry(64, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 65,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
    let first_seen = BTreeMap::from([(pending_hash, 0)]);
    let permutations = [
        vec![genesis.clone(), pending.clone(), veto.clone()],
        vec![genesis.clone(), veto.clone(), pending.clone()],
        vec![pending.clone(), genesis.clone(), veto.clone()],
        vec![pending.clone(), veto.clone(), genesis.clone()],
        vec![veto.clone(), genesis.clone(), pending.clone()],
        vec![veto, pending, genesis],
    ];

    for entries in permutations {
        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, 200);
        assert!(
            !fold
                .roster
                .contains_key(&authority_key_from_ed(&ed_key(65)))
        );
        assert!(fold.vetoed_widens.contains(&pending_hash));
        assert!(fold.pending_widens.is_empty());
    }
}

#[test]
fn veto_after_local_seen_time_window_does_not_revoke_active_widen() {
    let owner = ed_key(95);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(95, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 96,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(&[veto, pending, genesis], &first_seen, delay);

    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(96)))
    );
    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&pending_hash));
}

#[test]
fn admin_without_owner_role_cannot_veto_pending_widen() {
    let owner = ed_key(81);
    let admin = ed_key(82);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(81, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 82,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_admin_hash = authority_entry_hash(&enroll_admin).unwrap();
    let pending = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_admin,
            &owner,
            EnrollSpec {
                seed: 83,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &admin,
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let veto = veto_entry(vault_id, &pending, &admin, pending_hash, 0);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(enroll_admin_hash, 0), (pending_hash, delay)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, pending, enroll_admin, genesis],
        &first_seen,
        delay,
    );

    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&pending_hash));
    assert!(fold.pending_widens.contains_key(&pending_hash));
}

#[test]
fn veto_child_of_delayed_rotation_survives_when_old_key_lands_revoked() {
    let owner = ed_key(73);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(73, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key.clone(), 74, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let malicious_widen = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 75,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 2,
        },
    );
    let malicious_hash = authority_entry_hash(&malicious_widen).unwrap();
    let veto = veto_entry(vault_id, &rotation, &owner, malicious_hash, 3);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let first_seen = BTreeMap::from([(rotation_hash, 0), (malicious_hash, delay)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, malicious_widen, rotation, genesis],
        &first_seen,
        delay,
    );

    assert!(fold.valid_entries.contains(&veto_hash));
    assert!(fold.vetoed_widens.contains(&malicious_hash));
    assert!(
        !fold
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(75)))
    );
    assert!(
        fold.roster
            .get(&owner_key)
            .is_some_and(|device| device.revoked)
    );
}

#[test]
fn delayed_rotation_veto_key_cannot_veto_descendant_widen() {
    let owner = ed_key(76);
    let owner_key = authority_key_from_ed(&owner);
    let new_owner = ed_key(77);
    let genesis = genesis_entry(76, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let rotation = rotate_entry(vault_id, &genesis, &owner, owner_key, 77, 1);
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let future_widen = enroll_device_entry(
        vault_id,
        &rotation,
        &new_owner,
        EnrollSpec {
            seed: 78,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 0,
            ts: 2,
        },
    );
    let future_hash = authority_entry_hash(&future_widen).unwrap();
    let veto = veto_entry(vault_id, &rotation, &owner, future_hash, 2);
    let veto_hash = authority_entry_hash(&veto).unwrap();
    let first_seen = BTreeMap::from([(rotation_hash, 0), (future_hash, 0)]);

    let fold = fold_authority_log_with_seen_times(
        &[veto, future_widen, rotation, genesis],
        &first_seen,
        DEFAULT_PENDING_WIDEN_DELAY_SECS,
    );

    assert!(!fold.valid_entries.contains(&veto_hash));
    assert!(!fold.vetoed_widens.contains(&future_hash));
    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(78)))
    );
}

#[test]
fn child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
    let owner = ed_key(97);
    let admin = ed_key(98);
    let child = ed_key(99);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(97, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 98,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending_admin).unwrap();
    let child_widen = cosign_ed(
        enroll_device_entry(
            vault_id,
            &pending_admin,
            &owner,
            EnrollSpec {
                seed: 99,
                roles: ROLE_AGENT,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &admin,
    );
    let child_hash = authority_entry_hash(&child_widen).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0), (child_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[child_widen.clone(), pending_admin.clone(), genesis.clone()],
        &first_seen,
        delay - 1,
    );
    assert!(!before.valid_entries.contains(&child_hash));
    assert!(!before.roster.contains_key(&authority_key_from_ed(&child)));

    let after = fold_authority_log_with_seen_times(
        &[child_widen, pending_admin, genesis],
        &first_seen,
        delay,
    );
    assert!(after.valid_entries.contains(&child_hash));
    assert!(after.roster.contains_key(&authority_key_from_ed(&child)));
}

#[test]
fn non_widen_child_of_pending_widen_waits_for_parent_seen_time_eligibility() {
    let owner = ed_key(100);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(100, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending_admin = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 101,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending_admin).unwrap();
    let child_ceiling = set_ceiling_entry(vault_id, &pending_admin, &owner, 2, 3);
    let child_hash = authority_entry_hash(&child_ceiling).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[
            child_ceiling.clone(),
            pending_admin.clone(),
            genesis.clone(),
        ],
        &first_seen,
        delay - 1,
    );
    assert!(!before.valid_entries.contains(&child_hash));
    assert!(before.pending_widens.contains_key(&pending_hash));

    let after = fold_authority_log_with_seen_times(
        &[child_ceiling, pending_admin, genesis],
        &first_seen,
        delay,
    );
    assert!(!after.valid_entries.contains(&child_hash));
    assert!(after.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::MissingQuorum(hash) if *hash == child_hash
    )));
}

#[test]
fn devices_with_different_first_seen_times_temporarily_diverge_then_converge() {
    let owner = ed_key(66);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(66, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 67,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let new_key = authority_key_from_ed(&ed_key(67));
    let early_seen = BTreeMap::from([(pending_hash, 0)]);
    let late_seen = BTreeMap::from([(pending_hash, delay - 25)]);

    let early_fold = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &early_seen,
        delay + 50,
    );
    let late_fold = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &late_seen,
        delay + 50,
    );
    assert!(early_fold.roster.contains_key(&new_key));
    assert!(!late_fold.roster.contains_key(&new_key));
    assert!(late_fold.pending_widens.contains_key(&pending_hash));

    let late_after = fold_authority_log_with_seen_times(&[genesis, pending], &late_seen, delay * 2);
    assert_eq!(early_fold.roster, late_after.roster);
    assert!(late_after.pending_widens.is_empty());
}

#[test]
fn concurrent_restriction_beats_pending_widen_after_delay() {
    let owner = ed_key(68);
    let second = ed_key(69);
    let target = ed_key(70);
    let target_key = authority_key_from_ed(&target);
    let delay = DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(68, delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 69,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Hardware,
            seq: 1,
            ts: 2,
        },
    );
    let pending = enroll_device_entry(
        vault_id,
        &enroll_second,
        &owner,
        EnrollSpec {
            seed: 70,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 2,
            ts: 3,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let revoke = cosign_ed(
        revoke_entry(vault_id, &enroll_second, &second, target_key.clone(), 0),
        &second,
        &owner,
    );
    let first_seen = BTreeMap::from([
        (authority_entry_hash(&enroll_second).unwrap(), 0),
        (pending_hash, delay),
    ]);

    let fold = fold_authority_log_with_seen_times(
        &[pending, revoke, enroll_second, genesis],
        &first_seen,
        delay * 2,
    );
    let folded = fold
        .roster
        .get(&target_key)
        .expect("restriction tombstone should keep the target visible");
    assert!(folded.revoked);
    assert_eq!(folded.roles, 0);
}

#[test]
fn genesis_delay_knob_defaults_within_band_and_custom_delay_is_honored() {
    let owner = ed_key(71);
    let custom_delay = MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS;
    let genesis = genesis_entry(71, custom_delay, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let pending = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 72,
            roles: ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let pending_hash = authority_entry_hash(&pending).unwrap();
    let first_seen = BTreeMap::from([(pending_hash, 0)]);

    let before = fold_authority_log_with_seen_times(
        &[genesis.clone(), pending.clone()],
        &first_seen,
        custom_delay - 1,
    );
    assert_eq!(
        before.pending_widens[&pending_hash].delay_secs,
        custom_delay
    );
    assert!(
        !before
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(72)))
    );

    let after = fold_authority_log_with_seen_times(&[genesis, pending], &first_seen, custom_delay);
    assert!(
        after
            .roster
            .contains_key(&authority_key_from_ed(&ed_key(72)))
    );
}

#[test]
fn timestamp_is_advisory_for_fold_output() {
    let owner = ed_key(7);
    let genesis_a = genesis_entry(7, 86_400, 1);
    let genesis_b = genesis_entry(7, 86_400, 999_999);
    let vault_a = genesis_vault_id(&genesis_a).unwrap();
    let vault_b = genesis_vault_id(&genesis_b).unwrap();
    let enroll_a = enroll_entry(vault_a, &genesis_a, &owner, 8, 1, 2);
    let enroll_b = enroll_entry(vault_b, &genesis_b, &owner, 8, 1, 999_998);

    let fold_a = fold_authority_log(&[genesis_a, enroll_a]);
    let fold_b = fold_authority_log(&[genesis_b, enroll_b]);
    let roles_a: Vec<_> = fold_a
        .roster
        .values()
        .map(|device| (device.roles, device.revoked))
        .collect();
    let roles_b: Vec<_> = fold_b
        .roster
        .values()
        .map(|device| (device.roles, device.revoked))
        .collect();
    assert_eq!(roles_a, roles_b);
}

proptest! {
    #[test]
    fn equivocation_alarm_is_permutation_invariant(
        perm in prop::collection::vec(0_usize..4, 4),
    ) {
        let owner = ed_key(90);
        let genesis = genesis_entry(90, 86_400, 1);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll = enroll_entry(vault_id, &genesis, &owner, 91, 1, 2);
        let left = set_ceiling_entry(vault_id, &enroll, &owner, 2, 3);
        let right = set_tier_floor_entry(vault_id, &enroll, &owner, 2, AuthorityTier::Hardware);
        let entries = vec![genesis, enroll, left, right];
        let baseline = fold_authority_log_without_seen_time_delay(&entries);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }

        let folded = fold_authority_log_without_seen_time_delay(&permuted);
        prop_assert_eq!(folded.authority_forks, baseline.authority_forks);
        prop_assert_eq!(folded.fork_alarms, baseline.fork_alarms);
        prop_assert_eq!(folded.valid_entries, baseline.valid_entries);
    }

    #[test]
    fn fold_permutation_property_including_pending_widen_delay(
        delay in 86_400_u64..=172_800,
        include_revoke in any::<bool>(),
        perm in prop::collection::vec(0_usize..4, 4),
    ) {
        let owner = ed_key(10);
        let genesis = genesis_entry(10, delay, 11);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let enroll_a = enroll_entry(vault_id, &genesis, &owner, 11, 1, 12);
        let enroll_b = enroll_entry(vault_id, &genesis, &owner, 12, 2, 13);
        let revoke = revoke_entry(
            vault_id,
            &enroll_a,
            &owner,
            authority_key_from_ed(&ed_key(11)),
            3,
        );
        let mut entries = vec![genesis, enroll_a, enroll_b];
        if include_revoke {
            entries.push(revoke);
        }
        let baseline = fold_authority_log(&entries);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }
        let folded = fold_authority_log(&permuted);
        prop_assert_eq!(folded.vault_id, baseline.vault_id);
        prop_assert_eq!(folded.roster, baseline.roster);
        prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
    }

    #[test]
    fn fold_seen_time_veto_race_is_permutation_invariant(
        delay in 86_400_u64..=172_800,
        include_veto in any::<bool>(),
        perm in prop::collection::vec(0_usize..3, 3),
    ) {
        let owner = ed_key(20);
        let genesis = genesis_entry(20, delay, 21);
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let pending = enroll_device_entry(
            vault_id,
            &genesis,
            &owner,
            EnrollSpec {
                seed: 21,
                roles: ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 1,
                ts: 22,
            },
        );
        let pending_hash = authority_entry_hash(&pending).unwrap();
        let veto = veto_entry(vault_id, &genesis, &owner, pending_hash, 2);
        let mut entries = vec![genesis, pending];
        if include_veto {
            entries.push(veto);
        }
        let first_seen = BTreeMap::from([(pending_hash, 0)]);
        let baseline = fold_authority_log_with_seen_times(&entries, &first_seen, delay - 1);

        let mut permuted = Vec::new();
        for index in perm {
            if let Some(entry) = entries.get(index % entries.len()) {
                permuted.push(entry.clone());
            }
        }
        for entry in &entries {
            if !permuted.iter().any(|candidate| candidate == entry) {
                permuted.push(entry.clone());
            }
        }
        let folded = fold_authority_log_with_seen_times(&permuted, &first_seen, delay - 1);
        prop_assert_eq!(folded.vault_id, baseline.vault_id);
        prop_assert_eq!(folded.roster, baseline.roster);
        prop_assert_eq!(folded.pending_widens, baseline.pending_widens);
        prop_assert_eq!(folded.vetoed_widens, baseline.vetoed_widens);
        prop_assert_eq!(folded.tier_floor, baseline.tier_floor);
    }
}

// ---------------------------------------------------------------------------
// Federation lifecycle (ONE-1408)
// ---------------------------------------------------------------------------

fn scope_entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn symmetric_scope(
    facets: crate::federation::FederationScopeFacets,
    bands: crate::federation::FederationScopeBands,
) -> FederationPactScope {
    let half = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::All,
        facets,
        bands,
    };
    FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    }
}

fn default_pact_scope() -> FederationPactScope {
    FederationPactScope {
        lo_to_hi: FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::All,
            facets: crate::federation::FederationScopeFacets::All,
            bands: crate::federation::FederationScopeBands::All,
        },
        hi_to_lo: FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::Base,
            facets: crate::federation::FederationScopeFacets::All,
            bands: crate::federation::FederationScopeBands::All,
        },
    }
}

fn scope_digest_for(scope: &FederationPactScope, nonce: &[u8; 16]) -> [u8; 32] {
    federation_scope_digest(nonce, &encode_federation_pact_scope(scope).unwrap())
}

struct PactFixture {
    owner: SigningKey,
    peer: SigningKey,
    genesis: AuthorityLogEntry,
    peer_genesis: AuthorityLogEntry,
    vault_id: AuthorityVaultId,
    peer_vault_id: AuthorityVaultId,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_nonce: [u8; 16],
    scope: FederationPactScope,
    scope_digest: [u8; 32],
}

fn pact_fixture_with_scope(seed: u8, scope: FederationPactScope) -> PactFixture {
    let owner = ed_key(seed);
    let genesis = genesis_entry(seed, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let peer = ed_key(seed.wrapping_add(1));
    let peer_genesis = genesis_entry(seed.wrapping_add(1), 86_400, 1);
    let peer_vault_id = genesis_vault_id(&peer_genesis).unwrap();
    let pact_nonce = [seed.wrapping_add(2); 16];
    PactFixture {
        scope_digest: scope_digest_for(&scope, &pact_nonce),
        owner,
        peer,
        genesis,
        peer_genesis,
        vault_id,
        peer_vault_id,
        pact_id: [seed.wrapping_add(3); 32],
        grant_ref: scope_entity(seed.wrapping_add(4)),
        pact_nonce,
        scope,
    }
}

fn pact_fixture(seed: u8) -> PactFixture {
    pact_fixture_with_scope(seed, default_pact_scope())
}

#[allow(clippy::too_many_arguments)]
fn ed_pact_gesture(
    kind: FederationLifecycleKind,
    pact_id: &[u8; 32],
    vault_a: &AuthorityVaultId,
    vault_b: &AuthorityVaultId,
    pact_epoch: u64,
    scope_digest: &[u8; 32],
    successor: Option<&AuthorityVaultId>,
    pact_nonce: &[u8; 16],
    peer: &SigningKey,
) -> FederationPactGesture {
    sign_federation_pact_gesture(
        kind,
        pact_id,
        vault_a,
        vault_b,
        pact_epoch,
        scope_digest,
        successor,
        pact_nonce,
        authority_key_from_ed(peer),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .unwrap()
}

fn connect_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    scope: &FederationPactScope,
    nonce: [u8; 16],
) -> FederationLifecycleAction {
    let digest = scope_digest_for(scope, &nonce);
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch: 1,
        pact_scope: Some(scope.clone()),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Connect,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            1,
            &digest,
            None,
            &nonce,
            &fixture.peer,
        )),
        successor_vault_id: None,
        pact_nonce: nonce,
    }
}

fn connect_action(fixture: &PactFixture) -> FederationLifecycleAction {
    connect_action_with(
        fixture,
        fixture.pact_id,
        fixture.grant_ref,
        &fixture.scope,
        fixture.pact_nonce,
    )
}

fn narrow_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    effective: FederationDirectionScope,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Rescope,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: Some(effective),
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    }
}

fn repact_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    scope: &FederationPactScope,
    nonce: [u8; 16],
) -> FederationLifecycleAction {
    let digest = scope_digest_for(scope, &nonce);
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Rescope,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: Some(scope.clone()),
        effective_scope: None,
        scope_digest: Some(digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Rescope,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            pact_epoch,
            &digest,
            None,
            &nonce,
            &fixture.peer,
        )),
        successor_vault_id: None,
        pact_nonce: nonce,
    }
}

fn unilateral_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    kind: FederationLifecycleKind,
    pact_epoch: u64,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: None,
        gesture: None,
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    }
}

fn promote_action_with(
    fixture: &PactFixture,
    pact_id: [u8; 32],
    grant_ref: EntityId,
    pact_epoch: u64,
    stored_digest: [u8; 32],
    successor: AuthorityVaultId,
) -> FederationLifecycleAction {
    FederationLifecycleAction {
        kind: FederationLifecycleKind::Promote,
        pact_id,
        grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        pact_epoch,
        pact_scope: None,
        effective_scope: None,
        scope_digest: Some(stored_digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Promote,
            &pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            pact_epoch,
            &stored_digest,
            Some(&successor),
            &fixture.pact_nonce,
            &fixture.peer,
        )),
        successor_vault_id: Some(successor),
        pact_nonce: fixture.pact_nonce,
    }
}

fn lifecycle_entry(
    fixture: &PactFixture,
    parents: Vec<AuthorityEntryHash>,
    seq: u64,
    action: FederationLifecycleAction,
) -> AuthorityLogEntry {
    sign_ed(
        unsigned_entry(
            Some(fixture.vault_id),
            seq,
            parents,
            AuthorityOp::FederationLifecycle(action),
            authority_key_from_ed(&fixture.owner),
            100 + seq,
        ),
        &fixture.owner,
    )
}

fn lifecycle_rejection(
    fold: &AuthorityFold,
    hash: AuthorityEntryHash,
) -> Option<FederationLifecycleRejection> {
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::FederationLifecycleRejected { entry, reason } if *entry == hash => {
            Some(*reason)
        }
        _ => None,
    })
}

#[test]
fn federation_connect_activates_pact_on_both_sides() {
    let fixture = pact_fixture(120);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    let fold =
        fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), connect.clone()]);
    assert!(
        fold.valid_entries
            .contains(&authority_entry_hash(&connect).unwrap())
    );
    let pact = fold
        .federation_pacts
        .get(&fixture.pact_id)
        .expect("connect must activate the pact");
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(pact.grant_ref, fixture.grant_ref);
    assert_eq!(pact.peer_vault_id, fixture.peer_vault_id);
    assert_eq!(
        pact.peer_owner_key,
        authority_key_from_ed(&fixture.peer),
        "peer key must be pinned at connect"
    );
    assert_eq!(pact.scope_digest, fixture.scope_digest);
    assert_eq!(pact.pact_scope, fixture.scope);
    let expected_half = if fixture.vault_id <= fixture.peer_vault_id {
        fixture.scope.lo_to_hi.clone()
    } else {
        fixture.scope.hi_to_lo.clone()
    };
    assert_eq!(pact.effective_scope, expected_half);
    assert_eq!(pact.successor_vault_id, None);
    assert_eq!(pact.terminal_epoch, None);
    assert_eq!(fold.pact_for_grant(&fixture.grant_ref), Some(pact));
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &scope_entity(0x77)),
        FederationGrantActivation::Unpacted
    );

    // Symmetric entry on B: same pact id, same digest, gesture signed by A's
    // owner over the identical (sorted-vault) transcript.
    let symmetric_grant = scope_entity(0x41);
    let symmetric_action = FederationLifecycleAction {
        kind: FederationLifecycleKind::Connect,
        pact_id: fixture.pact_id,
        grant_ref: symmetric_grant,
        peer_vault_id: fixture.vault_id,
        pact_epoch: 1,
        pact_scope: Some(fixture.scope.clone()),
        effective_scope: None,
        scope_digest: Some(fixture.scope_digest),
        gesture: Some(ed_pact_gesture(
            FederationLifecycleKind::Connect,
            &fixture.pact_id,
            &fixture.vault_id,
            &fixture.peer_vault_id,
            1,
            &fixture.scope_digest,
            None,
            &fixture.pact_nonce,
            &fixture.owner,
        )),
        successor_vault_id: None,
        pact_nonce: fixture.pact_nonce,
    };
    let symmetric_connect = sign_ed(
        unsigned_entry(
            Some(fixture.peer_vault_id),
            1,
            vec![authority_entry_hash(&fixture.peer_genesis).unwrap()],
            AuthorityOp::FederationLifecycle(symmetric_action),
            authority_key_from_ed(&fixture.peer),
            2,
        ),
        &fixture.peer,
    );
    let peer_fold = fold_authority_log_without_seen_time_delay(&[
        fixture.peer_genesis.clone(),
        symmetric_connect,
    ]);
    let peer_pact = peer_fold
        .federation_pacts
        .get(&fixture.pact_id)
        .expect("symmetric connect must activate on B");
    assert_eq!(peer_pact.status, FederationPactStatus::Active);
    assert_eq!(
        peer_pact.peer_owner_key,
        authority_key_from_ed(&fixture.owner)
    );
    let expected_peer_half = if fixture.peer_vault_id <= fixture.vault_id {
        fixture.scope.lo_to_hi.clone()
    } else {
        fixture.scope.hi_to_lo.clone()
    };
    assert_eq!(peer_pact.effective_scope, expected_peer_half);
    assert_eq!(
        federation_grant_activation(&peer_fold, &symmetric_grant),
        FederationGrantActivation::Active
    );
}

#[test]
fn federation_connect_digest_mismatch_never_activates() {
    // (a) Gesture signed over digest Y while the entry claims X: the scope
    // recomputes to X, so the gesture check fails.
    let fixture = pact_fixture(124);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let mut action = connect_action(&fixture);
    action.gesture = Some(ed_pact_gesture(
        FederationLifecycleKind::Connect,
        &fixture.pact_id,
        &fixture.vault_id,
        &fixture.peer_vault_id,
        1,
        &[0xEE; 32],
        None,
        &fixture.pact_nonce,
        &fixture.peer,
    ));
    let entry = lifecycle_entry(&fixture, vec![genesis_hash], 1, action);
    let entry_hash = authority_entry_hash(&entry).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), entry]);
    assert!(fold.federation_pacts.is_empty(), "no pact state may form");
    assert_eq!(fold.pact_for_grant(&fixture.grant_ref), None);
    assert_eq!(
        lifecycle_rejection(&fold, entry_hash),
        Some(FederationLifecycleRejection::GestureInvalid)
    );

    // (b) Entry's pact_scope tampered: the recompute no longer matches the
    // claimed (and gesture-signed) digest.
    let fixture = pact_fixture(126);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let mut action = connect_action(&fixture);
    action.pact_scope = Some(symmetric_scope(
        crate::federation::FederationScopeFacets::Bottom,
        crate::federation::FederationScopeBands::All,
    ));
    let entry = lifecycle_entry(&fixture, vec![genesis_hash], 1, action);
    let entry_hash = authority_entry_hash(&entry).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), entry]);
    assert!(fold.federation_pacts.is_empty(), "no pact state may form");
    assert_eq!(
        lifecycle_rejection(&fold, entry_hash),
        Some(FederationLifecycleRejection::ScopeDigestMismatch)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Unpacted
    );
}

#[test]
fn federation_rescope_narrow_and_repact_rules() {
    let ceiling_facets = crate::federation::FederationScopeFacets::Some(vec![
        scope_entity(0x21),
        scope_entity(0x22),
    ]);
    let fixture = pact_fixture_with_scope(
        128,
        symmetric_scope(ceiling_facets, crate::federation::FederationScopeBands::All),
    );
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();

    // Widen attempt: effective facets = All escapes the Some([...]) ceiling.
    let widen = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            FederationDirectionScope {
                worlds: crate::federation::FederationScopeWorlds::All,
                facets: crate::federation::FederationScopeFacets::All,
                bands: crate::federation::FederationScopeBands::All,
            },
        ),
    );
    let widen_hash = authority_entry_hash(&widen).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        widen,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, widen_hash),
        Some(FederationLifecycleRejection::WidenWithoutGesture)
    );
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.effective_scope, fixture.scope.lo_to_hi,
        "rejected widen must leave the effective scope unchanged"
    );

    // Narrowing rescope (⊑ ceiling, epoch == cur) replaces effective_scope.
    let narrowed = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::Base,
        facets: crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x21)]),
        bands: crate::federation::FederationScopeBands::Some(vec![TypeByteBand::Semantic]),
    };
    let narrow = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            narrowed.clone(),
        ),
    );
    let narrow_hash = authority_entry_hash(&narrow).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        narrow.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(pact.effective_scope, narrowed);

    // Dual-signed repact at epoch+1 replaces ceiling + digest wholesale.
    let new_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x23)]),
        crate::federation::FederationScopeBands::All,
    );
    let new_nonce = [0x5A; 16];
    let repact = lifecycle_entry(
        &fixture,
        vec![narrow_hash],
        4,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &new_scope,
            new_nonce,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        narrow,
        repact,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.pact_scope, new_scope);
    assert_eq!(pact.scope_digest, scope_digest_for(&new_scope, &new_nonce));
    assert_eq!(pact.effective_scope, new_scope.lo_to_hi);
}

#[test]
fn federation_disconnect_is_terminal_for_every_subsequent_op() {
    let fixture = pact_fixture(132);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let disconnect = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        unilateral_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );
    let disconnect_hash = authority_entry_hash(&disconnect).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        disconnect.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Disconnected);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Disconnected)
    );

    // Every subsequent lifecycle op on P parented after the disconnect.
    let followups = vec![
        (
            "connect",
            lifecycle_entry(&fixture, vec![disconnect_hash], 3, connect_action(&fixture)),
        ),
        (
            "narrow",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                4,
                narrow_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    1,
                    fixture.scope.hi_to_lo.clone(),
                ),
            ),
        ),
        (
            "repact",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                5,
                repact_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    2,
                    &fixture.scope,
                    [0x66; 16],
                ),
            ),
        ),
        (
            "promote",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                6,
                promote_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    2,
                    fixture.scope_digest,
                    [0xCC; 32],
                ),
            ),
        ),
        (
            "dissolve",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                7,
                unilateral_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    FederationLifecycleKind::Dissolve,
                    1,
                ),
            ),
        ),
        (
            "second disconnect",
            lifecycle_entry(
                &fixture,
                vec![disconnect_hash],
                8,
                unilateral_action_with(
                    &fixture,
                    fixture.pact_id,
                    fixture.grant_ref,
                    FederationLifecycleKind::Disconnect,
                    1,
                ),
            ),
        ),
    ];

    let mut entries = vec![fixture.genesis.clone(), connect, disconnect];
    let mut followup_hashes = Vec::new();
    for (name, entry) in followups {
        followup_hashes.push((name, authority_entry_hash(&entry).unwrap()));
        entries.push(entry);
    }
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    for (name, hash) in followup_hashes {
        assert_eq!(
            lifecycle_rejection(&fold, hash),
            Some(FederationLifecycleRejection::TerminalPact),
            "{name} after disconnect must reject TerminalPact"
        );
    }
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Disconnected);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(fold.federation_pacts.len(), 1);

    // Re-covering the SAME grant_ref under a NEW pact id stays rejected even
    // though the binding pact is terminal: revoked access never resurrects.
    let rebind = lifecycle_entry(
        &fixture,
        vec![disconnect_hash],
        9,
        connect_action_with(
            &fixture,
            [0xD1; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x67; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();
    entries.push(rebind);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(fold.federation_pacts.len(), 1);
}

#[test]
fn federation_connect_rejects_rebinding_an_actively_bound_grant() {
    let fixture = pact_fixture(136);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let rebind = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        connect_action_with(
            &fixture,
            [0xD2; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x68; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();

    let fold =
        fold_authority_log_without_seen_time_delay(&[fixture.genesis.clone(), connect, rebind]);
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(fold.federation_pacts.len(), 1);
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );
}

#[test]
fn federation_promote_records_successor_and_is_terminal() {
    let fixture = pact_fixture(140);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let successor = [0xCD; 32];
    let promote = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        promote_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope_digest,
            successor,
        ),
    );
    let promote_hash = authority_entry_hash(&promote).unwrap();
    let after = lifecycle_entry(
        &fixture,
        vec![promote_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope.hi_to_lo.clone(),
        ),
    );
    let after_hash = authority_entry_hash(&after).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        promote,
        after,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Promoted);
    assert_eq!(pact.successor_vault_id, Some(successor));
    assert_eq!(pact.terminal_epoch, Some(2));
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(
        lifecycle_rejection(&fold, after_hash),
        Some(FederationLifecycleRejection::TerminalPact)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Promoted)
    );

    // Promote with a digest that differs from the stored one never lands.
    let fixture = pact_fixture(144);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let bad_promote = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        promote_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            [0xEF; 32],
            successor,
        ),
    );
    let bad_hash = authority_entry_hash(&bad_promote).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        bad_promote,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, bad_hash),
        Some(FederationLifecycleRejection::ScopeDigestMismatch)
    );
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );
}

#[test]
fn federation_dissolve_is_terminal_and_never_recovered() {
    let fixture = pact_fixture(148);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let dissolve = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        unilateral_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            FederationLifecycleKind::Dissolve,
            1,
        ),
    );
    let dissolve_hash = authority_entry_hash(&dissolve).unwrap();
    let repact_after = lifecycle_entry(
        &fixture,
        vec![dissolve_hash],
        3,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &fixture.scope,
            [0x69; 16],
        ),
    );
    let repact_hash = authority_entry_hash(&repact_after).unwrap();
    let rebind = lifecycle_entry(
        &fixture,
        vec![dissolve_hash],
        4,
        connect_action_with(
            &fixture,
            [0xD3; 32],
            fixture.grant_ref,
            &fixture.scope,
            [0x6A; 16],
        ),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        dissolve,
        repact_after,
        rebind,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Dissolved);
    assert_eq!(pact.terminal_epoch, Some(1));
    assert_eq!(
        lifecycle_rejection(&fold, repact_hash),
        Some(FederationLifecycleRejection::TerminalPact)
    );
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Dissolved)
    );
}

#[test]
fn federation_suspended_pact_heals_via_fresh_repact() {
    let fixture = pact_fixture(152);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let left_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x21)]),
        crate::federation::FederationScopeBands::All,
    );
    let right_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x22)]),
        crate::federation::FederationScopeBands::All,
    );
    let left = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &left_scope,
            [0x6B; 16],
        ),
    );
    let right = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            &right_scope,
            [0x6C; 16],
        ),
    );
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        left.clone(),
        right.clone(),
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.status,
        FederationPactStatus::Suspended,
        "divergent equal-epoch repacts must suspend"
    );
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
    );

    // Narrow/Promote on the suspended pact reject SuspendedPact.
    let narrow_on_suspended = lifecycle_entry(
        &fixture,
        vec![left_hash, right_hash],
        4,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            2,
            fixture.scope.hi_to_lo.clone(),
        ),
    );
    let narrow_hash = authority_entry_hash(&narrow_on_suspended).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect.clone(),
        left.clone(),
        right.clone(),
        narrow_on_suspended,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, narrow_hash),
        Some(FederationLifecycleRejection::SuspendedPact)
    );

    // A fresh dual-signed repact at epoch+1 heals the suspension.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x23)]),
        crate::federation::FederationScopeBands::All,
    );
    let heal_nonce = [0x6D; 16];
    let heal = lifecycle_entry(
        &fixture,
        vec![left_hash, right_hash],
        5,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            3,
            &heal_scope,
            heal_nonce,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect,
        left,
        right,
        heal,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 3);
    assert_eq!(pact.pact_scope, heal_scope);
    assert_eq!(
        pact.scope_digest,
        scope_digest_for(&heal_scope, &heal_nonce)
    );
    assert_eq!(
        federation_grant_activation(&fold, &fixture.grant_ref),
        FederationGrantActivation::Active
    );
}

fn pact_state_with_status(
    fixture: &PactFixture,
    status: FederationPactStatus,
) -> FederationPactState {
    FederationPactState {
        status,
        grant_ref: fixture.grant_ref,
        peer_vault_id: fixture.peer_vault_id,
        peer_owner_key: authority_key_from_ed(&fixture.peer),
        pact_epoch: 1,
        scope_digest: fixture.scope_digest,
        pact_scope: fixture.scope.clone(),
        effective_scope: local_outbound_scope(
            &fixture.vault_id,
            &fixture.peer_vault_id,
            &fixture.scope,
        ),
        successor_vault_id: None,
        terminal_epoch: status.is_terminal().then_some(1),
    }
}

fn fold_state_with_pact(fixture: &PactFixture, status: Option<FederationPactStatus>) -> FoldState {
    let owner_key = authority_key_from_ed(&fixture.owner);
    let mut state = FoldState {
        vault_id: fixture.vault_id,
        roster: BTreeMap::from([(
            owner_key.clone(),
            FoldedDevice {
                key: owner_key.clone(),
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
                revoked: false,
            },
        )]),
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
        pending_widens: BTreeMap::new(),
        vetoed_widens: BTreeSet::new(),
        delayed_rotation_veto_revocations: BTreeMap::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        seqs: BTreeMap::from([(owner_key, 0)]),
    };
    if let Some(status) = status {
        state
            .federation_pacts
            .insert(fixture.pact_id, pact_state_with_status(fixture, status));
    }
    state
}

fn totality_ops(fixture: &PactFixture) -> Vec<(&'static str, FederationLifecycleAction)> {
    let narrowed = FederationDirectionScope {
        worlds: crate::federation::FederationScopeWorlds::Base,
        facets: crate::federation::FederationScopeFacets::All,
        bands: crate::federation::FederationScopeBands::All,
    };
    let repact_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    vec![
        ("connect", connect_action(fixture)),
        (
            "narrow",
            narrow_action_with(fixture, fixture.pact_id, fixture.grant_ref, 1, narrowed),
        ),
        (
            "repact",
            repact_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                2,
                &repact_scope,
                [0x7A; 16],
            ),
        ),
        (
            "disconnect",
            unilateral_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                FederationLifecycleKind::Disconnect,
                1,
            ),
        ),
        (
            "promote",
            promote_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                2,
                fixture.scope_digest,
                [0xCE; 32],
            ),
        ),
        (
            "dissolve",
            unilateral_action_with(
                fixture,
                fixture.pact_id,
                fixture.grant_ref,
                FederationLifecycleKind::Dissolve,
                1,
            ),
        ),
    ]
}

fn expected_transition(
    status: Option<FederationPactStatus>,
    op: &str,
) -> std::result::Result<FederationPactStatus, FederationLifecycleRejection> {
    use FederationLifecycleRejection as R;
    use FederationPactStatus as S;
    match (status, op) {
        (None, "connect") => Ok(S::Active),
        (None, _) => Err(R::UnknownPact),
        (Some(current), _) if current.is_terminal() => Err(R::TerminalPact),
        (Some(_), "connect") => Err(R::DuplicateConnect),
        (Some(S::Suspended), "narrow") | (Some(S::Suspended), "promote") => Err(R::SuspendedPact),
        (Some(_), "narrow") | (Some(_), "repact") => Ok(S::Active),
        (Some(_), "disconnect") => Ok(S::Disconnected),
        (Some(_), "promote") => Ok(S::Promoted),
        (Some(_), "dissolve") => Ok(S::Dissolved),
        (status, op) => panic!("uncovered transition pair ({status:?}, {op})"),
    }
}

#[test]
fn federation_lifecycle_transition_table_is_total() {
    let fixture = pact_fixture(156);
    let statuses = [
        None,
        Some(FederationPactStatus::Active),
        Some(FederationPactStatus::Suspended),
        Some(FederationPactStatus::Promoted),
        Some(FederationPactStatus::Disconnected),
        Some(FederationPactStatus::Dissolved),
    ];
    for status in statuses {
        for (name, action) in totality_ops(&fixture) {
            let mut state = fold_state_with_pact(&fixture, status);
            let before = state.federation_pacts.clone();
            let result = apply_federation_lifecycle(&mut state, &action);
            match expected_transition(status, name) {
                Ok(next) => {
                    assert_eq!(result, Ok(()), "({status:?}, {name}) must apply");
                    assert_eq!(
                        state.federation_pacts[&fixture.pact_id].status, next,
                        "({status:?}, {name}) next status"
                    );
                }
                Err(reason) => {
                    assert_eq!(result, Err(reason), "({status:?}, {name}) rejection");
                    assert_eq!(
                        state.federation_pacts, before,
                        "({status:?}, {name}) rejected op must not mutate state"
                    );
                }
            }
        }
    }
}

struct LifecycleDag {
    fixture: PactFixture,
    entries: Vec<AuthorityLogEntry>,
    pact_two: [u8; 32],
    pact_three: [u8; 32],
    low_scope: FederationPactScope,
    low_digest: [u8; 32],
    scope_three: FederationPactScope,
    digest_three: [u8; 32],
}

/// Eleven-entry lifecycle+device DAG exercising the three merge shapes:
/// concurrent narrows (intersection incl. band ⊥), concurrent divergent
/// repacts (Suspended), and Disconnect vs higher-epoch repact (terminal wins).
fn lifecycle_dag() -> LifecycleDag {
    let facet = scope_entity;
    let fixture = pact_fixture_with_scope(
        200,
        symmetric_scope(
            crate::federation::FederationScopeFacets::Some(vec![
                facet(0x21),
                facet(0x22),
                facet(0x23),
            ]),
            crate::federation::FederationScopeBands::All,
        ),
    );
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_hash = authority_entry_hash(&connect).unwrap();
    let narrow_left = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        2,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            FederationDirectionScope {
                worlds: crate::federation::FederationScopeWorlds::All,
                facets: crate::federation::FederationScopeFacets::Some(vec![
                    facet(0x21),
                    facet(0x22),
                ]),
                bands: crate::federation::FederationScopeBands::Some(vec![TypeByteBand::Semantic]),
            },
        ),
    );
    let narrow_right = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        3,
        narrow_action_with(
            &fixture,
            fixture.pact_id,
            fixture.grant_ref,
            1,
            FederationDirectionScope {
                worlds: crate::federation::FederationScopeWorlds::All,
                facets: crate::federation::FederationScopeFacets::Some(vec![
                    facet(0x22),
                    facet(0x23),
                ]),
                bands: crate::federation::FederationScopeBands::Some(vec![TypeByteBand::Core]),
            },
        ),
    );
    let enroll = enroll_entry(
        fixture.vault_id,
        &fixture.genesis,
        &fixture.owner,
        210,
        4,
        50,
    );

    let pact_two = [0xB2; 32];
    let grant_two = scope_entity(0x32);
    let scope_two = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let connect_two = lifecycle_entry(
        &fixture,
        vec![connect_hash],
        5,
        connect_action_with(&fixture, pact_two, grant_two, &scope_two, [0x71; 16]),
    );
    let connect_two_hash = authority_entry_hash(&connect_two).unwrap();
    let left_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![facet(0x21)]),
        crate::federation::FederationScopeBands::All,
    );
    let left_nonce = [0x72; 16];
    let repact_left = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        6,
        repact_action_with(&fixture, pact_two, grant_two, 2, &left_scope, left_nonce),
    );
    let right_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::Some(vec![facet(0x22)]),
        crate::federation::FederationScopeBands::All,
    );
    let right_nonce = [0x73; 16];
    let repact_right = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        7,
        repact_action_with(&fixture, pact_two, grant_two, 2, &right_scope, right_nonce),
    );
    let left_digest = scope_digest_for(&left_scope, &left_nonce);
    let right_digest = scope_digest_for(&right_scope, &right_nonce);
    let (low_scope, low_digest) = if left_digest < right_digest {
        (left_scope, left_digest)
    } else {
        (right_scope, right_digest)
    };

    let pact_three = [0xB3; 32];
    let grant_three = scope_entity(0x33);
    let scope_three = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let nonce_three = [0x74; 16];
    let connect_three = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        8,
        connect_action_with(&fixture, pact_three, grant_three, &scope_three, nonce_three),
    );
    let connect_three_hash = authority_entry_hash(&connect_three).unwrap();
    let repact_three = lifecycle_entry(
        &fixture,
        vec![connect_three_hash],
        9,
        repact_action_with(
            &fixture,
            pact_three,
            grant_three,
            2,
            &symmetric_scope(
                crate::federation::FederationScopeFacets::Some(vec![facet(0x23)]),
                crate::federation::FederationScopeBands::All,
            ),
            [0x75; 16],
        ),
    );
    let disconnect_three = lifecycle_entry(
        &fixture,
        vec![connect_three_hash],
        10,
        unilateral_action_with(
            &fixture,
            pact_three,
            grant_three,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );

    let digest_three = scope_digest_for(&scope_three, &nonce_three);
    let entries = vec![
        fixture.genesis.clone(),
        connect,
        narrow_left,
        narrow_right,
        enroll,
        connect_two,
        repact_left,
        repact_right,
        connect_three,
        repact_three,
        disconnect_three,
    ];
    LifecycleDag {
        fixture,
        entries,
        pact_two,
        pact_three,
        low_scope,
        low_digest,
        scope_three,
        digest_three,
    }
}

#[test]
fn federation_lifecycle_dag_merges_pacts_fail_closed() {
    let dag = lifecycle_dag();
    let fold = fold_authority_log_without_seen_time_delay(&dag.entries);
    assert!(
        fold.issues.is_empty(),
        "unexpected issues: {:?}",
        fold.issues
    );
    assert_eq!(fold.valid_entries.len(), dag.entries.len());
    assert!(
        fold.roster
            .contains_key(&authority_key_from_ed(&ed_key(210)))
    );

    // P1: concurrent unilateral narrows merge to the INTERSECTION; the
    // disjoint band sets meet at the kind-tagged ⊥, never at all-bands.
    let p1 = &fold.federation_pacts[&dag.fixture.pact_id];
    assert_eq!(p1.status, FederationPactStatus::Active);
    assert_eq!(p1.pact_epoch, 1);
    assert_eq!(
        p1.effective_scope,
        FederationDirectionScope {
            worlds: crate::federation::FederationScopeWorlds::All,
            facets: crate::federation::FederationScopeFacets::Some(vec![scope_entity(0x22)]),
            bands: crate::federation::FederationScopeBands::Bottom,
        }
    );

    // P2: concurrent equal-epoch divergent-digest repacts suspend, with the
    // min-digest side's scope fields (determinism-only pick).
    let p2 = &fold.federation_pacts[&dag.pact_two];
    assert_eq!(p2.status, FederationPactStatus::Suspended);
    assert_eq!(p2.pact_epoch, 2);
    assert_eq!(p2.scope_digest, dag.low_digest);
    assert_eq!(p2.pact_scope, dag.low_scope);
    assert_eq!(p2.successor_vault_id, None);
    assert_eq!(p2.terminal_epoch, None);

    // P3: concurrent Disconnect + higher-epoch repact merges to Disconnected
    // (terminal beats epoch), keeping the terminal side's fields verbatim.
    let p3 = &fold.federation_pacts[&dag.pact_three];
    assert_eq!(p3.status, FederationPactStatus::Disconnected);
    assert_eq!(p3.pact_epoch, 1);
    assert_eq!(p3.terminal_epoch, Some(1));
    assert_eq!(p3.scope_digest, dag.digest_three);
    assert_eq!(p3.pact_scope, dag.scope_three);
}

#[test]
fn lifecycle_entries_use_existing_type_122_doors() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let fixture = pact_fixture(190);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    let genesis_id = scope_entity(0x51);
    let connect_id = scope_entity(0x52);
    vault
        .put_authority_log_entry(
            &genesis_id,
            &fixture.genesis,
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
    vault
        .put_authority_log_entry(&connect_id, &connect, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    assert_eq!(
        vault.get_authority_log_entry(&connect_id).unwrap(),
        Some(connect.clone()),
        "lifecycle entry must round-trip through the type-122 write door"
    );
    let fold = vault.authority_fold().unwrap();
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Active
    );

    let body = encode_authority_log_entry_body(&connect).unwrap();
    let err = vault
        .batch()
        .put(
            &scope_entity(0x53),
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 3, end: 3 },
            3,
            &body,
        )
        .commit()
        .expect_err("generic public type-122 put must stay rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::MaintenanceKindNotWritable
    );
}

proptest! {
    #[test]
    fn federation_lifecycle_fold_is_permutation_invariant(
        perm in prop::collection::vec(0_usize..11, 11),
    ) {
        let dag = lifecycle_dag();
        let baseline = fold_authority_log_without_seen_time_delay(&dag.entries);
        prop_assert!(baseline.issues.is_empty());

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
        prop_assert_eq!(folded, baseline);
    }
}

#[test]
fn federation_lifecycle_rejects_all_zero_peer_vault_id() {
    let fixture = pact_fixture(164);
    let mut action = connect_action(&fixture);
    action.peer_vault_id = [0; 32];
    // Unsigned entry (zeroed signature): the all-zero peer vault id must fail
    // closed in validate_op on Connect, before any signature work.
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        1,
        vec![authority_entry_hash(&fixture.genesis).unwrap()],
        AuthorityOp::FederationLifecycle(action),
        authority_key_from_ed(&fixture.owner),
        101,
    );
    let err = encode_authority_log_entry_body(&entry)
        .expect_err("all-zero peer vault id must fail closed");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);

    // Same rejection on the gesture-free kinds sharing the common key set.
    let mut disconnect = unilateral_action_with(
        &fixture,
        fixture.pact_id,
        fixture.grant_ref,
        FederationLifecycleKind::Disconnect,
        1,
    );
    disconnect.peer_vault_id = [0; 32];
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        2,
        vec![authority_entry_hash(&fixture.genesis).unwrap()],
        AuthorityOp::FederationLifecycle(disconnect),
        authority_key_from_ed(&fixture.owner),
        102,
    );
    let err = encode_authority_log_entry_body(&entry)
        .expect_err("all-zero peer vault id must fail closed for unilateral kinds");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}
