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

/// Inverse of [`hex`], for decoding pinned golden vectors back to bytes.
fn hex_bytes(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex literal must be even");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
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

fn cosign_ed_two(
    mut entry: AuthorityLogEntry,
    signer: &SigningKey,
    first_cosigner: &SigningKey,
    second_cosigner: &SigningKey,
) -> AuthorityLogEntry {
    for cosigner in [first_cosigner, second_cosigner] {
        let cosigner_key = authority_key_from_ed(cosigner);
        entry.cosigns.push(AuthoritySignature {
            suite: cosigner_key.suite(),
            public_key: cosigner_key,
            signature: vec![0; 64],
        });
    }
    entry.cosigns.sort_by(|left, right| {
        left.public_key
            .cmp(&right.public_key)
            .then_with(|| left.signature.cmp(&right.signature))
    });
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    for cosigner in [first_cosigner, second_cosigner] {
        let cosigner_key = authority_key_from_ed(cosigner);
        for cosign in &mut entry.cosigns {
            if cosign.public_key == cosigner_key {
                cosign.signature = cosigner.sign(&transcript).to_bytes().to_vec();
            }
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
    revoke_entry_at(vault_id, parent, signer, revoked, seq, 777)
}

fn revoke_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    revoked: AuthorityKey,
    seq: u64,
    ts: u64,
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
            ts,
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
    set_tier_floor_entry_at(vault_id, parent, signer, seq, tier_floor, 888)
}

fn set_tier_floor_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    seq: u64,
    tier_floor: AuthorityTier,
    ts: u64,
) -> AuthorityLogEntry {
    let signer_key = authority_key_from_ed(signer);
    sign_ed(
        unsigned_entry(
            Some(vault_id),
            seq,
            vec![authority_entry_hash(parent).unwrap()],
            AuthorityOp::SetTierFloor { tier_floor },
            signer_key,
            ts,
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
    recovery_reboot_entry_at(vault_id, parent, signer, new_seed, seq, 890)
}

fn recovery_reboot_entry_at(
    vault_id: AuthorityVaultId,
    parent: &AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
    ts: u64,
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
            ts,
        ),
        signer,
    )
}

fn sibling_fold_order_key(
    parent_hash: AuthorityEntryHash,
    entry: &AuthorityLogEntry,
) -> (bool, AuthorityEntryHash) {
    let hash = authority_entry_hash(entry).unwrap();
    (hash < parent_hash, hash)
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
    let authority_fork_vault_ids = BTreeMap::new();
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
            authority_fork_vault_ids: &authority_fork_vault_ids,
            equivocation_groups: &equivocation_groups,
            unresolved_equivocation_groups: &unresolved_equivocation_groups,
            entry_ancestors: None,
            chain_validated_fork_candidates: None,
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

/// ONE-1604-D1 T5: the type-122 store key is pinned to the first 16 bytes of
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

/// fix-leg 5 item 2: sub-second remainders must NOT be discarded.
///
/// `Duration::as_secs` truncates, so a per-call anchor reset banks a zero every
/// time two folds land inside the same wall second — a sustained >1 Hz readonly
/// fold would then freeze `now_secs` at its first observation and stall every
/// veto delay. The anchor is stable, so real elapsed time crosses the boundary.
#[test]
fn sub_second_readonly_folds_still_advance_the_observed_clock() {
    let domain = 0x1325_0004;
    let first = authority_observation_secs_for_domain(domain, 0, 1_000);
    assert_eq!(first, 1_000);

    // Six sub-second calls inside one ~0.6 s window: each measures a truncated
    // ZERO elapsed second and must leave the anchor alone.
    for _ in 0..6 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            authority_observation_secs_for_domain(domain, first, 1_000),
            first,
            "a sub-second call must not advance the whole-second observation"
        );
    }
    // Total real elapsed time is now > 1 s from the ORIGINAL anchor. With a
    // per-call reset every one of those 100 ms gaps truncated to zero and this
    // assert reads 1_000; with a stable anchor it reads 1_001.
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(
        authority_observation_secs_for_domain(domain, first, 1_000),
        first + 1,
        "sub-second remainders must accumulate: ~1.1 s of real time crosses a second boundary"
    );
    release_authority_clock_domain(domain);
}

/// The rebase half of the same anchor: a persisted floor ABOVE the
/// anchor-derived value re-origins the clock (monotone upward), and the next
/// call then advances from the NEW origin rather than from the stale one.
#[test]
fn persisted_floor_lift_rebases_the_authority_clock_anchor() {
    let domain = 0x1325_0005;
    let first = authority_observation_secs_for_domain(domain, 0, 1_000);
    assert_eq!(first, 1_000);

    // Another writer advanced the persisted floor well past this anchor.
    let lifted = authority_observation_secs_for_domain(domain, 5_000, 1_000);
    assert_eq!(lifted, 5_000, "a floor above the anchor must lift it");

    // The lifted value is now the origin: a lower floor cannot pull it back,
    // and elapsed time counts from the lift, not from the original anchor.
    let held = authority_observation_secs_for_domain(domain, 0, 1_000);
    assert_eq!(
        held, lifted,
        "the rebased anchor is monotone: a lower floor never moves it backward"
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
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
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

    let first_seen_at_secs = BTreeMap::new();
    let vetoed_widens = BTreeSet::new();
    let authority_forks = BTreeMap::new();
    let authority_fork_vault_ids = BTreeMap::new();
    let equivocation_groups = BTreeMap::new();
    let unresolved_equivocation_groups = BTreeSet::new();
    let context = FoldContext {
        first_seen_at_secs: &first_seen_at_secs,
        now_secs: None,
        enforce_seen_time_delay: false,
        vetoed_widens: &vetoed_widens,
        authority_forks: &authority_forks,
        authority_fork_vault_ids: &authority_fork_vault_ids,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: None,
        chain_validated_fork_candidates: None,
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
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        federation_grant_bindings: BTreeMap::new(),
        actor_bindings: BTreeMap::new(),
        actor_binding_revocations: BTreeMap::new(),
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
fn fold_records_equivocation_loser_denial_fact() {
    let left = genesis_entry(124, 86_400, 1);
    let right = genesis_entry(124, 86_400, 2);
    let signer = authority_key_from_ed(&ed_key(124));
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let loser_hash = left_hash.max(right_hash);

    let fold = fold_authority_log(&[left, right]);

    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser {
            entry,
            signer: key,
            seq: 0,
            winner,
        } if *entry == loser_hash && *key == signer && *winner == winner_hash
    )));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == loser_hash
    )));
}

#[test]
fn fold_records_signed_invalid_equivocation_candidate_as_loser() {
    let left = genesis_entry(125, 86_400, 1);
    let right = genesis_entry(125, 86_400, 2);
    let signer = ed_key(125);
    let signer_key = authority_key_from_ed(&signer);
    let signed_invalid = sign_ed(
        unsigned_entry(
            None,
            0,
            Vec::new(),
            AuthorityOp::Genesis {
                device: device(
                    authority_key_from_ed(&ed_key(126)),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
                genesis_nonce: [126; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: 86_400,
            },
            signer_key.clone(),
            3,
        ),
        &signer,
    );
    let mut ordinary_invalid = genesis_entry(127, 86_400, 4);
    ordinary_invalid.signer.signature[0] ^= 0xff;
    let left_hash = authority_entry_hash(&left).unwrap();
    let right_hash = authority_entry_hash(&right).unwrap();
    let winner_hash = left_hash.min(right_hash);
    let ready_loser_hash = left_hash.max(right_hash);
    let signed_invalid_hash = authority_entry_hash(&signed_invalid).unwrap();
    let ordinary_invalid_hash = authority_entry_hash(&ordinary_invalid).unwrap();

    let fold = fold_authority_log(&[left, right, signed_invalid, ordinary_invalid]);

    assert!(fold.valid_entries.contains(&winner_hash));
    for loser_hash in [ready_loser_hash, signed_invalid_hash] {
        assert!(fold.issues.iter().any(|issue| matches!(
            issue,
            AuthorityFoldIssue::EquivocationLoser {
                entry,
                signer,
                seq: 0,
                winner,
            } if *entry == loser_hash && *signer == signer_key && *winner == winner_hash
        )));
    }
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == signed_invalid_hash
    )));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidEntry(hash) if *hash == ordinary_invalid_hash
    )));
    assert!(!fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser { entry, .. } if *entry == ordinary_invalid_hash
    )));
}

#[test]
fn fold_records_missing_parent_equivocation_candidate_as_loser() {
    let owner = ed_key(128);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(128, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let valid_candidate = set_ceiling_entry(vault_id, &genesis, &owner, 1, 2);
    let missing_parent_candidate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xfe; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            3,
        ),
        &owner,
    );
    let winner_hash = authority_entry_hash(&valid_candidate).unwrap();
    let loser_hash = authority_entry_hash(&missing_parent_candidate).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        missing_parent_candidate,
        valid_candidate,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&winner_hash));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == loser_hash
    )));
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::EquivocationLoser {
            entry,
            signer,
            seq: 1,
            winner,
        } if *entry == loser_hash && *signer == owner_key && *winner == winner_hash
    )));
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
    // The three denied child mutations are themselves a second signed fork at
    // owner sequence 3, distinct from the original sequence-2 fork.
    assert_eq!(fold.authority_forks.len(), 2);
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| fork.seq)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(fold.authority_forks.iter().all(|fork| {
        fork.signer == owner_key && fork.status == AuthorityForkStatus::Quarantined
    }));
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
fn conflicting_root_preserves_resolved_authority_fork_status() {
    let owner = ed_key(129);
    let second = ed_key(130);
    let third = ed_key(131);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(129, 86_400, 1);
    let foreign_genesis = genesis_entry(132, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 130,
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
                seed: 131,
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

    let fold = fold_authority_log_without_seen_time_delay(&[
        foreign_genesis,
        revoke,
        fork_ceiling,
        fork_restrict,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(
        fold.issues
            .iter()
            .any(|issue| { matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }) })
    );
    assert_eq!(fold.authority_forks.len(), 1);
    assert_eq!(fold.authority_forks[0].signer, owner_key);
    assert_eq!(
        fold.authority_forks[0].status,
        AuthorityForkStatus::Resolved
    );
    assert_eq!(fold.fork_alarms.len(), 1);
}

#[test]
fn conflicting_root_foreign_revoke_does_not_resolve_authority_fork() {
    let forked_owner = ed_key(152);
    let _local_second = ed_key(153);
    let foreign_owner = ed_key(154);
    let foreign_third = ed_key(155);
    let forked_key = authority_key_from_ed(&forked_owner);
    let local_genesis = genesis_entry(152, 86_400, 1);
    let local_vault_id = genesis_vault_id(&local_genesis).unwrap();
    let local_enroll_second = enroll_device_entry(
        local_vault_id,
        &local_genesis,
        &forked_owner,
        EnrollSpec {
            seed: 153,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let foreign_genesis = genesis_entry(154, 86_400, 1);
    let foreign_vault_id = genesis_vault_id(&foreign_genesis).unwrap();
    let foreign_enroll_forked_key = enroll_device_entry(
        foreign_vault_id,
        &foreign_genesis,
        &foreign_owner,
        EnrollSpec {
            seed: 152,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let foreign_enroll_third = cosign_ed(
        enroll_device_entry(
            foreign_vault_id,
            &foreign_enroll_forked_key,
            &foreign_owner,
            EnrollSpec {
                seed: 155,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &foreign_owner,
        &forked_owner,
    );
    let foreign_revoke = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    foreign_vault_id,
                    &foreign_enroll_third,
                    &foreign_owner,
                    forked_key.clone(),
                    3,
                    40_000 + offset,
                ),
                &foreign_owner,
                &foreign_third,
            )
        })
        .max_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let foreign_revoke_hash = authority_entry_hash(&foreign_revoke).unwrap();
    let invalid_ceiling = (0_u64..256)
        .map(|offset| {
            set_ceiling_entry(
                local_vault_id,
                &local_enroll_second,
                &forked_owner,
                2,
                41_000 + offset,
            )
        })
        .min_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let invalid_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                local_vault_id,
                &local_enroll_second,
                &forked_owner,
                2,
                AuthorityTier::Hardware,
                42_000 + offset,
            )
        })
        .min_by_key(|entry| authority_entry_hash(entry).unwrap())
        .unwrap();
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    assert!(second_hash < foreign_revoke_hash);

    let fold = fold_authority_log_without_seen_time_delay(&[
        foreign_revoke,
        invalid_tier,
        invalid_ceiling,
        foreign_enroll_third,
        foreign_enroll_forked_key,
        foreign_genesis,
        local_enroll_second,
        local_genesis,
    ]);

    assert_eq!(fold.vault_id, None);
    assert_eq!(fold.valid_entries.len(), 0);
    assert_eq!(fold.roster.len(), 0);
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: forked_key.clone(),
            seq: 2,
            first_hash,
            second_hash,
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: forked_key,
            seq: 2,
            first_hash,
            second_hash,
        }]
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
            .count(),
        2
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
            .count(),
        6
    );
    assert_eq!(fold.issues.len(), 8);
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
            .count(),
        0
    );
}

#[test]
fn all_invalid_wrong_vault_fork_quarantines_signer_on_parent_vault() {
    let owner = ed_key(240);
    let second = ed_key(241);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(240, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let foreign_vault_id = genesis_vault_id(&genesis_entry(242, 86_400, 1)).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 241,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Same-(signer, seq) pair extending the local log while claiming a
    // foreign vault id: both fold as WrongVault, so the group resolves
    // all-invalid. The quarantine must scope to the parent vault the pair
    // tried to extend, not the bogus claimed id.
    let bogus_ceiling = set_ceiling_entry(foreign_vault_id, &enroll_second, &owner, 2, 3);
    let bogus_tier = set_tier_floor_entry_at(
        foreign_vault_id,
        &enroll_second,
        &owner,
        2,
        AuthorityTier::Hardware,
        4,
    );
    let ceiling_hash = authority_entry_hash(&bogus_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&bogus_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    // Later same-signer authorization on the real vault: the quarantined
    // owner cosigns a third-device enrollment signed by the second device.
    let enroll_third = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &second,
            EnrollSpec {
                seed: 243,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 0,
                ts: 5,
            },
        ),
        &second,
        &owner,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        enroll_third,
        bogus_tier,
        bogus_ceiling,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.roster.len(), 2);
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 2,
            first_hash,
            second_hash,
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 2,
            first_hash,
            second_hash,
        }]
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::WrongVault(_)))
            .count(),
        2
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
            .count(),
        1
    );
    assert_eq!(fold.issues.len(), 3);
}

#[test]
fn all_invalid_mixed_vault_claims_quarantine_every_plausible_vault() {
    let owner = ed_key(244);
    let second = ed_key(245);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(244, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    // Seed must stay below 246: genesis_nonce is [seed + 10; 32] via
    // wrapping_add, and an all-zero nonce fails body validation.
    let foreign_vault_id = genesis_vault_id(&genesis_entry(230, 86_400, 1)).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 245,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Neither candidate has a locally folded parent, and their claimed vault
    // ids disagree. Both claims remain plausible attack scopes, including the
    // real vault folded alongside this all-invalid group.
    let real_vault_claim = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xfa; 32]],
            AuthorityOp::SetCeiling {
                authority_key: owner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            owner_key.clone(),
            3,
        ),
        &owner,
    );
    let foreign_vault_claim = sign_ed(
        unsigned_entry(
            Some(foreign_vault_id),
            2,
            vec![[0xfb; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            4,
        ),
        &owner,
    );
    let real_claim_hash = authority_entry_hash(&real_vault_claim).unwrap();
    let foreign_claim_hash = authority_entry_hash(&foreign_vault_claim).unwrap();
    let first_hash = real_claim_hash.min(foreign_claim_hash);
    let second_hash = real_claim_hash.max(foreign_claim_hash);
    let valid_later = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 5),
        &owner,
        &second,
    );
    let valid_later_hash = authority_entry_hash(&valid_later).unwrap();
    let forward = vec![
        valid_later,
        foreign_vault_claim,
        real_vault_claim,
        enroll_second,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&valid_later_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == valid_later_hash))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn mixed_scope_fork_resolves_each_vault_independently() {
    let forked = ed_key(165);
    let vault_a_owner = ed_key(166);
    let vault_a_third = ed_key(167);
    let vault_b_owner = ed_key(168);
    let vault_b_third = ed_key(169);
    let forked_key = authority_key_from_ed(&forked);

    let genesis_a = genesis_entry(166, 86_400, 1);
    let vault_a = genesis_vault_id(&genesis_a).unwrap();
    let enroll_third_a = enroll_device_entry(
        vault_a,
        &genesis_a,
        &vault_a_owner,
        EnrollSpec {
            seed: 167,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_forked_a = cosign_ed(
        enroll_device_entry(
            vault_a,
            &enroll_third_a,
            &vault_a_owner,
            EnrollSpec {
                seed: 165,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &vault_a_owner,
        &vault_a_third,
    );

    let genesis_b = genesis_entry(168, 86_400, 1);
    let vault_b = genesis_vault_id(&genesis_b).unwrap();
    let enroll_third_b = enroll_device_entry(
        vault_b,
        &genesis_b,
        &vault_b_owner,
        EnrollSpec {
            seed: 169,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_forked_b = cosign_ed(
        enroll_device_entry(
            vault_b,
            &enroll_third_b,
            &vault_b_owner,
            EnrollSpec {
                seed: 165,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &vault_b_owner,
        &vault_b_third,
    );

    // Both candidates are ancestry-invalid, but their claims make the one
    // signer fork gate both vaults.
    let fork_a = sign_ed(
        unsigned_entry(
            Some(vault_a),
            1,
            vec![[0xd1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: forked_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            forked_key.clone(),
            4,
        ),
        &forked,
    );
    let fork_b = sign_ed(
        unsigned_entry(
            Some(vault_b),
            1,
            vec![[0xd2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            forked_key.clone(),
            5,
        ),
        &forked,
    );
    let fork_a_hash = authority_entry_hash(&fork_a).unwrap();
    let fork_b_hash = authority_entry_hash(&fork_b).unwrap();

    let resolve_a = cosign_ed(
        revoke_entry(
            vault_a,
            &enroll_forked_a,
            &vault_a_third,
            forked_key.clone(),
            0,
        ),
        &vault_a_third,
        &vault_a_owner,
    );
    let resolve_a_hash = authority_entry_hash(&resolve_a).unwrap();
    let later_a = cosign_ed(
        set_ceiling_entry(vault_a, &resolve_a, &vault_a_owner, 3, 6),
        &vault_a_owner,
        &vault_a_third,
    );
    let later_a_hash = authority_entry_hash(&later_a).unwrap();
    let unresolved_later_b = cosign_ed(
        set_ceiling_entry(vault_b, &enroll_forked_b, &vault_b_owner, 3, 7),
        &vault_b_owner,
        &forked,
    );
    let unresolved_later_b_hash = authority_entry_hash(&unresolved_later_b).unwrap();

    let partially_resolved = vec![
        unresolved_later_b,
        later_a,
        resolve_a,
        fork_b.clone(),
        fork_a.clone(),
        enroll_third_b.clone(),
        enroll_forked_b.clone(),
        genesis_b.clone(),
        enroll_third_a.clone(),
        enroll_forked_a.clone(),
        genesis_a.clone(),
    ];
    let mut expected_partial = None;
    for entries in [
        partially_resolved.clone(),
        partially_resolved.iter().rev().cloned().collect(),
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 0);
        assert_eq!(fold.roster.len(), 0);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, forked_key);
        assert_eq!(
            fold.authority_forks[0].first_hash,
            fork_a_hash.min(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].second_hash,
            fork_a_hash.max(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == unresolved_later_b_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == later_a_hash || *hash == resolve_a_hash
                ))
                .count(),
            0
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
                .count(),
            8
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::ConflictingVaultRoot { entry, .. }
                        if *entry == later_a_hash || *entry == resolve_a_hash
                ))
                .count(),
            2
        );
        assert_eq!(fold.issues.len(), 11);
        if let Some(expected) = &expected_partial {
            assert_eq!(&fold, expected);
        } else {
            expected_partial = Some(fold);
        }
    }

    let resolve_b = cosign_ed(
        revoke_entry(
            vault_b,
            &enroll_forked_b,
            &vault_b_third,
            forked_key.clone(),
            0,
        ),
        &vault_b_third,
        &vault_b_owner,
    );
    let resolve_b_hash = authority_entry_hash(&resolve_b).unwrap();
    let later_b = cosign_ed(
        set_ceiling_entry(vault_b, &resolve_b, &vault_b_owner, 3, 8),
        &vault_b_owner,
        &vault_b_third,
    );
    let later_b_hash = authority_entry_hash(&later_b).unwrap();
    let fully_resolved = vec![
        later_b,
        resolve_b,
        partially_resolved[1].clone(),
        partially_resolved[2].clone(),
        fork_b,
        fork_a,
        enroll_third_b,
        enroll_forked_b,
        genesis_b,
        enroll_third_a,
        enroll_forked_a,
        genesis_a,
    ];
    let mut expected_full = None;
    for entries in [
        fully_resolved.clone(),
        fully_resolved.iter().rev().cloned().collect(),
    ] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 0);
        assert_eq!(fold.roster.len(), 0);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, forked_key);
        assert_eq!(
            fold.authority_forks[0].first_hash,
            fork_a_hash.min(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].second_hash,
            fork_a_hash.max(fork_b_hash)
        );
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
                .count(),
            0
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
                .count(),
            10
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::ConflictingVaultRoot { entry, .. }
                        if *entry == later_a_hash
                            || *entry == later_b_hash
                            || *entry == resolve_a_hash
                            || *entry == resolve_b_hash
                ))
                .count(),
            4
        );
        assert_eq!(fold.issues.len(), 12);
        if let Some(expected) = &expected_full {
            assert_eq!(&fold, expected);
        } else {
            expected_full = Some(fold);
        }
    }
}

#[test]
fn empty_scope_genesis_shaped_fork_quarantines_signer_universally() {
    let owner = ed_key(153);
    let forked = ed_key(154);
    let owner_key = authority_key_from_ed(&owner);
    let forked_key = authority_key_from_ed(&forked);
    let genesis = genesis_entry(153, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_forked = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 154,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let prefork_entry = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_forked, &forked, 1, 3),
        &forked,
        &owner,
    );
    let prefork_hash = authority_entry_hash(&prefork_entry).unwrap();
    let later_entry = cosign_ed(
        set_ceiling_entry(vault_id, &prefork_entry, &forked, 3, 4),
        &forked,
        &owner,
    );
    let later_hash = authority_entry_hash(&later_entry).unwrap();
    let genesis_shaped = |nonce: u8, ts: u64| {
        sign_ed(
            unsigned_entry(
                None,
                2,
                Vec::new(),
                AuthorityOp::Genesis {
                    device: device(
                        forked_key.clone(),
                        ROLE_OWNER | ROLE_ADMIN,
                        AuthorityTier::Software,
                    ),
                    genesis_nonce: [nonce; 32],
                    tier_floor: AuthorityTier::Software,
                    pending_widen_delay_secs: 86_400,
                },
                forked_key.clone(),
                ts,
            ),
            &forked,
        )
    };
    let fork_left = genesis_shaped(0xa1, 5);
    let fork_right = genesis_shaped(0xa2, 6);
    let left_hash = authority_entry_hash(&fork_left).unwrap();
    let right_hash = authority_entry_hash(&fork_right).unwrap();
    let first_hash = left_hash.min(right_hash);
    let second_hash = left_hash.max(right_hash);
    let forward = vec![
        later_entry,
        fork_right,
        fork_left,
        prefork_entry,
        enroll_forked,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert!(!fold.valid_entries.contains(&later_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: forked_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: forked_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
                .count(),
            3
        );
        for rejected_hash in [left_hash, right_hash, later_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::SignerNotInAncestry(hash)
                            if *hash == rejected_hash
                    ))
                    .count(),
                1
            );
        }
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn recovery_fork_winner_requires_quorum_without_forked_signer() {
    let owner = ed_key(155);
    let second = ed_key(156);
    let third = ed_key(157);
    let owner_key = authority_key_from_ed(&owner);
    let recovered_bad_key = authority_key_from_ed(&ed_key(158));
    let recovered_independent_key = authority_key_from_ed(&ed_key(159));
    let genesis = genesis_entry(155, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 156,
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
                seed: 157,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let recovery_with_forked_quorum = cosign_ed(
        recovery_reboot_entry_at(vault_id, &enroll_third, &owner, 158, 3, 4),
        &owner,
        &second,
    );
    let bad_recovery_hash = authority_entry_hash(&recovery_with_forked_quorum).unwrap();

    for recovery_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 20_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (bad_recovery_hash < authority_entry_hash(entry).unwrap()) == recovery_hash_is_first
            })
            .expect("test fixture must cover both recovery candidate hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(bad_recovery_hash < competing_hash, recovery_hash_is_first);
        let first_hash = bad_recovery_hash.min(competing_hash);
        let second_hash = bad_recovery_hash.max(competing_hash);
        let forward = vec![
            competing,
            recovery_with_forked_quorum.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        let mut expected = None;

        for entries in [forward, reverse] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&competing_hash));
            assert!(!fold.valid_entries.contains(&bad_recovery_hash));
            assert_eq!(fold.roster.len(), 3);
            assert!(!fold.roster.contains_key(&recovered_bad_key));
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 3,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Quarantined,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::MissingQuorum(hash)
                            if *hash == bad_recovery_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { signer, seq: 3 }
                            if *signer == owner_key
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationLoser {
                            entry,
                            signer,
                            seq: 3,
                            winner,
                        } if *entry == bad_recovery_hash
                            && *signer == owner_key
                            && *winner == competing_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 3);
            if let Some(expected) = &expected {
                assert_eq!(&fold, expected);
            } else {
                expected = Some(fold);
            }
        }
    }

    let recovery_with_independent_quorum = cosign_ed_two(
        recovery_reboot_entry_at(vault_id, &enroll_third, &owner, 159, 3, 5),
        &owner,
        &second,
        &third,
    );
    let independent_recovery_hash =
        authority_entry_hash(&recovery_with_independent_quorum).unwrap();

    for recovery_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 30_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (independent_recovery_hash < authority_entry_hash(entry).unwrap())
                    == recovery_hash_is_first
            })
            .expect("test fixture must cover both independent recovery hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(
            independent_recovery_hash < competing_hash,
            recovery_hash_is_first
        );
        let first_hash = independent_recovery_hash.min(competing_hash);
        let second_hash = independent_recovery_hash.max(competing_hash);
        let forward = vec![
            competing,
            recovery_with_independent_quorum.clone(),
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        let mut expected = None;

        for entries in [forward, reverse] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&independent_recovery_hash));
            assert!(!fold.valid_entries.contains(&competing_hash));
            assert_eq!(fold.roster.len(), 4);
            assert_eq!(
                fold.roster
                    .get(&recovered_independent_key)
                    .map(|device| device.revoked),
                Some(false)
            );
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 3,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Resolved,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { signer, seq: 3 }
                            if *signer == owner_key
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationLoser {
                            entry,
                            signer,
                            seq: 3,
                            winner,
                        } if *entry == competing_hash
                            && *signer == owner_key
                            && *winner == independent_recovery_hash
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::MissingQuorum(_)
                            | AuthorityFoldIssue::MissingAuthorityConsent(_)
                    ))
                    .count(),
                0
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected {
                assert_eq!(&fold, expected);
            } else {
                expected = Some(fold);
            }
        }
    }
}

#[test]
fn missing_parent_fork_preserves_one_owner_prefork_consent() {
    let owner = ed_key(160);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(160, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let prefork_entry = set_ceiling_entry(vault_id, &genesis, &owner, 1, 2);
    let prefork_hash = authority_entry_hash(&prefork_entry).unwrap();
    let later_entry = set_ceiling_entry(vault_id, &prefork_entry, &owner, 3, 3);
    let later_hash = authority_entry_hash(&later_entry).unwrap();
    let missing_ceiling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xc1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: owner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            owner_key.clone(),
            4,
        ),
        &owner,
    );
    let missing_tier = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![[0xc2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            owner_key.clone(),
            5,
        ),
        &owner,
    );
    let ceiling_hash = authority_entry_hash(&missing_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&missing_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let forward = vec![
        later_entry,
        missing_tier,
        missing_ceiling,
        prefork_entry,
        genesis,
    ];
    let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
    let mut expected = None;

    for entries in [forward, reverse] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert!(!fold.valid_entries.contains(&later_hash));
        assert_eq!(fold.roster.len(), 1);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        for missing_hash in [ceiling_hash, tier_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::InvalidAncestry(hash) if *hash == missing_hash
                    ))
                    .count(),
                1
            );
        }
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == later_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingAuthorityConsent(_)))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn missing_parent_cosigner_fork_fails_closed_for_unprovable_cosigns() {
    let owner = ed_key(175);
    let cosigner = ed_key(176);
    let cosigner_key = authority_key_from_ed(&cosigner);
    let genesis = genesis_entry(175, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_cosigner = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 176,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let cosigner_seq_zero = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_cosigner, &cosigner, 0, 3),
        &cosigner,
        &owner,
    );
    // Cosigned before the fork existed (ts 4), but the fork candidates have
    // missing parents, so no ancestry can prove it — indistinguishable from
    // a post-quarantine cosign by an attacker holding the cosigner's key,
    // and therefore rejected alongside it.
    let unprovable_prefix = cosign_ed(
        set_ceiling_entry(vault_id, &cosigner_seq_zero, &owner, 2, 4),
        &owner,
        &cosigner,
    );
    let unprovable_prefix_hash = authority_entry_hash(&unprovable_prefix).unwrap();
    let unproven_postfork = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_cosigner, &owner, 3, 7),
        &owner,
        &cosigner,
    );
    let unproven_postfork_hash = authority_entry_hash(&unproven_postfork).unwrap();
    let missing_ceiling = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xe1; 32]],
            AuthorityOp::SetCeiling {
                authority_key: cosigner_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            cosigner_key.clone(),
            5,
        ),
        &cosigner,
    );
    let missing_tier = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![[0xe2; 32]],
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            cosigner_key.clone(),
            6,
        ),
        &cosigner,
    );
    let missing_ceiling_hash = authority_entry_hash(&missing_ceiling).unwrap();
    let missing_tier_hash = authority_entry_hash(&missing_tier).unwrap();
    let entries = vec![
        unproven_postfork,
        missing_tier,
        missing_ceiling,
        unprovable_prefix,
        cosigner_seq_zero,
        enroll_cosigner,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(!fold.valid_entries.contains(&unprovable_prefix_hash));
        assert!(!fold.valid_entries.contains(&unproven_postfork_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(fold.authority_forks[0].signer, cosigner_key);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Quarantined
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == missing_ceiling_hash || *hash == missing_tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == unproven_postfork_hash || *hash == unprovable_prefix_hash
                ))
                .count(),
            2
        );
        assert_eq!(fold.issues.len(), 4);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn self_rotation_winner_stays_quarantined_until_real_quorum_revoke() {
    let owner = ed_key(247);
    let second = ed_key(248);
    let rotated = ed_key(249);
    let owner_key = authority_key_from_ed(&owner);
    let rotated_key = authority_key_from_ed(&rotated);
    let genesis = genesis_entry(247, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 248,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    // Losing one role bit makes rotation the deterministic rank winner rather
    // than relying on its terminal hash. Exercise both relative hash orders.
    let rotate = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&enroll_second).unwrap()],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(rotated_key.clone(), ROLE_ADMIN, AuthorityTier::Software),
            },
            owner_key.clone(),
            3,
        ),
        &owner,
        &second,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();

    for rotate_hash_is_first in [true, false] {
        let competing = (0_u64..4_096)
            .map(|offset| {
                cosign_ed(
                    set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 10_000 + offset),
                    &owner,
                    &second,
                )
            })
            .find(|entry| {
                (rotate_hash < authority_entry_hash(entry).unwrap()) == rotate_hash_is_first
            })
            .expect("test fixture must cover both relative candidate hash orders");
        let competing_hash = authority_entry_hash(&competing).unwrap();
        assert_eq!(rotate_hash < competing_hash, rotate_hash_is_first);
        let first_hash = rotate_hash.min(competing_hash);
        let second_hash = rotate_hash.max(competing_hash);
        let quarantine_entries = vec![
            competing.clone(),
            rotate.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let mut expected_quarantine = None;

        for entries in [
            quarantine_entries.clone(),
            quarantine_entries.iter().rev().cloned().collect(),
        ] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 3);
            assert!(fold.valid_entries.contains(&rotate_hash));
            assert!(!fold.valid_entries.contains(&competing_hash));
            assert_eq!(fold.roster.len(), 3);
            assert!(
                fold.roster
                    .get(&owner_key)
                    .is_some_and(|device| device.revoked)
            );
            assert!(
                fold.roster
                    .get(&rotated_key)
                    .is_some_and(|device| !device.revoked)
            );
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 2,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Quarantined,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { .. }
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationLoser { .. }))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected_quarantine {
                assert_eq!(&fold, expected);
            } else {
                expected_quarantine = Some(fold);
            }
        }

        let real_revoke = cosign_ed(
            revoke_entry(vault_id, &rotate, &second, owner_key.clone(), 0),
            &second,
            &rotated,
        );
        let real_revoke_hash = authority_entry_hash(&real_revoke).unwrap();
        let resolved_entries = vec![
            real_revoke,
            competing,
            rotate.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ];
        let mut expected_resolved = None;

        for entries in [
            resolved_entries.clone(),
            resolved_entries.iter().rev().cloned().collect(),
        ] {
            let fold = fold_authority_log_without_seen_time_delay(&entries);

            assert_eq!(fold.valid_entries.len(), 4);
            assert!(fold.valid_entries.contains(&real_revoke_hash));
            assert_eq!(fold.roster.len(), 3);
            assert_eq!(
                fold.authority_forks,
                vec![AuthorityFork {
                    signer: owner_key.clone(),
                    seq: 2,
                    first_hash,
                    second_hash,
                    status: AuthorityForkStatus::Resolved,
                }]
            );
            assert_eq!(fold.fork_alarms.len(), 1);
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::EquivocationDetected { .. }
                    ))
                    .count(),
                1
            );
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationLoser { .. }))
                    .count(),
                1
            );
            assert_eq!(fold.issues.len(), 2);
            if let Some(expected) = &expected_resolved {
                assert_eq!(&fold, expected);
            } else {
                expected_resolved = Some(fold);
            }
        }
    }
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
fn all_invalid_same_seq_group_quarantines_later_entry() {
    let owner = ed_key(96);
    let second = ed_key(97);
    let owner_key = authority_key_from_ed(&owner);
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
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
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

    assert!(!fold.valid_entries.contains(&valid_later_hash));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 2,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
            status: AuthorityForkStatus::Quarantined,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 2,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
        }]
    );
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
    assert!(fold.issues.iter().any(|issue| matches!(
        issue,
        AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == valid_later_hash
    )));
}

#[test]
fn forged_candidate_ancestors_do_not_exempt_postfork_signer_entry() {
    let owner = ed_key(176);
    let second = ed_key(177);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(176, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 177,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let postfork = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_second,
            &owner,
            EnrollSpec {
                seed: 182,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 3,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let postfork_hash = authority_entry_hash(&postfork).unwrap();
    let invalid_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &postfork, &owner, 2, 4),
        &owner,
        &second,
    );
    let invalid_tier = cosign_ed(
        set_tier_floor_entry_at(vault_id, &postfork, &owner, 2, AuthorityTier::Hardware, 5),
        &owner,
        &second,
    );
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);

    // In isolation each forged child reaches the seq-3 parent and fails for
    // the intended reason. Pairing them must not turn that unvalidated parent
    // claim into a prefork proof for the seq-3 entry.
    for (candidate, candidate_hash) in [
        (invalid_ceiling.clone(), ceiling_hash),
        (invalid_tier.clone(), tier_hash),
    ] {
        let probe = fold_authority_log_without_seen_time_delay(&[
            candidate,
            postfork.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);
        assert_eq!(
            probe
                .issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::NonMonotonicSeq(hash) if *hash == candidate_hash
                ))
                .count(),
            1
        );
        assert_eq!(probe.issues.len(), 1);
    }

    let entries = vec![
        invalid_tier,
        invalid_ceiling,
        postfork,
        enroll_second,
        genesis,
    ];
    let mut expected = None;
    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&postfork_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == postfork_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == ceiling_hash || *hash == tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 3);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn validated_fork_candidates_preserve_genuine_prefork_ancestor() {
    let owner = ed_key(178);
    let second = ed_key(179);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(178, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let prefork = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 179,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let prefork_hash = authority_entry_hash(&prefork).unwrap();
    let fork_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &prefork, &owner, 2, 3),
        &owner,
        &second,
    );
    let fork_tier = cosign_ed(
        set_tier_floor_entry_at(vault_id, &prefork, &owner, 2, AuthorityTier::Hardware, 4),
        &owner,
        &second,
    );
    let ceiling_hash = authority_entry_hash(&fork_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&fork_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let entries = vec![fork_tier, fork_ceiling, prefork, genesis];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 3);
        assert!(fold.valid_entries.contains(&prefork_hash));
        assert_eq!(
            [ceiling_hash, tier_hash]
                .iter()
                .filter(|hash| fold.valid_entries.contains(*hash))
                .count(),
            1
        );
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationLoser { .. }))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash) if *hash == prefork_hash
                ))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 2);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn invalid_candidates_do_not_exempt_forked_cosigner_ancestor() {
    let owner = ed_key(180);
    let forked = ed_key(181);
    let owner_key = authority_key_from_ed(&owner);
    let forked_key = authority_key_from_ed(&forked);
    let forged_enrolled_key = authority_key_from_ed(&ed_key(182));
    let genesis = genesis_entry(180, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_forked = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 181,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let postfork_signer_entry = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_forked, &forked, 3, 3),
        &forked,
        &owner,
    );
    let postfork_signer_hash = authority_entry_hash(&postfork_signer_entry).unwrap();
    let forged_cosigner_ancestor = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_forked,
            &owner,
            EnrollSpec {
                seed: 182,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 4,
            },
        ),
        &owner,
        &forked,
    );
    let forged_cosigner_hash = authority_entry_hash(&forged_cosigner_ancestor).unwrap();
    let mut forged_parents = vec![postfork_signer_hash, forged_cosigner_hash];
    forged_parents.sort_unstable();
    let invalid_ceiling = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            forged_parents.clone(),
            AuthorityOp::SetCeiling {
                authority_key: forked_key.clone(),
                actor_class: "agent".to_owned(),
                ceiling: 1,
            },
            forked_key.clone(),
            5,
        ),
        &forked,
        &owner,
    );
    let invalid_tier = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            forged_parents,
            AuthorityOp::SetTierFloor {
                tier_floor: AuthorityTier::Hardware,
            },
            forked_key.clone(),
            6,
        ),
        &forked,
        &owner,
    );
    let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let first_hash = ceiling_hash.min(tier_hash);
    let second_hash = ceiling_hash.max(tier_hash);
    let entries = vec![
        invalid_tier,
        invalid_ceiling,
        forged_cosigner_ancestor,
        postfork_signer_entry,
        enroll_forked,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 2);
        assert!(!fold.valid_entries.contains(&forged_cosigner_hash));
        assert!(!fold.valid_entries.contains(&postfork_signer_hash));
        assert_eq!(fold.roster.len(), 2);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(false)
        );
        assert!(!fold.roster.contains_key(&forged_enrolled_key));
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: forked_key.clone(),
                seq: 2,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::SignerNotInAncestry(hash)
                        if *hash == forged_cosigner_hash || *hash == postfork_signer_hash
                ))
                .count(),
            2
        );
        for quarantined_hash in [forged_cosigner_hash, postfork_signer_hash] {
            assert_eq!(
                fold.issues
                    .iter()
                    .filter(|issue| matches!(
                        issue,
                        AuthorityFoldIssue::SignerNotInAncestry(hash)
                            if *hash == quarantined_hash
                    ))
                    .count(),
                1
            );
        }
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::InvalidAncestry(hash)
                        if *hash == ceiling_hash || *hash == tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        assert_eq!(fold.issues.len(), 4);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn all_invalid_same_seq_group_resolves_clean_prefix_revoke() {
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
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let revoke_owner = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
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
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 3,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
            status: AuthorityForkStatus::Resolved,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 3,
            first_hash: invalid_ceiling_hash.min(invalid_tier_hash),
            second_hash: invalid_ceiling_hash.max(invalid_tier_hash),
        }]
    );
    assert!(
        !fold
            .issues
            .iter()
            .any(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
    );
}

#[test]
fn recovery_reboot_sibling_resolves_all_invalid_fork_in_both_hash_orders() {
    let owner = ed_key(145);
    let second = ed_key(146);
    let third = ed_key(147);
    let recovered = ed_key(148);
    let owner_key = authority_key_from_ed(&owner);
    let recovered_key = authority_key_from_ed(&recovered);
    let genesis = genesis_entry(145, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 146,
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
                seed: 147,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let mut recovery_candidates: Vec<_> = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                recovery_reboot_entry_at(vault_id, &enroll_third, &second, 148, 0, 10_000 + offset),
                &second,
                &third,
            )
        })
        .collect();
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();
    recovery_candidates.sort_by_key(|entry| sibling_fold_order_key(parent_hash, entry));
    let middle = recovery_candidates.len() / 2;
    let recovery = recovery_candidates.remove(middle);
    let recovery_hash = authority_entry_hash(&recovery).unwrap();

    let reboot_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 20_000 + offset))
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let reboot_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                21_000 + offset,
            )
        })
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 22_000 + offset))
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                23_000 + offset,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let expected_valid_entries = BTreeSet::from([
        authority_entry_hash(&genesis).unwrap(),
        authority_entry_hash(&enroll_second).unwrap(),
        authority_entry_hash(&enroll_third).unwrap(),
        recovery_hash,
    ]);
    let mut expected_roster = None;

    for (order, invalid_ceiling, invalid_tier) in [
        ("reboot-first", reboot_first_ceiling, reboot_first_tier),
        ("fork-first", fork_first_ceiling, fork_first_tier),
    ] {
        let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
        let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
        let first_hash = ceiling_hash.min(tier_hash);
        let second_hash = ceiling_hash.max(tier_hash);
        match order {
            "reboot-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &recovery)
                        < sibling_fold_order_key(parent_hash, &invalid_ceiling)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &recovery)
                        < sibling_fold_order_key(parent_hash, &invalid_tier)
                );
            }
            "fork-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_ceiling)
                        < sibling_fold_order_key(parent_hash, &recovery)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_tier)
                        < sibling_fold_order_key(parent_hash, &recovery)
                );
            }
            _ => unreachable!(),
        }

        let fold = fold_authority_log_without_seen_time_delay(&[
            recovery.clone(),
            invalid_tier,
            invalid_ceiling,
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert_eq!(fold.valid_entries, expected_valid_entries);
        assert_eq!(fold.roster.len(), 4);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(true)
        );
        assert_eq!(
            fold.roster.get(&recovered_key).map(|device| device.revoked),
            Some(false)
        );
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Resolved,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(fold.issues.len(), 2);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
                .count(),
            2
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        match &expected_roster {
            Some(roster) => assert_eq!(&fold.roster, roster),
            None => expected_roster = Some(fold.roster),
        }
    }
}

#[test]
fn late_all_invalid_quarantine_rechecks_previously_accepted_revoke() {
    let owner = ed_key(149);
    let second = ed_key(150);
    let third = ed_key(151);
    let owner_key = authority_key_from_ed(&owner);
    let third_key = authority_key_from_ed(&third);
    let genesis = genesis_entry(149, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 150,
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
                seed: 151,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let mut revoke_candidates: Vec<_> = (0_u64..256)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &second,
                    third_key.clone(),
                    0,
                    30_000 + offset,
                ),
                &second,
                &third,
            )
        })
        .collect();
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();
    revoke_candidates.sort_by_key(|entry| sibling_fold_order_key(parent_hash, entry));
    let middle = revoke_candidates.len() / 2;
    let revoke = revoke_candidates.remove(middle);
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let revoke_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 31_000 + offset))
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let revoke_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                32_000 + offset,
            )
        })
        .max_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_ceiling = (0_u64..256)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 33_000 + offset))
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let fork_first_tier = (0_u64..256)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                34_000 + offset,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let expected_valid_entries = BTreeSet::from([
        authority_entry_hash(&genesis).unwrap(),
        authority_entry_hash(&enroll_second).unwrap(),
        authority_entry_hash(&enroll_third).unwrap(),
    ]);
    let mut expected_roster = None;

    for (order, invalid_ceiling, invalid_tier) in [
        ("revoke-first", revoke_first_ceiling, revoke_first_tier),
        ("fork-first", fork_first_ceiling, fork_first_tier),
    ] {
        let ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
        let tier_hash = authority_entry_hash(&invalid_tier).unwrap();
        let first_hash = ceiling_hash.min(tier_hash);
        let second_hash = ceiling_hash.max(tier_hash);
        match order {
            "revoke-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &revoke)
                        < sibling_fold_order_key(parent_hash, &invalid_ceiling)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &revoke)
                        < sibling_fold_order_key(parent_hash, &invalid_tier)
                );
            }
            "fork-first" => {
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_ceiling)
                        < sibling_fold_order_key(parent_hash, &revoke)
                );
                assert!(
                    sibling_fold_order_key(parent_hash, &invalid_tier)
                        < sibling_fold_order_key(parent_hash, &revoke)
                );
            }
            _ => unreachable!(),
        }

        let fold = fold_authority_log_without_seen_time_delay(&[
            revoke.clone(),
            invalid_tier,
            invalid_ceiling,
            enroll_third.clone(),
            enroll_second.clone(),
            genesis.clone(),
        ]);

        assert_eq!(fold.valid_entries, expected_valid_entries);
        assert_eq!(fold.roster.len(), 3);
        assert!(fold.roster.values().all(|device| !device.revoked));
        assert_eq!(
            fold.authority_forks,
            vec![AuthorityFork {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
                status: AuthorityForkStatus::Quarantined,
            }]
        );
        assert_eq!(
            fold.fork_alarms,
            vec![AuthorityForkAlarm {
                signer: owner_key.clone(),
                seq: 3,
                first_hash,
                second_hash,
            }]
        );
        assert_eq!(fold.issues.len(), 3);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
                .count(),
            3
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
                .count(),
            0
        );
        match &expected_roster {
            Some(roster) => assert_eq!(&fold.roster, roster),
            None => expected_roster = Some(fold.roster),
        }
    }
}

#[test]
fn late_resolved_fork_rechecks_only_entries_outside_resolution_ancestry() {
    let owner = ed_key(172);
    let second = ed_key(173);
    let third = ed_key(174);
    let owner_key = authority_key_from_ed(&owner);
    let third_key = authority_key_from_ed(&third);
    let genesis = genesis_entry(172, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 173,
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
                seed: 174,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let parent_hash = authority_entry_hash(&enroll_third).unwrap();

    let revoke_third = (0_u64..4_096)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &second,
                    third_key.clone(),
                    0,
                    40_000 + offset,
                ),
                &second,
                &third,
            )
        })
        .min_by_key(|entry| sibling_fold_order_key(parent_hash, entry))
        .unwrap();
    let revoke_third_hash = authority_entry_hash(&revoke_third).unwrap();
    let revoke_order = sibling_fold_order_key(parent_hash, &revoke_third);

    let invalid_ceiling = (0_u64..4_096)
        .map(|offset| set_ceiling_entry(vault_id, &enroll_third, &owner, 3, 50_000 + offset))
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > revoke_order)
        .expect("fixture must discover the fork after the sibling revoke");
    let invalid_ceiling_order = sibling_fold_order_key(parent_hash, &invalid_ceiling);
    let invalid_tier = (0_u64..4_096)
        .map(|offset| {
            set_tier_floor_entry_at(
                vault_id,
                &enroll_third,
                &owner,
                3,
                AuthorityTier::Hardware,
                60_000 + offset,
            )
        })
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > revoke_order)
        .expect("fixture must discover both fork candidates after the sibling revoke");
    let invalid_tier_order = sibling_fold_order_key(parent_hash, &invalid_tier);
    let fork_order = invalid_ceiling_order.max(invalid_tier_order);

    let resolve_owner = (0_u64..4_096)
        .map(|offset| {
            cosign_ed(
                revoke_entry_at(
                    vault_id,
                    &enroll_third,
                    &third,
                    owner_key.clone(),
                    0,
                    70_000 + offset,
                ),
                &third,
                &second,
            )
        })
        .find(|entry| sibling_fold_order_key(parent_hash, entry) > fork_order)
        .expect("fixture must resolve the fork later in the same pass");
    let resolve_owner_hash = authority_entry_hash(&resolve_owner).unwrap();
    let after_resolution = cosign_ed(
        set_ceiling_entry(vault_id, &resolve_owner, &second, 1, 80_000),
        &second,
        &third,
    );
    let after_resolution_hash = authority_entry_hash(&after_resolution).unwrap();
    let invalid_ceiling_hash = authority_entry_hash(&invalid_ceiling).unwrap();
    let invalid_tier_hash = authority_entry_hash(&invalid_tier).unwrap();
    let entries = vec![
        after_resolution,
        resolve_owner,
        invalid_tier,
        invalid_ceiling,
        revoke_third,
        enroll_third,
        enroll_second,
        genesis,
    ];
    let mut expected = None;

    for entries in [entries.clone(), entries.iter().rev().cloned().collect()] {
        let fold = fold_authority_log_without_seen_time_delay(&entries);

        assert_eq!(fold.valid_entries.len(), 5);
        assert!(!fold.valid_entries.contains(&revoke_third_hash));
        assert!(fold.valid_entries.contains(&resolve_owner_hash));
        assert!(fold.valid_entries.contains(&after_resolution_hash));
        assert_eq!(fold.roster.len(), 3);
        assert_eq!(
            fold.roster.get(&owner_key).map(|device| device.revoked),
            Some(true)
        );
        assert_eq!(
            fold.roster.get(&third_key).map(|device| device.revoked),
            Some(false)
        );
        assert_eq!(fold.authority_forks.len(), 1);
        assert_eq!(
            fold.authority_forks[0].status,
            AuthorityForkStatus::Resolved
        );
        assert_eq!(fold.fork_alarms.len(), 1);
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(issue, AuthorityFoldIssue::MissingQuorum(_)))
                .count(),
            3
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash) if *hash == revoke_third_hash
                ))
                .count(),
            1
        );
        assert_eq!(
            fold.issues
                .iter()
                .filter(|issue| matches!(
                    issue,
                    AuthorityFoldIssue::MissingQuorum(hash)
                        if *hash == invalid_ceiling_hash || *hash == invalid_tier_hash
                ))
                .count(),
            2
        );
        assert_eq!(fold.issues.len(), 3);
        if let Some(expected) = &expected {
            assert_eq!(&fold, expected);
        } else {
            expected = Some(fold);
        }
    }
}

#[test]
fn post_revocation_same_seq_group_is_reported_resolved_with_denial_facts() {
    let owner = ed_key(139);
    let second = ed_key(140);
    let third = ed_key(141);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(139, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 140,
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
                seed: 141,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let revoke_owner = cosign_ed(
        revoke_entry(vault_id, &enroll_third, &second, owner_key.clone(), 0),
        &second,
        &third,
    );
    let post_revoke_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &revoke_owner, &owner, 3, 4),
        &owner,
        &second,
    );
    let post_revoke_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &revoke_owner, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let revoke_hash = authority_entry_hash(&revoke_owner).unwrap();
    let ceiling_hash = authority_entry_hash(&post_revoke_ceiling).unwrap();
    let tier_hash = authority_entry_hash(&post_revoke_tier).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        post_revoke_tier,
        post_revoke_ceiling,
        revoke_owner,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert!(fold.valid_entries.contains(&revoke_hash));
    assert_eq!(
        fold.authority_forks,
        vec![AuthorityFork {
            signer: owner_key.clone(),
            seq: 3,
            first_hash: ceiling_hash.min(tier_hash),
            second_hash: ceiling_hash.max(tier_hash),
            status: AuthorityForkStatus::Resolved,
        }]
    );
    assert_eq!(
        fold.fork_alarms,
        vec![AuthorityForkAlarm {
            signer: owner_key,
            seq: 3,
            first_hash: ceiling_hash.min(tier_hash),
            second_hash: ceiling_hash.max(tier_hash),
        }]
    );
    let denial_hashes: Vec<_> = fold
        .issues
        .iter()
        .filter_map(|issue| match issue {
            AuthorityFoldIssue::SignerNotInAncestry(hash) => Some(*hash),
            _ => None,
        })
        .collect();
    assert_eq!(denial_hashes.len(), 2);
    assert_eq!(
        denial_hashes.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([ceiling_hash, tier_hash])
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
    let authority_fork_vault_ids = BTreeMap::new();
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
        authority_fork_vault_ids: &authority_fork_vault_ids,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: Some(&entry_ancestors),
        chain_validated_fork_candidates: None,
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
    let authority_fork_vault_ids = BTreeMap::new();
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
        authority_fork_vault_ids: &authority_fork_vault_ids,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: Some(&entry_ancestors),
        chain_validated_fork_candidates: None,
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
    let authority_fork_vault_ids =
        BTreeMap::from([((key.clone(), 2), BTreeSet::from([state.vault_id]))]);
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
        authority_fork_vault_ids: &authority_fork_vault_ids,
        equivocation_groups: &equivocation_groups,
        unresolved_equivocation_groups: &unresolved_equivocation_groups,
        entry_ancestors: None,
        chain_validated_fork_candidates: None,
    };

    assert!(key_is_quarantined_for_entry(
        &state, context, &key, [9; 32], None
    ));
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
fn independent_recovery_equivocation_groups_resolve_without_deadlock() {
    let owner = ed_key(133);
    let second = ed_key(134);
    let third = ed_key(135);
    let fourth = ed_key(136);
    let owner_key = authority_key_from_ed(&owner);
    let second_key = authority_key_from_ed(&second);
    let genesis = genesis_entry(133, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 134,
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
                seed: 135,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 2,
                ts: 3,
            },
        ),
        &owner,
        &second,
    );
    let enroll_fourth = cosign_ed(
        enroll_device_entry(
            vault_id,
            &enroll_third,
            &owner,
            EnrollSpec {
                seed: 136,
                roles: ROLE_OWNER | ROLE_ADMIN,
                tier: AuthorityTier::Software,
                seq: 3,
                ts: 4,
            },
        ),
        &owner,
        &second,
    );
    let owner_recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_fourth, &owner, 137, 4),
        &owner,
        &third,
    );
    let owner_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_fourth, &owner, 4, 5),
        &owner,
        &third,
    );
    let second_recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_fourth, &second, 138, 0),
        &second,
        &fourth,
    );
    let second_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_fourth, &second, 0, 6),
        &second,
        &fourth,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        second_ceiling,
        owner_recovery,
        enroll_fourth,
        second_recovery,
        owner_ceiling,
        enroll_third,
        enroll_second,
        genesis,
    ]);

    assert_eq!(
        fold.authority_forks.len(),
        2,
        "forks: {:#?}",
        fold.authority_forks
    );
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| fork.signer.clone())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([owner_key, second_key])
    );
    assert_eq!(fold.fork_alarms.len(), 2);
    let detections: Vec<_> = fold
        .issues
        .iter()
        .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
        .collect();
    assert_eq!(detections.len(), 2, "detections: {detections:#?}");
}

#[test]
fn same_signer_recovery_fork_does_not_wait_on_higher_sequence_fork() {
    let owner = ed_key(142);
    let second = ed_key(143);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(142, 86_400, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enroll_second = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 143,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let recovery = cosign_ed(
        recovery_reboot_entry(vault_id, &enroll_second, &owner, 144, 2),
        &owner,
        &second,
    );
    let recovery_peer = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 2, 3),
        &owner,
        &second,
    );
    let later_tier = cosign_ed(
        set_tier_floor_entry(vault_id, &enroll_second, &owner, 3, AuthorityTier::Hardware),
        &owner,
        &second,
    );
    let later_ceiling = cosign_ed(
        set_ceiling_entry(vault_id, &enroll_second, &owner, 3, 4),
        &owner,
        &second,
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        later_ceiling,
        recovery_peer,
        later_tier,
        recovery,
        enroll_second,
        genesis,
    ]);

    assert_eq!(fold.authority_forks.len(), 2);
    assert_eq!(
        fold.authority_forks
            .iter()
            .map(|fork| (fork.signer.clone(), fork.seq))
            .collect::<Vec<_>>(),
        vec![(owner_key.clone(), 2), (owner_key, 3)]
    );
    assert_eq!(fold.fork_alarms.len(), 2);
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::EquivocationDetected { .. }))
            .count(),
        1
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::SignerNotInAncestry(_)))
            .count(),
        2
    );
    assert_eq!(
        fold.issues
            .iter()
            .filter(|issue| matches!(issue, AuthorityFoldIssue::InvalidAncestry(_)))
            .count(),
        0
    );
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
    crate::test_util::entity(byte)
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
        fork_resolution_revocations: BTreeSet::new(),
        authority_forks: BTreeMap::new(),
        federation_pacts: BTreeMap::new(),
        federation_grant_bindings: BTreeMap::new(),
        actor_bindings: BTreeMap::new(),
        actor_binding_revocations: BTreeMap::new(),
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
    pact_four: [u8; 32],
    pact_five: [u8; 32],
    pact_six: [u8; 32],
    grant_four_a: EntityId,
    grant_four_b: EntityId,
    grant_six: [EntityId; 3],
    low_scope: FederationPactScope,
    low_digest: [u8; 32],
    scope_three: FederationPactScope,
    digest_three: [u8; 32],
}

/// Seventeen-entry lifecycle+device DAG exercising the merge shapes:
/// concurrent narrows (intersection incl. band ⊥), concurrent divergent
/// repacts (Suspended), Disconnect vs higher-epoch repact (terminal wins),
/// concurrent Connects binding one pact id to two grants (Suspended, both
/// grants denied), one grant bound to TWO pacts (activation folds over
/// every binding — an Active second pact must not mask a suspended one),
/// and a THREE-way binding divergence (heal target = global lex-min under
/// every merge tree).
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

    // Concurrent Connects binding one pact id to two different grants: the
    // transcript carries no grant_ref, so one honest gesture covers both.
    let pact_four = [0xB4; 32];
    let grant_four_a = scope_entity(0x34);
    let grant_four_b = scope_entity(0x35);
    let scope_four = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let nonce_four = [0x76; 16];
    let connect_four_a = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        11,
        connect_action_with(&fixture, pact_four, grant_four_a, &scope_four, nonce_four),
    );
    let connect_four_b = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        12,
        connect_action_with(&fixture, pact_four, grant_four_b, &scope_four, nonce_four),
    );
    // grant_four_b bound to a SECOND pact on a branch that never saw the
    // P4 bindings: P5 folds Active with grant_four_b operative, but the
    // activation must still deny grant_four_b through suspended P4.
    let pact_five = [0xB5; 32];
    let connect_five = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        13,
        connect_action_with(&fixture, pact_five, grant_four_b, &scope_four, [0x77; 16]),
    );

    // THREE-way binding divergence on one pact: the merge must fold to the
    // GLOBAL lex-min grant (the heal target) under every merge tree, not to
    // whichever pair happened to suspend first.
    let pact_six = [0xB6; 32];
    let grant_six = [scope_entity(0x36), scope_entity(0x37), scope_entity(0x38)];
    let nonce_six = [0x79; 16];
    let connect_six_a = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        14,
        connect_action_with(&fixture, pact_six, grant_six[0], &scope_four, nonce_six),
    );
    let connect_six_b = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        15,
        connect_action_with(&fixture, pact_six, grant_six[1], &scope_four, nonce_six),
    );
    let connect_six_c = lifecycle_entry(
        &fixture,
        vec![connect_two_hash],
        16,
        connect_action_with(&fixture, pact_six, grant_six[2], &scope_four, nonce_six),
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
        connect_four_a,
        connect_four_b,
        connect_five,
        connect_six_a,
        connect_six_b,
        connect_six_c,
    ];
    LifecycleDag {
        fixture,
        entries,
        pact_two,
        pact_three,
        pact_four,
        pact_five,
        pact_six,
        grant_four_a,
        grant_four_b,
        grant_six,
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

    // P4: concurrent Connects binding one pact id to two grants suspend the
    // pact and deny BOTH grants — the discarded binding must never fall back
    // to Unpacted legacy-allow.
    let p4 = &fold.federation_pacts[&dag.pact_four];
    assert_eq!(p4.status, FederationPactStatus::Suspended);
    assert_eq!(p4.pact_epoch, 1);
    assert_eq!(p4.grant_ref, dag.grant_four_a.min(dag.grant_four_b));

    // P5: Active with grant_four_b operative — but activation folds over
    // EVERY pact the grant was ever bound to, so suspended P4 still denies
    // grant_four_b; a second live pact never masks a conflicted one.
    let p5 = &fold.federation_pacts[&dag.pact_five];
    assert_eq!(p5.status, FederationPactStatus::Active);
    assert_eq!(p5.grant_ref, dag.grant_four_b);
    for grant in [dag.grant_four_a, dag.grant_four_b] {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }

    // P6: three-way binding divergence folds to the GLOBAL lex-min grant —
    // the heal target must not depend on which pair suspended first.
    let p6 = &fold.federation_pacts[&dag.pact_six];
    assert_eq!(p6.status, FederationPactStatus::Suspended);
    assert_eq!(p6.pact_epoch, 1);
    assert_eq!(
        p6.grant_ref,
        dag.grant_six.iter().copied().min().unwrap(),
        "heal target must be the global tie-break winner"
    );
    for grant in dag.grant_six {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }
}

#[test]
fn lifecycle_entries_use_existing_type_122_doors() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let fixture = pact_fixture(190);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    vault
        .put_authority_log_entry(&fixture.genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let connect_id = vault
        .put_authority_log_entry(&connect, TimeRange { start: 2, end: 2 }, 2)
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
        perm in prop::collection::vec(0_usize..17, 17),
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
        // The HEAL TARGET (the grant_ref an epoch+1 repact must name) is
        // anchored to the GLOBAL tie-break winner under every permutation —
        // an absolute check, not just baseline equality, so a consistently
        // order-biased merge cannot pass.
        prop_assert_eq!(
            folded.federation_pacts[&dag.pact_four].grant_ref,
            dag.grant_four_a.min(dag.grant_four_b)
        );
        prop_assert_eq!(
            folded.federation_pacts[&dag.pact_six].grant_ref,
            dag.grant_six.iter().copied().min().unwrap()
        );
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

#[test]
fn federation_divergent_grant_bindings_suspend_and_deny_both_grants() {
    let fixture = pact_fixture(168);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grant_a = fixture.grant_ref;
    let grant_b = scope_entity(0x45);
    // Same pact id, same scope/nonce (equal digests) — the pact transcript
    // carries no grant_ref, so ONE honest peer gesture covers both bindings;
    // divergence detection must not ride the digest check.
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            fixture.pact_id,
            grant_b,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
    ]);
    assert!(
        fold.issues.is_empty(),
        "both connects fold valid on their branches"
    );
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(
        pact.status,
        FederationPactStatus::Suspended,
        "divergent grant bindings must suspend, never silently keep one"
    );
    assert_eq!(pact.pact_epoch, 1);
    assert_eq!(
        pact.grant_ref,
        grant_a.min(grant_b),
        "deterministic tie-break"
    );
    for grant in [grant_a, grant_b] {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
            "no Unpacted escape for a grant that appeared in a pact binding"
        );
        assert!(
            fold.federation_grant_bindings[&grant].contains(&fixture.pact_id),
            "both bindings must be registered"
        );
    }
}

#[test]
fn federation_divergent_binding_heals_under_the_surviving_grant_only() {
    let fixture = pact_fixture(172);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grant_a = fixture.grant_ref;
    let grant_b = scope_entity(0x46);
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            fixture.pact_id,
            grant_b,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_a_hash = authority_entry_hash(&connect_a).unwrap();
    let connect_b_hash = authority_entry_hash(&connect_b).unwrap();
    // Equal digests: the surviving binding is the lexicographic-min grant.
    let winner = grant_a.min(grant_b);
    let loser = grant_a.max(grant_b);

    // A repact naming the DISCARDED binding must not heal.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let bad_heal = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        3,
        repact_action_with(&fixture, fixture.pact_id, loser, 2, &heal_scope, [0x6E; 16]),
    );
    let bad_heal_hash = authority_entry_hash(&bad_heal).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a.clone(),
        connect_b.clone(),
        bad_heal,
    ]);
    assert_eq!(
        lifecycle_rejection(&fold, bad_heal_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
    assert_eq!(
        fold.federation_pacts[&fixture.pact_id].status,
        FederationPactStatus::Suspended
    );

    // An epoch+1 dual-signed repact naming the surviving grant restores
    // exactly that grant; the discarded binding stays denied.
    let heal_nonce = [0x6F; 16];
    let heal = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        4,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            winner,
            2,
            &heal_scope,
            heal_nonce,
        ),
    );
    // Nor can the discarded binding be re-covered by a fresh pact.
    let rebind = lifecycle_entry(
        &fixture,
        vec![connect_a_hash, connect_b_hash],
        5,
        connect_action_with(&fixture, [0xD4; 32], loser, &fixture.scope, [0x70; 16]),
    );
    let rebind_hash = authority_entry_hash(&rebind).unwrap();
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
        heal,
        rebind,
    ]);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.grant_ref, winner);
    assert_eq!(
        federation_grant_activation(&fold, &winner),
        FederationGrantActivation::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &loser),
        FederationGrantActivation::Inactive(FederationPactStatus::Active),
        "the discarded binding never returns to Unpacted or Active"
    );
    assert_eq!(
        lifecycle_rejection(&fold, rebind_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );
}

#[test]
fn federation_activation_denies_grant_bound_to_any_non_active_pact() {
    // The residual fail-open shape: grant G bound to pact P AND pact Q via
    // concurrent Connects (validate-time GrantAlreadyBound cannot stop a
    // merge of two independently folded branches). P also binds H with
    // H < G, so P suspends with H as its operative binding — P is then
    // invisible to an operative-state scan for G, and only the binding
    // registry knows G↔P. Activation must fold over EVERY registered pact:
    // Q being Active must never mask P.
    let fixture = pact_fixture(176);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    // Deliberate exception to the default 0x47 → 0x67 test-seed mapping:
    // this fixture requires H < G (0x48) to exercise the tie-break premise.
    let grant_h = scope_entity(0x46);
    let grant_g = scope_entity(0x48);
    let pact_p = fixture.pact_id;
    let pact_q = [0xD5; 32];

    let connect_p_g = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        1,
        connect_action_with(
            &fixture,
            pact_p,
            grant_g,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_p_h = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        connect_action_with(
            &fixture,
            pact_p,
            grant_h,
            &fixture.scope,
            fixture.pact_nonce,
        ),
    );
    let connect_q_g = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        3,
        connect_action_with(&fixture, pact_q, grant_g, &fixture.scope, [0x78; 16]),
    );
    let connect_p_g_hash = authority_entry_hash(&connect_p_g).unwrap();
    let connect_p_h_hash = authority_entry_hash(&connect_p_h).unwrap();

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_p_g.clone(),
        connect_p_h.clone(),
        connect_q_g.clone(),
    ]);
    assert!(fold.issues.is_empty());
    // P suspended with H operative (equal digests, H < G); Q Active with G
    // operative — so the operative-state scan for G sees ONLY Q.
    assert_eq!(
        fold.federation_pacts[&pact_p].status,
        FederationPactStatus::Suspended
    );
    assert_eq!(fold.federation_pacts[&pact_p].grant_ref, grant_h);
    assert_eq!(
        fold.federation_pacts[&pact_q].status,
        FederationPactStatus::Active
    );
    assert_eq!(
        fold.pact_for_grant(&grant_g).map(|pact| pact.status),
        Some(FederationPactStatus::Active),
        "operative-state scan alone would authorize G — activation is the gate"
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_g),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
        "suspended P must deny G despite Active Q"
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_h),
        FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
    );

    // Terminal revocation of P (unilateral Disconnect under its operative
    // binding) must keep G denied: no survival via Q.
    let disconnect_p = lifecycle_entry(
        &fixture,
        vec![connect_p_g_hash, connect_p_h_hash],
        4,
        unilateral_action_with(
            &fixture,
            pact_p,
            grant_h,
            FederationLifecycleKind::Disconnect,
            1,
        ),
    );
    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis,
        connect_p_g,
        connect_p_h,
        connect_q_g,
        disconnect_p,
    ]);
    assert_eq!(
        fold.federation_pacts[&pact_p].status,
        FederationPactStatus::Disconnected
    );
    assert_eq!(
        fold.federation_pacts[&pact_q].status,
        FederationPactStatus::Active
    );
    assert_eq!(
        federation_grant_activation(&fold, &grant_g),
        FederationGrantActivation::Inactive(FederationPactStatus::Disconnected),
        "G must not survive P's revocation through Q"
    );
}

#[test]
fn federation_three_way_divergence_heals_to_global_tiebreak_winner() {
    // Three concurrent Connects binding one pact to three grants with equal
    // digests: the tie-break is purely the grant_ref, and the merged carried
    // binding — the only grant an epoch+1 heal may name — must be the GLOBAL
    // minimum regardless of which pair the fold happened to merge first.
    let fixture = pact_fixture(184);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let grants = [scope_entity(0x49), scope_entity(0x4A), scope_entity(0x4B)];
    let winner = grants.iter().copied().min().unwrap();
    let connects: Vec<AuthorityLogEntry> = grants
        .iter()
        .enumerate()
        .map(|(index, grant)| {
            lifecycle_entry(
                &fixture,
                vec![genesis_hash],
                1 + index as u64,
                connect_action_with(
                    &fixture,
                    fixture.pact_id,
                    *grant,
                    &fixture.scope,
                    fixture.pact_nonce,
                ),
            )
        })
        .collect();
    let connect_hashes: Vec<AuthorityEntryHash> = connects
        .iter()
        .map(|entry| authority_entry_hash(entry).unwrap())
        .collect();

    let mut entries = vec![fixture.genesis.clone()];
    entries.extend(connects.iter().cloned());
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Suspended);
    assert_eq!(pact.grant_ref, winner, "heal target = global lex-min grant");
    for grant in grants {
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Suspended)
        );
    }

    // A heal naming a non-winner rejects; the winner heal restores exactly
    // the winner.
    let heal_scope = symmetric_scope(
        crate::federation::FederationScopeFacets::All,
        crate::federation::FederationScopeBands::All,
    );
    let loser = grants.iter().copied().max().unwrap();
    let bad_heal = lifecycle_entry(
        &fixture,
        connect_hashes.clone(),
        4,
        repact_action_with(&fixture, fixture.pact_id, loser, 2, &heal_scope, [0x7B; 16]),
    );
    let bad_heal_hash = authority_entry_hash(&bad_heal).unwrap();
    let mut with_bad_heal = entries.clone();
    with_bad_heal.push(bad_heal);
    let fold = fold_authority_log_without_seen_time_delay(&with_bad_heal);
    assert_eq!(
        lifecycle_rejection(&fold, bad_heal_hash),
        Some(FederationLifecycleRejection::GrantAlreadyBound)
    );

    let heal = lifecycle_entry(
        &fixture,
        connect_hashes,
        5,
        repact_action_with(
            &fixture,
            fixture.pact_id,
            winner,
            2,
            &heal_scope,
            [0x7C; 16],
        ),
    );
    entries.push(heal);
    let fold = fold_authority_log_without_seen_time_delay(&entries);
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(pact.pact_epoch, 2);
    assert_eq!(pact.grant_ref, winner);
    assert_eq!(
        federation_grant_activation(&fold, &winner),
        FederationGrantActivation::Active
    );
    for grant in grants {
        if grant == winner {
            continue;
        }
        assert_eq!(
            federation_grant_activation(&fold, &grant),
            FederationGrantActivation::Inactive(FederationPactStatus::Active)
        );
    }
}

#[test]
fn federation_equal_key_merge_picks_peer_fields_by_total_order() {
    // Two concurrent Connects with an identical (scope_digest, grant_ref)
    // key can still be dual-signed with DIFFERENT peers: the combined state
    // must pick the peer fields by a total order, never by which side the
    // fold happened to hold on the left.
    let fixture = pact_fixture(192);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let connect_a = lifecycle_entry(&fixture, vec![genesis_hash], 1, connect_action(&fixture));

    let other_peer = ed_key(212);
    let other_peer_vault_id = genesis_vault_id(&genesis_entry(212, 86_400, 1)).unwrap();
    let connect_b = lifecycle_entry(
        &fixture,
        vec![genesis_hash],
        2,
        FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id: fixture.pact_id,
            grant_ref: fixture.grant_ref,
            peer_vault_id: other_peer_vault_id,
            pact_epoch: 1,
            pact_scope: Some(fixture.scope.clone()),
            effective_scope: None,
            scope_digest: Some(fixture.scope_digest),
            gesture: Some(ed_pact_gesture(
                FederationLifecycleKind::Connect,
                &fixture.pact_id,
                &fixture.vault_id,
                &other_peer_vault_id,
                1,
                &fixture.scope_digest,
                None,
                &fixture.pact_nonce,
                &other_peer,
            )),
            successor_vault_id: None,
            pact_nonce: fixture.pact_nonce,
        },
    );

    let fold = fold_authority_log_without_seen_time_delay(&[
        fixture.genesis.clone(),
        connect_a,
        connect_b,
    ]);
    assert!(fold.issues.is_empty());
    let pact = &fold.federation_pacts[&fixture.pact_id];
    assert_eq!(pact.status, FederationPactStatus::Active);
    assert_eq!(
        pact.peer_vault_id,
        fixture.peer_vault_id.min(other_peer_vault_id)
    );
    assert_eq!(
        pact.peer_owner_key,
        authority_key_from_ed(&fixture.peer).min(authority_key_from_ed(&other_peer))
    );
    assert_eq!(pact.pact_scope, fixture.scope);
}

// ── S-AUTH3: actor-binding ops (ONE-1633 / ONE-1604-D2) ──────────────────

/// A rooted two-key vault: `owner` carries OWNER|ADMIN, `agent` is an enrolled
/// ROLE_AGENT software key. Two active roster keys means every non-genesis op
/// needs a peer cosign, which is exactly the shape the bind ops ship into.
struct BindFixture {
    owner: SigningKey,
    agent: SigningKey,
    owner_key: AuthorityKey,
    agent_key: AuthorityKey,
    vault_id: AuthorityVaultId,
    genesis: AuthorityLogEntry,
    enroll: AuthorityLogEntry,
    actor: EntityId,
}

fn bind_fixture(seed: u8) -> BindFixture {
    let genesis = genesis_entry(seed, DEFAULT_PENDING_WIDEN_DELAY_SECS, 100);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner = ed_key(seed);
    let agent = ed_key(seed.wrapping_add(1));
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: seed.wrapping_add(1),
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 101,
        },
    );
    BindFixture {
        owner_key: authority_key_from_ed(&owner),
        agent_key: authority_key_from_ed(&agent),
        owner,
        agent,
        vault_id,
        genesis,
        enroll,
        actor: scope_entity(seed),
    }
}

/// Signs an owner op onto `parents` with the agent as peer cosigner — the
/// two-key roster makes a cosign mandatory for every non-genesis op.
fn cosigned_entry(
    fixture: &BindFixture,
    parents: Vec<AuthorityEntryHash>,
    seq: u64,
    op: AuthorityOp,
    ts: u64,
) -> AuthorityLogEntry {
    let entry = unsigned_entry(
        Some(fixture.vault_id),
        seq,
        parents,
        op,
        fixture.owner_key.clone(),
        ts,
    );
    cosign_ed(entry, &fixture.owner, &fixture.agent)
}

fn bind_op(key: &AuthorityKey, actor: EntityId, class: &str, epoch: u64) -> AuthorityOp {
    AuthorityOp::BindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: class.to_owned(),
        epoch,
    }
}

fn rebind_op(key: &AuthorityKey, actor: EntityId, class: &str, epoch: u64) -> AuthorityOp {
    AuthorityOp::RebindActor {
        authority_key: key.clone(),
        actor_ref: actor,
        actor_class: class.to_owned(),
        epoch,
    }
}

fn revoke_actor_op(key: &AuthorityKey, epoch: u64) -> AuthorityOp {
    AuthorityOp::RevokeActor {
        authority_key: key.clone(),
        epoch,
    }
}

/// The rejection reason recorded for `entry`, if the fold refused it.
fn binding_rejection(
    fold: &AuthorityFold,
    entry: &AuthorityLogEntry,
) -> Option<ActorBindingRejection> {
    let hash = authority_entry_hash(entry).unwrap();
    fold.issues.iter().find_map(|issue| match issue {
        AuthorityFoldIssue::ActorBindingRejected {
            entry: rejected,
            reason,
        } if *rejected == hash => Some(*reason),
        _ => None,
    })
}

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

/// Folded status for `key`, or `None` when no binding folded at all.
fn folded_status(fold: &AuthorityFold, key: &AuthorityKey) -> Option<ActorBindingStatus> {
    fold.actor_bindings.get(key).map(|binding| binding.status)
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

#[test]
fn readonly_fold_matches_full_fold_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // A settled store: single-key roster, so no enroll widen is in flight and
    // the binding is live. (A pending widen would make dependent entries
    // Waiting in BOTH fold variants identically — the divergence D5 bounds.)
    //
    // Coverage boundary (fix-leg 2): being settled is exactly why this test is
    // BLIND to which clock the readonly fold reads. With no widen in flight
    // every observation time folds to the same roster, so wall-clock skew is
    // invisible here. The two `readonly_fold_*_wall_clock_skew_*` tests below
    // build logs with a widen actually pending — the only shape that can drive
    // the two folds apart on the clock alone.
    let genesis = genesis_entry(208, DEFAULT_PENDING_WIDEN_DELAY_SECS, 200);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let owner = ed_key(208);
    let owner_key = authority_key_from_ed(&owner);
    let actor = scope_entity(0x5d);
    let bind = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key,
            201,
        ),
        &owner,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();

    // Settle first: the full fold backfills sidecars and advances the
    // first-seen clock, so compare against a settled baseline.
    let full = vault.authority_fold().unwrap();
    assert!(actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        readonly, full,
        "the in-txn fold must agree with the full fold on a settled store"
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "the readonly fold must not write a single sync_state byte"
    );
}

/// Forward wall-clock skew must not mature a pending widen in the readonly fold.
///
/// `readonly_fold_matches_full_fold_and_writes_nothing` above CANNOT see this:
/// its log is settled — no widen in flight — so every clock value folds to the
/// same roster and the two variants agree by construction. Only a log with a
/// widen actually pending can drive the folds apart on the clock alone, which
/// is what this fixture builds.
///
/// The skew modelled: the device's monotonic authority clock has barely moved
/// (it sits at 1_000) while the wall clock reads real Unix time, far past the
/// 24h delay. A readonly fold on the raw wall clock would mature the owner
/// enrollment, fold the cosigned `BindActor` child, and hand the facade's
/// owner gate an Active human binding INSIDE the veto window.
#[test]
fn readonly_fold_forward_wall_clock_skew_keeps_owner_enrollment_pending() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // A freshly opened vault owns an untouched clock domain; seed it low so
    // the monotonic reading stays far behind real Unix time for the whole test.
    let domain = vault.store.authority_clock_domain;
    assert_eq!(
        authority_observation_secs_for_domain(domain, 0, 1_000),
        1_000
    );

    let owner = ed_key(213);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(213, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(214);
    let second_key = authority_key_from_ed(&second);
    // Owner-capable, so a "human" bind on it is admissible the moment the
    // enrollment lands — the whole point of the delay.
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 214,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x5e);
    // Cosigned: once the enrollment applies the roster holds two active keys,
    // so the bind needs a quorum. A lone-signed bind would be rejected for
    // MissingQuorum on the skewed path and hide the divergence.
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );

    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&enroll_hash),
        "the monotonic clock keeps the enrollment inside its delay"
    );
    assert!(!full.roster.contains_key(&second_key));
    assert!(!actor_binding_is_active(&full, &actor, "human"));

    let sync_state_before = sync_state_snapshot(&vault);
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "wall-clock skew must not mature the enrollment and expose an owner binding inside the veto window"
    );
    assert_eq!(
        readonly, full,
        "both folds must read the same monotonic observation time"
    );
    assert_eq!(
        sync_state_snapshot(&vault),
        sync_state_before,
        "deriving the observation time must not make the readonly fold write"
    );
}

/// Backward wall-clock skew must not un-apply an elapsed widen.
///
/// Mirror of the forward case: here the device's authority clock has legitimately
/// advanced past a rotation's delay (so the rotation APPLIED and killed the old
/// key's owner binding), and the wall clock then reads far BELOW the persisted
/// floor. A readonly fold on the raw wall clock would put the rotation back in
/// `pending_widens`, leaving the retired key unrevoked and its owner binding
/// Active again — a revoked device speaking for the owner.
///
/// Checked TWICE, because the monotonic clock has two layers and only the
/// second pins the persisted floor:
///
/// 1. same process — the process-local clock alone already refuses the
///    rollback;
/// 2. after a reopen — the process-local clock is gone with the old vault, so
///    the ONLY thing standing between the rolled-back wall clock and a
///    resurrected owner binding is the floor this fold reads through `txn`.
#[test]
fn readonly_fold_backward_wall_clock_skew_keeps_elapsed_rotation_applied() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Park the authority clock well ahead of real Unix time. Every first-seen
    // sidecar and the persisted floor are then written from that future
    // reading, so `unix_seconds_now()` is the BACKWARD-skewed clock here.
    let domain = vault.store.authority_clock_domain;
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    assert_eq!(
        authority_observation_secs_for_domain(domain, 0, future),
        future
    );

    let owner = ed_key(215);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(215, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let actor = scope_entity(0x5f);
    let bind = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![authority_entry_hash(&genesis).unwrap()],
            bind_op(&owner_key, actor, "human", 1),
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    // A rotation retires `owner_key`; bindings deliberately do not migrate, so
    // the human binding dies with the key the moment this widen applies.
    let rotated = ed_key(216);
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![authority_entry_hash(&bind).unwrap()],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&rotated),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            3,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();

    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
            (rotate, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let pending = vault.authority_fold().unwrap();
    assert!(
        pending.pending_widens.contains_key(&rotate_hash),
        "the rotation starts inside its delay"
    );
    assert!(actor_binding_is_active(&pending, &actor, "human"));

    // Let the MONOTONIC clock run past the delay (raising the floor is the only
    // way time moves here; the wall clock stays where it is).
    let elapsed_at = future + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert_eq!(
        authority_observation_secs_for_domain(domain, elapsed_at, 0),
        elapsed_at
    );
    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&rotate_hash),
        "the rotation must mature once the local clock passes the delay"
    );
    assert!(
        !actor_binding_is_active(&full, &actor, "human"),
        "the applied rotation retires the bound key, so the binding must die with it"
    );

    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &actor, "human"),
        "wall-clock rollback must not un-apply the rotation and resurrect the retired key's owner binding"
    );
    assert_eq!(
        readonly, full,
        "both folds must read the same monotonic observation time"
    );

    // Layer 2: reopen. Dropping the vault releases its clock domain, so the
    // process-local floor is gone and the rolled-back wall clock is the only
    // candidate reading left. The persisted floor read through the txn is what
    // must hold the line now.
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let rtxn = reopened.store.env.read_txn().unwrap();
    let after_reopen = reopened.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !after_reopen.pending_widens.contains_key(&rotate_hash),
        "the persisted clock floor must survive a reopen and keep the rotation applied"
    );
    assert!(
        !actor_binding_is_active(&after_reopen, &actor, "human"),
        "a reopen under a rolled-back wall clock must not resurrect the retired key's owner binding"
    );
}

/// Rewinds a vault to the pre-migration shape a legacy rooted store has: every
/// first-seen sidecar gone and the one-shot backfill marker unset.
fn strip_first_seen_sidecars(vault: &crate::Vault, drop_backfill_marker: bool) {
    let rtxn = vault.store.env.read_txn().unwrap();
    let keys: Vec<String> = vault
        .store
        .sync_state
        .iter(&rtxn)
        .unwrap()
        .map(|row| row.unwrap().0.into_owned())
        .filter(|key| {
            key.starts_with("authlog:first_seen:")
                && key != authority_first_seen_clock_sync_key()
                && (drop_backfill_marker || key != authority_first_seen_backfill_sync_key())
        })
        .collect();
    drop(rtxn);
    assert!(
        !keys.is_empty(),
        "fixture must have written sidecars to strip"
    );
    vault
        .with_write_txn(|wtxn| {
            for key in &keys {
                assert!(vault.store.sync_state.delete(wtxn, key.as_str())?);
            }
            Ok(())
        })
        .unwrap();
}

/// A SIDECAR-LESS rotation must not leave the retired key authorizing — pending
/// is fail-OPEN for the mixed ops, so the readonly fold refuses instead.
///
/// The naive readonly fold simply omitted an entry with no sidecar from
/// `first_seen_at_secs`, on the reasoning that a widen without a first-seen time
/// stays pending and pending is conservative. It is not, for the two ops that
/// revoke while they grant. Here a legacy rooted vault's `RotateKey` K→K2 is
/// sidecar-less; an attacker still holding the RETIRED K files a DAG SIBLING
/// `BindActor(K, attacker, "human")` parented at genesis, so no topological rule
/// kills it. Leave the rotation pending and K is still a live owner-capable
/// roster key, so that binding folds Active and the attacker passes every owner
/// verb.
///
/// fix-leg 4 rewrites the answer. `learned_at` is peer-written metadata, so the
/// long-past values here prove nothing about when THIS vault saw the rows; the
/// fold assumes first-seen-now, which leaves the rotation pending, and then
/// refuses because a pending entry it cannot date is deciding the roster. The
/// attacker is denied through the refusal rather than through a maturity verdict
/// synthesized from their own claim.
#[test]
fn readonly_fold_refuses_when_a_sidecarless_rotation_decides_the_roster() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(219);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(219, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();

    let rotated = ed_key(220);
    let rotate = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::RotateKey {
                old_key: owner_key.clone(),
                new_device: device(
                    authority_key_from_ed(&rotated),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key.clone(),
            2,
        ),
        &owner,
    );
    let rotate_hash = authority_entry_hash(&rotate).unwrap();
    let attacker = scope_entity(0x62);
    // Sibling, not descendant: parented at GENESIS, so it does not sit behind
    // the rotation in the DAG and only the rotation's own maturity can kill it.
    let squat = sign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![genesis_hash],
            bind_op(&owner_key, attacker, "human", 1),
            owner_key,
            3,
        ),
        &owner,
    );

    // `learned_at` values sit far in the past, which is what a legacy vault's
    // stored rows look like — the rotation's delay elapsed long ago.
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (rotate, TimeRange { start: 2, end: 2 }, 2),
            (squat, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("an undatable rotation must not silently decide the roster");
    drop(rtxn);
    assert!(
        is_indeterminate_first_seen(&err),
        "a pre-migration gap is recoverable, not corruption: {err}"
    );

    // The refusal is not a permanent brick. One write-path fold records the
    // local observation, and the rotation then serves its delay from THERE —
    // still pending (it was observed moments ago, not at its long-past claimed
    // `learned_at`), but now on a time this vault actually witnessed, so the
    // readonly fold computes instead of refusing.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&rotate_hash),
        "migration dates the rotation at local observation time, so its delay has NOT elapsed"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let after_backfill = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        after_backfill, full,
        "once observed locally, both folds must agree"
    );
    // The attacker's sibling bind rides a key the rotation has not yet retired,
    // so it is live here — and that is correct: the rotation genuinely has not
    // matured on any clock this vault can vouch for. What fix-leg 4 removes is
    // the ability to reach a MATURE verdict from the attacker's own metadata.
    assert!(
        actor_binding_is_active(&after_backfill, &attacker, "human"),
        "before the freshly dated rotation matures the retired key is still live"
    );
}

/// The assumed first-seen time is the LOCAL observation regardless of what
/// `learned_at` claims — in either direction.
///
/// Fix-leg 3 clamped with `min(learned_at, now)`, which handled a forged FUTURE
/// claim (park past every reachable deadline) but swallowed a forged PAST one.
/// Taking the observation outright covers both: this fixture ships the future
/// claim, its twin below ships `learned_at = 0`, and neither moves the value.
#[test]
fn readonly_fold_ignores_future_learned_at_and_assumes_local_observation() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(221);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(221, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let enrolled = ed_key(222);
    let enroll = sign_ed(
        unsigned_entry(
            Some(vault_id),
            1,
            vec![genesis_hash],
            AuthorityOp::EnrollDevice {
                device: device(
                    authority_key_from_ed(&enrolled),
                    ROLE_OWNER | ROLE_ADMIN,
                    AuthorityTier::Software,
                ),
            },
            owner_key,
            2,
        ),
        &owner,
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let far_future = crate::unix_seconds_now() + 3650 * 24 * 60 * 60;
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (
                enroll,
                TimeRange {
                    start: 2,
                    end: far_future,
                },
                far_future,
            ),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("an undated pending enrollment must refuse, not authorize");
    drop(rtxn);
    assert!(is_indeterminate_first_seen(&err), "{err}");

    // The migration records the local observation, and the forged future date
    // leaves no trace in it.
    let full = vault.authority_fold().unwrap();
    let pending = full
        .pending_widens
        .get(&enroll_hash)
        .expect("a freshly observed enrollment must still be inside its delay");
    assert_eq!(
        pending.first_seen_at_secs,
        Some(readonly_observation_secs(&vault)),
        "first-seen must be the local observation, never the forged future"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    assert_eq!(vault.authority_fold_readonly_in_txn(&rtxn).unwrap(), full);
    drop(rtxn);
}

/// The P2 this leg exists for: `learned_at = 0` must not read as "first seen in
/// the distant past, delay long elapsed".
///
/// Mirror of the future-dated case, and the dangerous direction. A legacy,
/// sidecar-less `EnrollDevice` of an OWNER-CAPABLE key is shipped claiming
/// `learned_at = 0`; a child `BindActor(new_key, attacker, "human")` rides it.
/// Under `learned_at.min(floor)` the enrollment dates to 1970, folds MATURE on
/// arrival, puts the attacker's key in the owner-capable roster, and the child
/// bind folds ACTIVE — every owner verb, no veto window, straight through both
/// folds. `observed_floor` never caught this: it clamps FUTURE claims only.
///
/// Local observation is the whole fix. Neither fold can date the row, so the
/// readonly fold refuses; the migration then dates it NOW, which keeps it
/// pending for the full delay and the bind non-authorizing.
#[test]
fn zero_learned_at_enrollment_cannot_instantly_authorize_a_child_bind() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(225);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(225, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();

    // Owner-capable, so a "human" bind on it is admissible the instant the
    // enrollment applies — which is exactly what the delay exists to prevent.
    let attacker_signing = ed_key(226);
    let attacker_key = authority_key_from_ed(&attacker_signing);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 226,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let attacker = scope_entity(0x64);
    // Cosigned: once the enrollment applies the roster holds two active keys,
    // so a lone-signed bind would die on MissingQuorum and hide the divergence.
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&attacker_key, attacker, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &attacker_signing,
    );

    // `learned_at = 0` on every row: the peer's claim that these were learned at
    // the epoch. Only the ENROLL's claim matters — it is the delayable widen.
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 0),
            (enroll, TimeRange { start: 1, end: 1 }, 0),
            (bind, TimeRange { start: 1, end: 1 }, 0),
        ])
        .unwrap();
    strip_first_seen_sidecars(&vault, true);

    let rtxn = vault.store.env.read_txn().unwrap();
    let err = vault
        .authority_fold_readonly_in_txn(&rtxn)
        .expect_err("a `learned_at = 0` enrollment must not date itself into maturity");
    drop(rtxn);
    assert!(is_indeterminate_first_seen(&err), "{err}");

    // The migration is the other half: it must date the row at local observation
    // too, or the attack simply moves one fold over.
    let full = vault.authority_fold().unwrap();
    assert!(
        full.pending_widens.contains_key(&enroll_hash),
        "an enrollment first observed just now is inside its delay, whatever it claims"
    );
    assert!(
        !full.roster.contains_key(&attacker_key),
        "a pending enrollment must not put the attacker's key in the roster"
    );
    assert!(
        !actor_binding_is_active(&full, &attacker, "human"),
        "the child bind must not authorize while its enrollment is inside the veto window"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !actor_binding_is_active(&readonly, &attacker, "human"),
        "both folds must deny; divergence here is the bug class this leg kills"
    );
    assert_eq!(readonly, full);
}

/// The denial above must not be a blanket "nothing ever matures": an enrollment
/// this vault has genuinely held past its delay still matures and still
/// authorizes its child bind, through BOTH folds.
///
/// Without this row the fix is indistinguishable from breaking the feature.
#[test]
fn locally_matured_enrollment_still_authorizes_its_child_bind() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = ed_key(227);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(227, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(228);
    let second_key = authority_key_from_ed(&second);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 228,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x65);
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    // Sidecars exist (the write path recorded them), so the fold is computable
    // from the start and the enrollment begins inside its delay.
    let before = vault.authority_fold().unwrap();
    assert!(before.pending_widens.contains_key(&enroll_hash));
    assert!(!actor_binding_is_active(&before, &actor, "human"));

    // Advance the LOCAL monotonic clock past the delay — the only kind of time
    // that counts here.
    let matured_at = readonly_observation_secs(&vault) + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert_eq!(
        authority_observation_secs_for_domain(vault.store.authority_clock_domain, matured_at, 0),
        matured_at
    );

    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&enroll_hash),
        "a locally matured enrollment must apply"
    );
    assert!(full.roster.contains_key(&second_key));
    assert!(
        actor_binding_is_active(&full, &actor, "human"),
        "the child bind must authorize once its enrollment has genuinely matured"
    );
    let rtxn = vault.store.env.read_txn().unwrap();
    let readonly = vault.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert_eq!(
        readonly, full,
        "both folds must agree on the matured roster"
    );
}

/// The observation seconds a readonly fold would derive right now, without
/// disturbing the persisted floor.
fn readonly_observation_secs(vault: &crate::Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().unwrap();
    let floor = vault
        .store
        .sync_state
        .get(&rtxn, authority_first_seen_clock_sync_key())
        .unwrap()
        .and_then(|raw| decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    drop(rtxn);
    authority_observation_secs_for_domain(
        vault.store.authority_clock_domain,
        floor,
        crate::unix_seconds_now(),
    )
}

/// A sidecar missing AFTER the one-shot migration ran is unrecoverable, so the
/// readonly fold must refuse rather than pick a side.
///
/// Synthesis is only sound while the backfill has not run: it reproduces what
/// the migration WOULD write. Once the marker is set the migration will never
/// visit that row again, so a re-synthesized `learned_at.min(now)` would silently
/// disagree with every sidecar its peers kept — and both available guesses are
/// unsafe (mature early = skipped veto window; stay pending = live retired key).
/// An undecodable row is the same state and takes the same door.
#[test]
fn readonly_fold_rejects_sidecar_lost_after_backfill() {
    for corrupt_in_place in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let owner = ed_key(223);
        let owner_key = authority_key_from_ed(&owner);
        let genesis = genesis_entry(223, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
        let genesis_hash = authority_entry_hash(&genesis).unwrap();
        let vault_id = genesis_vault_id(&genesis).unwrap();
        let actor = scope_entity(0x63);
        let bind = sign_ed(
            unsigned_entry(
                Some(vault_id),
                1,
                vec![genesis_hash],
                bind_op(&owner_key, actor, "human", 1),
                owner_key,
                2,
            ),
            &owner,
        );
        let bind_hash = authority_entry_hash(&bind).unwrap();
        vault
            .put_authority_log_entries(&[
                (genesis, TimeRange { start: 1, end: 1 }, 1),
                (bind, TimeRange { start: 2, end: 2 }, 2),
            ])
            .unwrap();
        // Settle: this is what sets the one-shot marker.
        vault.authority_fold().unwrap();
        let rtxn = vault.store.env.read_txn().unwrap();
        assert!(
            vault
                .store
                .sync_state
                .get(&rtxn, authority_first_seen_backfill_sync_key())
                .unwrap()
                .is_some(),
            "the full fold must have set the one-shot marker"
        );
        drop(rtxn);

        let sidecar = authority_first_seen_sync_key(&bind_hash);
        vault
            .with_write_txn(|wtxn| {
                if corrupt_in_place {
                    // Present but undecodable: not 8 bytes.
                    vault.store.sync_state.put(wtxn, sidecar.as_str(), &[9])?;
                } else {
                    assert!(vault.store.sync_state.delete(wtxn, sidecar.as_str())?);
                }
                Ok(())
            })
            .unwrap();

        let rtxn = vault.store.env.read_txn().unwrap();
        let err = vault
            .authority_fold_readonly_in_txn(&rtxn)
            .expect_err("a post-migration sidecar gap must refuse the fold");
        drop(rtxn);
        assert!(
            is_corrupt_first_seen_sidecar(&err),
            "corrupt_in_place={corrupt_in_place}: {err}"
        );
    }
}

fn sync_state_snapshot(vault: &crate::Vault) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rtxn = vault.store.env.read_txn().unwrap();
    let rows = vault
        .store
        .sync_state
        .iter(&rtxn)
        .unwrap()
        .map(|row| {
            let (key, value) = row.unwrap();
            (key.as_bytes().to_vec(), value.to_vec())
        })
        .collect();
    drop(rtxn);
    rows
}

/// The pending-widen freeze that a `RevokeActor` builds its fixture from: a
/// two-key roster, a live human binding, and a cosigned `EnrollDevice` that is
/// still inside its veto delay, so `state.pending_widens` is non-empty for every
/// entry that follows.
struct PendingWidenFreeze {
    fixture: BindFixture,
    entries: Vec<AuthorityLogEntry>,
    first_seen: BTreeMap<AuthorityEntryHash, u64>,
    widen_hash: AuthorityEntryHash,
    bind_hash: AuthorityEntryHash,
    now_secs: u64,
}

/// Builds the freeze. `long_ago` first-seen times keep genesis/enroll/bind out of
/// the delay; the widen is first seen at `now`, which is what pins it pending.
fn pending_widen_freeze(seed: u8) -> PendingWidenFreeze {
    let fixture = bind_fixture(seed);
    let genesis_hash = authority_entry_hash(&fixture.genesis).unwrap();
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();

    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let widen = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        AuthorityOp::EnrollDevice {
            device: device(
                authority_key_from_ed(&ed_key(seed.wrapping_add(4))),
                ROLE_AGENT,
                AuthorityTier::Software,
            ),
        },
        103,
    );
    let widen_hash = authority_entry_hash(&widen).unwrap();

    let now_secs = 10_000_000;
    let mut first_seen = BTreeMap::new();
    for hash in [genesis_hash, enroll_hash, bind_hash] {
        first_seen.insert(hash, 1);
    }
    first_seen.insert(widen_hash, now_secs);

    PendingWidenFreeze {
        entries: vec![fixture.genesis.clone(), fixture.enroll.clone(), bind, widen],
        fixture,
        first_seen,
        widen_hash,
        bind_hash,
        now_secs,
    }
}

/// fix-leg 11 P1-1: a `RevokeActor` must NOT wait behind an unrelated pending
/// widen — a revocation is the operator's emergency brake.
///
/// A pending widen freezes the log: `fold_entry_state` returned `Waiting` for
/// every entry that followed one, so a revocation filed while any enrollment sat
/// inside its veto window did not take effect until that enrollment matured. The
/// consequences run the wrong way on every axis. The revocation is the response
/// to a compromise, so the window it is deferred across is exactly the window the
/// compromised key keeps every owner verb — up to
/// `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`. And the delay is ATTACKER-CHOSEN: the
/// compromised key can cosign a delayable widen of its own and thereby extend the
/// life of its own authority, re-arming the freeze each time one matures.
///
/// Folding the revocation early is sound because a revocation cannot widen: it
/// only raises a per-key watermark, so an early fold strictly REMOVES authority.
/// Nothing about the pending widen changes — it still matures on its own clock,
/// which the last assertion pins.
///
/// MUTATION PROBE: restore the unconditional deferral (drop the
/// `op_applies_despite_pending_widen` term at the `pending_widens.is_empty()`
/// guard) and this test fails — the revocation folds Waiting and the binding
/// stays Active.
#[test]
fn revoke_actor_applies_immediately_despite_an_unrelated_pending_widen() {
    let freeze = pending_widen_freeze(240);
    let key = freeze.fixture.owner_key.clone();
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        revoke_actor_op(&key, 5),
        104,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    // Baseline: with no revocation the binding authorizes, so the assertions
    // below pin the revocation's effect and not a broken fixture.
    let before =
        fold_authority_log_with_seen_times(&freeze.entries, &freeze.first_seen, freeze.now_secs);
    assert!(
        before.pending_widens.contains_key(&freeze.widen_hash),
        "fixture: the widen must start inside its veto delay"
    );
    assert!(
        actor_binding_is_active(&before, &freeze.fixture.actor, "human"),
        "fixture: the binding must authorize before the revocation"
    );

    let mut entries = freeze.entries.clone();
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(revoke_hash, freeze.now_secs);
    let after = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        after.issues.is_empty(),
        "the revocation must fold cleanly: {:?}",
        after.issues
    );
    assert!(
        after.valid_entries.contains(&revoke_hash),
        "the revocation must fold VALID, not park as Waiting behind the widen"
    );
    assert_eq!(
        folded_status(&after, &key),
        Some(ActorBindingStatus::Revoked),
        "the revocation must kill the binding NOW"
    );
    assert!(
        !actor_binding_is_active(&after, &freeze.fixture.actor, "human"),
        "a revoked actor must lose its authority immediately, not when an \
         unrelated enrollment matures"
    );
    // The widen keeps its OWN clock: the revocation neither matures nor vetoes it.
    assert!(
        after.pending_widens.contains_key(&freeze.widen_hash),
        "the pending widen must still mature on its own clock"
    );
    assert_eq!(
        after.pending_widens[&freeze.widen_hash], before.pending_widens[&freeze.widen_hash],
        "the revocation must not disturb the pending widen's delay bookkeeping"
    );
}

/// The other half of the same ruling: GRANTS still wait.
///
/// `RevokeActor` skips the freeze because withdrawing consent is unconditional.
/// `BindActor` and `RebindActor` do the opposite — they hand an actor authority —
/// so they keep the deferral: folding a grant against a roster the pending widen
/// may still change is exactly what the freeze exists to prevent. Pinned so a
/// future edit cannot widen the exemption from "the withdrawal" to "the actor
/// ops".
///
/// MUTATION PROBE: make `op_applies_despite_pending_widen` return true for the
/// bind arms and this test fails.
#[test]
fn bind_and_rebind_still_defer_behind_a_pending_widen() {
    for (label, op, seq) in [
        (
            "rebind",
            rebind_op(
                &pending_widen_freeze(244).fixture.owner_key,
                scope_entity(0x71),
                "human",
                2,
            ),
            4_u64,
        ),
        (
            "bind",
            bind_op(
                &pending_widen_freeze(244).fixture.agent_key,
                scope_entity(0x72),
                "agent",
                1,
            ),
            4,
        ),
    ] {
        let freeze = pending_widen_freeze(244);
        let entry = cosigned_entry(&freeze.fixture, vec![freeze.widen_hash], seq, op, 104);
        let entry_hash = authority_entry_hash(&entry).unwrap();
        let mut entries = freeze.entries.clone();
        entries.push(entry);
        let mut first_seen = freeze.first_seen.clone();
        first_seen.insert(entry_hash, freeze.now_secs);

        let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);
        assert!(
            fold.pending_widens.contains_key(&freeze.widen_hash),
            "{label}: fixture — the widen must still be pending"
        );
        assert!(
            !fold.valid_entries.contains(&entry_hash),
            "{label}: a GRANT must stay deferred behind the pending widen"
        );
        // The pre-existing binding is untouched: the deferred grant changed nothing.
        assert!(
            actor_binding_is_active(&fold, &freeze.fixture.actor, "human"),
            "{label}: the deferred grant must leave the existing binding alone"
        );
        assert!(
            fold.valid_entries.contains(&freeze.bind_hash),
            "{label}: the pre-widen bind must remain valid"
        );
    }
}

/// fix-leg 12 P1: the freeze exemption must survive the ANCESTRY hurdle — a
/// revoked key cannot stall its own revocation by parenting it on a grant the
/// key itself froze.
///
/// fix-leg 11 exempted `RevokeActor` from the pending-widen freeze, but the
/// exemption sits BELOW the parent-ancestry resolution: a parent with no folded
/// state returns `Waiting` before any op-specific rule runs. The compromised key
/// C turns that ordering into a stall lever. C files a grant of its own as a
/// child of an unrelated pending widen; by fix-11's own (correct) ruling that
/// grant defers. The operator's `RevokeActor` naming the deferred grant as its
/// parent then inherits the wait, and C keeps every owner verb its binding
/// carries until the widen matures — up to `MAX_DEFAULT_PENDING_WIDEN_DELAY_SECS`
/// on the compromised key's own forging. That is the exact live bug fix-11
/// shipped against, re-entered one level up.
///
/// Note what C needs to build the lever: only the ability to author a
/// `BindActor`, which asks for ordinary authority consent and never inspects the
/// signer's own actor binding. A key already stripped down to veto-only can
/// still do it, so "C cannot mature its own widen" does not close the hole —
/// the stall is the veto WINDOW, not the widen.
///
/// MUTATION PROBE: drop the `RevokeActor` arm from
/// `unstick_stalled_revocation` (or restore the unconditional
/// `return EntryFold::Waiting` for an unresolved parent) and this test fails —
/// the revocation lands in `issues` as `InvalidAncestry` and the binding stays
/// Active.
#[test]
fn revoke_actor_folds_past_a_grant_frozen_in_its_own_ancestry() {
    let freeze = pending_widen_freeze(248);
    let key = freeze.fixture.owner_key.clone();

    // C's stall lever: C's OWN grant, filed under the pending widen so the
    // freeze parks it. `bind_and_rebind_still_defer_behind_a_pending_widen`
    // pins that this entry cannot fold while the widen is pending.
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x73), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    // The operator's emergency brake, parented on that deferred grant.
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![stall_hash],
        5,
        revoke_actor_op(&key, 5),
        105,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(revoke_hash, freeze.now_secs);
    let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        fold.valid_entries.contains(&revoke_hash),
        "the revocation must fold past a parent frozen behind an unrelated widen"
    );
    assert_eq!(
        folded_status(&fold, &key),
        Some(ActorBindingStatus::Revoked),
        "withdrawal of consent must take effect NOW, not when the widen matures"
    );
    assert!(
        !actor_binding_is_active(&fold, &freeze.fixture.actor, "human"),
        "a revoked actor must not keep owner authority because it parented the \
         revocation on a grant it froze itself"
    );
    // The exemption stays exactly one op wide: the GRANT keeps waiting, and the
    // widen keeps its own clock.
    assert!(
        !fold.valid_entries.contains(&stall_hash),
        "the deferred grant must NOT be dragged past the freeze with the revocation"
    );
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "the pending widen must still mature on its own clock"
    );
}

/// The second fix-12 narrowing: the bypass steps over a FROZEN parent, never an
/// invalid one.
///
/// "Resolve against the nearest ready ancestor" is only sound while the skipped
/// entries are ones the fold is deliberately holding. An entry the fold REJECTED
/// is a different animal: nothing above it was ever validated, and walking past
/// it would let a revocation fold over ancestry the vault refused. The
/// revocation is removal-only, so this is not a privilege escalation — but it
/// would silently admit an entry whose parent is not part of the log's valid
/// history, which is a fold-integrity break the wider machinery (permutation
/// invariance, `valid_entries` as the authority of record) relies on not
/// happening.
///
/// Here the revocation's parent is a double-`BindActor`, rejected with
/// `BindingExists`. No pending widen is involved at all, so the revocation must
/// simply fail its ancestry as it always did.
///
/// MUTATION PROBE: relax `nearest_unfrozen_ancestor_state` to walk past any
/// unfolded ancestor (drop the `pending` / `entry_is_frozen_by_pending_widen`
/// terms) and this test fails — the revocation folds valid on top of a rejected
/// parent.
#[test]
fn the_bypass_does_not_walk_past_a_rejected_parent() {
    let fixture = bind_fixture(228);
    let enroll_hash = authority_entry_hash(&fixture.enroll).unwrap();
    let key = fixture.owner_key.clone();

    let bind = cosigned_entry(
        &fixture,
        vec![enroll_hash],
        2,
        bind_op(&key, fixture.actor, "human", 1),
        102,
    );
    let bind_hash = authority_entry_hash(&bind).unwrap();
    // Rejected: a live binding already exists on this key.
    let double_bind = cosigned_entry(
        &fixture,
        vec![bind_hash],
        3,
        bind_op(&key, scope_entity(0x76), "human", 5),
        103,
    );
    let double_bind_hash = authority_entry_hash(&double_bind).unwrap();
    let revoke = cosigned_entry(
        &fixture,
        vec![double_bind_hash],
        4,
        revoke_actor_op(&key, 5),
        104,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let entries = vec![
        fixture.genesis.clone(),
        fixture.enroll,
        bind,
        double_bind.clone(),
        revoke,
    ];
    let fold = fold_authority_log_without_seen_time_delay(&entries);

    assert_eq!(
        binding_rejection(&fold, &double_bind),
        Some(ActorBindingRejection::BindingExists),
        "fixture: the parent must be REJECTED, not merely deferred"
    );
    assert!(
        !fold.valid_entries.contains(&revoke_hash),
        "the bypass must not carry a revocation over a parent the fold rejected: \
         only a parent frozen by a pending widen may be stepped over"
    );
}

/// The `RevokeActor`-only gate on the fix-12 bypass, probed where it actually
/// bites: `VetoPendingWiden`.
///
/// Most ops are held back a second time by the freeze check inside
/// `fold_entry_state`, so opening the bypass to them changes nothing
/// observable. A veto is the exception — `fold_entry_state` resolves it BEFORE
/// the freeze, since a veto's whole job is to kill a pending widen. So a veto
/// is the one op that would really travel through an ancestry bypass, and it is
/// the one that must not: a veto folded against a state from before the frozen
/// entry is a veto evaluated against a roster the vault has not settled, decided
/// on `has_veto_authority_consent` from stale ancestry.
///
/// Here C parents a veto of the widen on its own frozen grant. The veto must
/// stay stuck. It carries the same shape as the revocation that DOES get
/// through in the test above, so what separates them is only the op gate.
///
/// MUTATION PROBE: drop the `matches!(entry.op, AuthorityOp::RevokeActor {..})`
/// guard from `revocation_bypass_states` and this test fails — the veto folds
/// valid and the pending widen dies without ever being weighed against a
/// settled roster.
#[test]
fn a_veto_may_not_ride_the_revocation_ancestry_bypass() {
    let freeze = pending_widen_freeze(236);
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x75), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    let veto = veto_entry(
        freeze.fixture.vault_id,
        &stall,
        &freeze.fixture.owner,
        freeze.widen_hash,
        5,
    );
    let veto_hash = authority_entry_hash(&veto).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(veto);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(veto_hash, freeze.now_secs);
    let fold = fold_authority_log_with_seen_times(&entries, &first_seen, freeze.now_secs);

    assert!(
        !fold.valid_entries.contains(&veto_hash),
        "a veto must NOT travel the revocation bypass: it is resolved before the \
         freeze check, so an ancestry bypass would let it kill a widen from a \
         roster the fold has not settled"
    );
    assert!(
        !fold.vetoed_widens.contains(&freeze.widen_hash),
        "the widen must not be vetoed by an entry that never folded"
    );
    assert!(
        fold.pending_widens.contains_key(&freeze.widen_hash),
        "the widen must still be pending on its own clock"
    );
}

/// The other half of the fix-12 ruling: a revocation folded past the freeze must
/// stay in force once the widen it bypassed matures.
///
/// The bypass resolves the revocation against an ancestry state that predates
/// the frozen grant, so the obvious failure mode is a stranded watermark: the
/// widen matures, the grant folds for real, the revocation re-folds on the
/// now-available parent, and some ordering loses the raised
/// `actor_binding_revocations` entry. Merge is monotone by max, so this should
/// fall out — pinned so it stays true.
#[test]
fn revocation_folded_past_a_freeze_survives_the_widen_maturing() {
    let freeze = pending_widen_freeze(252);
    let key = freeze.fixture.owner_key.clone();
    let stall = cosigned_entry(
        &freeze.fixture,
        vec![freeze.widen_hash],
        4,
        bind_op(&freeze.fixture.agent_key, scope_entity(0x74), "agent", 1),
        104,
    );
    let stall_hash = authority_entry_hash(&stall).unwrap();
    let revoke = cosigned_entry(
        &freeze.fixture,
        vec![stall_hash],
        5,
        revoke_actor_op(&key, 5),
        105,
    );
    let revoke_hash = authority_entry_hash(&revoke).unwrap();

    let mut entries = freeze.entries.clone();
    entries.push(stall);
    entries.push(revoke);
    let mut first_seen = freeze.first_seen.clone();
    first_seen.insert(stall_hash, freeze.now_secs);
    first_seen.insert(revoke_hash, freeze.now_secs);

    // Same log, one clock apart: frozen, then matured.
    let matured_at = freeze.now_secs + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    let after = fold_authority_log_with_seen_times(&entries, &first_seen, matured_at);
    assert!(
        !after.pending_widens.contains_key(&freeze.widen_hash),
        "fixture: the widen must have matured at the later reading"
    );
    assert!(
        after.valid_entries.contains(&stall_hash),
        "fixture: the grant must fold once the freeze lifts"
    );
    assert!(
        after.valid_entries.contains(&revoke_hash),
        "the revocation must still fold once its parent is available for real"
    );
    assert_eq!(
        folded_status(&after, &key),
        Some(ActorBindingStatus::Revoked),
        "the revocation's watermark must survive the widen maturing"
    );
    assert!(
        !actor_binding_is_active(&after, &freeze.fixture.actor, "human"),
        "a matured widen must not resurrect the revoked actor's authority"
    );
}

/// fix-leg 11 P1-2: a matured ENROLLMENT must survive a restart under a
/// rolled-back wall clock, which is what makes the write fold's floor
/// persistence load-bearing in the GRANT direction.
///
/// `readonly_fold_backward_wall_clock_skew_keeps_elapsed_rotation_applied`
/// already pins the revoke direction: a matured `RotateKey` must stay applied, or
/// the retired key's owner binding comes back. That test cannot catch a
/// regression in the other direction, because a lost floor pushes a rotation back
/// INTO `pending_widens`, which for a rotation is the fail-OPEN outcome its
/// assertions are built around.
///
/// The grant direction fails the opposite way and needs its own row. An
/// `EnrollDevice` matured on this vault's monotonic clock authorizes its child
/// bind; if the floor is not persisted, a restart drops the process-local clock,
/// the fold falls back to a wall clock sitting far BELOW the observation, and the
/// enrollment reverts to pending — so a legitimately matured owner enrollment
/// silently loses its authority. That is fail-CLOSED but wrong, and it is
/// indistinguishable from the feature simply not working: the operator waited out
/// the veto window, and a reboot took it back.
///
/// MUTATION PROBE: drop the floor `put` from `Vault::authority_fold`'s write txn
/// and this test fails at the post-reopen assertions.
#[test]
fn matured_enrollment_survives_a_restart_under_a_rolled_back_wall_clock() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    // Park the authority clock far ahead of real Unix time, so every later
    // observation is written from a future reading and `unix_seconds_now()` is
    // the BACKWARD-skewed clock a reopen would otherwise trust.
    let domain = vault.store.authority_clock_domain;
    let future = crate::unix_seconds_now() + 10 * 24 * 60 * 60;
    assert_eq!(
        authority_observation_secs_for_domain(domain, 0, future),
        future
    );

    let owner = ed_key(231);
    let owner_key = authority_key_from_ed(&owner);
    let genesis = genesis_entry(231, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let second = ed_key(232);
    let second_key = authority_key_from_ed(&second);
    let enroll = enroll_device_entry(
        vault_id,
        &genesis,
        &owner,
        EnrollSpec {
            seed: 232,
            roles: ROLE_OWNER | ROLE_ADMIN,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    let enroll_hash = authority_entry_hash(&enroll).unwrap();
    let actor = scope_entity(0x67);
    let bind = cosign_ed(
        unsigned_entry(
            Some(vault_id),
            2,
            vec![enroll_hash],
            bind_op(&second_key, actor, "human", 1),
            owner_key,
            3,
        ),
        &owner,
        &second,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (enroll, TimeRange { start: 2, end: 2 }, 2),
            (bind, TimeRange { start: 3, end: 3 }, 3),
        ])
        .unwrap();

    let before = vault.authority_fold().unwrap();
    assert!(
        before.pending_widens.contains_key(&enroll_hash),
        "the enrollment starts inside its veto delay"
    );
    assert!(
        !actor_binding_is_active(&before, &actor, "human"),
        "its child bind must not authorize while the enrollment is pending"
    );

    // Run the local monotonic clock past the delay, then let a WRITE fold record
    // the observation — this is the commit whose floor must outlive the process.
    let matured_at = future + DEFAULT_PENDING_WIDEN_DELAY_SECS + 1;
    assert_eq!(
        authority_observation_secs_for_domain(domain, matured_at, 0),
        matured_at
    );
    let full = vault.authority_fold().unwrap();
    assert!(
        !full.pending_widens.contains_key(&enroll_hash),
        "the enrollment must mature once the local clock passes its delay"
    );
    assert!(
        actor_binding_is_active(&full, &actor, "human"),
        "the matured enrollment must authorize its child bind"
    );
    // The floor is the durable half of that observation.
    let rtxn = vault.store.env.read_txn().unwrap();
    let persisted_floor = vault
        .store
        .sync_state
        .get(&rtxn, authority_first_seen_clock_sync_key())
        .unwrap()
        .and_then(|raw| decode_authority_first_seen_secs(&raw))
        .unwrap_or(0);
    drop(rtxn);
    assert!(
        persisted_floor >= matured_at,
        "the write fold must persist its derived observation as the floor \
         (monotone max): floor={persisted_floor} < observed={matured_at}"
    );

    // Restart. The process-local clock dies with the vault, so the rolled-back
    // wall clock is the only other candidate reading — the persisted floor is
    // the sole thing keeping the enrollment matured.
    drop(vault);
    let reopened = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let rtxn = reopened.store.env.read_txn().unwrap();
    let after_reopen = reopened.authority_fold_readonly_in_txn(&rtxn).unwrap();
    drop(rtxn);
    assert!(
        !after_reopen.pending_widens.contains_key(&enroll_hash),
        "a restart under a rolled-back wall clock must not un-mature the \
         enrollment — the persisted floor is what carries the observation across"
    );
    assert!(
        actor_binding_is_active(&after_reopen, &actor, "human"),
        "a legitimately matured owner enrollment must keep authorizing its child \
         bind across a restart"
    );
}
