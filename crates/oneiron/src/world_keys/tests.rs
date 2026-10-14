//! P6b done-means checks on the key core. The vault doors add their own checks once
//! the machine roster (P1) and the world settings (P2) land.

use oneiron_crypto::{Envelope, HybridSecretKey, Kek, Purpose, SealKey, SealParams, SuiteId, seal};
use oneiron_keystore::{DeviceKeystore, MemoryKeystore};

use super::*;

const VAULT: [u8; 32] = [0x5a; 32];
const INSTALL: [u8; 16] = [0x3c; 16];

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; 16])
}

fn binding(key: &WorldKey) -> WorldKeyBinding {
    WorldKeyBinding {
        vault_id: VAULT,
        key: *key.id(),
        owner: entity(0x0a),
        policy: PolicyRevision([0x0b; 32]),
        commitment: key.commitment(),
    }
}

/// Done means (packet P6b): a world key opens only for an allowed machine's key and
/// for the kit. A wrap made for machine A does not open for machine B, even when B
/// names A as the recipient, and the kit's seed opens the root's wrap.
#[test]
fn a_world_key_opens_only_for_its_machine_and_for_the_kit() {
    let keys_a = MemoryKeystore::new();
    let keys_b = MemoryKeystore::new();
    let a = machine_secret(&keys_a, VAULT, INSTALL).unwrap();
    let b = machine_secret(&keys_b, VAULT, INSTALL).unwrap();
    let seed = RecoveryRootSeed::generate().unwrap();
    let root = seed.public(&VAULT).unwrap();
    let key = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    let bound = binding(&key);
    let to_a = WrapRecipient::Machine(entity(0xa1));
    let to_b = WrapRecipient::Machine(entity(0xb1));
    let to_root = WrapRecipient::RecoveryRoot(root.id);

    let for_a = seal_world_key(&bound, to_a, a.public_key(), &key).unwrap();
    let for_root = seal_world_key(&bound, to_root, &root.recovery_key, &key).unwrap();

    let opened = open_world_key(&bound, to_a, &a, &for_a).unwrap();
    assert_eq!(opened.expose(), key.expose());
    assert!(open_world_key(&bound, to_a, &b, &for_a).is_err());
    assert!(open_world_key(&bound, to_b, &b, &for_a).is_err());
    assert!(open_world_key(&bound, to_root, &a, &for_root).is_err());

    // The kit, restored on a new machine: only the 32 seed bytes come back.
    let restored = RecoveryRootSeed::from_kit_bytes(seed.kit_bytes()).unwrap();
    let opened = open_world_key(
        &bound,
        to_root,
        &restored.recovery_secret().unwrap(),
        &for_root,
    )
    .unwrap();
    assert_eq!(opened.expose(), key.expose());
    assert_eq!(restored.public(&VAULT).unwrap(), root);

    // The machine secret is this install's: a second use returns the same key.
    assert_eq!(
        machine_secret(&keys_a, VAULT, INSTALL)
            .unwrap()
            .public_key(),
        a.public_key()
    );
}

/// Done means (packet P6b, ruling fix 1): the vault key alone opens no world key, and
/// neither does the host's material. A world key is drawn fresh; nothing derives it
/// from the vault key. Here a vault key is tried as each kind of secret the wraps
/// could take, and every attempt fails.
#[test]
fn the_vault_key_alone_opens_no_world_key() {
    let mut vault_key = [0u8; 32];
    os_fill(&mut vault_key).unwrap();
    let keys = MemoryKeystore::new();
    let machine = machine_secret(&keys, VAULT, INSTALL).unwrap();
    let root = RecoveryRootSeed::generate()
        .unwrap()
        .public(&VAULT)
        .unwrap();
    let key = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    let bound = binding(&key);
    let to_machine = WrapRecipient::Machine(entity(0xa1));
    let to_root = WrapRecipient::RecoveryRoot(root.id);
    let wraps = [
        (
            to_machine,
            seal_world_key(&bound, to_machine, machine.public_key(), &key).unwrap(),
        ),
        (
            to_root,
            seal_world_key(&bound, to_root, &root.recovery_key, &key).unwrap(),
        ),
    ];
    let as_seed = RecoveryRootSeed::from_kit_bytes(zeroize::Zeroizing::new(vault_key)).unwrap();
    let candidates = [
        as_seed.recovery_secret().unwrap(),
        HybridSecretKey::from_seed(&vault_key, b"oneiron/machine-encryption/v1").unwrap(),
        HybridSecretKey::from_seed(&vault_key, b"oneiron/world-recovery-root/v1").unwrap(),
        HybridSecretKey::from_seeds(
            &<[u8; 64]>::try_from([vault_key, vault_key].concat()).unwrap(),
            &vault_key,
        ),
    ];
    for (to, wrap) in &wraps {
        for secret in &candidates {
            assert!(open_world_key(&bound, *to, secret, wrap).is_err());
        }
        let kek = Kek::from_bytes(vault_key);
        let policy_free = wrap.open(
            oneiron_crypto::OpenKey::SymmetricKek(&kek),
            &oneiron_crypto::OpenPolicy {
                purpose: Purpose::WorldDek,
                vault_id: &VAULT,
                recipient: &to.envelope_recipient(),
                key_id: &bound.key.envelope_key_id(),
                wraps: &[
                    oneiron_crypto::WrapType::HybridCapsule,
                    oneiron_crypto::WrapType::SymmetricKek,
                ],
                aead_suites: &[SuiteId::XCHACHA20POLY1305_V1],
                kem_suites: &[SuiteId::KEM_X25519_MLKEM1024_V1],
                min_epoch: 1,
                argon2_max: oneiron_crypto::Argon2Cost::RFC9106_SECOND,
            },
        );
        assert!(policy_free.is_err());
    }
}

/// Done means (packet P6b): a mismatched world, generation, owner, policy or suite is
/// refused. The header checks run before any key derivation.
#[test]
fn a_mismatched_world_generation_or_suite_is_refused() {
    let keys = MemoryKeystore::new();
    let machine = machine_secret(&keys, VAULT, INSTALL).unwrap();
    let key = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    let bound = binding(&key);
    let to = WrapRecipient::Machine(entity(0xa1));
    let wrap = seal_world_key(&bound, to, machine.public_key(), &key).unwrap();
    assert!(open_world_key(&bound, to, &machine, &wrap).is_ok());

    let mut other_world = bound;
    other_world.key.world = entity(0x78);
    let mut next_generation = bound;
    next_generation.key.generation += 1;
    let mut other_mint = bound;
    other_mint.key.mint[0] ^= 1;
    let mut other_owner = bound;
    other_owner.owner = entity(0x0c);
    let mut other_policy = bound;
    other_policy.policy.0[0] ^= 1;
    let mut other_vault = bound;
    other_vault.vault_id[0] ^= 1;
    for wrong in [
        other_world,
        next_generation,
        other_mint,
        other_owner,
        other_policy,
        other_vault,
    ] {
        assert!(open_world_key(&wrong, to, &machine, &wrap).is_err());
    }

    // This wrap's own payload under a suite the reader does not accept, and under
    // another purpose: only the header field differs (Sol code-R1 S1-F9).
    let key_id = bound.key.envelope_key_id();
    let recipient = to.envelope_recipient();
    let payload = super::wrap::world_key_payload(&bound, &key);
    let reseal = |suite, purpose, kem_suite| {
        seal(
            &SealParams {
                suite,
                purpose,
                epoch: WORLD_KEY_EPOCH,
                key_id: &key_id,
                recipient: &recipient,
                vault_id: &VAULT,
            },
            SealKey::Hybrid {
                recipient: machine.public_key(),
                kem_suite,
            },
            &payload,
            &mut getrandom::SysRng,
        )
    };
    let resealed = reseal(
        SuiteId::XCHACHA20POLY1305_V1,
        Purpose::WorldDek,
        SuiteId::KEM_X25519_MLKEM1024_V1,
    )
    .unwrap();
    assert!(open_world_key(&bound, to, &machine, &resealed).is_ok());
    let wrong: Vec<Envelope> = [
        (
            SuiteId::AES256GCM_V1,
            Purpose::WorldDek,
            SuiteId::KEM_X25519_MLKEM1024_V1,
        ),
        (
            SuiteId::XCHACHA20POLY1305_V1,
            Purpose::VaultDek,
            SuiteId::KEM_X25519_MLKEM1024_V1,
        ),
        (
            SuiteId::XCHACHA20POLY1305_V1,
            Purpose::WorldDek,
            SuiteId::KEM_X25519_MLKEM768_V1,
        ),
    ]
    .into_iter()
    .filter_map(|(suite, purpose, kem)| reseal(suite, purpose, kem).ok())
    .collect();
    assert!(wrong.len() >= 2);
    for envelope in &wrong {
        assert!(open_world_key(&bound, to, &machine, envelope).is_err());
    }

    // A binding that names another key cannot seal this one.
    assert!(seal_world_key(&other_world, to, machine.public_key(), &key).is_err());
    // Base reality never gets a key.
    assert!(WorldKey::mint(oneiron_contracts::claim::base_world_id(), 1).is_err());
}

/// Done means (contract F2): one key id names one key. A wrap sealed by a machine that
/// substituted other bytes under the same id opens, but the commitment refuses it.
#[test]
fn a_wrap_with_substituted_key_bytes_is_refused() {
    let keys = MemoryKeystore::new();
    let machine = machine_secret(&keys, VAULT, INSTALL).unwrap();
    let key = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    let bound = binding(&key);
    let to = WrapRecipient::Machine(entity(0xa1));
    let mut other = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    other.id = *key.id();
    let substituted = binding(&other);
    let forged = seal_world_key(&substituted, to, machine.public_key(), &other).unwrap();
    assert!(open_world_key(&substituted, to, &machine, &forged).is_ok());
    assert!(open_world_key(&bound, to, &machine, &forged).is_err());
    assert!(seal_world_key(&bound, to, machine.public_key(), &other).is_err());
}

/// Sol R1-F1 (repro): the pairing fingerprint must bind the anchor. A host that copies
/// the owner's public recovery key under its own anchor, or replays the owner's root in
/// another vault, gets another id, so the owner's fingerprint never names its copy.
/// The v1 id hashed the recovery key alone, and both roots carried one fingerprint.
#[test]
fn the_root_fingerprint_binds_the_anchor_and_the_vault() {
    let owner = RecoveryRootSeed::generate()
        .unwrap()
        .public(&VAULT)
        .unwrap();
    let host = RecoveryRootSeed::generate()
        .unwrap()
        .public(&VAULT)
        .unwrap();
    let copied = RecoveryRootId::of(&VAULT, &owner.recovery_key, &host.anchor_key);
    assert_ne!(copied, owner.id);
    let mut other_vault = VAULT;
    other_vault[0] ^= 1;
    let elsewhere = RecoveryRootId::of(&other_vault, &owner.recovery_key, &owner.anchor_key);
    assert_ne!(elsewhere, owner.id);
    assert_eq!(
        RecoveryRootId::of(&VAULT, &owner.recovery_key, &owner.anchor_key),
        owner.id
    );
}

/// Debug output never prints key or seed material.
#[test]
fn debug_output_carries_no_secret() {
    let key = WorldKey::mint(entity(0x77), FIRST_GENERATION).unwrap();
    let seed = RecoveryRootSeed::generate().unwrap();
    let printed = format!("{key:?} {seed:?}");
    for secret in [&key.expose()[..], &seed.kit_bytes()[..]] {
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!printed.contains(&hex));
        assert!(!printed.contains(&format!("{secret:?}")));
    }
    assert!(printed.contains("redacted"));
    let keys = MemoryKeystore::new();
    assert!(!format!("{keys:?}").contains('['));
    assert_eq!(
        keys.locality(),
        oneiron_keystore::KeystoreLocality::ProcessOnly
    );
}
