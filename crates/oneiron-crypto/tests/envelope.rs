//! Envelope contract: round trips for every wrap type, fail-closed parsing, reader
//! policy, AAD binding of every header field, ciphertext swaps, nonces, hybrid capsule.

use std::convert::Infallible;

use oneiron_crypto::{
    Argon2Cost, Envelope, Error, HYBRID_PUBLIC_KEY_LEN, HybridPublicKey, HybridSecretKey, Kek,
    MAX_PLAINTEXT_LEN, NonceLedger, OpenKey, OpenPolicy, Passphrase, Purpose, RecoverySecret,
    SealKey, SealParams, SuiteId, WrapType, seal,
};
use rand_core::{TryCryptoRng, TryRng};

const KEY_ID: &[u8] = b"kek-1";
const RECIPIENT: &[u8] = b"device-a";
const VAULT: &[u8] = b"vault-1";
const ALL_WRAPS: &[WrapType] = &[
    WrapType::SymmetricKek,
    WrapType::Passphrase,
    WrapType::DeviceKeystore,
    WrapType::Passkey,
    WrapType::ShamirRecovery,
    WrapType::HybridCapsule,
];
const AEADS: &[SuiteId] = &[SuiteId::XCHACHA20POLY1305_V1, SuiteId::AES256GCM_V1];
const KEMS: &[SuiteId] = &[SuiteId::KEM_X25519_MLKEM1024_V1];
const FAST_ARGON: Argon2Cost = Argon2Cost {
    m_kib: Argon2Cost::MIN_M_KIB,
    t: 1,
    p: 1,
};
const SHARE_SET: [u8; 16] = [7; 16];
const PLAINTEXT: &[u8] = b"a 256-bit vault DEK would go here";

fn rng() -> getrandom::SysRng {
    getrandom::SysRng
}

/// Always yields the same byte: two seals draw the same salt and nonce.
struct FixedRng;
impl TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(0x4242_4242)
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(0x4242_4242_4242_4242)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.fill(0x42);
        Ok(())
    }
}
impl TryCryptoRng for FixedRng {}

/// Always fails.
struct FailingRng;
impl TryRng for FailingRng {
    type Error = getrandom::Error;
    fn try_next_u32(&mut self) -> Result<u32, getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
    fn try_next_u64(&mut self) -> Result<u64, getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
    fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), getrandom::Error> {
        Err(getrandom::Error::UNSUPPORTED)
    }
}
impl TryCryptoRng for FailingRng {}

fn params(suite: SuiteId) -> SealParams<'static> {
    SealParams {
        suite,
        purpose: Purpose::VaultDek,
        epoch: 3,
        key_id: KEY_ID,
        recipient: RECIPIENT,
        vault_id: VAULT,
    }
}

fn policy() -> OpenPolicy<'static> {
    OpenPolicy {
        purpose: Purpose::VaultDek,
        vault_id: VAULT,
        recipient: RECIPIENT,
        key_id: KEY_ID,
        wraps: ALL_WRAPS,
        aead_suites: AEADS,
        kem_suites: KEMS,
        min_epoch: 1,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    }
}

struct Keys {
    kek: Kek,
    other_kek: Kek,
    passphrase: Passphrase,
    recovery: RecoverySecret,
    hybrid: HybridSecretKey,
}

fn keys() -> Keys {
    Keys {
        kek: Kek::from_bytes([1; 32]),
        other_kek: Kek::from_bytes([2; 32]),
        passphrase: Passphrase::new(b"correct horse battery staple").expect("passphrase"),
        recovery: RecoverySecret::from_bytes([3; 32]),
        hybrid: HybridSecretKey::from_seeds(&[4; 64], &[5; 32]),
    }
}

fn seal_key(keys: &Keys, wrap: WrapType) -> SealKey<'_> {
    match wrap {
        WrapType::SymmetricKek => SealKey::SymmetricKek(&keys.kek),
        WrapType::Passphrase => SealKey::Passphrase {
            passphrase: &keys.passphrase,
            cost: FAST_ARGON,
        },
        WrapType::DeviceKeystore => SealKey::DeviceKeystore(&keys.kek),
        WrapType::Passkey => SealKey::Passkey(&keys.kek),
        WrapType::ShamirRecovery => SealKey::ShamirRecovery {
            secret: &keys.recovery,
            threshold: 2,
            shares: 3,
            share_set_id: SHARE_SET,
        },
        WrapType::HybridCapsule => SealKey::Hybrid {
            recipient: keys.hybrid.public_key(),
            kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
        },
    }
}

fn open_key(keys: &Keys, wrap: WrapType) -> OpenKey<'_> {
    match wrap {
        WrapType::SymmetricKek => OpenKey::SymmetricKek(&keys.kek),
        WrapType::Passphrase => OpenKey::Passphrase(&keys.passphrase),
        WrapType::DeviceKeystore => OpenKey::DeviceKeystore(&keys.kek),
        WrapType::Passkey => OpenKey::Passkey(&keys.kek),
        WrapType::ShamirRecovery => OpenKey::ShamirRecovery(&keys.recovery),
        WrapType::HybridCapsule => OpenKey::Hybrid(&keys.hybrid),
    }
}

fn sealed(keys: &Keys, suite: SuiteId, wrap: WrapType) -> Vec<u8> {
    seal(&params(suite), seal_key(keys, wrap), PLAINTEXT, &mut rng())
        .expect("seal")
        .to_bytes()
}

fn open_bytes(bytes: &[u8], key: OpenKey<'_>, policy: &OpenPolicy<'_>) -> Result<Vec<u8>, Error> {
    Envelope::parse(bytes)?
        .open(key, policy)
        .map(|pt| pt.to_vec())
}

/// Byte offsets of the header fields of an envelope sealed with `params()`.
struct Layout {
    key_id: usize,
    recipient: usize,
    vault: usize,
    kdf: usize,
    after_kdf: usize,
}

fn layout(bytes: &[u8]) -> Layout {
    let key_id = 20;
    let recipient = key_id + usize::from(bytes[19]) + 1;
    let vault = recipient + usize::from(bytes[recipient - 1]) + 1;
    let kdf = vault + usize::from(bytes[vault - 1]);
    let after_kdf = kdf + 1 + if bytes[kdf] == 2 { 4 + 4 + 1 + 32 } else { 32 };
    Layout {
        key_id,
        recipient,
        vault,
        kdf,
        after_kdf,
    }
}

#[test]
fn unknown_forbidden_reserved_and_misplaced_suites_fail_closed() {
    let keys = keys();
    let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let relabel = |suite: u16| {
        let mut b = bytes.clone();
        b[6..8].copy_from_slice(&suite.to_be_bytes());
        Envelope::parse(&b)
    };
    assert_eq!(relabel(0x7777), Err(Error::UnknownSuite(0x7777)));
    assert_eq!(relabel(0x0003), Err(Error::ForbiddenSuite("aes128gcm-v1")));
    assert_eq!(
        relabel(0x01f0),
        Err(Error::ReservedSuite(
            "kem-x25519-mlkem1024-mceliece8192128-v1"
        ))
    );
    assert!(matches!(relabel(0x0101), Err(Error::WrongSuiteKind { .. })));
    assert!(matches!(relabel(0x0201), Err(Error::WrongSuiteKind { .. })));

    // Writers cannot produce them either.
    for (suite, err) in [
        (SuiteId::AES128GCM_V1, Error::ForbiddenSuite("aes128gcm-v1")),
        (SuiteId(0x7777), Error::UnknownSuite(0x7777)),
    ] {
        assert_eq!(
            seal(
                &params(suite),
                SealKey::SymmetricKek(&keys.kek),
                PLAINTEXT,
                &mut rng()
            )
            .err(),
            Some(err)
        );
    }
    for (kem, err) in [
        (
            SuiteId::KEM_X25519_V1,
            Error::ForbiddenSuite("kem-x25519-v1"),
        ),
        (
            SuiteId::KEM_X25519_MLKEM768_V1,
            Error::ForbiddenSuite("kem-x25519-mlkem768-v1"),
        ),
        (
            SuiteId::KEM_X25519_MLKEM1024_HQC256_V1,
            Error::ReservedSuite("kem-x25519-mlkem1024-hqc256-v1"),
        ),
    ] {
        let key = SealKey::Hybrid {
            recipient: keys.hybrid.public_key(),
            kem_suite: kem,
        };
        assert_eq!(
            seal(
                &params(SuiteId::XCHACHA20POLY1305_V1),
                key,
                PLAINTEXT,
                &mut rng()
            )
            .err(),
            Some(err)
        );
    }

    // A capsule relabelled to a classical-only or 768 KEM is refused by name.
    let hybrid = sealed(
        &keys,
        SuiteId::XCHACHA20POLY1305_V1,
        WrapType::HybridCapsule,
    );
    let at = layout(&hybrid).after_kdf;
    for (kem, name) in [
        (0x0103u16, "kem-x25519-v1"),
        (0x0102, "kem-x25519-mlkem768-v1"),
    ] {
        let mut b = hybrid.clone();
        b[at..at + 2].copy_from_slice(&kem.to_be_bytes());
        assert_eq!(Envelope::parse(&b), Err(Error::ForbiddenSuite(name)));
    }
}

#[test]
fn an_epoch_below_the_suite_minimum_is_refused() {
    let keys = keys();
    let mut b = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    b[11..19].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(
        Envelope::parse(&b),
        Err(Error::EpochBelowSuiteMinimum {
            suite: "xchacha20poly1305-v1",
            epoch: 0,
            min: 1
        })
    );
    let zero = SealParams {
        epoch: 0,
        ..params(SuiteId::AES256GCM_V1)
    };
    assert!(matches!(
        seal(
            &zero,
            SealKey::SymmetricKek(&keys.kek),
            PLAINTEXT,
            &mut rng()
        ),
        Err(Error::EpochBelowSuiteMinimum { .. })
    ));
}

#[test]
fn truncated_oversized_and_trailing_input_is_refused() {
    let keys = keys();
    for &wrap in ALL_WRAPS {
        let bytes = sealed(&keys, SuiteId::AES256GCM_V1, wrap);
        for cut in 0..bytes.len() {
            assert!(
                Envelope::parse(&bytes[..cut]).is_err(),
                "{wrap:?} truncated at {cut}"
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            Envelope::parse(&long),
            Err(Error::TrailingBytes { extra: 1 })
        );
    }
    let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    // A key id length of 65 bytes is over the bound.
    let mut b = bytes[..19].to_vec();
    b.push(65);
    b.extend([0u8; 65]);
    assert_eq!(
        Envelope::parse(&b),
        Err(Error::FieldLength {
            field: "key_id",
            len: 65,
            min: 1,
            max: 64
        })
    );
    // A zero-length recipient is under the bound.
    let l = layout(&bytes);
    let mut b = bytes[..l.recipient - 1].to_vec();
    b.push(0);
    assert!(matches!(
        Envelope::parse(&b),
        Err(Error::FieldLength {
            field: "recipient",
            ..
        })
    ));
    // A ciphertext length above the plaintext bound is refused before any read.
    let ct_len_at = bytes.len() - PLAINTEXT.len() - 16 - 4;
    let mut b = bytes;
    let over = u32::try_from(MAX_PLAINTEXT_LEN + 17).expect("u32");
    b[ct_len_at..ct_len_at + 4].copy_from_slice(&over.to_be_bytes());
    assert!(matches!(
        Envelope::parse(&b),
        Err(Error::FieldLength {
            field: "ciphertext",
            ..
        })
    ));
    let big = vec![0u8; MAX_PLAINTEXT_LEN + 1];
    assert!(matches!(
        seal(
            &params(SuiteId::AES256GCM_V1),
            SealKey::SymmetricKek(&keys.kek),
            &big,
            &mut rng()
        ),
        Err(Error::FieldLength {
            field: "plaintext",
            ..
        })
    ));
}

#[test]
fn unknown_codes_kdf_mismatch_and_hostile_costs_are_refused() {
    let keys = keys();
    let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let mut b = bytes.clone();
    b[0] = b'X';
    assert_eq!(
        Envelope::parse(&b),
        Err(Error::BadMagic {
            expected: "envelope"
        })
    );
    let mut b = bytes.clone();
    b[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert_eq!(Envelope::parse(&b), Err(Error::UnsupportedVersion(2)));
    let mut b = bytes.clone();
    b[8] = 0x99;
    assert_eq!(Envelope::parse(&b), Err(Error::UnknownWrap(0x99)));
    let mut b = bytes.clone();
    b[9..11].copy_from_slice(&999u16.to_be_bytes());
    assert_eq!(Envelope::parse(&b), Err(Error::UnknownPurpose(999)));
    let l = layout(&bytes);
    let mut b = bytes.clone();
    b[l.kdf] = 9;
    assert_eq!(Envelope::parse(&b), Err(Error::UnknownKdf(9)));
    // A passphrase wrap relabelled onto the HKDF-only path (and back) is refused.
    let mut b = bytes;
    b[8] = WrapType::Passphrase as u8;
    assert!(matches!(
        Envelope::parse(&b),
        Err(Error::KdfWrapMismatch { .. })
    ));
    let pass = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::Passphrase);
    let mut b = pass.clone();
    b[8] = WrapType::SymmetricKek as u8;
    assert!(matches!(
        Envelope::parse(&b),
        Err(Error::KdfWrapMismatch { .. })
    ));
    // Argon2id costs outside the bounds never reach Argon2.
    let pl = layout(&pass);
    for (offset, value, param) in [
        (1, Argon2Cost::MAX_M_KIB + 1, "argon2id m_kib"),
        (1, Argon2Cost::MIN_M_KIB - 1, "argon2id m_kib"),
        (5, Argon2Cost::MAX_T + 1, "argon2id t"),
    ] {
        let mut b = pass.clone();
        b[pl.kdf + offset..pl.kdf + offset + 4].copy_from_slice(&value.to_be_bytes());
        assert!(
            matches!(Envelope::parse(&b), Err(Error::KdfParamOutOfRange { param: p, .. }) if p == param)
        );
    }
    let mut b = pass;
    b[pl.kdf + 9] = 0;
    assert!(matches!(
        Envelope::parse(&b),
        Err(Error::KdfParamOutOfRange {
            param: "argon2id p",
            ..
        })
    ));
    // Shamir parameters must describe a real threshold.
    let shamir = sealed(
        &keys,
        SuiteId::XCHACHA20POLY1305_V1,
        WrapType::ShamirRecovery,
    );
    let at = layout(&shamir).after_kdf;
    for (threshold, shares) in [(1u8, 3u8), (4, 3), (2, 17)] {
        let mut b = shamir.clone();
        b[at] = threshold;
        b[at + 1] = shares;
        assert_eq!(
            Envelope::parse(&b),
            Err(Error::ShamirParamsInvalid { threshold, shares })
        );
    }
}

/// Flips one metadata field and opens with a policy that accepts the flipped value,
/// so only the cryptographic binding can refuse it.
fn assert_bound(
    bytes: &[u8],
    mutate: impl Fn(&mut Vec<u8>),
    key: OpenKey<'_>,
    policy: &OpenPolicy<'_>,
    field: &str,
) {
    let mut b = bytes.to_vec();
    mutate(&mut b);
    assert_ne!(b, bytes, "{field}: the mutation changed nothing");
    match Envelope::parse(&b) {
        Ok(env) => assert_eq!(
            env.open(key, policy).map(|p| p.to_vec()),
            Err(Error::OpenFailed),
            "{field}"
        ),
        Err(err) => {
            panic!("{field}: expected the parse to pass and the AEAD to refuse, got {err:?}")
        }
    }
}

#[test]
fn an_rng_failure_is_an_error_not_a_weaker_envelope() {
    let keys = keys();
    for &wrap in ALL_WRAPS {
        let result = seal(
            &params(SuiteId::XCHACHA20POLY1305_V1),
            seal_key(&keys, wrap),
            PLAINTEXT,
            &mut FailingRng,
        );
        assert_eq!(result.err(), Some(Error::Rng), "{wrap:?}");
    }
    assert_eq!(Kek::generate(&mut FailingRng).err(), Some(Error::Rng));
    assert_eq!(
        HybridSecretKey::generate(&mut FailingRng).err(),
        Some(Error::Rng)
    );
}

#[test]
fn hybrid_capsule_needs_both_component_secrets_and_the_right_recipient() {
    let keys = keys();
    let bytes = sealed(
        &keys,
        SuiteId::XCHACHA20POLY1305_V1,
        WrapType::HybridCapsule,
    );
    let wrong_x25519 = HybridSecretKey::from_seeds(&[4; 64], &[6; 32]);
    let wrong_mlkem = HybridSecretKey::from_seeds(&[8; 64], &[5; 32]);
    let recipient_b = HybridSecretKey::generate(&mut rng()).expect("key");
    for key in [&wrong_x25519, &wrong_mlkem, &recipient_b] {
        assert_eq!(
            open_bytes(&bytes, OpenKey::Hybrid(key), &policy()),
            Err(Error::OpenFailed)
        );
    }
    let as_b = OpenPolicy {
        recipient: b"device-b",
        ..policy()
    };
    assert_eq!(
        open_bytes(&bytes, OpenKey::Hybrid(&recipient_b), &as_b),
        Err(Error::RecipientMismatch)
    );
    assert_eq!(
        open_bytes(&bytes, OpenKey::Hybrid(&keys.hybrid), &policy()).expect("opens"),
        PLAINTEXT
    );
}

#[test]
fn bad_recipient_public_keys_are_refused() {
    let keys = keys();
    let mut pk = keys.hybrid.public_key().to_bytes();
    assert_eq!(pk.len(), HYBRID_PUBLIC_KEY_LEN);
    assert_eq!(
        HybridPublicKey::from_bytes(&pk).expect("valid"),
        *keys.hybrid.public_key()
    );
    // An all-zero X25519 key gives a non-contributory secret.
    pk[HYBRID_PUBLIC_KEY_LEN - 32..].fill(0);
    let zero_x = HybridPublicKey::from_bytes(&pk).expect("encoding is valid");
    let key = SealKey::Hybrid {
        recipient: &zero_x,
        kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
    };
    assert_eq!(
        seal(
            &params(SuiteId::XCHACHA20POLY1305_V1),
            key,
            PLAINTEXT,
            &mut rng()
        )
        .err(),
        Some(Error::KemKeyRejected)
    );
    // ML-KEM coefficients at or above q fail the FIPS 203 modulus check.
    let mut pk = keys.hybrid.public_key().to_bytes();
    pk[..3].fill(0xff);
    assert_eq!(
        HybridPublicKey::from_bytes(&pk).err(),
        Some(Error::KemKeyRejected)
    );
    assert!(matches!(
        HybridPublicKey::from_bytes(&pk[..100]),
        Err(Error::FieldLength { .. })
    ));
}

#[test]
fn an_argon2_cost_over_the_reader_budget_is_refused_before_argon2_runs() {
    let keys = keys();
    let pass = sealed(&keys, SuiteId::AES256GCM_V1, WrapType::Passphrase);
    let at = layout(&pass).kdf;
    let mut b = pass.clone();
    b[at + 1..at + 5].copy_from_slice(&Argon2Cost::MAX_M_KIB.to_be_bytes());
    b[at + 5..at + 9].copy_from_slice(&Argon2Cost::MAX_T.to_be_bytes());
    let requested = Argon2Cost {
        m_kib: Argon2Cost::MAX_M_KIB,
        t: Argon2Cost::MAX_T,
        p: 1,
    };
    assert_eq!(
        open_bytes(&b, OpenKey::Passphrase(&keys.passphrase), &policy()),
        Err(Error::Argon2OverBudget {
            requested,
            budget: Argon2Cost::RFC9106_SECOND
        })
    );
    let tight = OpenPolicy {
        argon2_max: Argon2Cost {
            m_kib: Argon2Cost::MIN_M_KIB,
            t: 1,
            p: 1,
        },
        ..policy()
    };
    assert_eq!(
        open_bytes(&pass, OpenKey::Passphrase(&keys.passphrase), &tight).expect("within budget"),
        PLAINTEXT
    );
}

/// Oracle: the two seeds come from RFC 5869 HKDF-SHA256 (no salt), computed outside this
/// crate (Python `hmac`/`hashlib`) for seed 0x01..=0x20 and label `oneiron/test-label/v1`.
#[test]
fn a_seed_key_expands_by_rfc5869_hkdf_under_its_label() {
    let seed: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let label = b"oneiron/test-label/v1";
    let mlkem: [u8; 64] = hex::decode(
        "071d3eb1e0ff5f451ac63ffe52977fb6c35677c1e4d78932cb7084cb5fefc563\
         69dda93b5d9ecd7cb1d6f2bba948ea2204a92cd8f1f2f4bb4d994413d8cc0d33",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let x25519: [u8; 32] =
        hex::decode("f16fb7f655ddf5a759275d8bd4ac8ecfc0a2b70e1d4947e9cae0adf8255c36b4")
            .unwrap()
            .try_into()
            .unwrap();
    let expanded = HybridSecretKey::from_seed(&seed, label).unwrap();
    let expected = HybridSecretKey::from_seeds(&mlkem, &x25519);
    assert_eq!(expanded.public_key(), expected.public_key());
    let other = HybridSecretKey::from_seed(&seed, b"oneiron/other-label/v1").unwrap();
    assert_ne!(other.public_key(), expected.public_key());
    assert!(HybridSecretKey::from_seed(&[0; 32], label).is_err());
}
