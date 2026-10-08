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
fn every_wrap_type_round_trips_under_both_aead_suites() {
    let keys = keys();
    for &suite in AEADS {
        for &wrap in ALL_WRAPS {
            let bytes = sealed(&keys, suite, wrap);
            let opened = open_bytes(&bytes, open_key(&keys, wrap), &policy()).expect("opens");
            assert_eq!(opened, PLAINTEXT, "{suite:?} {wrap:?}");
            let env = Envelope::parse(&bytes).expect("parses");
            assert_eq!(env.to_bytes(), bytes, "canonical re-encoding");
            assert_eq!(env.header().wrap, wrap);
        }
    }
}

#[test]
fn a_wrong_key_does_not_open_any_wrap_type() {
    let keys = keys();
    let wrong = Keys {
        kek: Kek::from_bytes([9; 32]),
        other_kek: Kek::from_bytes([9; 32]),
        passphrase: Passphrase::new(b"Tr0ub4dor&3").expect("passphrase"),
        recovery: RecoverySecret::from_bytes([9; 32]),
        hybrid: HybridSecretKey::from_seeds(&[9; 64], &[9; 32]),
    };
    for &wrap in ALL_WRAPS {
        let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, wrap);
        assert_eq!(
            open_bytes(&bytes, open_key(&wrong, wrap), &policy()),
            Err(Error::OpenFailed),
            "{wrap:?}"
        );
    }
    let bytes = sealed(&keys, SuiteId::AES256GCM_V1, WrapType::SymmetricKek);
    assert_eq!(
        open_bytes(&bytes, OpenKey::SymmetricKek(&keys.other_kek), &policy()),
        Err(Error::OpenFailed)
    );
}

#[test]
fn the_reader_policy_is_checked_before_any_crypto() {
    let keys = keys();
    let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let key = || OpenKey::SymmetricKek(&keys.kek);
    let cases: Vec<(OpenPolicy<'_>, Error)> = vec![
        (
            OpenPolicy {
                aead_suites: &[SuiteId::AES256GCM_V1],
                ..policy()
            },
            Error::SuiteNotAccepted("xchacha20poly1305-v1"),
        ),
        (
            OpenPolicy {
                wraps: &[WrapType::HybridCapsule],
                ..policy()
            },
            Error::WrapNotAccepted(WrapType::SymmetricKek),
        ),
        (
            OpenPolicy {
                min_epoch: 4,
                ..policy()
            },
            Error::EpochBelowPolicyMinimum { epoch: 3, min: 4 },
        ),
        (
            OpenPolicy {
                purpose: Purpose::BackupArtifact,
                ..policy()
            },
            Error::PurposeMismatch {
                expected: Purpose::BackupArtifact,
                found: Purpose::VaultDek,
            },
        ),
        (
            OpenPolicy {
                vault_id: b"vault-2",
                ..policy()
            },
            Error::VaultMismatch,
        ),
        (
            OpenPolicy {
                recipient: b"device-b",
                ..policy()
            },
            Error::RecipientMismatch,
        ),
        (
            OpenPolicy {
                key_id: b"kek-2",
                ..policy()
            },
            Error::KeyIdMismatch,
        ),
    ];
    for (policy, expected) in cases {
        assert_eq!(open_bytes(&bytes, key(), &policy), Err(expected));
    }
    assert_eq!(
        open_bytes(&bytes, OpenKey::Passkey(&keys.kek), &policy()),
        Err(Error::WrongKeyForWrap {
            wrap: WrapType::SymmetricKek
        })
    );
    let hybrid = sealed(
        &keys,
        SuiteId::XCHACHA20POLY1305_V1,
        WrapType::HybridCapsule,
    );
    assert_eq!(
        open_bytes(
            &hybrid,
            OpenKey::Hybrid(&keys.hybrid),
            &OpenPolicy {
                kem_suites: &[],
                ..policy()
            }
        ),
        Err(Error::SuiteNotAccepted("kem-x25519-mlkem1024-v1"))
    );
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
fn every_header_field_is_bound_into_the_aead() {
    let keys = keys();
    let bytes = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let l = layout(&bytes);
    let kek = || OpenKey::SymmetricKek(&keys.kek);
    let nonce_at = l.after_kdf;

    assert_bound(
        &bytes,
        |b| b[8] = WrapType::DeviceKeystore as u8,
        OpenKey::DeviceKeystore(&keys.kek),
        &policy(),
        "wrap",
    );
    let p = OpenPolicy {
        purpose: Purpose::RecoveryKek,
        ..policy()
    };
    assert_bound(
        &bytes,
        |b| b[9..11].copy_from_slice(&2u16.to_be_bytes()),
        kek(),
        &p,
        "purpose",
    );
    assert_bound(&bytes, |b| b[18] ^= 1, kek(), &policy(), "epoch");
    let p = OpenPolicy {
        key_id: b"kek-0",
        ..policy()
    };
    assert_bound(&bytes, |b| b[l.key_id + 4] = b'0', kek(), &p, "key_id");
    let p = OpenPolicy {
        recipient: b"device-b",
        ..policy()
    };
    assert_bound(
        &bytes,
        |b| b[l.recipient + 7] = b'b',
        kek(),
        &p,
        "recipient",
    );
    let p = OpenPolicy {
        vault_id: b"vault-2",
        ..policy()
    };
    assert_bound(&bytes, |b| b[l.vault + 6] = b'2', kek(), &p, "vault_id");
    assert_bound(&bytes, |b| b[l.kdf + 1] ^= 1, kek(), &policy(), "kdf salt");
    assert_bound(&bytes, |b| b[nonce_at] ^= 1, kek(), &policy(), "nonce");
    let last = bytes.len() - 1;
    assert_bound(&bytes, |b| b[last] ^= 1, kek(), &policy(), "ciphertext");

    let pass = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::Passphrase);
    let pl = layout(&pass);
    let key = || OpenKey::Passphrase(&keys.passphrase);
    assert_bound(
        &pass,
        |b| b[pl.kdf + 4] ^= 1,
        key(),
        &policy(),
        "argon2id m_kib",
    );
    assert_bound(&pass, |b| b[pl.kdf + 8] = 2, key(), &policy(), "argon2id t");
    assert_bound(&pass, |b| b[pl.kdf + 9] = 2, key(), &policy(), "argon2id p");

    let shamir = sealed(
        &keys,
        SuiteId::XCHACHA20POLY1305_V1,
        WrapType::ShamirRecovery,
    );
    let at = layout(&shamir).after_kdf;
    let key = || OpenKey::ShamirRecovery(&keys.recovery);
    assert_bound(&shamir, |b| b[at] = 3, key(), &policy(), "shamir threshold");
    assert_bound(
        &shamir,
        |b| b[at + 1] = 4,
        key(),
        &policy(),
        "shamir shares",
    );
    assert_bound(
        &shamir,
        |b| b[at + 2] ^= 1,
        key(),
        &policy(),
        "shamir share set",
    );

    // The two AEAD suites have different nonce lengths, so relabelling between them
    // cannot even parse; the version byte is refused as unsupported.
    let mut b = bytes;
    b[6..8].copy_from_slice(&SuiteId::AES256GCM_V1.0.to_be_bytes());
    assert!(Envelope::parse(&b).is_err(), "suite relabel");
}

#[test]
fn a_ciphertext_moved_under_another_header_does_not_open() {
    let keys = keys();
    let a = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let b = sealed(&keys, SuiteId::XCHACHA20POLY1305_V1, WrapType::SymmetricKek);
    let body = PLAINTEXT.len() + 16;
    let mut swapped = a[..a.len() - body].to_vec();
    swapped.extend_from_slice(&b[b.len() - body..]);
    assert_eq!(
        open_bytes(&swapped, OpenKey::SymmetricKek(&keys.kek), &policy()),
        Err(Error::OpenFailed)
    );
}

#[test]
fn a_duplicate_nonce_under_one_key_id_is_detected() {
    let keys = keys();
    let mut ledger = NonceLedger::new();
    let p = params(SuiteId::AES256GCM_V1);
    let first = seal(
        &p,
        SealKey::SymmetricKek(&keys.kek),
        PLAINTEXT,
        &mut FixedRng,
    )
    .expect("seal");
    let second = seal(
        &p,
        SealKey::SymmetricKek(&keys.kek),
        b"another",
        &mut FixedRng,
    )
    .expect("seal");
    ledger.record(&first).expect("first is new");
    assert_eq!(ledger.record(&second), Err(Error::DuplicateNonce));
    for _ in 0..64 {
        let env = seal(&p, SealKey::SymmetricKek(&keys.kek), PLAINTEXT, &mut rng()).expect("seal");
        ledger
            .record(&env)
            .expect("fresh random nonces do not collide");
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
fn hybrid_transcript_binds_every_field() {
    let keys = keys();
    let bytes = sealed(&keys, SuiteId::AES256GCM_V1, WrapType::HybridCapsule);
    let l = layout(&bytes);
    let key = || OpenKey::Hybrid(&keys.hybrid);
    let eph = l.after_kdf + 2;
    let ct_m = eph + 32;
    assert_bound(
        &bytes,
        |b| b[eph + 5] ^= 1,
        key(),
        &policy(),
        "x25519 ephemeral",
    );
    assert_bound(
        &bytes,
        |b| b[ct_m + 700] ^= 1,
        key(),
        &policy(),
        "mlkem ciphertext",
    );
    let p = OpenPolicy {
        recipient: b"device-b",
        ..policy()
    };
    assert_bound(
        &bytes,
        |b| b[l.recipient + 7] = b'b',
        key(),
        &p,
        "recipient",
    );
    let p = OpenPolicy {
        vault_id: b"vault-2",
        ..policy()
    };
    assert_bound(&bytes, |b| b[l.vault + 6] = b'2', key(), &p, "vault_id");
    let p = OpenPolicy {
        purpose: Purpose::EscrowRecipient,
        ..policy()
    };
    assert_bound(
        &bytes,
        |b| b[9..11].copy_from_slice(&10u16.to_be_bytes()),
        key(),
        &p,
        "purpose",
    );
    assert_bound(&bytes, |b| b[18] ^= 2, key(), &policy(), "epoch");
    let p = OpenPolicy {
        key_id: b"kek-0",
        ..policy()
    };
    assert_bound(&bytes, |b| b[l.key_id + 4] = b'0', key(), &p, "key_id");
    // A low-order ephemeral point is refused as an open failure.
    assert_bound(
        &bytes,
        |b| b[eph..eph + 32].fill(0),
        key(),
        &policy(),
        "low-order ephemeral",
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
fn sealed_bytes_match_an_independent_implementation_of_the_spec() {
    // tests/vectors/golden_envelopes.py builds these from README.md with OpenSSL,
    // libsodium and the reference Argon2, every random byte 0x42 as FixedRng gives.
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("vectors/golden_envelopes.json")).expect("golden json");
    let keys = keys();
    let cases = [
        (
            "aes256gcm_symmetric_kek",
            SuiteId::AES256GCM_V1,
            WrapType::SymmetricKek,
        ),
        (
            "xchacha20poly1305_symmetric_kek",
            SuiteId::XCHACHA20POLY1305_V1,
            WrapType::SymmetricKek,
        ),
        (
            "xchacha20poly1305_shamir_2_of_3",
            SuiteId::XCHACHA20POLY1305_V1,
            WrapType::ShamirRecovery,
        ),
        (
            "aes256gcm_passphrase_argon2id",
            SuiteId::AES256GCM_V1,
            WrapType::Passphrase,
        ),
    ];
    for (name, suite, wrap) in cases {
        let expected = hex::decode(golden[name].as_str().expect("hex")).expect("hex");
        let sealed = seal(
            &params(suite),
            seal_key(&keys, wrap),
            PLAINTEXT,
            &mut FixedRng,
        )
        .expect("seal");
        assert_eq!(sealed.to_bytes(), expected, "{name}");
        assert_eq!(
            open_bytes(&expected, open_key(&keys, wrap), &policy()).expect("opens"),
            PLAINTEXT,
            "{name}"
        );
    }
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

#[test]
fn the_recipient_x25519_public_key_bytes_are_bound_into_the_combiner() {
    // X25519 ignores the top bit of the u-coordinate (RFC 7748), so this alias gives the
    // same shared secret while its bytes differ. Only the combiner's binding of the
    // serialized recipient key can make the capsule fail for the real recipient.
    let keys = keys();
    let mut alias = keys.hybrid.public_key().to_bytes();
    alias[HYBRID_PUBLIC_KEY_LEN - 1] |= 0x80;
    let real_x: [u8; 32] = keys.hybrid.public_key().to_bytes()[HYBRID_PUBLIC_KEY_LEN - 32..]
        .try_into()
        .expect("32");
    let alias_x: [u8; 32] = alias[HYBRID_PUBLIC_KEY_LEN - 32..].try_into().expect("32");
    assert_eq!(
        x25519_dalek::x25519([5; 32], real_x),
        x25519_dalek::x25519([5; 32], alias_x)
    );
    let alias = HybridPublicKey::from_bytes(&alias).expect("valid encoding");
    let key = SealKey::Hybrid {
        recipient: &alias,
        kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
    };
    let env = seal(
        &params(SuiteId::XCHACHA20POLY1305_V1),
        key,
        PLAINTEXT,
        &mut rng(),
    )
    .expect("seal");
    assert_eq!(
        env.open(OpenKey::Hybrid(&keys.hybrid), &policy())
            .map(|p| p.to_vec()),
        Err(Error::OpenFailed)
    );
}
