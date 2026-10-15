//! Bounded property fuzzing of both parsers (runs in the normal test gate): random
//! bytes and mutations of valid encodings never panic, and anything that parses
//! re-encodes to exactly its input (one canonical encoding). The coverage-guided
//! cargo-fuzz targets for the same parsers live in `fuzz/`.

use oneiron_crypto::{
    Argon2Cost, Envelope, HybridSecretKey, Kek, Passphrase, Purpose, RecoverySecret, SealKey,
    SealParams, SigPurpose, SignatureRecord, SigningKey, SuiteId, seal, sign,
};
use proptest::prelude::*;

fn envelope_corpus() -> Vec<Vec<u8>> {
    let kek = Kek::from_bytes([1; 32]);
    let pass = Passphrase::new(b"pass phrase").expect("passphrase");
    let rec = RecoverySecret::from_bytes([2; 32]);
    let hybrid = HybridSecretKey::from_seeds(&[3; 64], &[4; 32]);
    let keys = [
        SealKey::SymmetricKek(&kek),
        SealKey::Passphrase {
            passphrase: &pass,
            cost: Argon2Cost {
                m_kib: Argon2Cost::MIN_M_KIB,
                t: 1,
                p: 1,
            },
        },
        SealKey::DeviceKeystore(&kek),
        SealKey::Passkey(&kek),
        SealKey::ShamirRecovery {
            secret: &rec,
            threshold: 2,
            shares: 3,
            share_set_id: [5; 16],
        },
        SealKey::Hybrid {
            recipient: hybrid.public_key(),
            kem_suite: SuiteId::KEM_X25519_MLKEM1024_V1,
        },
    ];
    keys.into_iter()
        .enumerate()
        .map(|(i, key)| {
            let suite = if i % 2 == 0 {
                SuiteId::XCHACHA20POLY1305_V1
            } else {
                SuiteId::AES256GCM_V1
            };
            let params = SealParams {
                suite,
                purpose: Purpose::VaultDek,
                epoch: 1,
                key_id: b"k",
                recipient: b"r",
                vault_id: b"v",
            };
            seal(&params, key, b"payload", &mut getrandom::SysRng)
                .expect("seal")
                .to_bytes()
        })
        .collect()
}

fn record_corpus() -> Vec<Vec<u8>> {
    let ed = SigningKey::generate_ed25519(&mut getrandom::SysRng).expect("ed");
    let slh = SigningKey::generate_slhdsa_sha2_256s(&mut getrandom::SysRng).expect("slh");
    let keys: [(&[u8], &SigningKey); 2] = [(b"e", &ed), (b"s", &slh)];
    [
        SuiteId::SIG_ED25519_V1,
        SuiteId::SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1,
    ]
    .into_iter()
    .map(|suite| {
        sign(
            suite,
            SigPurpose::BatchCheckpoint,
            1,
            b"signer",
            b"subject",
            &keys,
            &mut getrandom::SysRng,
        )
        .expect("sign")
        .to_bytes()
    })
    .collect()
}

#[derive(Debug, Clone)]
enum Mutation {
    Flip { at: usize, bit: u8 },
    Set { at: usize, value: u8 },
    Truncate { at: usize },
    Insert { at: usize, value: u8 },
    Remove { at: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 0u8..8).prop_map(|(at, bit)| Mutation::Flip { at, bit }),
        (any::<usize>(), any::<u8>()).prop_map(|(at, value)| Mutation::Set { at, value }),
        any::<usize>().prop_map(|at| Mutation::Truncate { at }),
        (any::<usize>(), any::<u8>()).prop_map(|(at, value)| Mutation::Insert { at, value }),
        any::<usize>().prop_map(|at| Mutation::Remove { at }),
    ]
}

fn apply(bytes: &[u8], mutations: &[Mutation]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    for m in mutations {
        if b.is_empty() {
            break;
        }
        let n = b.len();
        match *m {
            Mutation::Flip { at, bit } => b[at % n] ^= 1 << bit,
            Mutation::Set { at, value } => b[at % n] = value,
            Mutation::Truncate { at } => b.truncate(at % n),
            Mutation::Insert { at, value } => b.insert(at % (n + 1), value),
            Mutation::Remove { at } => {
                b.remove(at % n);
            }
        }
    }
    b
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4096, ..ProptestConfig::default() })]

    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(env) = Envelope::parse(&bytes) {
            prop_assert_eq!(env.to_bytes(), bytes.clone());
        }
        if let Ok(record) = SignatureRecord::parse(&bytes) {
            prop_assert_eq!(record.to_bytes(), bytes);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn mutated_envelopes_never_panic_and_stay_canonical(
        which in 0usize..6,
        mutations in proptest::collection::vec(mutation(), 1..4),
    ) {
        let corpus = envelope_corpus_cached();
        let bytes = apply(&corpus[which], &mutations);
        if let Ok(env) = Envelope::parse(&bytes) {
            prop_assert_eq!(env.to_bytes(), bytes);
        }
    }

    #[test]
    fn mutated_records_never_panic_and_stay_canonical(
        which in 0usize..2,
        mutations in proptest::collection::vec(mutation(), 1..4),
    ) {
        let corpus = record_corpus_cached();
        let bytes = apply(&corpus[which], &mutations);
        if let Ok(record) = SignatureRecord::parse(&bytes) {
            prop_assert_eq!(record.to_bytes(), bytes);
        }
    }
}

fn envelope_corpus_cached() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(envelope_corpus)
}

fn record_corpus_cached() -> &'static [Vec<u8>] {
    static CORPUS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(record_corpus)
}
