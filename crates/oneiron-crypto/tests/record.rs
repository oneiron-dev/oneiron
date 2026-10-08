//! Signature-record contract: single and dual signatures, the roster rule, the signed
//! transcript, fail-closed parsing, and checkpoint references that never verify.

use oneiron_crypto::{
    CheckpointRef, Error, RecordBody, SigPurpose, SignatureRecord, SigningKey, SuiteId,
    VerifyPolicy, VerifyingKey, sign,
};

const SIGNER: &[u8] = b"root-1";
const SUBJECT: &[u8] = b"release manifest v1: sha256 of artifacts";
const ED_ID: &[u8] = b"ed-1";
const SLH_ID: &[u8] = b"slh-1";
const DUAL: SuiteId = SuiteId::SIG_DUAL_ED25519_SLHDSA_SHA2_256S_V1;
const ED: SuiteId = SuiteId::SIG_ED25519_V1;
const SLH: SuiteId = SuiteId::SIG_SLHDSA_SHA2_256S_V1;

struct Keys {
    ed: SigningKey,
    slh: SigningKey,
    ed_vk: VerifyingKey,
    slh_vk: VerifyingKey,
}

fn keys() -> Keys {
    let ed = SigningKey::generate_ed25519(&mut getrandom::SysRng).expect("ed25519");
    let slh = SigningKey::generate_slhdsa_sha2_256s(&mut getrandom::SysRng).expect("slh-dsa");
    let (ed_vk, slh_vk) = (ed.verifying_key(), slh.verifying_key());
    Keys {
        ed,
        slh,
        ed_vk,
        slh_vk,
    }
}

fn policy(suite: SuiteId) -> VerifyPolicy<'static> {
    VerifyPolicy {
        suite,
        purpose: SigPurpose::ReleaseManifest,
        signer: SIGNER,
        min_epoch: 1,
    }
}

fn sign_with(keys: &Keys, suite: SuiteId) -> SignatureRecord {
    sign(
        suite,
        SigPurpose::ReleaseManifest,
        2,
        SIGNER,
        SUBJECT,
        &[(ED_ID, &keys.ed), (SLH_ID, &keys.slh)],
        &mut getrandom::SysRng,
    )
    .expect("sign")
}

fn verifying<'a>(keys: &'a Keys) -> [(&'static [u8], &'a VerifyingKey); 2] {
    [(ED_ID, &keys.ed_vk), (SLH_ID, &keys.slh_vk)]
}

/// Offset of the body tag: magic 4, version 2, suite 2, purpose 2, epoch 8, signer lp8.
fn body_at() -> usize {
    4 + 2 + 2 + 2 + 8 + 1 + SIGNER.len()
}

/// Length of one encoded entry: suite 2, key id lp8, length 4, signature.
fn entry_len(key_id: &[u8], sig_len: usize) -> usize {
    2 + 1 + key_id.len() + 4 + sig_len
}

#[test]
fn single_and_dual_records_round_trip_and_verify() {
    let keys = keys();
    for suite in [ED, SLH, DUAL] {
        let record = sign_with(&keys, suite);
        let bytes = record.to_bytes();
        let parsed = SignatureRecord::parse(&bytes).expect("parses");
        assert_eq!(parsed, record);
        assert_eq!(parsed.to_bytes(), bytes, "canonical");
        parsed
            .verify(SUBJECT, &policy(suite), &verifying(&keys))
            .expect("verifies");
        assert_eq!(
            parsed.verify(b"another subject", &policy(suite), &verifying(&keys)),
            Err(Error::SignatureInvalid(if suite == SLH {
                "sig-slhdsa-sha2-256s-v1"
            } else {
                "sig-ed25519-v1"
            }))
        );
    }
}

#[test]
fn a_dual_record_with_one_signature_stripped_is_refused() {
    let keys = keys();
    let bytes = sign_with(&keys, DUAL).to_bytes();
    let count_at = body_at() + 1;
    let ed_entry = entry_len(ED_ID, 64);

    let mut no_slh = bytes[..count_at + 1 + ed_entry].to_vec();
    no_slh[count_at] = 1;
    assert_eq!(
        SignatureRecord::parse(&no_slh),
        Err(Error::SignatureMissing("sig-slhdsa-sha2-256s-v1"))
    );

    let mut no_ed = bytes[..count_at + 1].to_vec();
    no_ed.extend_from_slice(&bytes[count_at + 1 + ed_entry..]);
    no_ed[count_at] = 1;
    assert_eq!(
        SignatureRecord::parse(&no_ed),
        Err(Error::SignatureMissing("sig-ed25519-v1"))
    );

    // Relabelled to the single Ed25519 suite as well: it parses, but a verifier that
    // requires the dual policy refuses it, and the signature no longer verifies under
    // the single policy because the suite and roster are signed.
    let mut relabelled = no_slh.clone();
    relabelled[6..8].copy_from_slice(&ED.0.to_be_bytes());
    let record = SignatureRecord::parse(&relabelled).expect("structurally a single record");
    assert_eq!(
        record.verify(SUBJECT, &policy(DUAL), &verifying(&keys)),
        Err(Error::SuiteNotAccepted("sig-ed25519-v1"))
    );
    assert_eq!(
        record.verify(SUBJECT, &policy(ED), &verifying(&keys)),
        Err(Error::SignatureInvalid("sig-ed25519-v1"))
    );
}

#[test]
fn the_roster_must_be_exact_and_ordered() {
    let keys = keys();
    let ed = sign_with(&keys, ED).to_bytes();
    let dual = sign_with(&keys, DUAL).to_bytes();
    let count_at = body_at() + 1;
    let ed_entry = &ed[count_at + 1..];
    let slh_entry = &dual[count_at + 1 + entry_len(ED_ID, 64)..];

    let mut dup = ed.clone();
    dup[count_at] = 2;
    dup.extend_from_slice(ed_entry);
    assert_eq!(
        SignatureRecord::parse(&dup),
        Err(Error::SignatureDuplicate("sig-ed25519-v1"))
    );

    let mut unsorted = dual[..count_at + 1].to_vec();
    unsorted.extend_from_slice(slh_entry);
    unsorted.extend_from_slice(&dual[count_at + 1..count_at + 1 + entry_len(ED_ID, 64)]);
    assert_eq!(
        SignatureRecord::parse(&unsorted),
        Err(Error::UnsortedSignatures)
    );

    let mut extra = ed.clone();
    extra[count_at] = 2;
    extra.extend_from_slice(slh_entry);
    assert_eq!(
        SignatureRecord::parse(&extra),
        Err(Error::SignatureUnexpected("sig-slhdsa-sha2-256s-v1"))
    );

    let missing_key = sign(
        DUAL,
        SigPurpose::ReleaseManifest,
        2,
        SIGNER,
        SUBJECT,
        &[(ED_ID, &keys.ed)],
        &mut getrandom::SysRng,
    );
    assert_eq!(
        missing_key.err(),
        Some(Error::SigningKeyMissing("sig-slhdsa-sha2-256s-v1"))
    );
}

#[test]
fn component_key_ids_and_policy_fields_are_enforced() {
    let keys = keys();
    let record = sign_with(&keys, ED);
    let vks = verifying(&keys);
    assert_eq!(
        record.verify(
            SUBJECT,
            &VerifyPolicy {
                purpose: SigPurpose::RootDelegation,
                ..policy(ED)
            },
            &vks
        ),
        Err(Error::SigPurposeMismatch {
            expected: SigPurpose::RootDelegation,
            found: SigPurpose::ReleaseManifest
        })
    );
    assert_eq!(
        record.verify(
            SUBJECT,
            &VerifyPolicy {
                signer: b"root-2",
                ..policy(ED)
            },
            &vks
        ),
        Err(Error::SignerMismatch)
    );
    assert_eq!(
        record.verify(
            SUBJECT,
            &VerifyPolicy {
                min_epoch: 3,
                ..policy(ED)
            },
            &vks
        ),
        Err(Error::EpochBelowPolicyMinimum { epoch: 2, min: 3 })
    );
    assert_eq!(
        record.verify(SUBJECT, &policy(ED), &[(SLH_ID, &keys.slh_vk)]),
        Err(Error::VerifyingKeyMissing("sig-ed25519-v1"))
    );
    // Another Ed25519 key under the right id does not verify.
    let other = SigningKey::generate_ed25519(&mut getrandom::SysRng)
        .expect("key")
        .verifying_key();
    assert_eq!(
        record.verify(SUBJECT, &policy(ED), &[(ED_ID, &other)]),
        Err(Error::SignatureInvalid("sig-ed25519-v1"))
    );

    // A component key id is signed: renaming it breaks the signature even when the
    // verifier maps the new name to the right key.
    let mut bytes = record.to_bytes();
    let key_id_at = body_at() + 2 + 2 + 1;
    bytes[key_id_at] = b'E';
    let renamed = SignatureRecord::parse(&bytes).expect("parses");
    assert_eq!(
        renamed.verify(SUBJECT, &policy(ED), &[(b"Ed-1".as_slice(), &keys.ed_vk)]),
        Err(Error::SignatureInvalid("sig-ed25519-v1"))
    );
}

#[test]
fn record_parsing_fails_closed() {
    let keys = keys();
    let bytes = sign_with(&keys, ED).to_bytes();
    let with = |at: usize, new: &[u8]| {
        let mut b = bytes.clone();
        b[at..at + new.len()].copy_from_slice(new);
        SignatureRecord::parse(&b)
    };
    assert_eq!(
        with(0, b"X"),
        Err(Error::BadMagic {
            expected: "signature record"
        })
    );
    assert_eq!(
        with(4, &2u16.to_be_bytes()),
        Err(Error::UnsupportedVersion(2))
    );
    assert_eq!(
        with(6, &0x7777u16.to_be_bytes()),
        Err(Error::UnknownSuite(0x7777))
    );
    assert!(matches!(
        with(6, &0x0101u16.to_be_bytes()),
        Err(Error::WrongSuiteKind { .. })
    ));
    assert_eq!(
        with(8, &99u16.to_be_bytes()),
        Err(Error::UnknownSigPurpose(99))
    );
    assert!(matches!(
        with(10, &0u64.to_be_bytes()),
        Err(Error::EpochBelowSuiteMinimum { epoch: 0, .. })
    ));
    assert_eq!(with(body_at(), &[7]), Err(Error::UnknownBody(7)));
    assert!(matches!(
        with(body_at() + 1, &[0]),
        Err(Error::FieldLength {
            field: "signatures",
            ..
        })
    ));
    // Signature lengths are exact per suite.
    let len_at = body_at() + 2 + 2 + 1 + ED_ID.len();
    assert!(matches!(
        with(len_at, &63u32.to_be_bytes()),
        Err(Error::FieldLength {
            field: "signature",
            ..
        })
    ));
    // An entry naming a dual policy is not a signature suite.
    assert!(matches!(
        with(body_at() + 2, &DUAL.0.to_be_bytes()),
        Err(Error::WrongSuiteKind { .. })
    ));
    for cut in 0..bytes.len() {
        assert!(
            SignatureRecord::parse(&bytes[..cut]).is_err(),
            "truncated at {cut}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        SignatureRecord::parse(&long),
        Err(Error::TrailingBytes { extra: 1 })
    );
}

#[test]
fn checkpoint_references_parse_but_never_verify() {
    let keys = keys();
    let cref = CheckpointRef {
        checkpoint_epoch: 9,
        tree_size: 8,
        leaf_index: 5,
        root: [1; 32],
        proof: vec![[2; 32]; 3],
    };
    let record = SignatureRecord::checkpoint_ref(SLH, SigPurpose::Receipt, 2, SIGNER, cref.clone())
        .expect("record");
    let parsed = SignatureRecord::parse(&record.to_bytes()).expect("parses");
    assert_eq!(parsed.body(), &RecordBody::Checkpoint(cref.clone()));
    let p = VerifyPolicy {
        purpose: SigPurpose::Receipt,
        ..policy(SLH)
    };
    assert_eq!(
        parsed.verify(SUBJECT, &p, &verifying(&keys)),
        Err(Error::CheckpointRefUnverified)
    );

    let bad = CheckpointRef {
        leaf_index: 8,
        ..cref.clone()
    };
    assert_eq!(
        SignatureRecord::checkpoint_ref(SLH, SigPurpose::Receipt, 2, SIGNER, bad).err(),
        Some(Error::CheckpointIndexOutOfRange {
            leaf_index: 8,
            tree_size: 8
        })
    );
    let long = CheckpointRef {
        proof: vec![[0; 32]; 65],
        ..cref
    };
    assert!(matches!(
        SignatureRecord::checkpoint_ref(SLH, SigPurpose::Receipt, 2, SIGNER, long),
        Err(Error::FieldLength {
            field: "inclusion proof",
            ..
        })
    ));
}

#[test]
fn verifying_keys_parse_per_suite() {
    let keys = keys();
    let VerifyingKey::Ed25519(ed) = &keys.ed_vk else {
        panic!("ed25519 key")
    };
    assert_eq!(
        VerifyingKey::from_bytes(ED, &ed.to_bytes()).expect("ed25519"),
        keys.ed_vk
    );
    assert!(matches!(
        VerifyingKey::from_bytes(ED, &[0; 31]),
        Err(Error::FieldLength { .. })
    ));
    assert!(matches!(
        VerifyingKey::from_bytes(DUAL, &[0; 32]),
        Err(Error::WrongSuiteKind { .. })
    ));
    assert_eq!(
        VerifyingKey::from_bytes(SuiteId(0x7777), &[0; 32]),
        Err(Error::UnknownSuite(0x7777))
    );
}
