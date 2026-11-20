//! The carrier signature of a row act (`oneiron_authority::authority::CarrierSignature`,
//! Fable pass 28 DESIGN 3.4): the one transcript a carrier signs, and the one check of it.
//! A changed byte of any part the transcript names makes the signature stand for nothing.

use ed25519_dalek::{Signer, SigningKey};
use oneiron_authority::authority::{
    AuthorityVaultId, CARRIER_TRANSCRIPT_TAG, CarrierSignature, carrier_signature_verifies,
    carrier_transcript,
};
use oneiron_contracts::EntityId;

const DOMAIN: &[u8] = b"oneiron/test-row-act/v1";
const VAULT: AuthorityVaultId = [7; 32];
const BODY: &[u8] = b"canonical row body without its carrier signature";

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes_unchecked([byte; 16])
}

fn carrier(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// `key`'s carrier signature for machine `machine` over the test row.
fn signed(key: &SigningKey, machine: EntityId, row: EntityId) -> CarrierSignature {
    let transcript = carrier_transcript(DOMAIN, &VAULT, &row, &machine, BODY);
    CarrierSignature {
        machine,
        key: key.verifying_key().to_bytes(),
        signature: key.sign(&transcript).to_bytes(),
    }
}

#[test]
fn the_transcript_is_tag_domain_vault_row_machine_and_body_digest() {
    let (row, machine) = (id(1), id(2));
    let mut expected = CARRIER_TRANSCRIPT_TAG.to_vec();
    expected.extend_from_slice(DOMAIN);
    expected.extend_from_slice(&VAULT);
    expected.extend_from_slice(row.as_bytes());
    expected.extend_from_slice(machine.as_bytes());
    expected.extend_from_slice(blake3::hash(BODY).as_bytes());
    assert_eq!(
        carrier_transcript(DOMAIN, &VAULT, &row, &machine, BODY),
        expected,
        "a changed layout changes every stored carrier signature"
    );
    assert_eq!(CARRIER_TRANSCRIPT_TAG, b"oneiron/carrier-act/v1");
}

#[test]
fn a_carrier_signature_verifies_only_over_the_exact_row_it_signed() {
    let key = carrier(3);
    let (row, machine) = (id(1), id(2));
    let signature = signed(&key, machine, row);
    assert!(carrier_signature_verifies(
        &signature, DOMAIN, &VAULT, &row, BODY
    ));

    let other_vault: AuthorityVaultId = [8; 32];
    let cases: [(&str, &[u8], &AuthorityVaultId, EntityId, &[u8]); 4] = [
        (
            "another row kind",
            b"oneiron/test-row-act/v2",
            &VAULT,
            row,
            BODY,
        ),
        ("another vault", DOMAIN, &other_vault, row, BODY),
        ("another row", DOMAIN, &VAULT, id(9), BODY),
        (
            "another body",
            DOMAIN,
            &VAULT,
            row,
            b"canonical row body, edited",
        ),
    ];
    for (case, domain, vault, row, body) in cases {
        assert!(
            !carrier_signature_verifies(&signature, domain, vault, &row, body),
            "{case}: the signature stands for nothing"
        );
    }
}

#[test]
fn a_signature_relabelled_to_another_machine_or_key_stands_for_nothing() {
    let (row, machine) = (id(1), id(2));
    let signature = signed(&carrier(3), machine, row);

    let relabelled = CarrierSignature {
        machine: id(4),
        ..signature
    };
    assert!(!carrier_signature_verifies(
        &relabelled,
        DOMAIN,
        &VAULT,
        &row,
        BODY
    ));

    let other_key = CarrierSignature {
        key: carrier(5).verifying_key().to_bytes(),
        ..signature
    };
    assert!(!carrier_signature_verifies(
        &other_key, DOMAIN, &VAULT, &row, BODY
    ));

    let mut flipped = signature;
    flipped.signature[0] ^= 1;
    assert!(!carrier_signature_verifies(
        &flipped, DOMAIN, &VAULT, &row, BODY
    ));
}

#[test]
fn a_small_order_key_never_verifies() {
    // The identity point with R = identity and S = 0 satisfies the plain Ed25519 equation for
    // every message; a weak key must never carry an act.
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    let mut forged = [0_u8; 64];
    forged[0] = 1;
    let signature = CarrierSignature {
        machine: id(2),
        key: identity,
        signature: forged,
    };
    assert!(!carrier_signature_verifies(
        &signature,
        DOMAIN,
        &VAULT,
        &id(1),
        BODY
    ));
}

#[test]
fn a_domain_boundary_moved_by_a_byte_gives_another_transcript() {
    let (row, machine) = (id(1), id(2));
    let short = carrier_transcript(b"oneiron/a", &VAULT, &row, &machine, BODY);
    let long = carrier_transcript(b"oneiron/a\x07", &VAULT, &row, &machine, BODY);
    assert_ne!(short, long);
    assert_eq!(
        long.len(),
        short.len() + 1,
        "every part after the domain has a fixed length"
    );
}
