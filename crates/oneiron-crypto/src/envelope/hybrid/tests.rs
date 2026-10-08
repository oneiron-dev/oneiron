//! Every combiner input reaches the output: changing any one of them alone changes
//! the wrap secret (the transcript binding the hybrid acceptance asks for).

use super::combine;
use crate::keys::{HybridSecretKey, MLKEM1024_CIPHERTEXT_LEN};

#[test]
fn changing_any_single_combiner_input_changes_the_wrap_secret() {
    let recipient = HybridSecretKey::from_seeds(&[4; 64], &[5; 32]);
    let other_mlkem = HybridSecretKey::from_seeds(&[8; 64], &[5; 32]);
    let other_x25519 = HybridSecretKey::from_seeds(&[4; 64], &[6; 32]);
    assert_eq!(
        recipient.public_key().x25519().as_bytes(),
        other_mlkem.public_key().x25519().as_bytes()
    );
    assert_eq!(
        recipient.public_key().mlkem_bytes(),
        other_x25519.public_key().mlkem_bytes()
    );

    let (ss_m, ss_x, ct_m, ct_x) = (
        [1u8; 32],
        [2u8; 32],
        [3u8; MLKEM1024_CIPHERTEXT_LEN],
        [4u8; 32],
    );
    let base = combine(&ss_m, &ss_x, &ct_m, &ct_x, recipient.public_key());
    let flip = |mut bytes: Vec<u8>| {
        bytes[0] ^= 1;
        bytes
    };
    let ss_m2 = flip(ss_m.to_vec());
    let ss_x2: [u8; 32] = flip(ss_x.to_vec()).try_into().expect("32");
    let ct_m2: [u8; MLKEM1024_CIPHERTEXT_LEN] = flip(ct_m.to_vec()).try_into().expect("1568");
    let ct_x2: [u8; 32] = flip(ct_x.to_vec()).try_into().expect("32");
    let variants = [
        (
            "ss_mlkem",
            combine(&ss_m2, &ss_x, &ct_m, &ct_x, recipient.public_key()),
        ),
        (
            "ss_x25519",
            combine(&ss_m, &ss_x2, &ct_m, &ct_x, recipient.public_key()),
        ),
        (
            "ct_mlkem",
            combine(&ss_m, &ss_x, &ct_m2, &ct_x, recipient.public_key()),
        ),
        (
            "ct_x25519",
            combine(&ss_m, &ss_x, &ct_m, &ct_x2, recipient.public_key()),
        ),
        (
            "ek_mlkem",
            combine(&ss_m, &ss_x, &ct_m, &ct_x, other_mlkem.public_key()),
        ),
        (
            "pk_x25519",
            combine(&ss_m, &ss_x, &ct_m, &ct_x, other_x25519.public_key()),
        ),
    ];
    for (input, secret) in variants {
        assert_ne!(*secret, *base, "{input} does not reach the wrap secret");
    }
}
