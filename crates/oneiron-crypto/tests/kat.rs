//! Published known-answer vectors for every primitive the crate uses, run against the
//! exact pinned crates. Sources (with ACVP tgId/tcId) are recorded in
//! `tests/vectors/kat.json` next to each vector.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::Signer as _;
use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::{Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport};
use serde_json::Value;
use sha2::Sha256;
use slh_dsa::Sha2_256s;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/kat.json")).expect("kat.json parses")
}

fn hex_field(v: &Value, name: &str, field: &str) -> Vec<u8> {
    hex::decode(v[name][field].as_str().expect("hex field")).expect("valid hex")
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

#[test]
fn x25519_rfc7748() {
    let v = vectors();
    for name in ["x25519_rfc7748_s5_2_a", "x25519_rfc7748_s5_2_b"] {
        let out = x25519_dalek::x25519(
            arr32(&hex_field(&v, name, "scalar")),
            arr32(&hex_field(&v, name, "u")),
        );
        assert_eq!(out.to_vec(), hex_field(&v, name, "out"), "{name}");
    }
    let n = "x25519_rfc7748_s6_1";
    let alice = x25519_dalek::StaticSecret::from(arr32(&hex_field(&v, n, "alice_priv")));
    let bob = x25519_dalek::StaticSecret::from(arr32(&hex_field(&v, n, "bob_priv")));
    let alice_pub = x25519_dalek::PublicKey::from(&alice);
    let bob_pub = x25519_dalek::PublicKey::from(&bob);
    assert_eq!(alice_pub.as_bytes().to_vec(), hex_field(&v, n, "alice_pub"));
    assert_eq!(bob_pub.as_bytes().to_vec(), hex_field(&v, n, "bob_pub"));
    assert_eq!(
        alice.diffie_hellman(&bob_pub).as_bytes().to_vec(),
        hex_field(&v, n, "shared")
    );
    assert_eq!(
        bob.diffie_hellman(&alice_pub).as_bytes().to_vec(),
        hex_field(&v, n, "shared")
    );
}

#[test]
fn hkdf_sha256_rfc5869() {
    let v = vectors();
    for name in [
        "hkdf_sha256_rfc5869_a1",
        "hkdf_sha256_rfc5869_a2",
        "hkdf_sha256_rfc5869_a3",
    ] {
        let salt = hex_field(&v, name, "salt");
        let ikm = hex_field(&v, name, "ikm");
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(prk.to_vec(), hex_field(&v, name, "prk"), "{name} prk");
        let mut okm = vec![0u8; usize::try_from(v[name]["l"].as_u64().expect("l")).expect("usize")];
        hk.expand(&hex_field(&v, name, "info"), &mut okm)
            .expect("expand");
        assert_eq!(okm, hex_field(&v, name, "okm"), "{name} okm");
    }
}

#[test]
fn argon2id_rfc9106() {
    use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
    let v = vectors();
    let n = "argon2id_rfc9106_s5_3";
    let ad = hex_field(&v, n, "ad");
    let secret = hex_field(&v, n, "secret");
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(AssociatedData::new(&ad).expect("ad"))
        .output_len(32)
        .build()
        .expect("params");
    let argon = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("argon2");
    let mut tag = [0u8; 32];
    argon
        .hash_password_into(
            &hex_field(&v, n, "password"),
            &hex_field(&v, n, "salt"),
            &mut tag,
        )
        .expect("hash");
    assert_eq!(tag.to_vec(), hex_field(&v, n, "tag"));
}

#[test]
fn xchacha20poly1305_draft_irtf_cfrg_xchacha_03() {
    let v = vectors();
    let n = "xchacha20poly1305_draft03_a3_1";
    let cipher = XChaCha20Poly1305::new_from_slice(&hex_field(&v, n, "key")).expect("key");
    let nonce = XNonce::try_from(hex_field(&v, n, "iv").as_slice()).expect("nonce");
    let aad = hex_field(&v, n, "aad");
    let mut expected = hex_field(&v, n, "ciphertext");
    expected.extend(hex_field(&v, n, "tag"));
    let pt = hex_field(&v, n, "plaintext");
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .expect("encrypt");
    assert_eq!(ct, expected);
    assert_eq!(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ct,
                    aad: &aad
                }
            )
            .expect("decrypt"),
        pt
    );
}

#[test]
fn aes256gcm_wycheproof() {
    let v = vectors();
    for name in ["aes256gcm_wycheproof_91", "aes256gcm_wycheproof_101"] {
        let cipher = Aes256Gcm::new_from_slice(&hex_field(&v, name, "key")).expect("key");
        let nonce =
            aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(hex_field(&v, name, "iv").as_slice())
                .expect("nonce");
        let aad = hex_field(&v, name, "aad");
        let pt = hex_field(&v, name, "plaintext");
        let mut expected = hex_field(&v, name, "ciphertext");
        expected.extend(hex_field(&v, name, "tag"));
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &pt,
                    aad: &aad,
                },
            )
            .expect("encrypt");
        assert_eq!(ct, expected, "{name}");
        assert_eq!(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &ct,
                        aad: &aad
                    }
                )
                .expect("decrypt"),
            pt
        );
    }
}

#[test]
fn ed25519_rfc8032() {
    let v = vectors();
    for name in [
        "ed25519_rfc8032_test1",
        "ed25519_rfc8032_test2",
        "ed25519_rfc8032_test3",
    ] {
        let key = ed25519_dalek::SigningKey::from_bytes(&arr32(&hex_field(&v, name, "secret_key")));
        assert_eq!(
            key.verifying_key().to_bytes().to_vec(),
            hex_field(&v, name, "public_key"),
            "{name}"
        );
        let msg = hex_field(&v, name, "message");
        let sig = key.sign(&msg);
        assert_eq!(
            sig.to_bytes().to_vec(),
            hex_field(&v, name, "signature"),
            "{name}"
        );
        key.verifying_key()
            .verify_strict(&msg, &sig)
            .expect("verifies");
    }
}

#[test]
fn mlkem1024_acvp_keygen_encap_decap() {
    let v = vectors();
    let mut seed = hex_field(&v, "mlkem1024_keygen", "d");
    seed.extend(hex_field(&v, "mlkem1024_keygen", "z"));
    let dk = DecapsulationKey1024::from_seed(Array::try_from(seed.as_slice()).expect("seed"));
    assert_eq!(
        dk.encapsulation_key().to_bytes().to_vec(),
        hex_field(&v, "mlkem1024_keygen", "ek")
    );

    let ek_bytes = hex_field(&v, "mlkem1024_encap", "ek");
    let ek = EncapsulationKey1024::new(&Array::try_from(ek_bytes.as_slice()).expect("ek"))
        .expect("valid ek");
    let m = Array::try_from(hex_field(&v, "mlkem1024_encap", "m").as_slice()).expect("m");
    let (c, k) = ek.encapsulate_deterministic(&m);
    assert_eq!(c.to_vec(), hex_field(&v, "mlkem1024_encap", "c"));
    assert_eq!(k.to_vec(), hex_field(&v, "mlkem1024_encap", "k"));

    let dk_bytes = hex_field(&v, "mlkem1024_decap", "dk");
    #[allow(
        deprecated,
        reason = "ACVP decapsulation vectors carry the expanded key form"
    )]
    let dk =
        DecapsulationKey1024::from_expanded(&Array::try_from(dk_bytes.as_slice()).expect("dk"))
            .expect("valid dk");
    let c =
        ml_kem::ml_kem_1024::Ciphertext::try_from(hex_field(&v, "mlkem1024_decap", "c").as_slice())
            .expect("c");
    assert_eq!(
        dk.decapsulate(&c).to_vec(),
        hex_field(&v, "mlkem1024_decap", "k")
    );
}

#[test]
fn slhdsa_sha2_256s_acvp_keygen() {
    let v = vectors();
    let n = "slhdsa_sha2_256s_keygen";
    let key = slh_dsa::SigningKey::<Sha2_256s>::slh_keygen_internal(
        &hex_field(&v, n, "skSeed"),
        &hex_field(&v, n, "skPrf"),
        &hex_field(&v, n, "pkSeed"),
    );
    assert_eq!(key.to_vec(), hex_field(&v, n, "sk"));
    let vk: &slh_dsa::VerifyingKey<Sha2_256s> = key.as_ref();
    assert_eq!(vk.to_vec(), hex_field(&v, n, "pk"));
}

#[test]
fn slhdsa_sha2_256s_acvp_sigver_and_siggen() {
    let v = vectors();
    let n = "slhdsa_sha2_256s_sigver";
    let vk = slh_dsa::VerifyingKey::<Sha2_256s>::try_from(hex_field(&v, n, "pk").as_slice())
        .expect("pk");
    let sig = slh_dsa::Signature::<Sha2_256s>::try_from(hex_field(&v, n, "signature").as_slice())
        .expect("sig");
    let mut msg = hex_field(&v, n, "message");
    let ctx = hex_field(&v, n, "context");
    vk.try_verify_with_context(&msg, &ctx, &sig)
        .expect("published signature verifies");
    msg[0] ^= 1;
    assert!(
        vk.try_verify_with_context(&msg, &ctx, &sig).is_err(),
        "a changed message must not verify"
    );

    let n = "slhdsa_sha2_256s_siggen";
    let sk =
        slh_dsa::SigningKey::<Sha2_256s>::try_from(hex_field(&v, n, "sk").as_slice()).expect("sk");
    let sig = sk
        .try_sign_with_context(
            &hex_field(&v, n, "message"),
            &hex_field(&v, n, "context"),
            None,
        )
        .expect("sign");
    assert_eq!(sig.to_vec(), hex_field(&v, n, "signature"));
}
