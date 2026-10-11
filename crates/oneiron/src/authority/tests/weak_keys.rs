//! A small-order Ed25519 key has no authority (engine-crates-04). Under the
//! identity point, R = B and S = 1 verify every message with a cofactorless
//! check, so the forgery needs no secret at all.
use super::*;

/// The identity point, compressed: y = 1.
fn identity_point() -> [u8; 32] {
    let mut key = [0; 32];
    key[0] = 1;
    key
}

/// R = the base point, S = 1: valid for every message under the identity key
/// when the check is not strict.
fn forged_signature() -> [u8; 64] {
    // The base point, compressed (RFC 8032 §5.1): 0x58 then 0x66 × 31.
    let mut signature = [0x66; 64];
    signature[0] = 0x58;
    signature[32..].fill(0);
    signature[32] = 1;
    signature
}

#[test]
fn a_forged_signature_under_a_small_order_key_never_verifies() {
    let signature = AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: AuthorityKey::Ed25519(identity_point()),
        signature: forged_signature().to_vec(),
    };
    assert!(signature.public_key.validate().is_err());
    assert!(!verify_authority_signature(&signature, b"any transcript"));
    assert!(!verify_authority_signature(&signature, b"another transcript"));
}

#[test]
fn a_host_refuses_to_enroll_a_small_order_machine_key() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let machine = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&machine, crate::registry::ENTITY_TYPE_MACHINE, at, 1, b"machine")
        .unwrap();
    let issuer = HostSlipIssuer::from_secret(b"weak key host root").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    assert!(
        vault
            .enroll_machine_identity(&issuer, machine, identity_point(), [17; 32], |_| {
                Ok(forged_signature())
            })
            .is_err(),
        "a key whose signatures anyone can forge is never enrolled"
    );
    let fold = vault.authority_fold().unwrap();
    assert!(
        !fold
            .actor_bindings
            .contains_key(&AuthorityKey::Ed25519(identity_point()))
    );
}
