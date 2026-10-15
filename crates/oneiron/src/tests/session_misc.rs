//! Session/context-board serialization, basic entity CRUD, short-ID alias and vault identity.

use super::*;

#[test]
fn encode_edge_key_has_exact_layout() {
    let src = EntityId::from_bytes_unchecked([0x11; 16]);
    let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
    let kind = EdgeKind::DerivedFrom;

    let key = Store::encode_edge_key(&src, kind, &tgt);

    assert_eq!(key.len(), 33);
    assert_eq!(&key[..16], src.as_bytes());
    assert_eq!(key[16], kind as u8);
    assert_eq!(&key[17..], tgt.as_bytes());
}

/// ONE-1930 item 6 is WORDING-ONLY. The vault identity algorithm is untouched:
/// genesis derives its vault id from the same BLAKE3 authority-entry hash, at
/// the same 32-byte width. `vtN` is a slug that resolves to this; it is never
/// an input to it.
#[test]
fn blake3_vault_identity_algorithm_unchanged() -> Result<()> {
    use crate::authority::{
        AUTHORITY_HASH_LEN, AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp,
        AuthoritySignature, AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
        authority_entry_hash, authority_transcript, genesis_vault_id,
    };
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x31; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: AuthorityOp::Genesis {
            device: DeviceAuthority {
                key: key.clone(),
                transport_key_binding: [7; 32],
                attestation: AuthorityAttestation {
                    kind: "SoftwareArgon2id".to_owned(),
                    evidence: vec![1, 2, 3],
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            genesis_nonce: [0x41; 32],
            recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: crate::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    entry.signer.signature = signing
        .sign(&authority_transcript(&entry)?)
        .to_bytes()
        .to_vec();

    let vault_id = genesis_vault_id(&entry)?;
    assert_eq!(
        vault_id,
        authority_entry_hash(&entry)?,
        "genesis_vault_id must remain exactly the authority entry hash"
    );
    assert_eq!(vault_id.len(), AUTHORITY_HASH_LEN);
    assert_eq!(AUTHORITY_HASH_LEN, 32);
    Ok(())
}
