//! Checkpoint signatures, replay equivalence and chain linkage.
use super::support::*;
use super::*;
use crate::{TimeRange, Vault, VaultConfig};

#[test]
fn quorum_checkpoint_roundtrip_matches_replay_and_rejects_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let root = ed_key(151);
    let peer = ed_key(152);
    let root_key = authority_key_from_ed(&root);
    let peer_key = authority_key_from_ed(&peer);
    let mut genesis = genesis_entry(151, DEFAULT_PENDING_WIDEN_DELAY_SECS, 1);
    if let AuthorityOp::Genesis { device, .. } = &mut genesis.op {
        device.tier = AuthorityTier::Hardware;
    }
    genesis = sign_ed(genesis, &root);
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    let first = vault
        .write_authority_checkpoint(vec![root_key.clone()], |_, bytes| {
            Ok(root.sign(bytes).to_bytes().to_vec())
        })
        .unwrap();
    let first_hash = authority_checkpoint_hash(&first).unwrap();
    let enroll = enroll_device_entry(
        genesis_vault_id(&genesis).unwrap(),
        &genesis,
        &root,
        EnrollSpec {
            seed: 152,
            roles: ROLE_AGENT,
            tier: AuthorityTier::Software,
            seq: 1,
            ts: 2,
        },
    );
    vault
        .put_authority_log_entry(&enroll, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();
    assert!(
        vault
            .write_authority_checkpoint(vec![root_key.clone()], |_, bytes| Ok(root
                .sign(bytes)
                .to_bytes()
                .to_vec()))
            .is_err()
    );
    let checkpoint = vault
        .write_authority_checkpoint(vec![root_key.clone(), peer_key], |key, bytes| {
            Ok(if key == &root_key {
                root.sign(bytes).to_bytes().to_vec()
            } else {
                peer.sign(bytes).to_bytes().to_vec()
            })
        })
        .unwrap();
    assert_eq!(checkpoint.parent_hashes, vec![first_hash]);
    assert_eq!(checkpoint.roster, vault.authority_fold().unwrap().roster);
    let bytes = encode_authority_checkpoint(&checkpoint).unwrap();
    let decoded = decode_authority_checkpoint(&bytes).unwrap();
    assert_eq!(decoded, checkpoint);
    vault.verify_authority_checkpoint(&decoded).unwrap();
    let hash = authority_checkpoint_hash(&decoded).unwrap();
    assert_eq!(
        vault.read_authority_checkpoint(&hash).unwrap(),
        Some(decoded)
    );
    let mut bad = checkpoint.clone();
    bad.horizon += 1;
    assert!(vault.verify_authority_checkpoint(&bad).is_err());
    let mut bad = checkpoint.clone();
    bad.signatures[0].signature[0] ^= 1;
    assert!(vault.verify_authority_checkpoint(&bad).is_err());
    let mut bad = checkpoint;
    bad.parent_hashes = vec![[0xAA; 32]];
    let transcript = authority_checkpoint_transcript(&bad).unwrap();
    for signature in &mut bad.signatures {
        signature.signature = if signature.public_key == root_key {
            root.sign(&transcript).to_bytes().to_vec()
        } else {
            peer.sign(&transcript).to_bytes().to_vec()
        };
    }
    assert!(vault.verify_authority_checkpoint(&bad).is_err());
    assert!(
        vault
            .read_authority_checkpoint(&first_hash)
            .unwrap()
            .is_some()
    );
}
