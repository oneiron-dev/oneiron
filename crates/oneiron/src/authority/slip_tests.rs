//! Caller-observable slip, pairing and residue regressions.
use super::*;
use crate::authority::*;
use crate::federation::{ScopeAxis, ScopeId};
use crate::{Vault, VaultConfig};
use ed25519_dalek::{Signer, SigningKey};

const SECRET: &[u8] = b"test retained host root secret";
fn fixture() -> (tempfile::TempDir, Vault, HostSlipIssuer, CapabilitySlip) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    (dir, vault, issuer, root)
}
fn verify(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    slip: &CapabilitySlip,
) -> crate::Result<VerifiedSlip> {
    let proof = issuer.binding_proof(slip, b"request-1").unwrap();
    vault.verify_capability_slip(issuer, slip, b"request-1", &proof)
}
#[test]
fn bootstrap_commits_genesis_and_slip_mint_and_reuses_one_root() {
    let (_dir, vault, issuer, root) = fixture();
    let fold = vault.authority_fold().unwrap();
    assert!(verify(&vault, &issuer, &root).unwrap().allows_verb("read"));
    assert_eq!(fold.valid_entries.len(), 2);
    assert_eq!(fold.slips.mints.len(), 1);
    assert!(!fold.genesis_fragile);
    assert_eq!(vault.ensure_host_root_slip(&issuer).unwrap(), root);
    assert_eq!(vault.authority_fold().unwrap().valid_entries.len(), 2);
}
#[test]
fn v2_roundtrip_tamper_and_missing_binding_deny() {
    let (_dir, vault, issuer, root) = fixture();
    let decoded = CapabilitySlip::from_token(&root.to_token().unwrap()).unwrap();
    assert_eq!(decoded, root);
    assert!(
        vault
            .verify_capability_slip(&issuer, &root, b"request-1", &[])
            .is_err()
    );
    let mut tampered = root.clone();
    tampered.claims.expires_at += 1;
    assert!(verify(&vault, &issuer, &tampered).is_err());
    let mut wire: serde_json::Value = serde_json::to_value(&root).unwrap();
    wire["mac"][0] = serde_json::json!(wire["mac"][0].as_u64().unwrap() ^ 1);
    let forged: CapabilitySlip = serde_json::from_value(wire).unwrap();
    assert!(verify(&vault, &issuer, &forged).is_err());
    let mut unsupported = root;
    unsupported.version = 1;
    assert!(verify(&vault, &issuer, &unsupported).is_err());
}
#[test]
fn offline_meet_order_and_ttl_expiry_never_widen() {
    let (_dir, vault, issuer, root) = fixture();
    let mut narrow = Scope::top();
    narrow.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(
        crate::EntityId::from_bytes([7; 16]).unwrap(),
    )]));
    let a = SlipCaveat {
        scope: Some(narrow.clone()),
        ttl_secs: Some(23),
        expires_at: Some(root.claims.issued_at + 120),
        ..Default::default()
    };
    let b = SlipCaveat {
        scope: Some(Scope::top()),
        ttl_secs: Some(300),
        expires_at: Some(root.claims.issued_at + 600),
        ..Default::default()
    };
    let mut ab = root.clone();
    ab.attenuate(a.clone()).unwrap();
    ab.attenuate(b.clone()).unwrap();
    let mut ba = root.clone();
    ba.attenuate(b).unwrap();
    ba.attenuate(a).unwrap();
    let first = verify(&vault, &issuer, &ab).unwrap();
    let second = verify(&vault, &issuer, &ba).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.scope(), &narrow);
    assert_eq!(first.claims().ttl_secs, 23);
    assert_eq!(first.claims().expires_at, root.claims.issued_at + 120);
    ab.caveats.remove(0);
    assert!(verify(&vault, &issuer, &ab).is_err());
    let mut reordered = ba.clone();
    reordered.caveats.reverse();
    assert!(verify(&vault, &issuer, &reordered).is_err());
}
#[test]
fn log_mint_requires_parent_narrowing_and_revoke_kills_subtree() {
    let (_dir, vault, issuer, root) = fixture();
    let mut claims = root.claims.clone();
    claims.slip_id = [8; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.ttl_secs = 60;
    claims.expires_at = claims.issued_at + 60;
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".into()]));
    let child = vault.mint_capability_slip(&issuer, claims).unwrap();
    assert!(verify(&vault, &issuer, &child).is_ok());
    let mut wide = child.claims.clone();
    wide.slip_id = [9; 32];
    wide.parent_id = Some(child.claims.slip_id);
    wide.scope = Scope::top();
    assert!(vault.mint_capability_slip(&issuer, wide).is_err());
    assert_eq!(vault.authority_fold().unwrap().slips.mints.len(), 2);
    vault
        .revoke_capability_slip(&issuer, root.claims.slip_id)
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_err());
    assert!(verify(&vault, &issuer, &child).is_err());
    assert!(vault.ensure_host_root_slip(&issuer).is_err());
}
#[test]
fn log_single_use_burn_is_atomic_and_survives_fresh_decode() {
    let (_dir, vault, issuer, root) = fixture();
    let mut claims = root.claims.clone();
    claims.slip_id = [10; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.single_use = true;
    claims.expires_at = claims.issued_at + 60;
    claims.ttl_secs = 60;
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let proof = issuer.binding_proof(&slip, b"one-shot").unwrap();
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &slip, b"one-shot", &proof, &[1; 16])
            .is_ok()
    );
    let decoded = CapabilitySlip::from_token(&slip.to_token().unwrap()).unwrap();
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &decoded, b"one-shot", &proof, &[2; 16])
            .is_err()
    );
    assert!(
        vault
            .authority_fold()
            .unwrap()
            .slips
            .consumed
            .contains(&slip.claims.slip_id)
    );
}
#[test]
fn pairing_link_mints_once_and_requires_connection_private_key() {
    let (_dir, vault, issuer, _root) = fixture();
    let holder = SigningKey::from_bytes(&[31; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    let transcript = pairing_binding_transcript(&link.ticket, &public, "test-holder").unwrap();
    let sig = holder.sign(&transcript).to_bytes();
    assert!(
        vault
            .redeem_pairing_link(&issuer, &link.ticket, "test-holder", public, &[])
            .is_err()
    );
    let paired = vault
        .redeem_pairing_link(&issuer, &link.ticket, "test-holder", public, &sig)
        .unwrap();
    assert!(
        vault
            .redeem_pairing_link(&issuer, &link.ticket, "test-holder", public, &sig)
            .is_err()
    );
    let proof = holder
        .sign(&paired.binding_transcript(b"holder-request").unwrap())
        .to_bytes();
    assert!(
        vault
            .verify_capability_slip(&issuer, &paired, b"holder-request", &proof)
            .is_ok()
    );
    assert!(
        vault
            .verify_capability_slip(
                &issuer,
                &paired,
                b"holder-request",
                &issuer.binding_proof(&paired, b"holder-request").unwrap()
            )
            .is_err()
    );
    assert_eq!(vault.authority_fold().unwrap().slips.mints.len(), 2);
}
#[test]
fn one_1191_root_rotation_residue_cannot_mint_or_authorize() {
    let (_dir, vault, issuer, root) = fixture();
    // Old DEVICE rows are deliberately malformed. Neither mint nor verify reads them.
    vault
        .with_write_txn(|txn| {
            vault.store.sync_state.put(
                txn,
                crate::identity::KEY_DEVICE_SK,
                b"old corrupt residue",
            )?;
            vault.store.sync_state.put(
                txn,
                crate::identity::KEY_DEVICE_PK,
                b"old public residue",
            )?;
            Ok(())
        })
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_ok());
    let replacement = HostSlipIssuer::from_secret(b"next retained host root").unwrap();
    let signer = SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        SECRET,
    ));
    vault
        .re_root_authority(
            DeviceAuthority {
                key: replacement.public_key(),
                transport_key_binding: replacement.binding_key(),
                attestation: AuthorityAttestation {
                    kind: "HostRoot".into(),
                    evidence: Vec::new(),
                },
                tier: AuthorityTier::Software,
                roles: ROLE_OWNER | ROLE_ADMIN,
            },
            issuer.public_key(),
            |bytes| Ok(signer.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_err());
    let mut claims = root.claims;
    claims.slip_id = [20; 32];
    assert!(vault.mint_capability_slip(&issuer, claims).is_err());
    assert!(vault.ensure_host_root_slip(&issuer).is_err());
    assert!(vault.ensure_host_root_slip(&replacement).is_ok());
}

#[test]
fn consuming_child_spends_single_use_ancestor_and_siblings() {
    let (_dir, vault, issuer, root) = fixture();
    let mut claims = root.claims;
    claims.slip_id = [40; 32];
    claims.single_use = true;
    claims.expires_at = claims.issued_at + 60;
    claims.ttl_secs = 60;
    let parent = vault.mint_capability_slip(&issuer, claims).unwrap();
    let mut child = parent.claims.clone();
    child.slip_id = [41; 32];
    child.parent_id = Some(parent.claims.slip_id);
    let first = vault.mint_capability_slip(&issuer, child.clone()).unwrap();
    child.slip_id = [42; 32];
    let sibling = vault.mint_capability_slip(&issuer, child).unwrap();
    let proof = issuer.binding_proof(&first, b"consume-child").unwrap();
    vault
        .authenticate_capability_slip(&issuer, &first, b"consume-child", &proof, &[7; 16])
        .unwrap();
    assert!(verify(&vault, &issuer, &parent).is_err());
    assert!(verify(&vault, &issuer, &sibling).is_err());
}

#[test]
fn a_later_signer_fork_quarantines_even_the_pre_fork_root_slip() {
    let (_dir, vault, issuer, root) = fixture();
    let parent = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    let at = crate::TimeRange {
        start: root.claims.issued_at,
        end: root.claims.issued_at,
    };
    let first = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::SlipRevoke { slip_id: [71; 32] },
            at.start,
        )
        .unwrap();
    let second = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::SlipRevoke { slip_id: [72; 32] },
            at.start,
        )
        .unwrap();
    vault
        .put_authority_log_entries(&[(first, at, at.start), (second, at, at.start)])
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_err());
    assert!(vault.ensure_host_root_slip(&issuer).is_err());
}
#[test]
fn pending_device_enrollment_cannot_delay_a_slip_withdrawal() {
    let (_dir, vault, issuer, root) = fixture();
    let parent = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    let at = crate::TimeRange {
        start: root.claims.issued_at,
        end: root.claims.issued_at,
    };
    let device = HostSlipIssuer::from_secret(b"pending member device").unwrap();
    let enroll = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::EnrollDevice {
                device: DeviceAuthority {
                    key: device.public_key(),
                    transport_key_binding: device.binding_key(),
                    attestation: AuthorityAttestation {
                        kind: "software".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_AGENT,
                },
            },
            at.start,
        )
        .unwrap();
    vault
        .put_authority_log_entry(&enroll, at, at.start)
        .unwrap();
    assert_eq!(vault.authority_fold().unwrap().pending_widens.len(), 1);
    vault
        .revoke_capability_slip(&issuer, root.claims.slip_id)
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_err());
}

#[test]
fn named_record_meets_and_empty_channel_meets_never_restore_generic_reads() {
    let (_dir, vault, issuer, root) = fixture();
    let a = SlipCaveat {
        records: Some(BTreeSet::from(["record:a".into()])),
        ..Default::default()
    };
    let b = SlipCaveat {
        records: Some(BTreeSet::from(["record:b".into()])),
        ..Default::default()
    };
    let mut named = root.clone();
    named.attenuate(a.clone()).unwrap();
    assert_eq!(
        verify(&vault, &issuer, &named).unwrap().claims().records,
        BTreeSet::from(["record:a".into()])
    );
    let mut ab = named;
    ab.attenuate(b.clone()).unwrap();
    ab.attenuate(a.clone()).unwrap();
    let mut ba = root.clone();
    ba.attenuate(b).unwrap();
    ba.attenuate(a).unwrap();
    let denied = verify(&vault, &issuer, &ab).unwrap();
    assert_eq!(denied, verify(&vault, &issuer, &ba).unwrap());
    assert!(!denied.allows_verb("read"));
    let mut empty = root.clone();
    empty
        .attenuate(SlipCaveat {
            records: Some(BTreeSet::new()),
            ..Default::default()
        })
        .unwrap();
    assert!(!verify(&vault, &issuer, &empty).unwrap().allows_verb("read"));

    let mut claims = root.claims.clone();
    claims.slip_id = [43; 32];
    claims.records = BTreeSet::from(["record:a".into()]);
    claims.channels = BTreeSet::from(["provider:a".into()]);
    let channel = vault.mint_capability_slip(&issuer, claims).unwrap();
    for remove_records in [false, true] {
        let mut wider = channel.claims.clone();
        wider.slip_id = [44; 32];
        wider.parent_id = Some(channel.claims.slip_id);
        if remove_records {
            wider.records.clear();
        } else {
            wider.channels.clear();
        }
        assert!(vault.mint_capability_slip(&issuer, wider).is_err());
    }
    let mut no_records = channel.claims.clone();
    no_records.slip_id = [45; 32];
    no_records.records.clear();
    let no_records = vault.mint_capability_slip(&issuer, no_records).unwrap();
    let mut wider = no_records.claims.clone();
    wider.slip_id = [46; 32];
    wider.parent_id = Some(no_records.claims.slip_id);
    wider.records = BTreeSet::from(["record:a".into()]);
    assert!(vault.mint_capability_slip(&issuer, wider).is_err());
    let mut no_records = no_records;
    no_records
        .attenuate(SlipCaveat {
            records: Some(BTreeSet::from(["record:a".into()])),
            ..Default::default()
        })
        .unwrap();
    assert!(
        !verify(&vault, &issuer, &no_records)
            .unwrap()
            .allows_verb("read")
    );
    for channels in [BTreeSet::new(), BTreeSet::from(["provider:b".into()])] {
        let mut narrowed = channel.clone();
        narrowed
            .attenuate(SlipCaveat {
                channels: Some(channels),
                ..Default::default()
            })
            .unwrap();
        assert!(
            !verify(&vault, &issuer, &narrowed)
                .unwrap()
                .allows_verb("read")
        );
    }
}
