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
fn rooted_log(vault: &Vault, root: &CapabilitySlip) -> (AuthorityLogEntry, AuthorityLogEntry) {
    let mint_hash = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    let mint = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&mint_hash).unwrap())
        .unwrap()
        .unwrap();
    let genesis = vault
        .get_authority_log_entry(
            &authority_log_entity_id_from_hash(&mint.parent_hashes[0]).unwrap(),
        )
        .unwrap()
        .unwrap();
    (genesis, mint)
}
#[test]
fn bootstrap_commits_genesis_and_slip_mint_and_reuses_one_root() {
    let (dir, vault, issuer, root) = fixture();
    let fold = vault.authority_fold().unwrap();
    assert!(verify(&vault, &issuer, &root).unwrap().allows_verb("read"));
    assert!(!fold.genesis_fragile);
    assert_eq!(vault.ensure_host_root_slip(&issuer).unwrap(), root);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    assert_eq!(vault.ensure_host_root_slip(&issuer).unwrap(), root);
    assert!(verify(&vault, &issuer, &root).unwrap().allows_verb("read"));
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
    let verified = verify(&vault, &issuer, &child).unwrap();
    let mut wide = child.claims.clone();
    wide.slip_id = [9; 32];
    wide.parent_id = Some(child.claims.slip_id);
    wide.scope = Scope::top();
    assert!(vault.mint_capability_slip(&issuer, wide).is_err());
    vault
        .revoke_capability_slip(&issuer, root.claims.slip_id)
        .unwrap();
    assert!(verify(&vault, &issuer, &root).is_err());
    assert!(verify(&vault, &issuer, &child).is_err());
    assert!(!vault.capability_slip_is_live(&verified).unwrap());
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
    let nonce = b"11111111111111111111111111111111";
    let timestamp = root.claims.issued_at;
    let challenge =
        super::super::slip_replay::request_challenge(timestamp, nonce, timestamp).unwrap();
    let proof = issuer.binding_proof(&slip, &challenge).unwrap();
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &slip, timestamp, &proof, nonce)
            .is_ok()
    );
    let decoded = CapabilitySlip::from_token(&slip.to_token().unwrap()).unwrap();
    let retry_nonce = b"22222222222222222222222222222222";
    let retry_challenge =
        super::super::slip_replay::request_challenge(timestamp, retry_nonce, timestamp).unwrap();
    let retry_proof = issuer.binding_proof(&decoded, &retry_challenge).unwrap();
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &decoded, timestamp, &retry_proof, retry_nonce)
            .is_err()
    );
    assert!(verify(&vault, &issuer, &decoded).is_err());
}
#[test]
fn pairing_link_mints_once_and_requires_connection_private_key() {
    let (_dir, vault, issuer, _root) = fixture();
    let holder = SigningKey::from_bytes(&[31; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    let transcript = pairing_binding_transcript(&link.code, &public, "test-holder").unwrap();
    let sig = holder.sign(&transcript).to_bytes();
    assert!(
        vault
            .redeem_pairing_link(&issuer, &link.code, "test-holder", public, &[])
            .is_err()
    );
    let paired = vault
        .redeem_pairing_link(&issuer, &link.code, "test-holder", public, &sig)
        .unwrap();
    assert!(
        vault
            .redeem_pairing_link(&issuer, &link.code, "test-holder", public, &sig)
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
}
#[test]
fn a_pairing_code_is_eight_unambiguous_characters() {
    let (_dir, vault, issuer, _root) = fixture();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    assert!(
        link.code.len() == 8
            && link
                .code
                .chars()
                .all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c))
    );
}
#[test]
fn a_pairing_code_is_stored_only_as_a_keyed_hash() {
    let (_dir, vault, issuer, _root) = fixture();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    let code = link.code.as_bytes();
    let rtxn = vault.store.env.read_txn().unwrap();
    let mut rows = vault.store.sync_state.iter(&rtxn).unwrap();
    assert!(rows.all(|row| {
        let (key, value) = row.unwrap();
        !key.as_bytes().windows(code.len()).any(|at| at == code)
            && !value.windows(code.len()).any(|at| at == code)
    }));
}
#[test]
fn a_pairing_link_expires_after_one_hour() {
    let (_dir, vault, issuer, _root) = fixture();
    let holder = SigningKey::from_bytes(&[32; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    vault
        .with_write_txn(|wtxn| {
            vault.store.sync_state.put(
                wtxn,
                "authlog:first_seen:clock_floor",
                &link.expires_at.to_be_bytes(),
            )?;
            Ok(())
        })
        .unwrap();
    let sig = holder
        .sign(&pairing_binding_transcript(&link.code, &public, "test-holder").unwrap())
        .to_bytes();
    assert!(
        vault
            .redeem_pairing_link(&issuer, &link.code, "test-holder", public, &sig)
            .is_err()
    );
}
#[test]
fn a_pairing_code_redeems_when_typed_in_lower_case() {
    let (_dir, vault, issuer, _root) = fixture();
    let holder = SigningKey::from_bytes(&[33; 32]);
    let public = holder.verifying_key().to_bytes();
    let link = vault
        .issue_pairing_link(&issuer, Scope::top(), 120)
        .unwrap();
    let sig = holder
        .sign(&pairing_binding_transcript(&link.code, &public, "test-holder").unwrap())
        .to_bytes();
    assert!(
        vault
            .redeem_pairing_link(
                &issuer,
                &link.code.to_ascii_lowercase(),
                "test-holder",
                public,
                &sig
            )
            .is_ok()
    );
}
#[test]
fn a_pairing_link_string_round_trips_its_origin_code_and_holder() {
    let origin = "https://example.invalid:8443/oneiron";
    let holder = crate::EntityId::now().to_hex();
    assert_eq!(
        parse_pairing_link(&format_pairing_link(origin, "K7M2Q9XA", &holder)).unwrap(),
        (origin.to_owned(), "K7M2Q9XA".to_owned(), holder)
    );
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
    let nonce = b"77777777777777777777777777777777";
    let timestamp = first.claims.issued_at;
    let challenge =
        super::super::slip_replay::request_challenge(timestamp, nonce, timestamp).unwrap();
    let proof = issuer.binding_proof(&first, &challenge).unwrap();
    vault
        .authenticate_capability_slip(&issuer, &first, timestamp, &proof, nonce)
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
fn a_slip_mint_signed_by_an_agent_device_folds_invalid_even_with_an_owner_cosigner() {
    let (_dir, vault, issuer, root) = fixture();
    let (genesis, root_mint) = rooted_log(&vault, &root);
    let parent = authority_entry_hash(&root_mint).unwrap();
    let agent = SigningKey::from_bytes(&[61; 32]);
    let agent_key = AuthorityKey::Ed25519(agent.verifying_key().to_bytes());
    let enroll = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::EnrollDevice {
                device: DeviceAuthority {
                    key: agent_key.clone(),
                    transport_key_binding: agent.verifying_key().to_bytes(),
                    attestation: AuthorityAttestation {
                        kind: "software".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_AGENT,
                },
            },
            root.claims.issued_at,
        )
        .unwrap();
    let enrolled_hash = authority_entry_hash(&enroll).unwrap();
    let enrolled = super::super::fold_engine::fold_authority_log_without_seen_time_delay(&[
        genesis.clone(),
        root_mint.clone(),
        enroll.clone(),
    ]);
    assert!(enrolled.valid_entries.contains(&enrolled_hash));
    assert_eq!(enrolled.roster[&agent_key].roles, ROLE_AGENT);

    let mut claims = root.claims.clone();
    claims.slip_id = [62; 32];
    let mut mint = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            0,
            vec![enrolled_hash],
            AuthorityOp::SlipMint(SlipMintAction { claims }),
            root.claims.issued_at,
        )
        .unwrap();
    mint.signer.public_key = agent_key;
    mint.cosigns.push(AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: issuer.public_key(),
        signature: vec![0; 64],
    });
    let transcript = authority_transcript(&mint).unwrap();
    mint.signer.signature = agent.sign(&transcript).to_bytes().to_vec();
    let owner = SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/host-authority-signing/v2",
        SECRET,
    ));
    assert_eq!(
        issuer.public_key(),
        AuthorityKey::Ed25519(owner.verifying_key().to_bytes())
    );
    mint.cosigns[0].signature = owner.sign(&transcript).to_bytes().to_vec();
    super::super::crypto::verify_entry_signatures(&mint).unwrap();
    let hash = authority_entry_hash(&mint).unwrap();
    let fold = super::super::fold_engine::fold_authority_log_without_seen_time_delay(&[
        genesis, root_mint, enroll, mint,
    ]);
    assert!(fold.valid_entries.contains(&enrolled_hash));
    assert!(!fold.valid_entries.contains(&hash));
}

#[test]
fn a_slip_revoke_signed_by_a_revoked_owner_device_folds_invalid() {
    let (_dir, vault, issuer, root) = fixture();
    let (genesis, mint) = rooted_log(&vault, &root);
    let mint_hash = authority_entry_hash(&mint).unwrap();
    let successor = HostSlipIssuer::from_secret(b"replacement owner device").unwrap();
    let rotation = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![mint_hash],
            AuthorityOp::RotateKey {
                old_key: issuer.public_key(),
                new_device: DeviceAuthority {
                    key: successor.public_key(),
                    transport_key_binding: successor.binding_key(),
                    attestation: AuthorityAttestation {
                        kind: "software".into(),
                        evidence: Vec::new(),
                    },
                    tier: AuthorityTier::Software,
                    roles: ROLE_OWNER | ROLE_ADMIN,
                },
            },
            root.claims.issued_at,
        )
        .unwrap();
    let rotation_hash = authority_entry_hash(&rotation).unwrap();
    let revoked = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            3,
            vec![rotation_hash],
            AuthorityOp::SlipRevoke {
                slip_id: root.claims.slip_id,
            },
            root.claims.issued_at,
        )
        .unwrap();
    let hash = authority_entry_hash(&revoked).unwrap();
    let fold = super::super::fold_engine::fold_authority_log_without_seen_time_delay(&[
        genesis, mint, rotation, revoked,
    ]);
    assert!(fold.valid_entries.contains(&rotation_hash));
    assert!(fold.roster[&issuer.public_key()].revoked);
    assert!(!fold.valid_entries.contains(&hash));
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
    assert!(vault.ensure_host_root_slip(&device).is_err());
    assert!(verify(&vault, &issuer, &root).is_ok());
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
    for slip in [&ab, &ba] {
        assert!(!verify(&vault, &issuer, slip).unwrap().allows_verb("read"));
    }
    // Effective TTL is time-relative. Compare complete verifier results at the
    // same instant, including a second rollover and the last live second.
    let fold = vault.authority_fold().unwrap();
    for now in [
        root.claims.issued_at,
        root.claims.issued_at + 1,
        root.claims.expires_at - 1,
    ] {
        let verify_at = |slip: &CapabilitySlip| {
            let proof = issuer.binding_proof(slip, b"request-1").unwrap();
            slip.verify(SECRET, &fold, now, b"request-1", &proof)
                .unwrap()
        };
        let denied = verify_at(&ab);
        assert_eq!(denied, verify_at(&ba));
        assert_eq!(denied.claims().ttl_secs, root.claims.expires_at - now);
        assert!(!denied.allows_verb("read"));
    }
    let mut empty = root.clone();
    empty
        .attenuate(SlipCaveat {
            records: Some(BTreeSet::new()),
            ..Default::default()
        })
        .unwrap();
    assert!(!verify(&vault, &issuer, &empty).unwrap().allows_verb("read"));

    let mut claims = root.claims;
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

#[test]
fn relay_refuses_host_root_bootstrap_without_writing_authority() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::default();
    config.privacy.posture = crate::HostingPrivacyPosture::Relay;
    let vault = Vault::open(dir.path(), config).unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    assert!(vault.ensure_host_root_slip(&issuer).is_err());
    assert!(vault.verified_host_root_slip(&issuer).is_err());
    assert!(vault.authority_fold().unwrap().vault_id.is_none());
}

#[test]
fn request_timestamp_and_nonce_are_signed_and_replay_is_refused() {
    let (_dir, vault, issuer, root) = fixture();
    let nonce = b"33333333333333333333333333333333";
    let timestamp = root.claims.issued_at;
    let challenge =
        super::super::slip_replay::request_challenge(timestamp, nonce, timestamp).unwrap();
    let proof = issuer.binding_proof(&root, &challenge).unwrap();
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &root, timestamp + 1, &proof, nonce)
            .is_err()
    );
    assert!(
        vault
            .authenticate_capability_slip(
                &issuer,
                &root,
                timestamp,
                &proof,
                b"44444444444444444444444444444444"
            )
            .is_err()
    );
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &root, timestamp, &proof, nonce)
            .is_ok()
    );
    assert!(
        vault
            .authenticate_capability_slip(&issuer, &root, timestamp, &proof, nonce)
            .is_err()
    );
}

#[test]
fn divergent_mints_poison_the_identifier_in_either_merge_order() {
    let (_dir, vault, issuer, root) = fixture();
    let base = vault.authority_fold().unwrap();
    let parent = base.slips.mints[&root.claims.slip_id].entry_hash;
    let mut claims = root.claims.clone();
    claims.slip_id = [77; 32];
    let mut other = claims.clone();
    other.ttl_secs = 60;
    let left = issuer
        .sign_entry(
            Some(claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::SlipMint(SlipMintAction { claims }),
            root.claims.issued_at,
        )
        .unwrap();
    let right = issuer
        .sign_entry(
            Some(other.vault_id),
            3,
            vec![parent],
            AuthorityOp::SlipMint(SlipMintAction { claims: other }),
            root.claims.issued_at,
        )
        .unwrap();
    let mut a = base.slips.clone();
    let mut b = base.slips.clone();
    a.apply(&left, authority_entry_hash(&left).unwrap())
        .unwrap();
    b.apply(&right, authority_entry_hash(&right).unwrap())
        .unwrap();
    let mut ab = a.clone();
    ab.merge_from(&b);
    let mut ba = b;
    ba.merge_from(&a);
    assert_eq!(ab, ba);
    assert!(ab.revoked.contains(&[77; 32]));
    assert!(!ab.is_live(&[77; 32], &base.roster));
    assert!(ab.is_live(&root.claims.slip_id, &base.roster));
}

#[test]
fn a_rejected_signed_local_entry_still_advances_the_next_sequence() {
    let (_dir, vault, issuer, root) = fixture();
    let fold = vault.authority_fold().unwrap();
    let parent = fold.slips.mints[&root.claims.slip_id].entry_hash;
    let mut invalid = root.claims.clone();
    invalid.slip_id = [73; 32];
    invalid.parent_id = Some([72; 32]);
    let rejected = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            7,
            vec![parent],
            AuthorityOp::SlipMint(SlipMintAction { claims: invalid }),
            root.claims.issued_at,
        )
        .unwrap();
    let hash = authority_entry_hash(&rejected).unwrap();
    vault
        .put_authority_log_entry(&rejected, crate::TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    assert!(
        !vault
            .authority_fold()
            .unwrap()
            .valid_entries
            .contains(&hash)
    );
    let mut claims = root.claims;
    claims.slip_id = [74; 32];
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let fold = vault.authority_fold().unwrap();
    let hash = fold.slips.mints[&slip.claims.slip_id].entry_hash;
    let entry = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.seq, 8);
    assert!(
        !entry
            .parent_hashes
            .contains(&authority_entry_hash(&rejected).unwrap())
    );
    assert!(verify(&vault, &issuer, &slip).is_ok());
}

#[test]
fn slip_mint_signed_wire_is_fieldwise_and_rejects_noncanonical_fields() {
    use crate::federation::{Sensitivity, SensitivityCeiling};
    use rmpv::Value;
    let issuer = HostSlipIssuer::from_secret(SECRET).unwrap();
    let scope = Scope {
        worlds: ScopeAxis::Some([ScopeId(crate::EntityId::from_bytes([2; 16]).unwrap())].into()),
        facets: ScopeAxis::Bottom,
        bands: ScopeAxis::Some([4, 7].into()),
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(["inject".into(), "lease".into()].into()),
        sensitivity: SensitivityCeiling::AtMost(Sensitivity::Private),
    };
    let claims = SlipClaims {
        slip_id: [3; 32],
        vault_id: [4; 32],
        parent_id: Some([5; 32]),
        holder_ref: "holder".into(),
        binding_key: issuer.binding_key(),
        scope,
        issued_at: 10,
        expires_at: 100,
        ttl_secs: 60,
        single_use: true,
        records: ["secret".into()].into(),
        channels: ["git.receive-pack".into()].into(),
        actor_class: Some("agent".into()),
        org_ref: Some(crate::EntityId::from_bytes([6; 16]).unwrap().to_hex()),
    };
    let entry = issuer
        .sign_entry(
            Some([4; 32]),
            2,
            vec![[8; 32]],
            AuthorityOp::SlipMint(SlipMintAction { claims }),
            10,
        )
        .unwrap();
    let bytes = encode_authority_log_entry_body(&entry).unwrap();
    assert_eq!(decode_authority_log_entry_body(&bytes).unwrap(), entry);
    let mut cursor = std::io::Cursor::new(&bytes);
    let value = rmpv::decode::read_value(&mut cursor).unwrap();
    let entries = super::super::map_entries(&value).unwrap();
    let op = super::super::required(entries, "op").unwrap();
    let fields = super::super::map_entries(op).unwrap();
    assert_eq!(
        fields
            .iter()
            .map(|(k, _)| k.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "kind",
            "slip_id",
            "vault_id",
            "parent_id",
            "holder_ref",
            "binding_key",
            "scope",
            "issued_at",
            "expires_at",
            "ttl_secs",
            "single_use",
            "records",
            "channels",
            "actor_class",
            "org_ref"
        ]
    );
    assert!(matches!(
        super::super::required(fields, "scope").unwrap(),
        Value::Map(_)
    ));
    let mut duplicate = fields.to_vec();
    duplicate.push(duplicate[1].clone());
    assert!(super::super::decode_op(&Value::Map(duplicate)).is_err());
    let mut unknown = fields.to_vec();
    unknown.push((Value::from("extra"), Value::Nil));
    assert!(super::super::decode_op(&Value::Map(unknown)).is_err());
    let mut missing = fields.to_vec();
    missing.pop();
    assert!(super::super::decode_op(&Value::Map(missing)).is_err());
    let blob = Value::Map(vec![
        (Value::from("kind"), Value::from("slip_mint")),
        (Value::from("slip"), Value::Binary(vec![])),
    ]);
    assert!(super::super::decode_op(&blob).is_err());
    let mut tampered = entry;
    if let AuthorityOp::SlipMint(action) = &mut tampered.op {
        action.claims.ttl_secs += 1;
    }
    assert!(
        decode_authority_log_entry_body(&encode_authority_log_entry_body(&tampered).unwrap())
            .is_err()
    );
}

#[test]
fn pact_caveats_meet_and_recheck_live_grant_state() {
    use crate::federation::{
        FederationDirectionScope, FederationPactScope, FederationScopeBands, FederationScopeFacets,
        FederationScopeWorlds,
    };
    let (_dir, vault, issuer, root) = fixture();
    let mut fold = vault.authority_fold().unwrap();
    let grant = crate::EntityId::from_bytes([41; 16]).unwrap();
    let wide = FederationDirectionScope {
        worlds: FederationScopeWorlds::All,
        facets: FederationScopeFacets::All,
        bands: FederationScopeBands::All,
    };
    let narrow = FederationDirectionScope {
        worlds: FederationScopeWorlds::Base,
        ..wide.clone()
    };
    fold.federation_pacts.insert(
        [42; 32],
        FederationPactState {
            status: FederationPactStatus::Active,
            grant_ref: grant,
            peer_vault_id: [43; 32],
            peer_owner_key: issuer.public_key(),
            pact_epoch: 1,
            scope_digest: [44; 32],
            pact_scope: FederationPactScope {
                lo_to_hi: wide.clone(),
                hi_to_lo: wide.clone(),
            },
            effective_scope: wide.clone(),
            successor_vault_id: None,
            terminal_epoch: None,
        },
    );
    fold.federation_grant_bindings
        .insert(grant, [[42; 32]].into());
    let caveat = |bound| SlipCaveat {
        pact: Some((grant, bound)),
        ..Default::default()
    };
    let mut slip = root.clone();
    slip.attenuate(caveat(narrow.clone())).unwrap();
    slip.attenuate(caveat(wide.clone())).unwrap();
    let proof = issuer.binding_proof(&slip, b"pact").unwrap();
    let checked = slip
        .verify(
            issuer.secret(),
            &fold,
            root.claims.issued_at,
            b"pact",
            &proof,
        )
        .unwrap();
    assert_eq!(checked.pact(), Some(&(grant, narrow)));
    assert!(
        vault
            .capability_slip_id_is_live(&root.claims.slip_id)
            .unwrap()
    );
    assert!(!vault.capability_slip_is_live(&checked).unwrap());
    let decoded = CapabilitySlip::from_token(&slip.to_token().unwrap()).unwrap();
    assert_eq!(decoded, slip);
    fold.federation_pacts.get_mut(&[42; 32]).unwrap().status = FederationPactStatus::Disconnected;
    assert!(
        slip.verify(
            issuer.secret(),
            &fold,
            root.claims.issued_at,
            b"pact",
            &proof
        )
        .is_err()
    );
    fold.federation_pacts.get_mut(&[42; 32]).unwrap().status = FederationPactStatus::Active;
    fold.federation_pacts
        .get_mut(&[42; 32])
        .unwrap()
        .effective_scope
        .facets = FederationScopeFacets::Bottom;
    assert!(
        slip.verify(
            issuer.secret(),
            &fold,
            root.claims.issued_at,
            b"pact",
            &proof
        )
        .is_err()
    );
    fold.federation_pacts
        .get_mut(&[42; 32])
        .unwrap()
        .effective_scope = wide.clone();
    fold.federation_grant_bindings
        .get_mut(&grant)
        .unwrap()
        .insert([45; 32]);
    assert!(
        slip.verify(
            issuer.secret(),
            &fold,
            root.claims.issued_at,
            b"pact",
            &proof
        )
        .is_err()
    );
    fold.federation_grant_bindings
        .get_mut(&grant)
        .unwrap()
        .remove(&[45; 32]);
    slip.attenuate(SlipCaveat {
        pact: Some((crate::EntityId::from_bytes([46; 16]).unwrap(), wide.clone())),
        ..Default::default()
    })
    .unwrap();
    let proof = issuer.binding_proof(&slip, b"pact").unwrap();
    assert!(
        slip.verify(
            issuer.secret(),
            &fold,
            root.claims.issued_at,
            b"pact",
            &proof
        )
        .is_err()
    );
    let mut slip = root;
    for id in [47, 48] {
        slip.attenuate(caveat(FederationDirectionScope {
            facets: FederationScopeFacets::Some(vec![
                crate::EntityId::from_bytes([id; 16]).unwrap(),
            ]),
            ..wide.clone()
        }))
        .unwrap();
    }
    slip.attenuate(caveat(wide)).unwrap();
    let proof = issuer.binding_proof(&slip, b"pact").unwrap();
    assert!(
        slip.verify(
            issuer.secret(),
            &fold,
            slip.claims.issued_at,
            b"pact",
            &proof
        )
        .is_err()
    );
}

#[test]
fn slip_validation_refuses_oversized_one_shots_and_floor_names() {
    let (_dir, vault, issuer, root) = fixture();
    let mut claims = root.claims.clone();
    claims.slip_id = [73; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.single_use = true;
    claims.expires_at = claims.issued_at + 301;
    claims.ttl_secs = 301;
    assert_eq!(
        claims.validate().unwrap_err().kind(),
        invalid_authority().kind()
    );
    assert_eq!(
        vault
            .mint_capability_slip(&issuer, claims.clone())
            .unwrap_err()
            .kind(),
        invalid_authority().kind()
    );
    claims.expires_at = claims.issued_at + 300;
    claims.ttl_secs = 300;
    assert!(claims.validate().is_ok());
    let slip = vault.mint_capability_slip(&issuer, claims.clone()).unwrap();
    assert!(verify(&vault, &issuer, &slip).is_ok());
    for token in ["DOOR_SCAN_ALWAYS_ON", "secret.door.floor.ttl"] {
        for field in 0..3 {
            let mut claims = claims.clone();
            match field {
                0 => claims.scope.verbs = ScopeAxis::Some([token.to_owned()].into()),
                1 => {
                    claims.records.insert(token.to_owned());
                }
                _ => {
                    claims.channels.insert(token.to_owned());
                }
            }
            assert_eq!(
                claims.validate().unwrap_err().kind(),
                invalid_authority().kind()
            );
        }
    }
}

#[test]
fn offline_one_shot_and_floor_caveats_are_checked_at_verification() {
    let (_dir, vault, issuer, root) = fixture();
    for caveat in [
        SlipCaveat {
            single_use: true,
            ..Default::default()
        },
        SlipCaveat {
            records: Some(["DOOR_SCAN_ALWAYS_ON".to_owned()].into()),
            ..Default::default()
        },
        SlipCaveat {
            channels: Some(["DOOR_SCAN_ALWAYS_ON".to_owned()].into()),
            ..Default::default()
        },
        SlipCaveat {
            scope: Some(Scope {
                verbs: ScopeAxis::Some(["secret.door.floor.ttl".to_owned()].into()),
                ..Scope::top()
            }),
            ..Default::default()
        },
    ] {
        let mut slip = root.clone();
        slip.attenuate(caveat).unwrap();
        assert_eq!(
            verify(&vault, &issuer, &slip).unwrap_err().kind(),
            invalid_authority().kind()
        );
    }
    let mut bounded = root.clone();
    bounded
        .attenuate(SlipCaveat {
            single_use: true,
            expires_at: Some(root.claims.issued_at + 300),
            ..Default::default()
        })
        .unwrap();
    assert!(verify(&vault, &issuer, &bounded).is_ok());
}

#[test]
fn rejected_mint_transaction_leaves_append_frontier_unchanged_after_reopen() {
    let (dir, vault, issuer, root) = fixture();
    let parent = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    let mut rejected = root.claims.clone();
    rejected.slip_id = [80; 32];
    rejected.parent_id = Some([81; 32]);
    assert!(vault.mint_capability_slip(&issuer, rejected).is_err());
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let mut claims = root.claims;
    claims.slip_id = [82; 32];
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let fold = vault.authority_fold().unwrap();
    let hash = fold.slips.mints[&slip.claims.slip_id].entry_hash;
    let entry = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(entry.seq, 2);
    assert_eq!(entry.parent_hashes, vec![parent]);
    assert!(fold.fork_alarms.is_empty());
    assert!(verify(&vault, &issuer, &slip).is_ok());
}

#[test]
fn concurrent_single_use_authentication_survives_reopen_and_mint_replay() {
    let (dir, vault, issuer, root) = fixture();
    let mut claims = root.claims.clone();
    claims.slip_id = [84; 32];
    claims.parent_id = Some(root.claims.slip_id);
    claims.single_use = true;
    claims.expires_at = claims.issued_at + 60;
    claims.ttl_secs = 60;
    let slip = vault.mint_capability_slip(&issuer, claims).unwrap();
    let hash = vault.authority_fold().unwrap().slips.mints[&slip.claims.slip_id].entry_hash;
    let entry = vault
        .get_authority_log_entry(&authority_log_entity_id_from_hash(&hash).unwrap())
        .unwrap()
        .unwrap();
    let timestamp = slip.claims.issued_at;
    let attempts: Vec<_> = [1, 2]
        .into_iter()
        .map(|n| {
            let nonce = format!("{n:032x}");
            let challenge = crate::authority::slip_replay::request_challenge(
                timestamp,
                nonce.as_bytes(),
                timestamp,
            )
            .unwrap();
            let signature = issuer.binding_proof(&slip, &challenge).unwrap();
            (nonce, signature)
        })
        .collect();
    let successes = std::thread::scope(|threads| {
        let handles: Vec<_> = attempts
            .iter()
            .map(|(nonce, signature)| {
                threads.spawn(|| {
                    vault
                        .authenticate_capability_slip(
                            &issuer,
                            &slip,
                            timestamp,
                            signature,
                            nonce.as_bytes(),
                        )
                        .is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(successes, 1);
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    vault
        .put_authority_log_entry(&entry, crate::TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    assert!(
        !vault
            .capability_slip_id_is_live(&slip.claims.slip_id)
            .unwrap()
    );
    assert!(verify(&vault, &issuer, &slip).is_err());
}
