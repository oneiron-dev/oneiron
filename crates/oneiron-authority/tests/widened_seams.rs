//! Direct calls into the authority-log checks `oneiron-authority` made `pub` so `oneiron`'s
//! fold and checkpoint code can reach them across the crate split. Called from outside the
//! engine, they still refuse bad input exactly as they did when they were module-private.

use ed25519_dalek::{Signer, SigningKey};
use oneiron_authority::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityConfirmKind, AuthorityKey,
    AuthorityLogEntry, AuthorityOp, AuthoritySignature, AuthoritySignatureSuite, AuthorityTier,
    CONFIRM_KIND_ACCEPT, CriticalWriteConfirmDisposition, CriticalWriteConfirmMethod,
    DEFAULT_PENDING_WIDEN_DELAY_SECS, DeviceAuthority, FederationLifecycleAction,
    FederationLifecycleKind, FoldedDevice, GenesisRecoveryStep, MAX_ATTESTATION_EVIDENCE_BYTES,
    MAX_COSIGNS, ROLE_ADMIN, ROLE_AGENT, ROLE_CLOUD, ROLE_OWNER, ROLE_RECOVERY, SlipClaims,
    SlipMintAction, authority_transcript, canonical_p256_key_bytes, decode_entry_value,
    decode_hash, decode_hash_array, decode_key, decode_op, decode_optional_hash,
    decode_signature_array, decode_slip_mint, decode_tier, entry_value,
    folded_device_can_authority_consent, folded_host_device_can_consent,
    folded_peer_device_is_consent_root, is_terminal_federation_lifecycle, key_value, required,
    roster_has_live_owner, slip_mint_value, tier_meets_floor, validate_op, verify_entry_signatures,
};
use oneiron_authority::credential_door::{DOOR_ONE_SHOT_MAX_LIFETIME_SECS, names_a_floor};
use oneiron_authority::federation::codec::{
    decode_canonical_entity_ref, decode_entity_ref, required_value,
};
use oneiron_authority::federation::pact_scope::base_world_axis;
use oneiron_authority::federation::scope_codec::{
    decode_scope_value, encode_scope_value, legacy_read_scope,
};
use oneiron_authority::federation::{
    FederationDirectionScope, FederationPactScope, Scope, ScopeAxis, ScopeId,
    decode_federation_direction_scope_value, decode_federation_pact_scope_value,
    federation_direction_scope_value, federation_pact_scope_value,
};
use oneiron_contracts::EntityId;
use p256::ecdsa::SigningKey as P256SigningKey;
use rmpv::Value;
use std::collections::BTreeMap;

fn key() -> AuthorityKey {
    AuthorityKey::Ed25519(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes())
}

fn ed25519_signature(seed: u8, transcript: &[u8]) -> AuthoritySignature {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    AuthoritySignature {
        suite: AuthoritySignatureSuite::Ed25519,
        public_key: AuthorityKey::Ed25519(signing.verifying_key().to_bytes()),
        signature: signing.sign(transcript).to_bytes().to_vec(),
    }
}

/// A non-genesis entry signed by the `[7; 32]` key, with `cosigners` co-signing it.
fn signed_entry(cosigners: &[u8]) -> AuthorityLogEntry {
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some([4; 32]),
        seq: 2,
        parent_hashes: vec![[8; 32]],
        op: AuthorityOp::SetTierFloor {
            tier_floor: AuthorityTier::Hardware,
        },
        signer: ed25519_signature(7, b"placeholder"),
        cosigns: cosigners
            .iter()
            .map(|seed| ed25519_signature(*seed, b"placeholder"))
            .collect(),
        ts: 10,
    };
    // The transcript names the signer and cosign keys but no signature bytes.
    let transcript = authority_transcript(&entry).expect("a transcript");
    entry.signer = ed25519_signature(7, &transcript);
    for (cosign, seed) in entry.cosigns.iter_mut().zip(cosigners) {
        *cosign = ed25519_signature(*seed, &transcript);
    }
    entry
}

fn claims() -> SlipClaims {
    SlipClaims {
        slip_id: [3; 32],
        vault_id: [4; 32],
        parent_id: None,
        holder_ref: "holder".to_owned(),
        binding_key: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        scope: Scope {
            verbs: ScopeAxis::Some(["inject".to_owned()].into()),
            ..Scope::top()
        },
        issued_at: 10,
        expires_at: 100,
        ttl_secs: 60,
        single_use: true,
        records: ["secret".to_owned()].into(),
        channels: ["git.receive-pack".to_owned()].into(),
        actor_class: Some("agent".to_owned()),
        org_ref: Some(
            EntityId::from_bytes([6; 16])
                .expect("a valid entity id")
                .to_hex(),
        ),
    }
}

fn folded(roles: u16, tier: AuthorityTier, revoked: bool) -> FoldedDevice {
    FoldedDevice {
        key: key(),
        tier,
        roles,
        revoked,
    }
}

fn device(roles: u16) -> DeviceAuthority {
    DeviceAuthority {
        key: key(),
        transport_key_binding: [1; 32],
        attestation: AuthorityAttestation {
            kind: "software".to_owned(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::Software,
        roles,
    }
}

#[test]
fn device_validation_refuses_empty_and_undefined_roles() {
    assert!(device(0).validate().is_err());
    assert!(device(0x8000).validate().is_err());
    assert!(device(ROLE_OWNER).validate().is_ok());
}

#[test]
fn signature_validation_refuses_a_suite_that_does_not_match_its_key() {
    let mismatched = AuthoritySignature {
        suite: AuthoritySignatureSuite::P256,
        public_key: key(),
        signature: vec![0; 64],
    };
    assert!(mismatched.validate().is_err());
}

#[test]
fn a_software_key_never_meets_a_hardware_floor() {
    assert!(!tier_meets_floor(
        AuthorityTier::Software,
        AuthorityTier::Hardware
    ));
    assert!(tier_meets_floor(
        AuthorityTier::Hardware,
        AuthorityTier::Hardware
    ));
}

#[test]
fn entry_signatures_refuse_tampering_a_foreign_signer_and_an_unsigned_cosign() {
    let entry = signed_entry(&[11]);
    assert!(verify_entry_signatures(&entry).is_ok());

    let mut tampered = entry.clone();
    tampered.seq += 1;
    assert!(verify_entry_signatures(&tampered).is_err());

    let transcript = authority_transcript(&entry).unwrap();
    let mut foreign = entry.clone();
    foreign.signer.signature = ed25519_signature(12, &transcript).signature;
    assert!(verify_entry_signatures(&foreign).is_err());

    let mut unsigned_cosign = entry;
    unsigned_cosign.cosigns[0].signature = vec![0; 64];
    assert!(verify_entry_signatures(&unsigned_cosign).is_err());
}

#[test]
fn entry_shape_refuses_bad_versions_parents_and_cosigners() {
    let entry = signed_entry(&[11]);
    assert!(entry.validate_shape().is_ok());

    let mut version = entry.clone();
    version.schema_version += 1;
    let mut duplicate_parent = entry.clone();
    duplicate_parent.parent_hashes = vec![[8; 32], [8; 32]];
    let mut no_vault = entry.clone();
    no_vault.vault_id = None;
    let mut self_cosign = entry.clone();
    self_cosign.cosigns = vec![entry.signer.clone()];
    let mut crowded = entry;
    crowded.cosigns = (20..21 + u8::try_from(MAX_COSIGNS).unwrap())
        .map(|seed| ed25519_signature(seed, b"any"))
        .collect();
    for refused in [version, duplicate_parent, no_vault, self_cosign, crowded] {
        assert!(refused.validate_shape().is_err(), "{refused:?}");
    }
}

#[test]
fn entry_decoder_refuses_unknown_missing_and_non_map_fields() {
    let entry = signed_entry(&[]);
    let value = entry_value(&entry, true);
    assert_eq!(decode_entry_value(&value).unwrap(), entry);

    let Value::Map(fields) = value else {
        panic!("an entry encodes as a map");
    };
    let mut extra = fields.clone();
    extra.push((Value::from("extra"), Value::from(1)));
    let mut missing = fields;
    missing.pop();
    for refused in [Value::Map(extra), Value::Map(missing), Value::from(1)] {
        assert!(decode_entry_value(&refused).is_err(), "{refused:?}");
    }
}

#[test]
fn key_and_attestation_checks_refuse_malformed_material() {
    // Empty, truncated, a bare tag, the identity point.
    for bytes in [&[][..], &[0x02; 2][..], &[0x04][..], &[0x00][..]] {
        assert!(canonical_p256_key_bytes(bytes).is_err(), "{bytes:?}");
        assert!(AuthorityKey::P256(bytes.to_vec()).validate().is_err());
    }
    // The uncompressed spelling of a real key decodes, but only the compressed form is
    // canonical, so the key check refuses it.
    let p256 = P256SigningKey::from_slice(&[1; 32]).unwrap();
    let uncompressed = p256
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let canonical = canonical_p256_key_bytes(&uncompressed).unwrap();
    assert_eq!(canonical.len(), 33);
    assert!(AuthorityKey::P256(canonical).validate().is_ok());
    assert!(AuthorityKey::P256(uncompressed).validate().is_err());
    for (kind, evidence) in [
        (String::new(), Vec::new()),
        ("k".repeat(65), Vec::new()),
        (
            "software".to_owned(),
            vec![0; MAX_ATTESTATION_EVIDENCE_BYTES + 1],
        ),
    ] {
        let attestation = AuthorityAttestation { kind, evidence };
        assert!(attestation.validate().is_err(), "{attestation:?}");
    }
}

#[test]
fn a_child_slip_that_widens_its_parent_does_not_narrow_it() {
    let parent = claims();
    assert!(parent.validate().is_ok());
    assert!(parent.narrows(&parent));

    let mut later = claims();
    later.expires_at += 1;
    let mut longer_ttl = claims();
    longer_ttl.ttl_secs += 1;
    let mut reusable = claims();
    reusable.single_use = false;
    let mut other_holder = claims();
    other_holder.holder_ref = "someone-else".to_owned();
    let mut wider_scope = claims();
    wider_scope.scope = Scope::top();
    let mut other_record = claims();
    other_record.records = ["other-secret".to_owned()].into();
    for child in [
        later,
        longer_ttl,
        reusable,
        other_holder,
        wider_scope,
        other_record,
    ] {
        assert!(!child.narrows(&parent), "{child:?}");
    }

    let mut shorter = claims();
    shorter.expires_at = 50;
    shorter.ttl_secs = 30;
    assert!(shorter.narrows(&parent));
}

#[test]
fn slip_claims_refuse_floor_names_and_overlong_one_shots() {
    assert!(names_a_floor("DOOR_SCAN_ALWAYS_ON"));
    assert!(names_a_floor("x-door_max_lease_ttl_secs"));
    assert!(names_a_floor("Secret.Door.Floor.lease"));
    assert!(names_a_floor("secret.door.scan.mode"));
    assert!(!names_a_floor("git.receive-pack"));

    let mut floor_verb = claims();
    floor_verb.scope.verbs = ScopeAxis::Some(["door_scan_always_on".to_owned()].into());
    let mut floor_record = claims();
    floor_record.records = ["secret.door.floor.ttl".to_owned()].into();
    let mut long_one_shot = claims();
    long_one_shot.expires_at = long_one_shot.issued_at + DOOR_ONE_SHOT_MAX_LIFETIME_SECS + 1;
    for refused in [floor_verb, floor_record, long_one_shot] {
        assert!(refused.validate().is_err(), "{refused:?}");
    }
}

#[test]
fn consent_predicates_refuse_revoked_non_owner_and_cloud_keys() {
    let owner = folded(ROLE_OWNER, AuthorityTier::Hardware, false);
    assert!(folded_device_can_authority_consent(&owner));
    assert!(folded_peer_device_is_consent_root(&owner));
    assert!(folded_host_device_can_consent(&owner));
    for refused in [
        folded(ROLE_OWNER, AuthorityTier::Hardware, true),
        folded(ROLE_AGENT, AuthorityTier::Hardware, false),
        folded(ROLE_RECOVERY, AuthorityTier::Hardware, false),
    ] {
        assert!(
            !folded_device_can_authority_consent(&refused),
            "{refused:?}"
        );
        assert!(!folded_peer_device_is_consent_root(&refused), "{refused:?}");
        assert!(!folded_host_device_can_consent(&refused), "{refused:?}");
    }
    // The local fold never takes consent from a cloud-marked key; only the peer and
    // managed-host arms ignore those markings.
    for cloud in [
        folded(ROLE_OWNER | ROLE_CLOUD, AuthorityTier::Hardware, false),
        folded(ROLE_OWNER, AuthorityTier::CloudCustodial, false),
    ] {
        assert!(!folded_device_can_authority_consent(&cloud), "{cloud:?}");
        assert!(folded_peer_device_is_consent_root(&cloud), "{cloud:?}");
    }
    assert!(!device(ROLE_AGENT).can_authority_consent());
    assert!(device(ROLE_ADMIN).can_authority_consent());

    let mut roster = BTreeMap::new();
    assert!(!roster_has_live_owner(&roster, &key()));
    roster.insert(key(), owner);
    assert!(roster_has_live_owner(&roster, &key()));
    roster.insert(key(), folded(ROLE_OWNER, AuthorityTier::Hardware, true));
    assert!(!roster_has_live_owner(&roster, &key()));
    roster.insert(key(), folded(ROLE_ADMIN, AuthorityTier::Hardware, false));
    assert!(!roster_has_live_owner(&roster, &key()));
}

#[test]
fn slip_mint_decoder_revalidates_the_claims_it_reads() {
    let action = SlipMintAction { claims: claims() };
    let Value::Map(entries) = slip_mint_value(&action) else {
        panic!("a slip mint encodes as a map");
    };
    assert_eq!(
        decode_slip_mint(&entries).unwrap(),
        AuthorityOp::SlipMint(action)
    );

    let mut expired = claims();
    expired.expires_at = expired.issued_at;
    let Value::Map(entries) = slip_mint_value(&SlipMintAction { claims: expired }) else {
        panic!("a slip mint encodes as a map");
    };
    assert!(decode_slip_mint(&entries).is_err());
}

#[test]
fn authority_vocabulary_parsers_refuse_unknown_spellings() {
    for value in ["", "ED25519", "secp256k1"] {
        assert_eq!(AuthoritySignatureSuite::parse(value), None, "{value:?}");
    }
    for value in ["", "Hardware", "tpm"] {
        assert_eq!(AuthorityTier::parse(value), None, "{value:?}");
    }
    for value in ["", "Accept", "approve"] {
        assert_eq!(AuthorityConfirmKind::parse(value), None, "{value:?}");
    }
    for value in ["", "Clear", "allow"] {
        assert_eq!(
            CriticalWriteConfirmDisposition::parse(value),
            None,
            "{value:?}"
        );
    }
    for value in ["", "Token_Reauth", "none"] {
        assert_eq!(CriticalWriteConfirmMethod::parse(value), None, "{value:?}");
    }
    for value in ["", "Connect", "merge"] {
        assert_eq!(FederationLifecycleKind::parse(value), None, "{value:?}");
    }
    assert_eq!(
        AuthorityConfirmKind::parse(CONFIRM_KIND_ACCEPT),
        Some(AuthorityConfirmKind::Accept)
    );
    assert_eq!(
        AuthorityTier::parse("cloud_custodial"),
        Some(AuthorityTier::CloudCustodial)
    );
}

fn genesis(
    device: DeviceAuthority,
    genesis_nonce: [u8; 32],
    recovery: GenesisRecoveryStep,
) -> AuthorityOp {
    AuthorityOp::Genesis {
        device,
        genesis_nonce,
        recovery,
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
    }
}

#[test]
fn op_validation_refuses_zero_ids_nonces_commitments_and_non_owner_roots() {
    let recovery = GenesisRecoveryStep::acknowledge(&[9; 32], true).unwrap();
    assert!(recovery.validate().is_ok());
    assert!(validate_op(&genesis(device(ROLE_OWNER), [5; 32], recovery.clone())).is_ok());
    assert!(validate_op(&AuthorityOp::SlipRevoke { slip_id: [1; 32] }).is_ok());

    assert!(GenesisRecoveryStep::acknowledge(&[0; 32], true).is_err());
    assert!(GenesisRecoveryStep::Dismissed([0; 32]).validate().is_err());
    for refused in [
        AuthorityOp::SlipRevoke { slip_id: [0; 32] },
        AuthorityOp::SlipConsume { slip_id: [0; 32] },
        genesis(device(ROLE_OWNER), [0; 32], recovery.clone()),
        genesis(
            device(ROLE_OWNER),
            [5; 32],
            GenesisRecoveryStep::Saved([0; 32]),
        ),
        genesis(device(ROLE_AGENT), [5; 32], recovery),
    ] {
        assert!(validate_op(&refused).is_err(), "{refused:?}");
    }
}

#[test]
fn value_decoders_refuse_wrong_shapes_lengths_and_names() {
    let binary = |len| Value::Binary(vec![1; len]);
    assert_eq!(decode_hash(&binary(32)).unwrap(), [1; 32]);
    for refused in [binary(31), binary(33), Value::from("hash"), Value::Nil] {
        assert!(decode_hash(&refused).is_err(), "{refused:?}");
    }
    assert_eq!(decode_optional_hash(&Value::Nil).unwrap(), None);
    assert!(decode_optional_hash(&binary(31)).is_err());
    assert_eq!(
        decode_hash_array(&Value::Array(vec![binary(32)])).unwrap(),
        [[1; 32]]
    );
    assert!(decode_hash_array(&binary(32)).is_err());
    assert!(decode_hash_array(&Value::Array(vec![binary(32), binary(31)])).is_err());

    assert_eq!(
        decode_tier(&Value::from("hardware")).unwrap(),
        AuthorityTier::Hardware
    );
    for refused in [Value::from("Hardware"), Value::from("tpm"), Value::from(1)] {
        assert!(decode_tier(&refused).is_err(), "{refused:?}");
    }

    assert_eq!(decode_key(&key_value(&key())).unwrap(), key());
    let key_map = |suite: &str, public_key: Value| {
        Value::Map(vec![
            (Value::from("suite"), Value::from(suite)),
            (Value::from("public_key"), public_key),
        ])
    };
    for refused in [
        key_map("rsa", binary(32)),
        key_map("ed25519", binary(31)),
        key_map("p256", binary(33)),
        Value::from(1),
    ] {
        assert!(decode_key(&refused).is_err(), "{refused:?}");
    }
    assert!(decode_signature_array(&Value::from(1)).is_err());
    // A key map is not a signature: the signature bytes are missing.
    assert!(decode_signature_array(&Value::Array(vec![key_value(&key())])).is_err());

    let op = |fields: Vec<(&str, Value)>| {
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::from(key), value))
                .collect(),
        )
    };
    for refused in [
        op(vec![("kind", Value::from("grant_everything"))]),
        op(vec![
            ("kind", Value::from("slip_revoke")),
            ("slip_id", binary(31)),
        ]),
        op(vec![
            ("kind", Value::from("slip_revoke")),
            ("slip_id", binary(32)),
            ("extra", Value::from(1)),
        ]),
        op(vec![("slip_id", binary(32))]),
    ] {
        assert!(decode_op(&refused).is_err(), "{refused:?}");
    }

    let entries = [(Value::from("present"), Value::from(1))];
    assert!(required(&entries, "absent").is_err());
    assert_eq!(required(&entries, "present").unwrap(), &Value::from(1));
}

fn direction() -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: base_world_axis(),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }
}

#[test]
fn federation_decoders_refuse_malformed_ids_scopes_and_foreign_worlds() {
    let id = EntityId::from_bytes([0x1A; 16]).unwrap();
    let lower = id.to_hex();
    let upper = lower.to_uppercase();
    assert_eq!(decode_entity_ref(&Value::from(lower.as_str())).unwrap(), id);
    assert_eq!(
        decode_canonical_entity_ref(&Value::from(lower.as_str())).unwrap(),
        id
    );
    // The general decoder is case-insensitive; the canonical one is not.
    assert_eq!(decode_entity_ref(&Value::from(upper.as_str())).unwrap(), id);
    assert!(decode_canonical_entity_ref(&Value::from(upper.as_str())).is_err());
    for refused in [
        Value::from("zz"),
        Value::from(1),
        Value::Binary(id.as_bytes().to_vec()),
    ] {
        assert!(decode_entity_ref(&refused).is_err(), "{refused:?}");
        assert!(
            decode_canonical_entity_ref(&refused).is_err(),
            "{refused:?}"
        );
    }
    let entries = [(Value::from("present"), Value::from(1))];
    assert!(required_value(&entries, "absent").is_err());

    assert_eq!(
        decode_scope_value(&encode_scope_value(&Scope::top()).unwrap()).unwrap(),
        Scope::top()
    );
    let unknown_axis = Value::Map(vec![(Value::from("everything"), Value::from(true))]);
    for refused in [Value::from(1), unknown_axis] {
        assert!(decode_scope_value(&refused).is_err(), "{refused:?}");
    }
    assert!(legacy_read_scope(None).is_some());
    for refused in [
        Value::from(1),
        Value::Map(vec![(Value::from("grant_everything"), Value::from(true))]),
        Value::Map(vec![(Value::from("max_sensitivity_band"), Value::from(9))]),
    ] {
        assert_eq!(legacy_read_scope(Some(&refused)), None, "{refused:?}");
    }

    let pact = FederationPactScope {
        lo_to_hi: direction(),
        hi_to_lo: direction(),
    };
    assert_eq!(
        decode_federation_pact_scope_value(&federation_pact_scope_value(&pact)).unwrap(),
        pact
    );
    let Value::Map(mut fields) = federation_pact_scope_value(&pact) else {
        panic!("a pact scope encodes as a map");
    };
    fields.push((Value::from("extra"), Value::from(1)));
    assert!(decode_federation_pact_scope_value(&Value::Map(fields)).is_err());
    assert!(decode_federation_pact_scope_value(&Value::from(1)).is_err());

    // Named worlds are local-range only: a foreign-range world id fails closed.
    let foreign = FederationDirectionScope {
        worlds: ScopeAxis::Some([ScopeId(EntityId::from_bytes([0xF0; 16]).unwrap())].into()),
        ..direction()
    };
    let encoded = federation_direction_scope_value(&foreign);
    assert!(decode_federation_direction_scope_value(&encoded).is_err());
    assert!(decode_federation_direction_scope_value(&Value::from(1)).is_err());
}

#[test]
fn only_disconnect_dissolve_and_promote_are_terminal_lifecycle_shapes() {
    let lifecycle = |kind| {
        let mut entry = signed_entry(&[]);
        entry.op = AuthorityOp::FederationLifecycle(FederationLifecycleAction {
            kind,
            pact_id: [1; 32],
            grant_ref: EntityId::from_bytes([2; 16]).expect("a valid entity id"),
            peer_vault_id: [3; 32],
            pact_epoch: 1,
            pact_scope: None,
            effective_scope: None,
            scope_digest: None,
            gesture: None,
            successor_vault_id: None,
            pact_nonce: [4; 16],
        });
        entry
    };
    for kind in [
        FederationLifecycleKind::Disconnect,
        FederationLifecycleKind::Dissolve,
        FederationLifecycleKind::Promote,
    ] {
        assert!(
            is_terminal_federation_lifecycle(&lifecycle(kind)),
            "{kind:?}"
        );
    }
    for kind in [
        FederationLifecycleKind::Connect,
        FederationLifecycleKind::Rescope,
    ] {
        assert!(
            !is_terminal_federation_lifecycle(&lifecycle(kind)),
            "{kind:?}"
        );
    }
    assert!(!is_terminal_federation_lifecycle(&signed_entry(&[])));
}
