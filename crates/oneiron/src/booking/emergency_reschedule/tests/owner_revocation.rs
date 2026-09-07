use super::*;
use crate::authority::*;
use ed25519_dalek::Signer;

fn sign(mut entry: AuthorityLogEntry, key: &ed25519_dalek::SigningKey) -> AuthorityLogEntry {
    entry.signer.signature = key
        .sign(&authority_transcript(&entry).unwrap())
        .to_bytes()
        .to_vec();
    entry
}

fn root_and_bind(vault: &Vault) -> AuthorityLogEntry {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[0x73; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let signature = || AuthoritySignature {
        suite: key.suite(),
        public_key: key.clone(),
        signature: vec![0; 64],
    };
    let genesis = sign(
        AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: None,
            seq: 0,
            parent_hashes: vec![],
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
                genesis_nonce: [0x74; 32],
                tier_floor: AuthorityTier::Software,
                pending_widen_delay_secs: DEFAULT_PENDING_WIDEN_DELAY_SECS,
            },
            signer: signature(),
            cosigns: vec![],
            ts: 100,
        },
        &signing,
    );
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let bind = sign(
        AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: 1,
            parent_hashes: vec![authority_entry_hash(&genesis).unwrap()],
            op: AuthorityOp::BindActor {
                authority_key: key.clone(),
                actor_ref: id(OWNER),
                actor_class: "human".to_owned(),
                epoch: 1,
            },
            signer: signature(),
            cosigns: vec![],
            ts: 101,
        },
        &signing,
    );
    let revoke = sign(
        AuthorityLogEntry {
            schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
            vault_id: Some(vault_id),
            seq: 2,
            parent_hashes: vec![authority_entry_hash(&bind).unwrap()],
            op: AuthorityOp::RevokeActor {
                authority_key: key.clone(),
                epoch: 1,
            },
            signer: signature(),
            cosigns: vec![],
            ts: 102,
        },
        &signing,
    );
    vault
        .put_authority_log_entries(&[
            (genesis, TimeRange { start: 1, end: 1 }, 1),
            (bind, TimeRange { start: 2, end: 2 }, 2),
        ])
        .unwrap();
    revoke
}

#[test]
fn revoked_owner_cannot_persist_plans_or_replay_a_pending_pick_at_outbound_gate() {
    let (_dir, vault, _, plan) = executable(EmergencyActionPolicy::Cancel);
    let revoke = root_and_bind(&vault);
    let mut sink = spy(&vault, &plan);
    let item = execute(&vault, &plan, &mut sink, NOW).unwrap();
    sink.fail_channel = Some("calendar");
    assert!(
        counterparty_pick(
            &vault,
            &item.actions[1],
            &calendars(),
            &consumer(&vault, NOW + 1),
            &mut sink
        )
        .is_err()
    );
    let pending = checkpoint(&vault, &plan).unwrap();
    vault
        .put_authority_log_entries(&[(revoke, TimeRange { start: 3, end: 3 }, 3)])
        .unwrap();
    let before = (meta(&vault), entities(&vault));
    assert!(
        plan_item(
            &vault,
            &plan.request,
            plan.booking.clone(),
            &calendars(),
            NOW
        )
        .is_err()
    );
    assert_eq!((meta(&vault), entities(&vault)), before);
    let count = sink.calls.len();
    let error = super::super::execution::dispatch_item_effect(
        &vault,
        &pending,
        super::super::execution::EmergencyEffect::Pick,
        &mut sink,
        NOW + 2,
    )
    .unwrap_err();
    assert_eq!(
        crate::memory::booking_error(error).code,
        crate::memory::MEMORY_CODE_FORBIDDEN
    );
    assert_eq!(sink.calls.len(), count);
    assert!(
        vault.get_entity_type(&id(OWNER)).unwrap().is_some(),
        "revocation, not deletion"
    );
}
