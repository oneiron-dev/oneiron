//! Shared fixtures for Scope admission tests.
use oneiron::TimeRange;
use oneiron::authority::{AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature};
use oneiron::disclosure::{DisclosureScopeAuthorization, ScopeCeiling};
use oneiron::error::Result;
use oneiron::{EntityId, Vault};

fn authority_root(
    seed: u8,
) -> (
    oneiron::authority::AuthorityLogEntry,
    ed25519_dalek::SigningKey,
) {
    use oneiron::authority::{
        AuthorityAttestation, AuthorityKey, AuthorityLogEntry, AuthorityOp, AuthoritySignature,
        AuthorityTier, DeviceAuthority, ROLE_ADMIN, ROLE_OWNER,
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let entry = AuthorityLogEntry {
        schema_version: oneiron::authority::AUTHORITY_LOG_SCHEMA_VERSION,
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
            genesis_nonce: [seed.wrapping_add(10); 32],
            tier_floor: AuthorityTier::Software,
            pending_widen_delay_secs: oneiron::authority::DEFAULT_PENDING_WIDEN_DELAY_SECS,
        },
        signer: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 100,
    };
    (sign_authority(entry, &signing), signing)
}

fn sign_authority(
    mut entry: oneiron::authority::AuthorityLogEntry,
    key: &ed25519_dalek::SigningKey,
) -> oneiron::authority::AuthorityLogEntry {
    use ed25519_dalek::Signer;
    let transcript = oneiron::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = key.sign(&transcript).to_bytes().to_vec();
    entry
}

pub(super) fn authorize(vault: &Vault, contact: &EntityId, ceiling: &ScopeCeiling) -> Result<()> {
    let authorization = authorization(vault, contact, ceiling)?;
    vault.authorize_counterparty_disclosure_scope(contact, ceiling, &authorization)
}

pub(super) fn authorization(
    vault: &Vault,
    contact: &EntityId,
    ceiling: &ScopeCeiling,
) -> Result<DisclosureScopeAuthorization> {
    use ed25519_dalek::Signer;
    let actor = EntityId::from_bytes([0x6A; 16])?;
    let (genesis, signing) = authority_root(0x42);
    let vault_id = oneiron::authority::genesis_vault_id(&genesis)?;
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    if vault.authority_fold()?.vault_id.is_none() {
        vault.put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&serde_json::json!({"name":"owner"})).expect("person"),
        )?;
        let bind = sign_authority(
            AuthorityLogEntry {
                schema_version: oneiron::authority::AUTHORITY_LOG_SCHEMA_VERSION,
                vault_id: Some(vault_id),
                seq: 1,
                parent_hashes: vec![oneiron::authority::authority_entry_hash(&genesis)?],
                op: AuthorityOp::BindActor {
                    authority_key: key.clone(),
                    actor_ref: actor,
                    actor_class: "human".into(),
                    epoch: 1,
                },
                signer: AuthoritySignature {
                    suite: key.suite(),
                    public_key: key.clone(),
                    signature: vec![0; 64],
                },
                cosigns: Vec::new(),
                ts: 101,
            },
            &signing,
        );
        vault.put_authority_log_entries(&[
            (
                genesis,
                TimeRange {
                    start: 100,
                    end: 100,
                },
                100,
            ),
            (
                bind,
                TimeRange {
                    start: 101,
                    end: 101,
                },
                101,
            ),
        ])?;
    }
    let mut authorization = DisclosureScopeAuthorization {
        vault_id,
        actor,
        epoch: 1,
        utterance: EntityId::now(),
        signature: AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![],
        },
    };
    authorization.signature.signature = signing
        .sign(&authorization.transcript(contact, ceiling)?)
        .to_bytes()
        .to_vec();
    Ok(authorization)
}

pub(super) fn projects(mut ids: Vec<EntityId>) -> ScopeCeiling {
    ids.sort_unstable();
    ids.dedup();
    let projects = if ids.is_empty() {
        oneiron::disclosure::ScopeIdAxis::Bottom
    } else {
        oneiron::disclosure::ScopeIdAxis::Some(ids)
    };
    ScopeCeiling {
        projects,
        sensitivity: 1,
        ..ScopeCeiling::top()
    }
}
