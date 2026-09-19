//! Admission and later reads both honor revoke/regrant causality, not backdated time.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error};
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value;

#[test]
fn concurrent_claim_quarantines_at_replay_and_later_read_while_regrant_descendant_lives() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let issuer = HostSlipIssuer::from_secret(b"causal claim root").unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let actor = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&actor, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"owner")
        .unwrap();
    let parent = vault.authority_fold().unwrap().slips.mints[&root.claims.slip_id].entry_hash;
    let bind = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            2,
            vec![parent],
            AuthorityOp::BindActor {
                authority_key: issuer.public_key(),
                actor_ref: actor,
                actor_class: "human".to_owned(),
                epoch: 1,
            },
            2,
        )
        .unwrap();
    vault.put_authority_log_entry(&bind, at, 1).unwrap();
    let bind_hash = authority_entry_hash(&bind).unwrap();
    let body = |frontier| {
        let actor = WriteActor::new(actor, EdgeActorClass::Human).with_authority_frontier(frontier);
        let envelope = WriteEnvelope::new(
            actor,
            ClaimSource::Observed,
            WriteProvenance::new(Value::from("signed writer context")).unwrap(),
            ClaimApprovalStatus::Approved,
        );
        let candidate = ClaimCandidate::new(
            "test.revocation",
            ClaimSubject::Entity(actor.entity_ref()),
            Value::from("fact"),
            1.0,
        );
        crate::claim::encode_claim_body(&candidate.into_claim_body(&envelope)).unwrap()
    };
    let early = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &early,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            1,
            &body(bind_hash),
        )
        .commit()
        .unwrap();
    let revoke = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            3,
            vec![bind_hash],
            AuthorityOp::RevokeActor {
                authority_key: issuer.public_key(),
                epoch: 1,
            },
            3,
        )
        .unwrap();
    let regrant = issuer
        .sign_entry(
            Some(root.claims.vault_id),
            4,
            vec![authority_entry_hash(&revoke).unwrap()],
            AuthorityOp::BindActor {
                authority_key: issuer.public_key(),
                actor_ref: actor,
                actor_class: "human".to_owned(),
                epoch: 2,
            },
            4,
        )
        .unwrap();
    vault
        .put_authority_log_entries(&[(revoke, at, 1), (regrant.clone(), at, 1)])
        .unwrap();
    assert_eq!(
        vault.claim_write_disposition(&early).unwrap(),
        Some(CausalWriteDisposition::Quarantined)
    );
    let concurrent = EntityId::now();
    assert!(matches!(
        vault
            .batch()
            .put_replicated(
                &concurrent,
                crate::registry::ENTITY_TYPE_CLAIM,
                at,
                1,
                &body(bind_hash)
            )
            .commit(),
        Err(Error::Claim(ClaimError::WriteConcurrentWithRevocation))
    ));
    assert!(vault.get(&concurrent).unwrap().is_none());
    let descendant = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &descendant,
            crate::registry::ENTITY_TYPE_CLAIM,
            at,
            1,
            &body(authority_entry_hash(&regrant).unwrap()),
        )
        .commit()
        .unwrap();
    assert_eq!(
        vault.claim_write_disposition(&descendant).unwrap(),
        Some(CausalWriteDisposition::Admitted)
    );
    let proof = vault.verified_host_root_slip(&issuer).unwrap();
    let reader = vault.scoped_read(ScopedReadActorKey::from_verified_slip(&proof).unwrap());
    assert!(reader.get(&early).unwrap().is_none());
    assert!(reader.get(&descendant).unwrap().is_some());
}
