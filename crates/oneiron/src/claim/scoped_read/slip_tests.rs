//! Root provisioning and fail-closed read admission land together.
use super::*;
use crate::authority::{HostSlipIssuer, SlipCaveat};
use crate::federation::{Scope, ScopeAxis, ScopeId};
use rmpv::Value;
use std::collections::BTreeSet;

#[test]
fn host_root_reads_stamped_rows_but_plain_keys_and_revoked_proofs_do_not() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let id = EntityId::now();
    let row = ClaimBody::new(
        "test.slip_read",
        ClaimSubject::Entity(id),
        Value::from("fact"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &encode_claim_body(&row)?,
        )
        .commit()?;
    let opaque = EntityId::now();
    vault.put_entity(
        &opaque,
        crate::registry::ENTITY_TYPE_ASSET_TEXT,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"document",
    )?;
    let issuer = HostSlipIssuer::from_secret(b"read acceptance host root")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let proof = vault.verified_host_root_slip(&issuer)?;
    let read =
        vault.scoped_read(ScopedReadActorKey::from_verified_slip(&proof).expect("read proof"));
    assert!(
        read.read(&[crate::claim::PointRead::id(id)], None)?
            .single()
            .is_some()
    );
    assert!(
        read.read(&[crate::claim::PointRead::id(opaque)], None)?
            .single()
            .is_some()
    );
    let unproven = vault
        .scoped_read(ScopedReadActorKey::new(proof.claims().holder_ref.clone()).expect("nonblank"));
    assert!(
        unproven
            .read(&[crate::claim::PointRead::id(id)], None)?
            .single()
            .is_none()
    );
    assert!(
        unproven
            .read(&[crate::claim::PointRead::id(opaque)], None)?
            .single()
            .is_none()
    );
    let mut world_only = root.clone();
    let world = EntityId::from_bytes([0x31; 16])?;
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(world)]));
    world_only.attenuate(SlipCaveat {
        scope: Some(scope),
        ..Default::default()
    })?;
    let narrowed = vault.verify_capability_slip(
        &issuer,
        &world_only,
        b"read-world",
        &issuer.binding_proof(&world_only, b"read-world")?,
    )?;
    assert!(
        vault
            .scoped_read(ScopedReadActorKey::from_verified_slip(&narrowed).expect("read proof"))
            .read(&[crate::claim::PointRead::id(id)], None)?
            .single()
            .is_none()
    );
    let mut named = root.clone();
    named.attenuate(SlipCaveat {
        records: Some(BTreeSet::from([opaque.to_hex()])),
        ..Default::default()
    })?;
    let named_proof = issuer.binding_proof(&named, b"named read")?;
    let verified = vault.verify_capability_slip(&issuer, &named, b"named read", &named_proof)?;
    let limited = vault.scoped_read(ScopedReadActorKey::from_verified_slip(&verified).unwrap());
    assert!(
        limited
            .read(&[crate::claim::PointRead::id(opaque)], None)?
            .single()
            .is_some()
    );
    assert!(
        limited
            .read(&[crate::claim::PointRead::id(id)], None)?
            .single()
            .is_none()
    );
    vault.delete_entity_with_reason(&id, crate::deletion::DeleteReason::UserDelete)?;
    // An erased claim cannot prove its read scope, so even the root proof
    // gets a withholding receipt instead of the deletion record.
    let timeline = read.memory_timeline(&id)?;
    assert!(timeline.records.is_empty());
    assert_eq!(timeline.receipt.suppressed_count, 1);
    assert!(limited.memory_timeline(&id)?.records.is_empty());
    assert!(unproven.memory_timeline(&id)?.records.is_empty());
    assert!(
        vault
            .scoped_read(ScopedReadActorKey::from_verified_slip(&narrowed).unwrap())
            .memory_timeline(&id)?
            .records
            .is_empty()
    );
    vault.revoke_capability_slip(&issuer, root.claims.slip_id)?;
    for revoked in [id, opaque] {
        assert!(matches!(
            read.read(&[crate::claim::PointRead::id(revoked)], None),
            Err(Error::InvalidClaimBody(
                "scoped read credential no longer live"
            ))
        ));
    }
    Ok(())
}
