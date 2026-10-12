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
    )?;
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
    issuer.attenuate(
        &mut world_only,
        SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        },
    )?;
    let narrowed = vault.verify_capability_slip(
        &issuer.public_key(),
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
    issuer.attenuate(
        &mut named,
        SlipCaveat {
            records: Some(BTreeSet::from([opaque.to_hex()])),
            ..Default::default()
        },
    )?;
    let named_proof = issuer.binding_proof(&named, b"named read")?;
    let verified =
        vault.verify_capability_slip(&issuer.public_key(), &named, b"named read", &named_proof)?;
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

/// Sol R7 on #1401: a credential that narrows neither worlds nor facets
/// excludes no TASK on them, so a TASK it is denied counts, stamped or not.
/// The root slip's NOTE-only search counts a replicated TASK, which arrives
/// unstamped, as it did before TASKs were born in worlds; a slip narrowed to
/// base reality cannot place that TASK, so it counts it nowhere.
#[test]
fn a_whole_slip_counts_an_unstamped_task_it_is_denied() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let writer = EntityId::now();
    vault.put_entity(
        &writer,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"writer",
    )?;
    // A TASK minted here lends the replica its body.
    let local = vault
        .memory(writer, crate::EdgeActorClass::Human)
        .tasks_create(&crate::task_verb::TaskCreateSpec::new(
            Value::from("lantern work"),
            None,
            None,
            Some(2),
        ))
        .expect("the writer creates a TASK")
        .task_ref
        .expect("the create mints a TASK");
    let body = vault.get(&local)?.expect("the TASK body");
    let replica = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &replica,
            crate::registry::ENTITY_TYPE_TASK,
            crate::TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .text(&replica, &[("body", "lantern harbor")])
        .commit()?;
    assert!(
        vault.record_scope(&replica)?.is_none(),
        "a replica is unstamped"
    );

    let issuer = HostSlipIssuer::from_secret(b"whole slip count host root")?;
    let mut base_only = vault.ensure_host_root_slip(&issuer)?;
    let root = vault.verified_host_root_slip(&issuer)?;
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]));
    issuer.attenuate(
        &mut base_only,
        SlipCaveat {
            scope: Some(scope),
            ..Default::default()
        },
    )?;
    let narrowed = vault.verify_capability_slip(
        &issuer.public_key(),
        &base_only,
        b"base only",
        &issuer.binding_proof(&base_only, b"base only")?,
    )?;
    let notes_only = crate::gate::RetrievalFilter {
        entity_types: Some(BTreeSet::from([crate::registry::ENTITY_TYPE_NOTE])),
        ..Default::default()
    };
    let counted = |proof: &crate::authority::VerifiedSlip| -> Result<usize> {
        Ok(vault
            .scoped_read(ScopedReadActorKey::from_verified_slip(proof).expect("read proof"))
            .search_text("lantern", 10, Some(&notes_only))?
            .receipt
            .suppressed_count)
    };
    assert_eq!(counted(&root)?, 1, "the root slip counts the replica");
    assert_eq!(counted(&narrowed)?, 0, "a base-only slip counts it nowhere");
    Ok(())
}

/// Astra #1384c: an epoch summary sits in the world its birth stamp proves.
/// A replica arrives unstamped, so a slip narrowed to base reality cannot
/// place it and counts it nowhere: its receipt is an absent id's, and its
/// retrieval neither finds nor counts it. A summary born here in base
/// reality, and one that is no epoch, read as base; one born in world W reads
/// in W and not in base.
#[test]
fn a_base_only_slip_counts_an_unplaced_epoch_summary_nowhere() -> Result<()> {
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochPlacement, EpochSummaryBody,
        encode_epoch_summary_body,
    };
    use crate::registry::ENTITY_TYPE_SUMMARY;
    let dir = tempfile::tempdir()?;
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default())?;
    let epoch = |n: u64| {
        encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: EntityId::now().to_hex(),
            epoch: n,
            turn_start: n * 3,
            turn_end: n * 3 + 2,
            level: EPOCH_SUMMARY_LEVEL,
            text: "the run read the harbor ledger".into(),
            actor: EntityId::now().to_hex(),
        })
    };
    let at = crate::TimeRange { start: 1, end: 1 };
    let (replica, base_born, world_born, plain) = (
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
        EntityId::now(),
    );
    vault
        .batch()
        .put_replicated(&replica, ENTITY_TYPE_SUMMARY, at, 1, &epoch(1)?)
        .put(&base_born, ENTITY_TYPE_SUMMARY, at, 1, &epoch(2)?)
        .put(&world_born, ENTITY_TYPE_SUMMARY, at, 1, &epoch(3)?)
        .put(
            &plain,
            ENTITY_TYPE_SUMMARY,
            at,
            1,
            b"a summary written by hand",
        )
        .text(&replica, &[("body", "harbor ledger")])
        .text(&base_born, &[("body", "harbor ledger")])
        .text(&world_born, &[("body", "harbor ledger")])
        .text(&plain, &[("body", "harbor ledger")])
        .commit()?;
    assert!(
        vault.record_scope(&replica)?.is_none(),
        "a replica is unstamped"
    );
    let world = EntityId::from_bytes([0x3b; 16])?;
    let placement = EpochPlacement {
        world: Some(world),
        facet: None,
    };
    vault.with_write_txn_grouped(|txn| placement.settle_in(&vault.store, txn, world_born))?;

    let issuer = HostSlipIssuer::from_secret(b"epoch world host root")?;
    let root_slip = vault.ensure_host_root_slip(&issuer)?;
    let root = vault.verified_host_root_slip(&issuer)?;
    let narrowed = |only: EntityId, context: &[u8]| -> Result<crate::authority::VerifiedSlip> {
        let mut slip = root_slip.clone();
        let mut scope = Scope::top();
        scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(only)]));
        issuer.attenuate(
            &mut slip,
            SlipCaveat {
                scope: Some(scope),
                ..Default::default()
            },
        )?;
        vault.verify_capability_slip(
            &issuer.public_key(),
            &slip,
            context,
            &issuer.binding_proof(&slip, context)?,
        )
    };
    let base_only = narrowed(crate::claim::base_world_id(), b"base only")?;
    let in_world = narrowed(world, b"world only")?;
    let read = |proof: &crate::authority::VerifiedSlip, id: EntityId| {
        vault
            .scoped_read(ScopedReadActorKey::from_verified_slip(proof).expect("read proof"))
            .read(&[crate::claim::PointRead::id(id)], None)
    };

    assert_eq!(
        read(&root, replica)?.receipt.suppressed_count,
        1,
        "the root slip is denied the unstamped replica and counts it"
    );
    let unplaced = read(&base_only, replica)?;
    assert_eq!(
        unplaced.receipt,
        read(&base_only, EntityId::now())?.receipt,
        "a base-only slip cannot place the replica, so it reads as absent"
    );
    assert!(unplaced.single().is_none());
    let found = |proof: &crate::authority::VerifiedSlip| -> Result<(Vec<EntityId>, usize)> {
        let hits = vault
            .scoped_read(ScopedReadActorKey::from_verified_slip(proof).expect("read proof"))
            .search_text("harbor", 10, None)?;
        Ok((hits.iter().map(|hit| hit.id).collect(), hits.receipt.suppressed_count))
    };
    let (in_base, counted) = found(&base_only)?;
    assert!(
        in_base.contains(&base_born) && in_base.contains(&plain),
        "a base-only retrieval finds the base summaries"
    );
    assert!(
        !in_base.contains(&replica) && !in_base.contains(&world_born),
        "a base-only retrieval returns neither the replica nor the W-born epoch"
    );
    assert_eq!(counted, 0, "a base-only retrieval counts the replica nowhere");
    assert!(
        found(&in_world)?.0.contains(&world_born),
        "a W-only retrieval finds the W-born epoch"
    );
    for (id, what) in [
        (base_born, "a base-born epoch"),
        (plain, "a summary that is no epoch"),
    ] {
        assert!(
            read(&base_only, id)?.single().is_some(),
            "{what} reads as base"
        );
    }
    assert!(
        read(&in_world, world_born)?.single().is_some(),
        "a W-born epoch reads in W"
    );
    assert!(
        read(&base_only, world_born)?.single().is_none(),
        "a W-born epoch is not base"
    );
    Ok(())
}
