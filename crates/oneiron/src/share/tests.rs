use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, encode_claim_body};
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, entity, entity_record, put_policy_manifest_bytes};

mod recipient_class;

pub(crate) fn fixture() -> Result<(tempfile::TempDir, Vault, WriteActor, Share)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), embedding_test_config())?;
    let issuer = WriteActor::new(entity(0x51), EdgeActorClass::Human);
    let share = Share {
        recipient_ref: entity(0x52),
        brief_ref: "brief:opaque-report".to_owned(),
        world_refs: BTreeSet::from([entity(0x61), entity(0x62)]),
        facet_refs: BTreeSet::from([entity(0x71), entity(0x72)]),
        include_unscoped: true,
        status: AccessGrantStatus::Active,
        created_at: 42,
        revoked_at: None,
    };
    vault.put_entity(
        &issuer.entity_ref(),
        ENTITY_TYPE_PERSON,
        time(1),
        1,
        b"issuer",
    )?;
    vault.put_entity(
        &share.recipient_ref,
        ENTITY_TYPE_PERSON,
        time(1),
        1,
        b"recipient",
    )?;
    for facet in &share.facet_refs {
        vault.put_entity(facet, ENTITY_TYPE_FACET, time(1), 1, b"facet")?;
    }
    policy(&vault, &issuer, &share, true, None)?;
    Ok((dir, vault, issuer, share))
}

fn time(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn policy(
    vault: &Vault,
    issuer: &WriteActor,
    share: &Share,
    allow_create: bool,
    read_scope: Option<Value>,
) -> Result<()> {
    let mut grants = Vec::new();
    if allow_create {
        grants.push(Value::Map(vec![
            (
                Value::from("actor_ref"),
                Value::from(issuer.entity_ref().to_hex()),
            ),
            (Value::from("effector"), Value::from("external:share_brief")),
            (
                Value::from("scope"),
                Value::Map(vec![(Value::from("channel"), Value::from("shared_brief"))]),
            ),
        ]));
    }
    grants.push(Value::Map(vec![
        (
            Value::from("actor_ref"),
            Value::from(share.recipient_ref.to_hex()),
        ),
        (Value::from("effector"), Value::from("core:read")),
        (Value::from("scope"), read_scope.unwrap_or(Value::Nil)),
        (Value::from("receipt_required"), Value::Boolean(false)),
    ]));
    let value = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("brief-share-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(vec![])),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("human")),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
        (Value::from("scoped_grants"), Value::Array(grants)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("policy encoding");
    put_policy_manifest_bytes(vault, crate::gate::default_policy_manifest_id()?, &bytes)
}

fn read_scope(world: EntityId, facet: EntityId) -> Value {
    Value::Map(vec![
        (Value::from("world_ref"), Value::from(world.to_hex())),
        (Value::from("facet_ref"), Value::from(facet.to_hex())),
    ])
}

fn claim(
    vault: &Vault,
    id: EntityId,
    world: Option<EntityId>,
    facets: &[EntityId],
    stale: bool,
) -> Result<()> {
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(entity(0x53)),
        Value::from("private value"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    body.world = world;
    body.stale = stale;
    let bytes = encode_claim_body(&body)?;
    vault.with_write_txn(|txn| {
        let raw = entity_record(ENTITY_TYPE_CLAIM, time(1), 1, &bytes);
        vault.store.entities.put(txn, id.as_bytes(), &raw)?;
        Ok(())
    })?;
    for facet in facets {
        vault.put_edge(&id, EdgeKind::FacetOf, facet, 1.0)?;
    }
    Ok(())
}

fn visible(
    vault: &Vault,
    id: &EntityId,
    share: &Share,
    candidates: &[EntityId],
) -> Result<Vec<EntityId>> {
    Ok(vault
        .resolve_share_for_view(id, &share.recipient_ref, None, candidates)?
        .expect("active share")
        .visible_claim_refs)
}

#[test]
fn share_writes_receipt() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    vault.create_share(&id, &issuer, &share)?;
    assert_eq!(vault.get_entity_type(&id)?, Some(ENTITY_TYPE_ACCESS_GRANT));
    assert_eq!(vault.get_access_grant(&id)?, Some(share.grant()));
    let query = ReceiptQuery::new(20).with_kind(ReceiptKind::Share);
    let receipts = vault.receipts(query.clone())?;
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_id, format!("share:brief:{}", id.to_hex()));
    assert_eq!(receipt.outcome, "granted");
    assert_eq!(receipt.occurred_at, 42);
    assert_eq!(receipt.fields["brief_ref"], share.brief_ref);
    assert_eq!(
        receipt.fields["recipient_ref"],
        share.recipient_ref.to_hex()
    );
    assert_eq!(
        receipt.fields["redaction_scope_hash"],
        share.redaction_scope_hash()
    );
    let gates = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    assert!(
        gates
            .iter()
            .any(|gate| gate.receipt_id == receipt.policy_trace[0] && gate.outcome == "allow")
    );
    assert_eq!(vault.receipts(query)?, receipts);
    assert!(
        vault
            .receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::ScopedRead))?
            .is_empty()
    );
    Ok(())
}

#[test]
fn render_time_scope_redaction() -> Result<()> {
    let (_dir, vault, issuer, mut share) = fixture()?;
    share.world_refs = BTreeSet::from([entity(0x61)]);
    share.facet_refs = BTreeSet::from([entity(0x71)]);
    let id = entity(0x81);
    vault.create_share(&id, &issuer, &share)?;
    let [base, allowed, wrong_world, wrong_facet, multiple] =
        [0x91, 0x92, 0x93, 0x94, 0x95].map(entity);
    claim(&vault, base, None, &[], false)?;
    claim(&vault, allowed, Some(entity(0x61)), &[entity(0x71)], false)?;
    claim(
        &vault,
        wrong_world,
        Some(entity(0x62)),
        &[entity(0x71)],
        false,
    )?;
    claim(
        &vault,
        wrong_facet,
        Some(entity(0x61)),
        &[entity(0x72)],
        false,
    )?;
    claim(
        &vault,
        multiple,
        Some(entity(0x61)),
        &[entity(0x71), entity(0x72)],
        false,
    )?;
    let candidates = [
        base,
        allowed,
        wrong_world,
        wrong_facet,
        multiple,
        allowed,
        entity(0x96),
    ];
    assert_eq!(
        visible(&vault, &id, &share, &candidates)?,
        vec![base, allowed, multiple]
    );

    // The recipient's authority changes AFTER creation, without request narrowing.
    policy(
        &vault,
        &issuer,
        &share,
        true,
        Some(read_scope(entity(0x61), entity(0x72))),
    )?;
    assert!(
        visible(&vault, &id, &share, &candidates)?.is_empty(),
        "facets A and B must not combine across stored and live grants"
    );
    policy(
        &vault,
        &issuer,
        &share,
        true,
        Some(read_scope(entity(0x61), entity(0x71))),
    )?;
    assert_eq!(
        visible(&vault, &id, &share, &candidates)?,
        vec![allowed, multiple]
    );

    // Re-read the candidate body, not a cached rendered copy or prior admission.
    claim(&vault, allowed, Some(entity(0x62)), &[], false)?;
    claim(&vault, multiple, Some(entity(0x61)), &[], true)?;
    assert!(visible(&vault, &id, &share, &candidates)?.is_empty());
    policy(&vault, &issuer, &share, true, None)?;
    let request = ShareViewerScope {
        world_refs: BTreeSet::from([entity(0x61), entity(0x62)]),
        facet_refs: BTreeSet::from([entity(0x71), entity(0x72)]),
        include_unscoped: false,
    };
    let view = vault
        .resolve_share_for_view(&id, &share.recipient_ref, Some(&request), &candidates)?
        .expect("active share");
    assert!(
        view.visible_claim_refs.is_empty(),
        "a wide request cannot widen the stored maximum"
    );
    Ok(())
}

#[test]
fn revoke_stops_resolution_and_cannot_be_bypassed() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    vault.create_share(&id, &issuer, &share)?;
    let created = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Share))?[0].clone();
    let stranger = WriteActor::new(entity(0x54), EdgeActorClass::Human);
    vault.put_entity(
        &stranger.entity_ref(),
        ENTITY_TYPE_PERSON,
        time(1),
        1,
        b"not owner",
    )?;
    assert!(vault.revoke_share(&id, &stranger, 50).is_err());
    assert!(vault.revoke_share(&id, &issuer, 41).is_err());
    assert!(vault.revoke_access_grant(&id, 50).is_err());
    assert!(vault.revoke_calendar_access_grant(&id, 50).is_err());
    assert!(
        vault
            .put_access_grant(
                &id,
                &AccessGrant::companion_profile_read(entity(0x52), entity(0x53), entity(0x54), 1)
            )
            .is_err()
    );
    // Make all new external effects Pending. Stopping an issued share still works.
    policy(&vault, &issuer, &share, false, None)?;
    let revoked = vault.revoke_share(&id, &issuer, 60)?;
    assert_eq!(revoked.status, AccessGrantStatus::Revoked);
    assert_eq!(vault.revoke_share(&id, &issuer, 70)?, revoked);
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[])?
            .is_none()
    );
    assert!(vault.create_share(&id, &issuer, &share).is_err());
    assert!(vault.put_access_grant(&id, &share.grant()).is_err());
    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Share))?;
    assert_eq!(receipts.len(), 2);
    assert!(
        receipts.contains(&created),
        "creation receipt is byte-stable after revocation"
    );
    let stopped = receipts
        .iter()
        .find(|receipt| receipt.outcome == "revoked")
        .expect("revoke receipt");
    assert_eq!(stopped.occurred_at, 60);
    assert_eq!(
        stopped.receipt_id,
        format!("share:brief:{}:revoked", id.to_hex())
    );
    // A stale replay of the active body cannot undo the local stop latch.
    vault.with_write_txn(|txn| {
        vault.apply_access_grant_body(txn, &id, 42, encode_access_grant_body(&share.grant())?)
    })?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[])?
            .is_none()
    );
    Ok(())
}

#[test]
fn pending_never_creates_and_generic_grants_never_mint_shares() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    policy(&vault, &issuer, &share, false, None)?;
    assert!(matches!(
        vault.create_share(&id, &issuer, &share),
        Err(Error::GateWriteRejected { .. })
    ));
    assert!(vault.get_access_grant(&id)?.is_none());
    assert!(
        vault
            .receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Share))?
            .is_empty()
    );
    assert!(
        vault
            .gate_decisions(20)?
            .iter()
            .any(|record| record.outcome == "pending")
    );
    assert!(vault.put_access_grant(&id, &share.grant()).is_err());
    assert!(vault.create_access_grant(&id, &share.grant()).is_err());
    assert!(
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_ACCESS_GRANT,
                time(42),
                42,
                &encode_access_grant_body(&share.grant())?
            )
            .is_err()
    );
    policy(&vault, &issuer, &share, true, None)?;
    vault.create_share(&id, &issuer, &share)?;
    assert!(
        vault
            .resolve_share_for_view(&id, &issuer.entity_ref(), None, &[])?
            .is_none()
    );
    assert!(
        vault
            .resolve_share_for_view(&entity(0x82), &share.recipient_ref, None, &[])?
            .is_none()
    );
    Ok(())
}

#[test]
fn effect_authority_binds_every_immutable_share_axis() -> Result<()> {
    let (_dir, _vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    let effect = crate::gate::share_create_effect(&id, &issuer, &share)?;
    let mut variants = Vec::new();
    let mut other = share.clone();
    other.brief_ref.push('x');
    variants.push(other);
    let mut other = share.clone();
    other.recipient_ref = entity(0x53);
    variants.push(other);
    let mut other = share.clone();
    other.world_refs.insert(entity(0x63));
    variants.push(other);
    let mut other = share.clone();
    other.facet_refs.insert(entity(0x73));
    variants.push(other);
    let mut other = share.clone();
    other.include_unscoped = false;
    variants.push(other);
    for other in variants {
        assert_ne!(
            effect.brief_ref,
            crate::gate::share_create_effect(&id, &issuer, &other)?.brief_ref
        );
    }
    assert_ne!(
        effect.brief_ref,
        crate::gate::share_create_effect(&entity(0x82), &issuer, &share)?.brief_ref
    );
    let other = WriteActor::new(entity(0x54), EdgeActorClass::Human);
    assert_ne!(
        effect.brief_ref,
        crate::gate::share_create_effect(&id, &other, &share)?.brief_ref
    );
    let mut reordered = share.clone();
    reordered.world_refs = share.world_refs.iter().rev().copied().collect();
    assert_eq!(
        share.redaction_scope_hash(),
        reordered.redaction_scope_hash()
    );
    assert_eq!(
        effect.brief_ref,
        crate::gate::share_create_effect(&id, &issuer, &reordered)?.brief_ref
    );
    Ok(())
}

#[test]
fn malformed_or_unadmitted_share_rows_return_no_view() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    // Simulate an opaque imported maintenance row. It has no local gate admission.
    vault.with_write_txn(|txn| {
        vault.apply_access_grant_body(txn, &id, 42, encode_access_grant_body(&share.grant())?)
    })?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[])?
            .is_none()
    );
    let admitted_id = entity(0x82);
    vault.create_share(&admitted_id, &issuer, &share)?;
    for bytes in [
        vec![],
        vec![ENTITY_TYPE_ACCESS_GRANT],
        entity_record(ENTITY_TYPE_ACCESS_GRANT, time(42), 42, b"bad body"),
    ] {
        vault.with_write_txn(|txn| {
            vault
                .store
                .entities
                .put(txn, admitted_id.as_bytes(), &bytes)?;
            Ok(())
        })?;
        assert!(
            vault
                .resolve_share_for_view(&admitted_id, &share.recipient_ref, None, &[])?
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn changed_policy_world_and_malformed_policy_fail_closed() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    let claim_id = entity(0x91);
    vault.create_share(&id, &issuer, &share)?;
    claim(&vault, claim_id, Some(entity(0x61)), &[entity(0x71)], false)?;
    policy(
        &vault,
        &issuer,
        &share,
        true,
        Some(read_scope(entity(0x61), entity(0x71))),
    )?;
    assert_eq!(visible(&vault, &id, &share, &[claim_id])?, vec![claim_id]);
    policy(
        &vault,
        &issuer,
        &share,
        true,
        Some(read_scope(entity(0x62), entity(0x71))),
    )?;
    assert!(visible(&vault, &id, &share, &[claim_id])?.is_empty());
    put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        b"invalid",
    )?;
    assert!(visible(&vault, &id, &share, &[claim_id])?.is_empty());
    // A broken policy is no new consent barrier to an authorized stop.
    vault.revoke_share(&id, &issuer, 60)?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[claim_id])?
            .is_none()
    );
    Ok(())
}

#[test]
fn share_admission_binding_rejects_tampering_and_foreign_actor_classes() -> Result<()> {
    let (_dir, vault, issuer, share) = fixture()?;
    let id = entity(0x81);
    let forged = WriteActor::new(issuer.entity_ref(), EdgeActorClass::System);
    assert!(vault.create_share(&id, &forged, &share).is_err());
    vault.create_share(&id, &issuer, &share)?;
    let original = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&txn, &admission_key(&id))?
            .expect("admission")
            .to_vec()
    };
    for bad in [vec![], vec![1], [original.as_slice(), &[0]].concat()] {
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, &admission_key(&id), &bad)?;
            Ok(())
        })?;
        assert!(
            vault
                .resolve_share_for_view(&id, &share.recipient_ref, None, &[])?
                .is_none()
        );
    }
    vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .put(txn, &admission_key(&id), &original)?;
        Ok(())
    })?;
    let mut altered = share.clone();
    altered.world_refs.insert(entity(0x63));
    vault.with_write_txn(|txn| {
        vault.apply_access_grant_body(txn, &id, 42, encode_access_grant_body(&altered.grant())?)
    })?;
    assert!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, None, &[])?
            .is_none()
    );
    Ok(())
}

#[test]
fn include_unscoped_is_conjunctive_in_both_dimensions() -> Result<()> {
    let (_dir, vault, issuer, mut share) = fixture()?;
    share.include_unscoped = false;
    let id = entity(0x81);
    vault.create_share(&id, &issuer, &share)?;
    let candidates = [entity(0x91), entity(0x92), entity(0x93), entity(0x94)];
    claim(&vault, candidates[0], None, &[], false)?;
    claim(&vault, candidates[1], None, &[entity(0x71)], false)?;
    claim(&vault, candidates[2], Some(entity(0x61)), &[], false)?;
    claim(
        &vault,
        candidates[3],
        Some(entity(0x61)),
        &[entity(0x71)],
        false,
    )?;
    assert_eq!(
        visible(&vault, &id, &share, &candidates)?,
        vec![candidates[3]]
    );
    let request = ShareViewerScope {
        world_refs: share.world_refs.clone(),
        facet_refs: share.facet_refs.clone(),
        include_unscoped: true,
    };
    assert_eq!(
        vault
            .resolve_share_for_view(&id, &share.recipient_ref, Some(&request), &candidates)?
            .expect("active share")
            .visible_claim_refs,
        vec![candidates[3]]
    );
    Ok(())
}
