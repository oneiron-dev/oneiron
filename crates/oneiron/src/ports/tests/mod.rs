//! One behavioral suite, two transaction implementations.
mod step21_conformance;
mod step22_conformance;
mod step23_conformance;
mod support;

mod migration_conformance;

use super::{
    ChangeLogStore, ChangeOp, DocumentRow, DocumentRowStore, DocumentSlot, EntityRecord,
    EntityStore, PendingUpdate, UpdateSeq,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::error::{Error, RegistryError, Result};
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    SurvivorshipPlan, decode_identity_topology_event_body,
};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON, ENTITY_TYPE_REDACTION_AUDIT};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

fn record(entity_type: u8, body: &[u8]) -> EntityRecord {
    EntityRecord {
        entity_type,
        occurred: TimeRange { start: 1, end: 1 },
        learned_at: 2,
        body: body.to_vec(),
    }
}

#[test]
fn a_port_entity_put_passes_the_same_gates_as_a_batch_put() -> Result<()> {
    let (_dir, vault) = open_vault();
    let mut claim = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(EntityId::now()),
        rmpv::Value::from("Alice"),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    claim.source = Some(ClaimSource::UserStated);
    let row = record(ENTITY_TYPE_CLAIM, &crate::claim::encode_claim_body(&claim)?);

    let port_claim = EntityId::now();
    let through_port = vault
        .with_write_txn(|txn| vault.port_entity_put(txn, &port_claim, &row))
        .expect_err("a raw claim carrying a source is refused through the port");
    let batch_claim = EntityId::now();
    let through_batch = vault
        .batch()
        .put(
            &batch_claim,
            row.entity_type,
            row.occurred,
            row.learned_at,
            &row.body,
        )
        .commit()
        .expect_err("a raw claim carrying a source is refused through the batch");

    assert_eq!(through_port.kind(), through_batch.kind());
    assert!(
        matches!(
            (&through_port, &through_batch),
            (Error::InvalidClaimBody(port), Error::InvalidClaimBody(batch)) if port == batch
        ),
        "{through_port:?} vs {through_batch:?}"
    );
    assert!(vault.get_claim(&port_claim)?.is_none());
    assert!(vault.get_claim(&batch_claim)?.is_none());
    Ok(())
}

#[test]
fn the_entity_port_put_refuses_what_the_batch_entry_refuses() -> Result<()> {
    let (_dir, vault) = open_vault();
    let row = record(ENTITY_TYPE_REDACTION_AUDIT, b"receipt");
    let id = EntityId::now();

    let through_port = vault
        .with_write_txn(|txn| vault.port_entity_put(txn, &id, &row))
        .expect_err("a maintenance kind is refused through the port");
    let through_batch = vault
        .batch()
        .put(
            &id,
            row.entity_type,
            row.occurred,
            row.learned_at,
            &row.body,
        )
        .commit()
        .expect_err("a maintenance kind is refused through the batch");

    for error in [through_port, through_batch] {
        assert!(
            matches!(
                error,
                Error::Registry(RegistryError::MaintenanceKindNotWritable(kind))
                    if kind == ENTITY_TYPE_REDACTION_AUDIT
            ),
            "{error:?}"
        );
    }
    assert!(vault.get_raw(&id)?.is_none());
    Ok(())
}

#[test]
fn no_raw_entity_edge_or_claim_write_remains_outside_ports() {
    use crate::test_util::source_scan::{SourceTree, production_source};

    let tree = SourceTree::read(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"));
    let raw_write = regex::Regex::new(
        r"\.\s*store\s*\.\s*(entities|edges_out|edges_in|claims)\s*\.\s*(put|delete|delete_range)\b",
    )
    .expect("raw write pattern");
    let mut scanned = 0_usize;
    let mut offenders = Vec::new();
    for (path, source) in tree.production_sources() {
        let relative = tree.relative(path);
        if relative.starts_with("ports/") {
            continue;
        }
        scanned += 1;
        let source = production_source(source);
        for hit in raw_write.find_iter(&source) {
            let line = source[..hit.start()].matches('\n').count() + 1;
            offenders.push(format!("{relative}:{line}"));
        }
    }

    // A floor, not a count: the crate held about 1,900 production files outside ports/.
    assert!(
        scanned >= 1_000,
        "the scan read only {scanned} files; it is mislocated"
    );
    assert!(
        offenders.is_empty(),
        "raw entity, edge or claim writes outside ports/: {offenders:#?}"
    );
}

#[test]
fn an_erased_record_is_rewritten_through_the_scrub_port() -> Result<()> {
    let (_dir, vault) = open_vault();
    let actor = EntityId::now();
    let survivor = EntityId::now();
    let loser = EntityId::now();
    for id in [&actor, &survivor, &loser] {
        vault.put_entity(
            id,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 200,
                end: 200,
            },
            201,
            b"scrub fixture body",
        )?;
    }
    let merge = IdentityTopologyOp::Merge(MergeOp {
        sources: vec![loser],
        survivor,
        evidence: IdentityOpEvidence::default(),
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    });
    let write = IdentityOpWrite::auto(ClaimSource::Inferred)
        .with_actor(WriteActor::new(actor, EdgeActorClass::Human));
    let event = match vault.apply_identity_topology_op(&merge, &write, 202)? {
        IdentityOpOutcome::Applied { event, .. } => event,
        outcome => panic!("auto merge must apply, got {outcome:?}"),
    };
    let authored = vault.get_raw(&event)?.expect("ledger event");
    let authored_event =
        decode_identity_topology_event_body(&authored[ENTITY_METADATA_HEADER_LEN..])?;
    assert!(authored_event.actor.is_some());

    vault.delete_entity_with_reason(&survivor, DeleteReason::UserHardDelete)?;

    let scrubbed = vault.get_raw(&event)?.expect("retained ledger event");
    assert_eq!(
        scrubbed[..ENTITY_METADATA_HEADER_LEN],
        authored[..ENTITY_METADATA_HEADER_LEN]
    );
    let scrubbed_event =
        decode_identity_topology_event_body(&scrubbed[ENTITY_METADATA_HEADER_LEN..])?;
    assert_eq!(scrubbed_event.actor, None);
    assert_eq!(scrubbed_event.action, authored_event.action);
    let rtxn = vault.store.env.read_txn()?;
    let audit = vault.port_changelog_list_by_entity(&rtxn, &event, 100)?;
    assert!(
        audit.iter().any(|row| row.op == ChangeOp::Redact),
        "{audit:?}"
    );
    Ok(())
}

#[test]
fn a_document_row_port_write_marks_the_state_vector_stale() -> Result<()> {
    let (_dir, vault) = open_vault();
    let slot = DocumentSlot::of(EntityId::now());
    let store = &vault.store;

    let seq = vault.with_write_txn(|txn| {
        store.port_document_snapshot_put(txn, slot, b"snapshot")?;
        store.port_document_state_vector_put(txn, slot, b"state vector")?;
        store.port_document_update_append(txn, slot, b"update")
    })?;

    assert_eq!(seq, 1);
    let rtxn = store.env.read_txn()?;
    assert_eq!(
        store.port_document_updates(&rtxn, slot)?,
        vec![PendingUpdate {
            seq: Some(UpdateSeq::Sequence(1)),
            bytes: b"update".to_vec(),
        }]
    );
    let key = format!("u:e:{}:00000001", slot.to_hex());
    assert_eq!(
        store.sync_state.get(&rtxn, &key)?.as_deref(),
        Some(&b"update"[..])
    );
    assert_eq!(
        store.port_document_row(&rtxn, slot, DocumentRow::StateVector)?,
        None
    );
    assert_eq!(
        store.port_document_row(&rtxn, slot, DocumentRow::Snapshot)?,
        Some(b"snapshot".to_vec())
    );
    Ok(())
}
