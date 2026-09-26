//! Native writer fixtures for the Imported-only expression archive adapter.
use super::*;
use crate::batch::{BatchOp, apply_ops};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    ExpressionPreferenceChange, ExpressionPreferenceKind, ExpressionPreferenceOrigin,
    ExpressionPreferenceValue, decode_claim_body, encode_claim_body,
};
use crate::context_pack::PackFormat;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, GateError, Result};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST};
use crate::serialize::ExportBody;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault, VaultConfig};
use rmpv::Value;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn fresh_vault() -> Result<(tempfile::TempDir, Vault, WriteActor)> {
    let dir = tempfile::tempdir()?;
    // Real open/seed path, not a raw-store fixture or replicated write.
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let writer = WriteActor::new(EntityId::now(), EdgeActorClass::Human);
    vault.put_entity(
        &writer.entity_ref(),
        ENTITY_TYPE_PERSON,
        at(1),
        1,
        b"local writer",
    )?;
    Ok((dir, vault, writer))
}

/// Local host policy fixture through the native maintenance apply path (the
/// graph_fs fixture pattern). This does NOT put raw LMDB bytes or use replay.
fn local_policy(vault: &Vault, permit: Option<EntityId>, ceiling: &str) -> Result<()> {
    let mut entries = vec![
        ("schema_version".into(), "1.1".into()),
        ("pack_id".into(), "expression-archive-fixture".into()),
        ("pack_version".into(), "v1".into()),
        (
            "min_engine_version".into(),
            env!("CARGO_PKG_VERSION").into(),
        ),
        (
            "defaults".into(),
            Value::Map(vec![
                ("criticality".into(), "normal".into()),
                ("sensitivity".into(), "normal".into()),
            ]),
        ),
        ("rules".into(), Value::Array(vec![])),
        (
            "actor_ceilings".into(),
            Value::Array(vec![
                Value::Map(vec![
                    ("actor_class".into(), "human".into()),
                    ("ceiling".into(), ceiling.into()),
                ]),
                Value::Map(vec![
                    ("actor_class".into(), "first_party".into()),
                    ("ceiling".into(), "auto".into()),
                ]),
            ]),
        ),
    ];
    if let Some(actor) = permit {
        entries.push((
            "source_trust".into(),
            Value::Map(vec![(
                "imported".into(),
                Value::Map(vec![
                    ("actor_ref".into(), actor.to_hex().into()),
                    (
                        "max_auto_sensitivity".into(),
                        u64::from(crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND).into(),
                    ),
                    ("receipted".into(), true.into()),
                    ("warned".into(), true.into()),
                ]),
            )]),
        ));
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).unwrap();
    vault.with_write_txn(|txn| {
        apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Put {
                id: crate::gate::default_policy_manifest_id()?,
                entity_type: ENTITY_TYPE_POLICY_MANIFEST,
                occurred: at(1),
                learned_at: 1,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            true,
            true,
            true,
        )
    })
}

fn preference(
    vault: &Vault,
    actor: &WriteActor,
    subject: EntityId,
    language: &str,
    origin: ExpressionPreferenceOrigin,
    time: u64,
) -> Result<EntityId> {
    let id = EntityId::now();
    vault.set_expression_preference(
        actor,
        id,
        ExpressionPreferenceChange {
            subject,
            value: ExpressionPreferenceValue::Language(language.into()),
            origin,
            valid_from: time,
        },
        at(time),
        time,
    )?;
    Ok(id)
}

struct Archive {
    bytes: Vec<u8>,
    subject: EntityId,
    first: EntityId,
    head: EntityId,
    dependent: EntityId,
    foreign_writer: WriteActor,
}

fn archive(origins: [ExpressionPreferenceOrigin; 2]) -> Result<Archive> {
    let (_dir, source, writer) = fresh_vault()?;
    local_policy(&source, None, "auto")?;
    let subject = EntityId::now();
    source.put_entity(&subject, ENTITY_TYPE_PERSON, at(1), 1, b"subject")?;
    let first = preference(&source, &writer, subject, "ja", origins[0], 10)?;
    let head = preference(&source, &writer, subject, "en-US", origins[1], 20)?;
    let dependent = EntityId::now();
    source.put_claim(
        &dependent,
        &ClaimBody::new(
            "archive.preference_note",
            ClaimSubject::Entity(head),
            "dependent".into(),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )?,
        at(30),
        30,
    )?;
    let bytes = source
        .export_whole_vault(PackFormat::Json)?
        .bytes()
        .to_vec();
    Ok(Archive {
        bytes,
        subject,
        first,
        head,
        dependent,
        foreign_writer: writer,
    })
}

fn stored_graph(vault: &Vault) -> Result<(Vec<ExportEntity>, Vec<ExportEdge>)> {
    let export = vault.export_whole_vault(PackFormat::Json)?;
    let document = vault.read_whole_vault_json(export.bytes())?;
    let mut entities: Vec<_> = document.entities().cloned().collect();
    entities.sort_by(|a, b| a.id.cmp(&b.id));
    Ok((entities, document.evidence_ledger.edges))
}

#[test]
fn expression_archive_requires_current_local_writer_and_auto_policy_atomically() -> Result<()> {
    let archive = archive([ExpressionPreferenceOrigin::ExplicitUser; 2])?;
    let (_dir, target, writer) = fresh_vault()?;
    let manifest = target.read_whole_vault_json(&archive.bytes)?.manifest;
    assert!(manifest.import_refusals.iter().any(|refusal| matches!(refusal,
        ExportImportRefusal::Entity { entity_id, reason: ImportRefusalReason::LocalExpressionWriterRequired }
            if *entity_id == archive.head.to_hex())));
    let before = stored_graph(&target)?;
    assert!(matches!(
        target.import_whole_vault_json(&archive.bytes),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(stored_graph(&target)?, before);
    // An archive author is not a local writer even when the archive carries its PERSON.
    assert!(matches!(
        target.import_whole_vault_json_with_actor(&archive.bytes, &archive.foreign_writer),
        Err(Error::EntityNotFound)
    ));
    assert_eq!(stored_graph(&target)?, before);
    for (permit, ceiling) in [
        (None, "auto"),
        (Some(archive.foreign_writer.entity_ref()), "auto"),
        (Some(writer.entity_ref()), "proposed"),
    ] {
        local_policy(&target, permit, ceiling)?;
        let before = stored_graph(&target)?;
        assert!(matches!(
            target.import_whole_vault_json_with_actor(&archive.bytes, &writer),
            Err(Error::Gate(GateError::FamilyRequiresAutoGrant { .. }))
        ));
        assert_eq!(stored_graph(&target)?, before);
        assert!(target.get_claim(&archive.first)?.is_none());
        assert!(target.get_claim(&archive.head)?.is_none());
        assert!(target.pending_gate_consents(128)?.is_empty());
    }
    Ok(())
}

#[test]
fn expression_archive_restores_native_generations_with_fresh_provenance_and_safe_repeats()
-> Result<()> {
    let archive = archive([ExpressionPreferenceOrigin::ExplicitUser; 2])?;
    let (_dir, target, writer) = fresh_vault()?;
    local_policy(&target, Some(writer.entity_ref()), "auto")?;
    target.import_whole_vault_json_with_actor(&archive.bytes, &writer)?;
    for (id, lifecycle, valid_to) in [
        (archive.first, ClaimLifecycleStatus::Superseded, Some(20)),
        (archive.head, ClaimLifecycleStatus::Active, None),
    ] {
        let body = target.get_claim(&id)?.unwrap();
        assert_eq!(body.source, Some(ClaimSource::Imported));
        assert_eq!(body.approval, ClaimApprovalStatus::Auto);
        assert_eq!(body.lifecycle, lifecycle);
        assert_eq!(body.valid_to, valid_to);
        assert_eq!(
            crate::claim::session_claim_producer(&body),
            Some(writer.entity_ref())
        );
        assert_ne!(
            crate::claim::session_claim_producer(&body),
            Some(archive.foreign_writer.entity_ref())
        );
    }
    let preferences = target.expression_preferences(&archive.subject, 30)?;
    assert_eq!(preferences.language.as_deref(), Some("en-US"));
    assert_eq!(
        preferences
            .winning_claim_ids
            .get(&ExpressionPreferenceKind::Language),
        Some(&archive.head)
    );
    assert_eq!(
        target.get_claim(&archive.dependent)?.unwrap().subject,
        ClaimSubject::Entity(archive.head)
    );
    assert!(
        target
            .edges_out(&archive.head)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::Supersedes && edge.target == archive.first)
    );
    let before = stored_graph(&target)?;
    let repeated = target.import_whole_vault_json_with_actor(&archive.bytes, &writer)?;
    assert_eq!(repeated.inserted_entities, 0);
    assert_eq!(stored_graph(&target)?, before);
    // Same id and provenance, divergent archive body: the local receipt is not
    // an id-wide permit. Keep the derivation index unchanged (evidence is unchanged).
    let mut divergent = target.read_whole_vault_json(&archive.bytes)?;
    let row = divergent
        .claims
        .iter_mut()
        .find(|row| row.id == archive.head.to_hex())
        .unwrap();
    let mut body = decode_claim_body(&row.body.to_bytes()?, false)?;
    body.value = "de-DE".into();
    row.body = ExportBody::from_bytes(&encode_claim_body(&body)?, row.entity_type);
    assert!(matches!(
        target
            .import_whole_vault_json_with_actor(&serde_json::to_vec(&divergent).unwrap(), &writer),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(stored_graph(&target)?, before);
    // A later local lifecycle change invalidates the actual-result half too.
    preference(
        &target,
        &writer,
        archive.subject,
        "fr",
        ExpressionPreferenceOrigin::ExplicitUser,
        40,
    )?;
    let before = stored_graph(&target)?;
    assert!(matches!(
        target.import_whole_vault_json_with_actor(&archive.bytes, &writer),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(stored_graph(&target)?, before);
    Ok(())
}

#[test]
fn expression_archive_cannot_supersede_an_existing_local_explicit_preference() -> Result<()> {
    let archive = archive([ExpressionPreferenceOrigin::ExplicitUser; 2])?;
    let (_dir, target, writer) = fresh_vault()?;
    local_policy(&target, Some(writer.entity_ref()), "auto")?;
    target.put_entity(&archive.subject, ENTITY_TYPE_PERSON, at(1), 1, b"subject")?;
    let local = preference(
        &target,
        &writer,
        archive.subject,
        "fr",
        ExpressionPreferenceOrigin::ExplicitUser,
        2,
    )?;
    target.import_whole_vault_json_with_actor(&archive.bytes, &writer)?;
    assert_eq!(
        target.get_claim(&local)?.unwrap().lifecycle,
        ClaimLifecycleStatus::Active
    );
    assert_eq!(
        target.get_claim(&archive.head)?.unwrap().source,
        Some(ClaimSource::Imported)
    );
    let resolved = target.expression_preferences(&archive.subject, 30)?;
    assert_eq!(resolved.language.as_deref(), Some("fr"));
    assert_eq!(
        resolved
            .winning_claim_ids
            .get(&ExpressionPreferenceKind::Language),
        Some(&local)
    );
    Ok(())
}

#[test]
fn expression_archive_refuses_mixed_precedence_and_missing_history_without_writes() -> Result<()> {
    let (_dir, target, writer) = fresh_vault()?;
    local_policy(&target, Some(writer.entity_ref()), "auto")?;
    let mixed = archive([
        ExpressionPreferenceOrigin::Inferred,
        ExpressionPreferenceOrigin::ExplicitUser,
    ])?;
    let before = stored_graph(&target)?;
    assert!(matches!(
        target.import_whole_vault_json_with_actor(&mixed.bytes, &writer),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(stored_graph(&target)?, before);
    let archive = archive([ExpressionPreferenceOrigin::ExplicitUser; 2])?;
    let mut missing = target.read_whole_vault_json(&archive.bytes)?;
    missing
        .evidence_ledger
        .edges
        .retain(|edge| edge.kind != EdgeKind::Supersedes as u8);
    assert!(matches!(
        target.import_whole_vault_json_with_actor(&serde_json::to_vec(&missing).unwrap(), &writer),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(stored_graph(&target)?, before);
    Ok(())
}
