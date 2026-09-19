//! NOTE admission and canonical cursor/provenance replication boundaries.
use super::*;
use crate::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use crate::sync::{SyncSelector, SyncSelectorWorld, WindowManager};
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;

const JTI: &str = "11111111111111111111111111111111";
fn actor(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .unwrap();
    id
}
fn selector(vault: &Vault, actor: EntityId, role: FederationGrantRole) -> SyncSelector {
    let id = EntityId::now();
    let grant = FederationGrant::new(
        crate::FederationGrantScope::vault(7),
        actor,
        role,
        FederationGrantPreset::Member,
    );
    vault
        .batch()
        .put_replicated(
            &id,
            crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &crate::federation::encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    SyncSelector::new(id, actor, SyncSelectorWorld::All, vec![], vec![])
}
fn edit(vault: &Vault, note: EntityId, start: usize, delete: usize, insert: &str) -> NoteOperation {
    NoteOperation {
        request_id: EntityId::now(),
        change: NoteChange::Edit {
            base: vault.note_document(note).unwrap().frontier,
            edits: vec![NoteEdit {
                start,
                delete,
                insert: insert.into(),
            }],
        },
    }
}
fn replicate_row(from: &Vault, to: &Vault, id: EntityId) {
    let raw = from.get_raw(&id).unwrap().unwrap();
    let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
    to.batch()
        .put_replicated(
            &id,
            header.entity_type,
            TimeRange { start: 1, end: 1 },
            header.learned_at,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )
        .commit()
        .unwrap();
}
fn manager(vault: Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault,
        Arc::new(crate::sync::bridge::Materializer::new()),
        "note-test",
    ))
}

#[test]
fn note_raw_import_writer_impersonation_revocation_and_birth_overwrite_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let author = actor(&vault);
    let stranger = actor(&vault);
    let memory = vault.memory(author, EdgeActorClass::Human);
    let note = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(author), "original")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let selectors = selector(&vault, author, FederationGrantRole::Member);
    let foreign = selector(&vault, stranger, FederationGrantRole::Member);
    let readonly = selector(&vault, author, FederationGrantRole::Viewer);
    let op = edit(&vault, note, 0, 0, "accepted ");
    let before = vault.note_document(note).unwrap();
    let mut collision = op.clone();
    collision.request_id = note;
    assert!(
        memory
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &selectors,
                JTI,
                &collision
            )
            .is_err()
    );
    assert!(
        memory
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &readonly,
                JTI,
                &op
            )
            .is_err()
    );
    assert!(
        vault
            .memory(stranger, EdgeActorClass::Human)
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &selectors,
                JTI,
                &op
            )
            .is_err()
    );
    assert!(
        vault
            .memory(stranger, EdgeActorClass::Human)
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &foreign,
                JTI,
                &op
            )
            .is_err()
    );
    let manager = manager(vault.clone());
    let handle = manager.documents().open(note).unwrap();
    assert!(handle.edit_text(0, 0, "raw ").is_err());
    let forged = loro::LoroDoc::new();
    forged.get_map("pins").insert("forged", "pin").unwrap();
    forged.commit_with(
        loro::CommitOptions::new()
            .commit_msg(&format!("oneiron.note/v1 actor={}", author.to_hex())),
    );
    let forged = forged.export(loro::ExportMode::Snapshot).unwrap();
    assert!(
        handle
            .import(crate::sync::transport::document_sub_tags::UPDATE, &forged)
            .is_err()
    );
    assert!(
        handle
            .import(crate::sync::transport::document_sub_tags::STATE, &forged)
            .is_err()
    );
    let mut birth = decode_note_body(&vault.get(&note).unwrap().unwrap()).unwrap();
    birth.author_ref = stranger;
    assert!(
        vault
            .batch()
            .put_replicated(
                &note,
                crate::registry::ENTITY_TYPE_NOTE,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_note_body(&birth).unwrap()
            )
            .commit()
            .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), before);
    let receipt = memory
        .admit_note_operation(
            note,
            crate::FederationGrantScope::vault(7),
            &selectors,
            JTI,
            &op,
        )
        .unwrap();
    assert!(
        matches!(&receipt.outcome, NoteEditOutcome::Applied(view) if view.markdown == "accepted original")
    );
    assert_eq!(
        memory
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &selectors,
                JTI,
                &op
            )
            .unwrap(),
        receipt
    );
    let after = vault.note_document(note).unwrap();
    assert!(
        after
            .authorship
            .iter()
            .any(|record| record.operation == op.request_id
                && record.actor == author
                && record.grant == Some(selectors.grant_id.to_hex()))
    );
    let next = edit(&vault, note, 0, 0, "revoked ");
    vault
        .sync_state_put(&format!("auth:revoked-token-jti:{JTI}"), &[])
        .unwrap();
    assert!(
        memory
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &selectors,
                JTI,
                &next
            )
            .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), after);
    vault
        .sync_state_delete(&format!("auth:revoked-token-jti:{JTI}"))
        .unwrap();
    vault.delete_entity(&selectors.grant_id).unwrap();
    assert!(
        memory
            .admit_note_operation(
                note,
                crate::FederationGrantScope::vault(7),
                &selectors,
                JTI,
                &next
            )
            .is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), after);
    vault.delete_entity(&note).unwrap();
    assert!(handle.text().is_err());
    assert!(handle.edit_text(0, 0, "resurrect").is_err());
    assert!(memory.apply_note_ops(note, &after.frontier, &[]).is_err());
    for prefix in ["d:e:", "sv:e:", "ssv:e:", "ds:e:"] {
        assert!(
            vault
                .sync_state_get(&format!("{prefix}{}", note.to_hex()))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn note_citations_and_authorship_cross_peer_state_reopen_and_guard_reviewed_edits() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Arc::new(Vault::open(a_dir.path(), VaultConfig::device()).unwrap());
    let b = Arc::new(Vault::open(b_dir.path(), VaultConfig::device()).unwrap());
    let author = actor(&a);
    let memory = a.memory(author, EdgeActorClass::Human);
    let claim = EntityId::now();
    memory
        .claim_upsert(&crate::memory::ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.name".into(),
            subject_ref: author.to_hex(),
            value: serde_json::json!("quote"),
            confidence: 0.9,
            source: "user_stated".into(),
            world_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .unwrap();
    let source = EntityId::from_hex(
        &memory
            .author_take(TakeTarget::Subject(author), "before quoted after")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    memory.bless_brief_kind().unwrap();
    let pin = a.pin_note_span(source, claim, 7, 13).unwrap();
    let brief = EntityId::from_hex(
        &memory
            .author_brief("A cited brief", std::slice::from_ref(&pin))
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let selectors = selector(&a, author, FederationGrantRole::Member);
    let free = edit(&a, source, 0, 0, "new ");
    memory
        .admit_note_operation(
            source,
            crate::FederationGrantScope::vault(7),
            &selectors,
            JTI,
            &free,
        )
        .unwrap();
    let a_manager = manager(a.clone());
    let b_manager = manager(b.clone());
    for id in [author, claim, source, brief] {
        replicate_row(&a, &b, id);
    }
    for id in [source, brief] {
        b_manager
            .documents()
            .subscribe_entity(id, &selectors)
            .unwrap();
        let vv = b_manager
            .documents()
            .open(id)
            .unwrap()
            .version_vector()
            .unwrap();
        let frame = a_manager
            .export_document(id, crate::FederationGrantScope::vault(7), &selectors, &vv)
            .unwrap();
        let frame = crate::sync::transport::decode_document(&frame[1..]).unwrap();
        assert_eq!(frame.kind, crate::sync::transport::document_sub_tags::STATE);
        super::import_note_from_authority(&b, id, frame.kind, frame.payload).unwrap();
        assert_eq!(a.note_document(id).unwrap(), b.note_document(id).unwrap());
    }
    assert_eq!(
        a.resolve_note_pin(&pin).unwrap(),
        b.resolve_note_pin(&pin).unwrap()
    );
    let before = a.note_document(source).unwrap();
    let protected = edit(&a, source, 12, 1, "x");
    let result = memory
        .admit_note_operation(
            source,
            crate::FederationGrantScope::vault(7),
            &selectors,
            JTI,
            &protected,
        )
        .unwrap();
    let NoteEditOutcome::Proposed(receipt) = result.outcome else {
        panic!("cited edit must be reviewed")
    };
    assert_eq!(receipt.approval, "proposed");
    assert!(receipt.receipt_ref.starts_with("gate:"));
    assert_eq!(a.note_document(source).unwrap(), before);
    let candidate = a
        .get_claim(&EntityId::from_hex(&receipt.claim_short_id).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(candidate.predicate, "note.edit.proposal");
    assert_eq!(
        candidate.approval,
        crate::claim::ClaimApprovalStatus::Proposed
    );
    let b_view = b.note_document(brief).unwrap();
    drop(b_manager);
    drop(b);
    let b = Vault::open(b_dir.path(), VaultConfig::device()).unwrap();
    assert_eq!(b.note_document(brief).unwrap(), b_view);
    assert!(
        matches!(b.resolve_note_pin(&pin).unwrap(), NoteSpanResolution::Mapped { claim: id, quote, .. } if id == claim && quote == "quoted")
    );
    // A replica cannot become a second admission authority before the source
    // learns its other citing documents. It must submit to the bound authority.
    assert!(
        b.memory(author, EdgeActorClass::Human)
            .apply_note_ops(source, &before.frontier, &[])
            .is_err()
    );
}

#[test]
fn note_birth_refusal_quarantines_without_wedging_valid_siblings_or_replay() {
    use crate::sync::{bridge::Materializer, quarantine::quarantined_records};
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let author = actor(&vault);
    let id = EntityId::from_hex(
        &vault
            .memory(author, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(author), "immutable birth")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let original = vault.get_raw(&id).unwrap().unwrap();
    let before = vault.note_document(id).unwrap();
    let header = crate::batch::EntityMetadataHeader::parse(&original).unwrap();
    let mut divergent =
        decode_note_body(&original[crate::batch::ENTITY_METADATA_HEADER_LEN..]).unwrap();
    divergent.markdown = "remote overwrite".into();
    let mut bad = original[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
    bad.extend(encode_note_body(&divergent).unwrap());
    let key = crate::sync::WindowKey::from_timestamp(header.learned_at);
    let doc = crate::sync::schema::create_window_doc("NOTE refusal", &key);
    let malformed = EntityId::now();
    let good = EntityId::now();
    let entities = doc.get_map("entities");
    crate::sync::loro_support::map_insert_bytes(&entities, &id.to_hex(), &bad).unwrap();
    for (entity, kind, body) in [
        (
            good,
            crate::registry::ENTITY_TYPE_TURN,
            b"valid sibling".as_slice(),
        ),
        (
            malformed,
            crate::registry::ENTITY_TYPE_NOTE,
            b"\xc0".as_slice(),
        ),
    ] {
        let blob = crate::test_util::entity_record(
            kind,
            TimeRange { start: 1, end: 1 },
            header.learned_at,
            body,
        );
        crate::sync::loro_support::map_insert_bytes(&entities, &entity.to_hex(), &blob).unwrap();
    }
    doc.commit();
    for _ in 0..2 {
        crate::sync::window::forward_rematerialize(&vault, &doc, &Materializer::new(), &key)
            .unwrap();
        assert_eq!(vault.get_raw(&id).unwrap().unwrap(), original);
        assert_eq!(vault.note_document(id).unwrap(), before);
        assert_eq!(
            vault.get(&good).unwrap().as_deref(),
            Some(b"valid sibling".as_slice())
        );
        assert!(vault.get_raw(&malformed).unwrap().is_none());
        let records = quarantined_records(&vault).unwrap();
        for refused in [id, malformed] {
            assert!(
                records
                    .iter()
                    .any(|(_, row)| row.reason_code == "InvalidNoteBody"
                        && row.crdt_key_hash
                            == xxhash_rust::xxh3::xxh3_64(refused.to_hex().as_bytes()))
            );
        }
        assert!(
            records
                .iter()
                .all(|(_, row)| row.reason_code == "InvalidNoteBody")
        );
    }
}

#[test]
fn note_receipts_require_coverage_replay_is_idempotent_and_erasure_does_not_restore_authority() {
    use crate::sync::transport::{decode_document, document_sub_tags};
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Arc::new(Vault::open(a_dir.path(), VaultConfig::device()).unwrap());
    let b = Arc::new(Vault::open(b_dir.path(), VaultConfig::device()).unwrap());
    let author = actor(&a);
    let note = EntityId::from_hex(
        &a.memory(author, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(author), "birth")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let selector = selector(&a, author, FederationGrantRole::Member);
    let a_manager = manager(a.clone());
    let b_manager = manager(b.clone());
    for id in [author, note] {
        replicate_row(&a, &b, id);
    }
    // Desired subscriptions name REMOTE grants. Absence on the replica is
    // ordinary and must not promote this replica to a second NOTE authority.
    assert!(b.get_raw(&selector.grant_id).unwrap().is_none());
    b_manager
        .documents()
        .subscribe_entity(note, &selector)
        .unwrap();
    assert_eq!(b_manager.documents().request_frames().unwrap().len(), 1);
    let op = edit(&b, note, 0, 0, "remote ");
    b_manager.documents().submit_note(note, &op).unwrap();
    let receipt = a
        .memory(author, EdgeActorClass::Human)
        .admit_note_operation(
            note,
            crate::FederationGrantScope::vault(7),
            &selector,
            JTI,
            &op,
        )
        .unwrap();
    let before = b.note_document(note).unwrap();
    let error = b_manager
        .documents()
        .accept_note_receipt(note, &receipt)
        .unwrap_err();
    assert!(matches!(
        error,
        crate::Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: crate::error::SyncProtocolValidation::DocumentAdmissionDenied,
        })
    ));
    assert!(
        b_manager
            .documents()
            .note_receipt(note, op.request_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        b_manager
            .documents()
            .pending_note_requests(note)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(b.note_document(note).unwrap(), before);
    let state = a_manager
        .export_document(
            note,
            crate::FederationGrantScope::vault(7),
            &selector,
            &loro::VersionVector::new().encode(),
        )
        .unwrap();
    let frame = decode_document(&state[1..]).unwrap();
    super::import_note_from_authority(&b, note, frame.kind, frame.payload).unwrap();
    b_manager
        .documents()
        .accept_note_receipt(note, &receipt)
        .unwrap();
    assert_eq!(
        b_manager
            .documents()
            .note_receipt(note, op.request_id)
            .unwrap(),
        Some(receipt.clone())
    );
    assert!(
        b_manager
            .documents()
            .pending_note_requests(note)
            .unwrap()
            .is_empty()
    );
    // Already-applied replay needs no second STATE if the current doc covers
    // the saved receipt. It is the same operation, not a new write.
    b_manager.documents().submit_note(note, &op).unwrap();
    b_manager
        .documents()
        .accept_note_receipt(note, &receipt)
        .unwrap();
    assert!(
        b_manager
            .documents()
            .pending_note_requests(note)
            .unwrap()
            .is_empty()
    );
    a.delete_entity(&selector.grant_id).unwrap();
    assert!(
        a_manager
            .export_document(
                note,
                crate::FederationGrantScope::vault(7),
                &selector,
                &loro::VersionVector::new().encode()
            )
            .is_err()
    );
    assert_eq!(b_manager.documents().request_frames().unwrap().len(), 1);
    assert!(
        b.memory(author, EdgeActorClass::Human)
            .apply_note_ops(note, &b.note_document(note).unwrap().frontier, &[])
            .is_err()
    );
    let pending = edit(&b, note, 0, 0, "pending ");
    b_manager.documents().submit_note(note, &pending).unwrap();
    b.delete_entity(&note).unwrap();
    assert!(
        b_manager
            .documents()
            .pending_note_requests(note)
            .unwrap()
            .is_empty()
    );
    assert!(
        b_manager
            .documents()
            .note_receipt(note, op.request_id)
            .unwrap()
            .is_none()
    );
    assert!(b_manager.documents().request_frames().unwrap().is_empty());
    assert!(
        super::import_note_from_authority(&b, note, document_sub_tags::STATE, frame.payload)
            .is_err()
    );
    b_manager
        .documents()
        .accept_note_receipt(note, &receipt)
        .unwrap();
    assert!(b.get_raw(&note).unwrap().is_none());
    assert!(
        b_manager
            .documents()
            .note_receipt(note, op.request_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn note_open_checkpoints_replayed_updates_without_dropping_them() {
    use crate::sync::documents::storage;
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let author = actor(&vault);
    let note = EntityId::from_hex(
        &vault
            .memory(author, EdgeActorClass::Human)
            .author_take(TakeTarget::Subject(author), "birth")
            .unwrap()
            .id_hex,
    )
    .unwrap();
    let frontier = vault
        .with_write_txn(|txn| {
            let doc = storage::load(&vault, txn, note)?;
            let before = doc.oplog_vv();
            doc.get_text("body").insert(5, " + recovered").unwrap();
            doc.commit();
            let update = doc.export(loro::ExportMode::updates(&before)).unwrap();
            storage::append(&vault, txn, note, &update)?;
            Ok(doc.oplog_vv().encode())
        })
        .unwrap();
    let manager = manager(vault.clone());
    let doc = manager.documents().open(note).unwrap();
    assert_eq!(doc.text().unwrap(), "birth + recovered");
    assert_eq!(doc.version_vector().unwrap(), frontier);
    drop(doc);
    assert_eq!(
        manager.documents().open(note).unwrap().text().unwrap(),
        "birth + recovered"
    );
    assert_eq!(
        vault.note_document(note).unwrap().markdown,
        "birth + recovered"
    );
}
