//! NOTE admission and canonical cursor/provenance replication boundaries.
use super::*;
use crate::sync::WindowManager;
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use std::sync::Arc;

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
        .expect("store fixture entity or grant");
    id
}
fn manager(vault: Arc<Vault>) -> Arc<WindowManager> {
    Arc::new(WindowManager::new(
        vault,
        Arc::new(crate::sync::bridge::Materializer::new()),
        "note-test",
    ))
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

mod program {
    //! Normal NOTE window transport, selector closure, and delete-wins regression laws.
    #[cfg(feature = "sync")]
    use crate::batch::EntityMetadataHeader;
    use crate::deletion::DeleteReason;
    #[cfg(feature = "sync")]
    use crate::deletion::{TombstoneReason, TombstoneValueV2};
    use crate::edge::EdgeActorClass;
    use crate::note::NoteProgramEdit as NoteEdit;
    use crate::note::*;
    #[cfg(feature = "sync")]
    use crate::sync::note as sync;
    use crate::write_envelope::WriteActor;
    use crate::{Vault, VaultConfig};

    fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
        let dir = tempfile::tempdir().expect("create note fixture directory");
        let vault =
            Vault::open(dir.path(), VaultConfig::default()).expect("open note fixture vault");
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("create fixture owner");
        (dir, vault, WriteActor::new(owner, EdgeActorClass::Human))
    }
    fn rewrite(vault: &Vault, note: EntityId, text: &str, actor: WriteActor) -> EntityId {
        vault
            .fork_note(
                note,
                &NoteEdit::Rewrite {
                    text: text.to_owned(),
                },
                actor,
            )
            .expect("fork fixture note")
    }
    fn assert_erased(vault: &Vault, note: EntityId) {
        let txn = vault
            .store
            .env
            .read_txn()
            .expect("read erased-note fixture");
        assert!(
            vault
                .store
                .sync_state
                .prefix_iter(&txn, &format!("note_doc:v1:{}:", note.to_hex()))
                .expect("scan erased-note documents")
                .next()
                .is_none()
        );
        assert!(
            vault
                .store
                .vault_meta
                .get(&txn, &documents::head_key(note))
                .expect("read erased-note head")
                .is_none()
        );
        drop(txn);
        assert!(vault.note_text(note).is_err());
    }

    #[test]
    fn hard_deletion_purges_current_forks_and_proposal_text_for_every_reason() {
        for reason in [
            DeleteReason::UserHardDelete,
            DeleteReason::GdprDelete,
            DeleteReason::PolicyDelete,
        ] {
            let (_dir, vault, actor) = fixture();
            let note = vault
                .create_note("research", "private current", actor)
                .unwrap();
            let fork = rewrite(&vault, note, "private fork", actor);
            let proposal = vault
                .open_note_proposal(&[fork], "private explainer", actor)
                .unwrap();
            let other = vault.create_note("research", "unrelated", actor).unwrap();
            let other_fork = rewrite(&vault, other, "unrelated rewrite", actor);
            let other_proposal = vault
                .open_note_proposal(&[other_fork], "unrelated explanation", actor)
                .unwrap();
            assert!(
                vault
                    .delete_entity_with_reason(&note, reason)
                    .unwrap()
                    .existed
            );
            assert_erased(&vault, note);
            assert!(vault.note_proposal(proposal.id).is_err());
            assert_eq!(vault.note_text(other).unwrap(), "unrelated");
            assert_eq!(
                vault.note_proposal(other_proposal.id).unwrap().waiting,
                other_proposal.waiting
            );
            let txn = vault.store.env.read_txn().unwrap();
            assert!(
                vault
                    .store
                    .vault_meta
                    .get(
                        &txn,
                        &[b"note_fork:v1:".as_slice(), fork.as_bytes()].concat()
                    )
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn headerless_note_sidecars_are_active_delete_scope_and_shared_explainer_is_redacted() {
        let (_dir, vault, actor) = fixture();
        let note = vault.create_note("research", "private", actor).unwrap();
        let other = vault.create_note("research", "survivor", actor).unwrap();
        let fork = rewrite(&vault, note, "private fork", actor);
        let other_fork = rewrite(&vault, other, "survivor fork", actor);
        let bundle = vault
            .open_note_proposal(&[fork, other_fork], "quotes private text", actor)
            .unwrap();
        vault
            .with_write_txn(|txn| {
                crate::batch::deindex_entity(&vault.store, txn, &note).map(|_| ())
            })
            .unwrap();
        assert!(vault.get_raw(&note).unwrap().is_none());
        assert!(vault.delete_entity(&note).unwrap());
        assert_erased(&vault, note);
        let bundle = vault.note_proposal(bundle.id).unwrap();
        assert_eq!(
            bundle
                .waiting
                .iter()
                .map(|fork| fork.note)
                .collect::<Vec<_>>(),
            vec![other]
        );
        assert_ne!(bundle.explainer, "quotes private text");
        assert_eq!(vault.note_text(other).unwrap(), "survivor");
    }

    #[cfg(feature = "sync")]
    mod transport {
        use super::*;
        use crate::sync::{
            bridge::Materializer,
            types::WindowKey,
            window::{export_window_updates_since, forward_rematerialize, reverse_rematerialize},
        };
        use loro::{LoroDoc, VersionVector};

        fn window(vault: &Vault, note: EntityId) -> WindowKey {
            let raw = vault
                .get_raw(&note)
                .expect("read fixture note")
                .expect("fixture note exists");
            WindowKey::from_timestamp(
                EntityMetadataHeader::parse(&raw)
                    .expect("fixture note header")
                    .learned_at,
            )
        }
        fn send(source: &Vault, doc: &LoroDoc, key: &WindowKey) -> Vec<u8> {
            export_window_updates_since(source, key, doc, &VersionVector::default().encode())
                .expect("export fixture window")
        }
        fn receive(peer: &Vault, bytes: &[u8], key: &WindowKey) -> LoroDoc {
            let doc = LoroDoc::from_snapshot(bytes).expect("decode fixture window");
            forward_rematerialize(peer, &doc, &Materializer::new(), key)
                .expect("materialize fixture window");
            doc
        }

        #[test]
        fn replay_purges_notes_and_stale_window_cannot_restore_erased_sidecars() {
            let (_dir, source, actor) = fixture();
            let peer_dir = tempfile::tempdir().unwrap();
            let peer = Vault::open(peer_dir.path(), VaultConfig::default()).unwrap();
            let note = source.create_note("research", "erase me", actor).unwrap();
            let fork = rewrite(&source, note, "erase this fork", actor);
            let bundle = source
                .open_note_proposal(&[fork], "erase this explanation", actor)
                .unwrap();
            let key = window(&source, note);
            let doc = LoroDoc::new();
            reverse_rematerialize(&source, &doc, &key).unwrap();
            let stale = send(&source, &doc, &key);
            let delete_retry_key = format!("rm:w:{key}:{}", note.to_hex());
            peer.with_write_txn(|txn| peer.store.sync_state.put(txn, &delete_retry_key, &[1]))
                .unwrap();
            receive(&peer, &stale, &key);
            assert!(peer.get_raw(&note).unwrap().is_none());
            assert!(peer.note_text(note).is_err());
            assert_eq!(
                crate::sync::quarantine::pending_remat_entities(&peer, key.as_str()).unwrap(),
                vec![note.to_hex()]
            );
            peer.with_write_txn(|txn| {
                peer.store
                    .sync_state
                    .delete(txn, &delete_retry_key)
                    .map(|_| ())
            })
            .unwrap();
            receive(&peer, &stale, &key);
            peer.apply_replayed_tombstone_for_sync(
                &note,
                &TombstoneValueV2 {
                    reason: TombstoneReason::GdprDelete,
                    deleted_at: 42,
                    request_id: *EntityId::now().as_bytes(),
                }
                .encode(),
            )
            .unwrap();
            assert_erased(&peer, note);
            receive(&peer, &stale, &key);
            assert_erased(&peer, note);
            assert!(peer.note_proposal(bundle.id).is_err());
            source.delete_entity(&note).unwrap();
            let scrubbed = LoroDoc::from_snapshot(&send(&source, &doc, &key)).unwrap();
            assert_eq!(scrubbed.get_map("documents").len(), 1); // format tag only
            assert_eq!(scrubbed.get_map("document_heads").len(), 0);
            assert_eq!(scrubbed.get_map("note_proposals").len(), 0);
        }

        #[test]
        fn selector_refuses_partial_bundle_and_soft_delete_redacts_shared_text() {
            let (_dir, source, actor) = fixture();
            let note = source
                .create_note("research", "private note", actor)
                .unwrap();
            let other = source
                .create_note("research", "remaining note", actor)
                .unwrap();
            let forks = [
                rewrite(&source, note, "private fork", actor),
                rewrite(&source, other, "remaining fork", actor),
            ];
            let bundle = source
                .open_note_proposal(&forks, "quotes private note", actor)
                .unwrap();
            let key = window(&source, note);
            let doc = LoroDoc::new();
            reverse_rematerialize(&source, &doc, &key).unwrap();
            let partial = LoroDoc::new();
            crate::sync::loro_support::map_insert_bytes(
                &partial.get_map("entities"),
                &other.to_hex(),
                &source.get_raw(&other).unwrap().unwrap(),
            )
            .unwrap();
            assert!(sync::copy_selected(&source, &doc, &partial).is_err());
            source
                .delete_entity_with_reason(&note, DeleteReason::UserDelete)
                .unwrap();
            assert_erased(&source, note);
            let exported = LoroDoc::from_snapshot(&send(&source, &doc, &key)).unwrap();
            assert!(
                exported
                    .get_map("document_heads")
                    .get(&note.to_hex())
                    .is_none()
            );
            let bytes = crate::sync::loro_support::map_get_bytes(
                &exported.get_map("note_proposals"),
                &bundle.id.to_hex(),
            )
            .unwrap();
            let remaining: NoteReviewBundle = rmp_serde::from_slice(&bytes).unwrap();
            assert_eq!(
                remaining
                    .waiting
                    .iter()
                    .map(|fork| fork.note)
                    .collect::<Vec<_>>(),
                vec![other]
            );
            assert_ne!(remaining.explainer, "quotes private note");
        }
    }
}
