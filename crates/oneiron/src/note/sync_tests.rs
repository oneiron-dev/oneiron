//! Normal NOTE window transport, selector closure, and delete-wins regression laws.
use super::*;
#[cfg(feature = "sync")]
use crate::batch::EntityMetadataHeader;
use crate::deletion::DeleteReason;
#[cfg(feature = "sync")]
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::edge::EdgeActorClass;
use crate::write_envelope::WriteActor;
use crate::{Vault, VaultConfig};

fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
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
        .unwrap()
}
fn assert_erased(vault: &Vault, note: EntityId) {
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_state
            .prefix_iter(&txn, &format!("note_doc:v1:{}:", note.to_hex()))
            .unwrap()
            .next()
            .is_none()
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&txn, &documents::head_key(note))
            .unwrap()
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
        .with_write_txn(|txn| crate::batch::deindex_entity(&vault.store, txn, &note).map(|_| ()))
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
        let raw = vault.get_raw(&note).unwrap().unwrap();
        WindowKey::from_timestamp(EntityMetadataHeader::parse(&raw).unwrap().learned_at)
    }
    fn send(source: &Vault, doc: &LoroDoc, key: &WindowKey) -> Vec<u8> {
        export_window_updates_since(source, key, doc, &VersionVector::default().encode()).unwrap()
    }
    fn receive(peer: &Vault, bytes: &[u8], key: &WindowKey) -> LoroDoc {
        let doc = LoroDoc::from_snapshot(bytes).unwrap();
        forward_rematerialize(peer, &doc, &Materializer::new(), key).unwrap();
        doc
    }

    #[test]
    fn normal_window_delivers_editable_note_edits_forks_and_head_moves() {
        let (_dir, source, actor) = fixture();
        let peer_dir = tempfile::tempdir().unwrap();
        let peer = Vault::open(peer_dir.path(), VaultConfig::default()).unwrap();
        let note = source.create_note("research", "alpha", actor).unwrap();
        let key = window(&source, note);
        let doc = LoroDoc::new();
        reverse_rematerialize(&source, &doc, &key).unwrap();
        let before_fork = send(&source, &doc, &key);
        receive(&peer, &before_fork, &key);
        assert_eq!(peer.note_text(note).unwrap(), "alpha");
        let before = source.note_document(note).unwrap().unwrap();
        let anchor = before.anchor(5).unwrap();
        source
            .edit_note(
                note,
                &NoteEdit::InsertAfter {
                    anchor,
                    text: " edited".to_owned(),
                },
                actor,
            )
            .unwrap();
        // No missing entity and no reopen/reverse-rematerialization step.
        receive(&peer, &send(&source, &doc, &key), &key);
        assert_eq!(peer.note_text(note).unwrap(), "alpha edited");
        let peer_doc = peer.note_document(note).unwrap().unwrap();
        assert_eq!(peer_doc.head(), before.head());
        assert!(peer_doc.anchor(12).is_ok());
        let fork = rewrite(&source, note, "replacement", actor);
        let bundle = source
            .open_note_proposal(&[fork], "switch head", actor)
            .unwrap();
        receive(&peer, &send(&source, &doc, &key), &key);
        assert_eq!(
            peer.note_proposal(bundle.id).unwrap().waiting,
            bundle.waiting
        );
        source
            .review_note_proposal(bundle.id, NoteVerdict::Switch, actor)
            .unwrap();
        receive(&peer, &send(&source, &doc, &key), &key);
        assert_eq!(peer.note_text(note).unwrap(), "replacement");
        assert_eq!(peer.note_document(note).unwrap().unwrap().head(), fork);
        assert!(peer.note_proposal(bundle.id).unwrap().waiting.is_empty());
        let stale = LoroDoc::from_snapshot(&before_fork).unwrap();
        assert!(forward_rematerialize(&peer, &stale, &Materializer::new(), &key).is_err());
        assert_eq!(peer.note_document(note).unwrap().unwrap().head(), fork);
        assert_eq!(peer.note_text(note).unwrap(), "replacement");
        assert!(peer.note_proposal(bundle.id).unwrap().waiting.is_empty());
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
    fn incomplete_document_is_refused_before_core_admission_and_selection_cannot_leak() {
        let (_dir, source, actor) = fixture();
        let peer_dir = tempfile::tempdir().unwrap();
        let peer = Vault::open(peer_dir.path(), VaultConfig::default()).unwrap();
        let note = source
            .create_note("research", "selected text", actor)
            .unwrap();
        let key = window(&source, note);
        let doc = LoroDoc::new();
        reverse_rematerialize(&source, &doc, &key).unwrap();
        let excluded = LoroDoc::new();
        sync::copy_selected(&source, &doc, &excluded).unwrap();
        assert_eq!(excluded.get_map("documents").len(), 1);
        let head = source.note_document(note).unwrap().unwrap().head();
        doc.get_map("documents")
            .delete(&documents::doc_key(note, head))
            .unwrap();
        doc.commit();
        assert!(forward_rematerialize(&peer, &doc, &Materializer::new(), &key).is_err());
        assert!(peer.get_raw(&note).unwrap().is_none());
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

    #[test]
    fn already_open_window_materializes_document_only_updates() {
        use crate::sync::window::LoadedWindow;
        use std::sync::Arc;
        struct NoteChanges(std::sync::mpsc::Sender<Vec<String>>);
        impl crate::sync::bridge::LiveQueryTee for NoteChanges {
            fn on_materialized(
                &self,
                _: &str,
                diff: &crate::sync::bridge::MaterializedDiffSummary,
                _: &crate::sync::bridge::OriginMark,
            ) {
                self.0.send(diff.containers.clone()).unwrap();
            }
        }
        let (_dir, source, actor) = fixture();
        let peer_dir = tempfile::tempdir().unwrap();
        let peer = Arc::new(Vault::open(peer_dir.path(), VaultConfig::default()).unwrap());
        let note = source.create_note("research", "live", actor).unwrap();
        let key = window(&source, note);
        let doc = LoroDoc::new();
        reverse_rematerialize(&source, &doc, &key).unwrap();
        let (changes, received) = std::sync::mpsc::channel();
        let tee: Arc<dyn crate::sync::bridge::LiveQueryTee> = Arc::new(NoteChanges(changes));
        let materializer = Arc::new(Materializer::new());
        materializer.attach_live_query_tee(&tee);
        let loaded = LoadedWindow::new("peer", key.clone(), &peer, &materializer);
        loaded.doc.import(&send(&source, &doc, &key)).unwrap();
        assert_eq!(peer.note_text(note).unwrap(), "live");
        received.try_iter().for_each(drop);
        let anchor = source
            .note_document(note)
            .unwrap()
            .unwrap()
            .anchor(4)
            .unwrap();
        source
            .edit_note(
                note,
                &NoteEdit::InsertAfter {
                    anchor,
                    text: " update".to_owned(),
                },
                actor,
            )
            .unwrap();
        loaded.doc.import(&send(&source, &doc, &key)).unwrap();
        assert_eq!(peer.note_text(note).unwrap(), "live update");
        assert!(
            received
                .try_iter()
                .flatten()
                .any(|path| path == format!("w:{key}/entities/{}", note.to_hex()))
        );
        drop(loaded);
        assert_eq!(peer.note_text(note).unwrap(), "live update");
    }
}
