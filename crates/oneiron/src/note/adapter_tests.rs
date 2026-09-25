//! Canonical program adapter laws; no native snapshot grants authority.
use super::*;
use crate::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};

fn fixture() -> (tempfile::TempDir, Vault, WriteActor) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    (dir, vault, WriteActor::new(owner, EdgeActorClass::Human))
}

#[test]
fn canonical_adapter_program_edit_keeps_birth_and_receipts() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "birth text", actor).unwrap();
    let birth = vault.get_raw(&note).unwrap();
    let read = vault.note_program_document(note).unwrap().unwrap();
    let result = vault
        .edit_note(
            note,
            &NoteProgramEdit::InsertAfter {
                anchor: read.anchor(10).unwrap(),
                text: " plus".into(),
            },
            actor,
        )
        .unwrap();
    assert_eq!(result, NoteProgramEditOutcome::Edited { head: note });
    assert_eq!(vault.get_raw(&note).unwrap(), birth);
    assert_eq!(vault.note_text(note).unwrap(), "birth text plus");
    assert_eq!(vault.note_document(note).unwrap().authorship.len(), 2);
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_state
            .get(&txn, &format!("d:e:{}", note.to_hex()))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        vault
            .store
            .sync_state
            .prefix_iter(&txn, &format!("nr:e:{}:", note.to_hex()))
            .unwrap()
            .count(),
        1
    );
    assert!(
        vault
            .store
            .vault_meta
            .get(&txn, &documents::head_key(note))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .store
            .sync_state
            .prefix_iter(&txn, "note_doc:v1:")
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn canonical_adapter_switch_is_semantic_and_does_not_import_fork_authority() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "before", actor).unwrap();
    let fork = vault
        .fork_note(
            note,
            &NoteProgramEdit::Rewrite {
                text: "after".into(),
            },
            actor,
        )
        .unwrap();
    let raw = {
        let txn = vault.store.env.read_txn().unwrap();
        vault
            .store
            .sync_state
            .get(&txn, &documents::doc_key(note, fork))
            .unwrap()
            .unwrap()
            .to_vec()
    };
    let proposed = document::NoteDocument::load(note, &raw)
        .unwrap()
        .view()
        .unwrap();
    assert!(proposed.authorship.is_empty() && proposed.pins.is_empty());
    let bundle = vault
        .open_note_proposal(&[fork], "review replacement", actor)
        .unwrap();
    assert_eq!(vault.note_text(note).unwrap(), "before");
    let landed = vault
        .review_note_proposal(bundle.id, NoteVerdict::Switch, actor)
        .unwrap();
    assert!(landed.waiting.is_empty());
    // A switch moves the head pointer to the fork; the fork's document, which
    // carries no authority, becomes the NOTE's text plane.
    assert_eq!(landed.landed[0].head, fork);
    assert_eq!(landed.landed[0].previous_head, note);
    assert_eq!(vault.note_text(note).unwrap(), "after");
    assert!(vault.note_document(note).unwrap().authorship.is_empty());
    let txn = vault.store.env.read_txn().unwrap();
    assert!(
        vault
            .store
            .sync_state
            .get(&txn, &documents::doc_key(note, fork))
            .unwrap()
            .is_some()
    );
}

#[test]
fn canonical_adapter_replica_refuses_local_program_and_landing() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "before", actor).unwrap();
    let read = vault.note_program_document(note).unwrap().unwrap();
    let fork = vault
        .fork_note(
            note,
            &NoteProgramEdit::Rewrite {
                text: "after".into(),
            },
            actor,
        )
        .unwrap();
    let bundle = vault
        .open_note_proposal(&[fork], "review replacement", actor)
        .unwrap();
    vault
        .with_write_txn(|txn| {
            vault
                .store
                .sync_state
                .put(txn, &format!("ds:e:{}", note.to_hex()), b"subscription")
        })
        .unwrap();
    assert!(
        vault
            .edit_note(
                note,
                &NoteProgramEdit::InsertAfter {
                    anchor: read.anchor(0).unwrap(),
                    text: "wrong".into()
                },
                actor
            )
            .is_err()
    );
    assert!(
        vault
            .review_note_proposal(bundle.id, NoteVerdict::Switch, actor)
            .is_err()
    );
    assert_eq!(vault.note_text(note).unwrap(), "before");
    assert_eq!(vault.note_proposal(bundle.id).unwrap(), bundle);
    let txn = vault.store.env.read_txn().unwrap();
    assert!(recovery::guard(&vault, &txn, note).is_err());
}

#[test]
fn canonical_adapter_recovery_uses_fresh_history_and_preserves_authorship() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "birth", actor).unwrap();
    let read = vault.note_program_document(note).unwrap().unwrap();
    vault
        .edit_note(
            note,
            &NoteProgramEdit::InsertAfter {
                anchor: read.anchor(5).unwrap(),
                text: " updated".into(),
            },
            actor,
        )
        .unwrap();
    let view = vault.note_document(note).unwrap();
    let rebuilt = recovery::rebuild(note, &view.markdown, &view.authorship).unwrap();
    let next = document::NoteDocument::from_loro(note, rebuilt)
        .unwrap()
        .view()
        .unwrap();
    assert_ne!(view.frontier, next.frontier);
    assert_eq!(view.markdown, next.markdown);
    assert_eq!(view.authorship, next.authorship);
    let txn = vault.store.env.read_txn().unwrap();
    assert!(recovery::guard(&vault, &txn, note).is_ok());
}

#[test]
fn canonical_adapter_updates_are_projected_featurelessly_and_fenced() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "before", actor).unwrap();
    vault
        .with_write_txn(|txn| {
            let doc = document_store::load(&vault, txn, note)?;
            let before = doc.doc.oplog_vv();
            doc.doc.get_text("body").insert(6, " update").unwrap();
            doc.doc.commit();
            let updates = doc.doc.export(loro::ExportMode::updates(&before)).unwrap();
            vault.store.sync_state.put(
                txn,
                &format!("u:e:{}:00000001", note.to_hex()),
                &updates,
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(vault.note_text(note).unwrap(), "before update");
    assert_eq!(
        decode_note_body(&vault.get(&note).unwrap().unwrap())
            .unwrap()
            .markdown,
        "before update"
    );
    vault
        .with_write_txn(|txn| {
            vault.store.vault_meta.put(
                txn,
                format!(
                    "note.erase/pending/{}:{}",
                    note.to_hex(),
                    EntityId::now().to_hex()
                )
                .as_bytes(),
                b"",
            )
        })
        .unwrap();
    assert!(vault.note_text(note).is_err());
    assert!(vault.note_program_document(note).is_err());
    assert!(vault.get(&note).is_err());
}

#[cfg(feature = "sync")]
#[test]
fn canonical_adapter_peer_window_cannot_install_recovery_values() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "before", actor).unwrap();
    let before = vault.note_document(note).unwrap();
    let doc = loro::LoroDoc::new();
    doc.get_map("documents")
        .insert("forged", b"value".as_slice())
        .unwrap();
    doc.commit();
    let materializer = crate::sync::bridge::Materializer::new();
    let window = crate::sync::types::WindowKey::new("2026-09");
    assert!(
        crate::sync::window::forward_rematerialize(&vault, &doc, &materializer, &window).is_err()
    );
    assert_eq!(vault.note_document(note).unwrap(), before);
}

#[cfg(feature = "sync")]
#[test]
fn canonical_adapter_window_proposals_are_values_not_retired_history() {
    let (_dir, vault, actor) = fixture();
    let note = vault.create_note("research", "before", actor).unwrap();
    let fork = vault
        .fork_note(
            note,
            &NoteProgramEdit::Rewrite {
                text: "safe".into(),
            },
            actor,
        )
        .unwrap();
    let raw = vault.get_raw(&note).unwrap().unwrap();
    let window = crate::sync::types::WindowKey::from_timestamp(
        crate::batch::EntityMetadataHeader::parse(&raw)
            .unwrap()
            .learned_at,
    );
    let carrier = loro::LoroDoc::new();
    crate::sync::note::refresh(&vault, &carrier, &window).unwrap();
    let key = documents::doc_key(note, fork);
    let encoded =
        crate::sync::loro_support::map_get_bytes(&carrier.get_map("documents"), &key).unwrap();
    assert_eq!(rmp_serde::from_slice::<String>(&encoded).unwrap(), "safe");
    crate::sync::note::validate(&carrier).unwrap();

    let historical = documents::proposal_value(note, "retired secret").unwrap();
    historical.get_text("body").delete(0, 14).unwrap();
    historical.get_text("body").insert(0, "safe").unwrap();
    historical.commit();
    let bytes = documents::snapshot(&historical).unwrap();
    assert_eq!(documents::proposal_text(note, &bytes).unwrap(), "safe");
    carrier
        .get_map("documents")
        .insert(&key, bytes.as_slice())
        .unwrap();
    carrier.commit();
    assert!(crate::sync::note::validate(&carrier).is_err());
    assert_eq!(vault.note_text(note).unwrap(), "before");
}
