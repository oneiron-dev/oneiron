use super::*;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ErrorKind, Result};
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::write_envelope::WriteActor;

fn actor() -> WriteActor {
    WriteActor::new(EntityId::now(), EdgeActorClass::Agent)
}

#[test]
fn concurrent_sessions_converge_and_receipts_survive_reopen() -> Result<()> {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let alice = actor();
    let bob = actor();
    let mut a = vault.open_code_document("repo", "src/a.rs", "α β", EntityId::now())?;
    let mut b = vault.open_code_document("repo", "src/a.rs", "α β", EntityId::now())?;
    assert!(vault.code_document_frontier("repo", "src/a.rs")?.is_none());
    let first = vault.apply_code_file_edit(
        &mut a,
        &CodeFileEdit::between("src/a.rs", "α β", "A α β"),
        alice,
    )?;
    let second = vault.apply_code_file_edit(
        &mut b,
        &CodeFileEdit::between("src/a.rs", "α β", "α β B"),
        bob,
    )?;
    vault.refresh_code_document(&mut a)?;
    assert_eq!(a.text(), "A α β B");
    assert_eq!(a.text(), b.text());
    assert_eq!(a.frontier()?, b.frontier()?);
    assert_eq!(first.sequence, 1);
    assert_eq!(second.sequence, 2);
    assert_eq!(first.actor, alice);
    assert_eq!(second.actor, bob);
    assert_eq!(vault.code_document_at(&first.after)?, "A α β");
    assert_eq!(
        vault
            .open_code_document_at(&first.after, EntityId::now())?
            .text(),
        "A α β"
    );
    let id = a.document_id();
    let frontier = a.frontier()?;
    drop(a);
    drop(b);
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config())?;
    let c = reopened.open_code_document("repo", "src/a.rs", "ignored", EntityId::now())?;
    assert_eq!(c.document_id(), id);
    assert_eq!(c.text(), "A α β B");
    assert_eq!(c.frontier()?, frontier);
    assert_eq!(reopened.code_document_receipts(&id)?, vec![first, second]);
    Ok(())
}

#[test]
fn unicode_spans_follow_unrelated_edits_and_drift_on_replacement() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut file = vault.open_code_document("repo", "code.rs", "λ token 终", EntityId::now())?;
    let span = file.anchor_span(2, 7)?;
    let receipt = vault.apply_code_file_edit(
        &mut file,
        &CodeFileEdit::between("code.rs", "λ token 终", "🙂 λ token 终"),
        actor(),
    )?;
    assert_eq!(receipt.edit.start, 0);
    assert_eq!(receipt.edit.end, 0);
    assert_eq!(
        file.resolve_span(&span)?,
        CodeSpanResolution::Mapped { start: 4, end: 9 }
    );
    vault.apply_code_file_edit(
        &mut file,
        &CodeFileEdit::between("code.rs", "🙂 λ token 终", "🙂 λ other 终"),
        actor(),
    )?;
    assert_eq!(file.resolve_span(&span)?, CodeSpanResolution::Drifted);
    let before = file.frontier()?;
    let bad = CodeFileEdit {
        path: "code.rs".into(),
        start: 4,
        end: 9,
        expected: "token".into(),
        replacement: "bad".into(),
        new_path: None,
    };
    assert_eq!(
        vault
            .apply_code_file_edit(&mut file, &bad, actor())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidCodeArtifactBody
    );
    assert_eq!(file.frontier()?, before);
    assert_eq!(vault.code_document_receipts(&file.document_id())?.len(), 2);
    Ok(())
}

#[test]
fn rename_keeps_identity_and_never_overwrites_another_document() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut file = vault.open_code_document("repo", "old.rs", "body", EntityId::now())?;
    let id = file.document_id();
    let receipt = vault.apply_code_file_edit(
        &mut file,
        &CodeFileEdit::rename("old.rs", "new.rs"),
        actor(),
    )?;
    assert_eq!(receipt.before.document_id, receipt.after.document_id);
    assert_eq!(file.path()?, "new.rs");
    assert!(vault.code_document_frontier("repo", "old.rs")?.is_none());
    assert_eq!(
        vault
            .open_code_document("repo", "new.rs", "", EntityId::now())?
            .document_id(),
        id
    );
    let mut reused = vault.open_code_document("repo", "old.rs", "fresh", EntityId::now())?;
    assert_ne!(reused.document_id(), id);
    vault.apply_code_file_edit(
        &mut reused,
        &CodeFileEdit::between("old.rs", "fresh", "fresh!"),
        actor(),
    )?;
    assert_eq!(file.text(), "body");
    let mut other = vault.open_code_document("repo", "other.rs", "x", EntityId::now())?;
    vault.apply_code_file_edit(
        &mut other,
        &CodeFileEdit::between("other.rs", "x", "y"),
        actor(),
    )?;
    assert!(
        vault
            .apply_code_file_edit(
                &mut file,
                &CodeFileEdit::rename("new.rs", "other.rs"),
                actor()
            )
            .is_err()
    );
    assert_eq!(file.path()?, "new.rs");
    assert_eq!(other.text(), "y");
    Ok(())
}

#[test]
fn operation_fold_is_commutative_for_concurrent_update_arrival() -> Result<()> {
    use loro::{CommitOptions, ExportMode, LoroDoc};
    let base = LoroDoc::new();
    base.set_peer_id(0).unwrap();
    base.get_map("meta").insert("path", "a.rs").unwrap();
    base.get_text("body").insert(0, "ab").unwrap();
    base.commit();
    let a = base.fork();
    let b = base.fork();
    a.get_text("body").insert(0, "A").unwrap();
    a.commit_with(CommitOptions::new().commit_msg("actor:a"));
    b.get_text("body").insert(2, "B").unwrap();
    b.commit_with(CommitOptions::new().commit_msg("actor:b"));
    let a = a.export(ExportMode::all_updates()).unwrap();
    let b = b.export(ExportMode::all_updates()).unwrap();
    let ab = base.fork();
    let ba = base.fork();
    ab.import(&a).unwrap();
    ab.import(&b).unwrap();
    ba.import(&b).unwrap();
    ba.import(&a).unwrap();
    assert_eq!(ab.get_text("body").to_string(), "AabB");
    let front = super::codec::frontier(&ab, "repo", [4; 32])?;
    assert_eq!(front, super::codec::frontier(&ba, "repo", [4; 32])?);
    // Actor identity participates even when rendered code and operation IDs do not change.
    let mut history = ab.export_json_updates_without_peer_compression(
        &loro::VersionVector::default(),
        &ab.oplog_vv(),
    );
    history
        .changes
        .iter_mut()
        .find(|c| c.msg.as_deref() == Some("actor:a"))
        .unwrap()
        .msg = Some("actor:forged".into());
    let tampered = LoroDoc::new();
    tampered.import_json_updates(history).unwrap();
    assert_eq!(tampered.get_text("body").to_string(), "AabB");
    assert_ne!(
        front.op_fold,
        super::codec::frontier(&tampered, "repo", [4; 32])?.op_fold
    );
    Ok(())
}

#[test]
fn forged_tested_frontier_and_different_genesis_are_refused() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut first = vault.open_code_document("repo", "a.rs", "one", EntityId::now())?;
    let mut wrong = vault.open_code_document("repo", "a.rs", "two", EntityId::now())?;
    let receipt = vault.apply_code_file_edit(
        &mut first,
        &CodeFileEdit::between("a.rs", "one", "one!"),
        actor(),
    )?;
    assert!(
        vault
            .apply_code_file_edit(
                &mut wrong,
                &CodeFileEdit::between("a.rs", "two", "two!"),
                actor()
            )
            .is_err()
    );
    assert_eq!(wrong.text(), "two");
    let mut forged = receipt.after;
    forged.text_hash[0] ^= 1;
    assert_eq!(
        vault.code_document_at(&forged).unwrap_err().kind(),
        ErrorKind::InvalidCodeArtifactBody
    );
    Ok(())
}

#[test]
fn stored_snapshot_tampering_is_detected_by_full_regeneration() -> Result<()> {
    use loro::ExportMode;
    use rmpv::Value;
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let mut file = vault.open_code_document("repo", "checked.rs", "ok", EntityId::now())?;
    let tested = vault
        .apply_code_file_edit(
            &mut file,
            &CodeFileEdit::between("checked.rs", "ok", "good"),
            actor(),
        )?
        .after;
    let forged = file.doc.fork();
    forged.get_text("body").insert(0, "tampered ").unwrap();
    forged.commit();
    let snapshot = forged.export(ExportMode::Snapshot).unwrap();
    let key = super::codec::snapshot_key(&tested);
    let mut txn = vault.store.env.write_txn()?;
    let raw = vault.store.vault_meta.get(&txn, &key)?.unwrap();
    let Value::Map(mut row) = rmpv::decode::read_value(&mut raw.as_ref()).unwrap() else {
        panic!("snapshot row");
    };
    row.iter_mut()
        .find(|(k, _)| k.as_str() == Some("snapshot"))
        .unwrap()
        .1 = Value::Array(snapshot.into_iter().map(Value::from).collect());
    let mut changed = Vec::new();
    rmpv::encode::write_value(&mut changed, &Value::Map(row)).unwrap();
    vault.store.vault_meta.put(&mut txn, &key, &changed)?;
    txn.commit()?;
    assert_eq!(
        vault.code_document_at(&tested).unwrap_err().kind(),
        ErrorKind::InvalidCodeArtifactBody
    );
    Ok(())
}

#[test]
fn durable_ingress_identity_replays_without_a_second_operation() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let actor = actor();
    let session_id = EntityId::now();
    let operation = EntityId::now();
    let edit = CodeFileEdit::between("a.rs", "ab", "aXb");
    let mut doc = vault.open_code_document("repo", "a.rs", "ab", session_id)?;
    let first = vault.apply_code_file_edit_once(operation, &mut doc, &edit, actor)?;
    let mut reopened = vault.open_code_document("repo", "a.rs", "ab", session_id)?;
    let replay = vault.apply_code_file_edit_once(operation, &mut reopened, &edit, actor)?;
    assert_eq!(first, replay);
    assert_eq!(reopened.text(), "aXb");
    assert_eq!(vault.code_document_receipts(&first.document_id)?.len(), 1);
    assert!(
        vault
            .apply_code_file_edit_once(
                operation,
                &mut reopened,
                &CodeFileEdit::between("a.rs", "aXb", "aYb"),
                actor
            )
            .is_err()
    );
    Ok(())
}
