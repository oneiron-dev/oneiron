//! Caller-visible canonical carry-list, bounded ladder and forward-rebuild laws.

use super::*;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::ArtifactError;
use crate::note::{NoteEdit, NoteEditOutcome, NoteVerdict};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault, VaultConfig};
use loro::LoroDoc;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    snapshot: CanonicalSnapshot,
    note: EntityId,
    soft: EntityId,
    hard: EntityId,
}

fn fixture() -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("fixture owner");
    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let note = vault
        .create_note("research", "birth document", actor)
        .unwrap();
    let NoteEditOutcome::RewriteFork { fork } = vault
        .edit_note(
            note,
            &NoteEdit::Rewrite {
                text: "before 🦀 secret after".to_owned(),
            },
            actor,
        )
        .unwrap()
    else {
        panic!("expected rewrite fork");
    };
    let proposal = vault.open_note_proposal(&[fork], "Replace", actor).unwrap();
    vault
        .review_note_proposal(proposal.id, NoteVerdict::Switch, actor)
        .unwrap();
    let soft = EntityId::now();
    vault.put_entity(
        &soft,
        crate::registry::ENTITY_TYPE_ASSET_TEXT,
        TimeRange { start: 42, end: 42 },
        42,
        b"deletedbody",
    )?;
    vault
        .batch()
        .edge(&soft, EdgeKind::DerivedFrom, &note, 1.0)
        .commit()?;
    let soft_value = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 100,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    vault.apply_replayed_tombstone(&soft, &soft_value)?;
    let hard = EntityId::now();
    let hard_value = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 101,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    vault.apply_replayed_tombstone(&hard, &hard_value)?;
    let window = LoroDoc::new();
    // The soft-delete publisher may have removed its entity/edge map entries.
    // Capture must recover its retained shell and graph without its old body.
    for id in [owner, note] {
        canonical::insert(
            &window,
            "entities",
            &id.to_hex(),
            &vault.get_raw(&id)?.unwrap(),
        )?;
    }
    {
        let txn = vault.store.env.read_txn()?;
        for row in vault.store.edges_out.prefix_iter(&txn, note.as_bytes())? {
            let (key, value) = row?;
            let target = EntityId::from_bytes(key[17..].try_into().unwrap())?;
            let key = format!("{}:{:02}:{}", note.to_hex(), key[16], target.to_hex());
            canonical::insert(&window, "edges", &key, &value)?;
        }
    }
    canonical::insert(&window, "tombstones", &soft.to_hex(), &soft_value)?;
    canonical::insert(&window, "tombstones", &hard.to_hex(), &hard_value)?;
    let snapshot = capture_canonical_window(&vault, "2026-09", &window)?;
    Ok(Fixture {
        _dir: dir,
        vault,
        snapshot,
        note,
        soft,
        hard,
    })
}

#[test]
fn canonical_carry_list_round_trips_with_blake3_and_fresh_documents() -> Result<()> {
    let fixture = fixture()?;
    let snapshot = &fixture.snapshot;
    assert_eq!(snapshot.doc_snapshots.len(), 2);
    assert_eq!(snapshot.head_move_receipts.len(), 1);
    assert_eq!(snapshot.tombstones.len(), 2);
    assert!(
        snapshot
            .entity_blobs
            .iter()
            .any(|row| row.id == *fixture.soft.as_bytes()
                && row.blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
    );
    assert!(
        !snapshot
            .entity_blobs
            .iter()
            .any(|row| row.id == *fixture.hard.as_bytes())
    );
    assert!(!snapshot.base_edges.is_empty());
    let bytes = snapshot.encode()?;
    assert_eq!(CanonicalSnapshot::decode(&bytes)?, *snapshot);
    assert_eq!(snapshot.blake3()?, *blake3::hash(&bytes).as_bytes());
    let rebuilt = rebuild_vault_window_from_canonical(snapshot)?;
    assert_eq!(
        capture_canonical_window(&fixture.vault, "2026-09", &rebuilt)?,
        *snapshot
    );
    for document in &snapshot.doc_snapshots {
        let fresh = document.rebuild()?;
        assert_eq!(fresh.get_text("body").to_string(), document.text);
    }
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        CanonicalSnapshot::decode(&corrupt),
        Err(Error::Artifact(ArtifactError::InvalidRecoveryArtifact(_)))
    ));
    Ok(())
}

#[test]
fn recovery_ladder_quarantines_before_rebuild_and_never_drops_pressure() -> Result<()> {
    let fixture = fixture()?;
    let snapshot = &fixture.snapshot;
    let manifest = RecoveryManifest::from_snapshot(snapshot)?;
    assert_eq!(
        assess_recovery(Some(&manifest), snapshot)?,
        RecoveryTier::Healthy
    );
    assert_eq!(assess_recovery(None, snapshot)?, RecoveryTier::FullRebuild);
    let mut damaged = manifest.clone();
    damaged.chunks.insert("entities".to_owned(), [3; 32]);
    assert_eq!(
        assess_recovery(Some(&damaged), snapshot)?,
        RecoveryTier::TargetedChunkRepair
    );
    damaged.chunks.insert("edges".to_owned(), [4; 32]);
    assert_eq!(
        assess_recovery(Some(&damaged), snapshot)?,
        RecoveryTier::FullRebuild
    );
    let path = fixture._dir.path().join("manifest");
    fs::write(&path, b"bad manifest")?;
    let error = match prepare_recovery(
        &path,
        snapshot,
        RecoveryBudget {
            max_bytes: usize::MAX,
            max_obligations: 0,
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("pressure must refuse all work"),
    };
    assert!(matches!(
        error,
        Error::Artifact(ArtifactError::OverlayLimit { .. })
    ));
    assert_eq!(error.kind(), crate::error::ErrorKind::OverlayLimit);
    assert!(error.is_retryable());
    assert_eq!(fs::read(&path)?, b"bad manifest");
    assert!(!invalid_artifact_path(&path, 1).exists());
    let prepared = prepare_recovery(&path, snapshot, RecoveryBudget::default())?;
    assert_eq!(prepared.tier, RecoveryTier::FullRebuild);
    assert_eq!(
        fs::read(prepared.quarantine_path.as_ref().unwrap())?,
        b"bad manifest"
    );
    assert!(!path.exists());
    assert_eq!(prepared.repaired_manifest(), &manifest);
    Ok(())
}

#[test]
fn redaction_preserves_unrelated_canonical_bytes_and_refuses_unresolved_copies() -> Result<()> {
    let fixture = fixture()?;
    let snapshot = &fixture.snapshot;
    let head = snapshot
        .document_heads
        .iter()
        .find(|row| row.entity_id == *fixture.note.as_bytes())
        .unwrap();
    let head = EntityId::from_bytes(head.head)?;
    let quote = *blake3::hash("🦀 secret".as_bytes()).as_bytes();
    let redacted = snapshot.excluding_document_span(fixture.note, head, 7, 15, quote)?;
    let mut expected = snapshot.clone();
    expected
        .doc_snapshots
        .iter_mut()
        .find(|row| row.head == *head.as_bytes())
        .unwrap()
        .text = "before  after".to_owned();
    assert_eq!(redacted.encode()?, expected.encode()?);
    assert_eq!(redacted.entity_blobs, snapshot.entity_blobs);
    assert_eq!(redacted.base_edges, snapshot.base_edges);
    assert_eq!(redacted.head_move_receipts, snapshot.head_move_receipts);
    let fresh = rebuild_vault_window_from_canonical(&redacted)?;
    assert_eq!(
        capture_canonical_window(&fixture.vault, "2026-09", &fresh)?.entity_blobs,
        snapshot.entity_blobs
    );
    assert!(
        snapshot
            .excluding_document_span(fixture.note, head, 7, 15, [0; 32])
            .is_err()
    );
    let mut copies = snapshot.clone();
    copies
        .doc_snapshots
        .iter_mut()
        .find(|row| row.head != *head.as_bytes())
        .unwrap()
        .text
        .push_str(" 🦀 secret");
    assert!(
        copies
            .excluding_document_span(fixture.note, head, 7, 15, quote)
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_head_binding_and_soft_payload_are_rejected_before_rebuild() -> Result<()> {
    let fixture = fixture()?;
    let mut invalid = fixture.snapshot.clone();
    invalid.document_heads[0].head = *EntityId::now().as_bytes();
    assert!(invalid.validate().is_err());
    invalid = fixture.snapshot.clone();
    invalid
        .entity_blobs
        .iter_mut()
        .find(|row| row.id == *fixture.soft.as_bytes())
        .unwrap()
        .blob
        .push(b'x');
    assert!(rebuild_vault_window_from_canonical(&invalid).is_err());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn standard_forward_rebuild_restores_documents_shells_graph_and_indexes() -> Result<()> {
    let fixture = fixture()?;
    let dir = tempfile::tempdir()?;
    let target = Vault::open(dir.path(), VaultConfig::default())?;
    let path = dir.path().join("manifest");
    fs::write(&path, b"corrupt")?;
    let materializer = crate::sync::bridge::Materializer::new();
    let recovery = recover_vault_window(
        &target,
        &materializer,
        &path,
        &fixture.snapshot,
        RecoveryBudget::default(),
    )?;
    assert_eq!(recovery.tier, RecoveryTier::FullRebuild);
    assert_eq!(
        target.note_text(fixture.note)?,
        fixture.vault.note_text(fixture.note)?
    );
    assert_eq!(
        target.get_raw(&fixture.soft)?,
        fixture.vault.get_raw(&fixture.soft)?
    );
    assert!(target.get_raw(&fixture.hard)?.is_none());
    assert_eq!(
        target.targets(&fixture.soft, EdgeKind::DerivedFrom, None)?,
        vec![fixture.note]
    );
    assert!(
        target
            .search_text("secret", 20)?
            .iter()
            .any(|row| row.id == fixture.note)
    );
    assert_eq!(
        RecoveryManifest::decode(&fs::read(&path)?)?,
        RecoveryManifest::from_snapshot(&fixture.snapshot)?
    );
    let again = recover_vault_window(
        &target,
        &materializer,
        &path,
        &fixture.snapshot,
        RecoveryBudget::default(),
    )?;
    assert_eq!(again.tier, RecoveryTier::Healthy);
    let head = target.note_document(fixture.note)?.unwrap().head();
    let redacted = fixture.snapshot.excluding_document_span(
        fixture.note,
        head,
        7,
        15,
        *blake3::hash("🦀 secret".as_bytes()).as_bytes(),
    )?;
    recover_vault_window(
        &target,
        &materializer,
        &path,
        &redacted,
        RecoveryBudget::default(),
    )?;
    assert_eq!(target.note_text(fixture.note)?, "before  after");
    assert!(
        !target
            .search_text("secret", 20)?
            .iter()
            .any(|row| row.id == fixture.note)
    );
    assert_eq!(
        target.get_raw(&fixture.note)?,
        fixture.vault.get_raw(&fixture.note)?
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn hard_delete_marker_blocks_soft_shell_recreation_without_quarantining_manifest() -> Result<()> {
    let fixture = fixture()?;
    let dir = tempfile::tempdir()?;
    let target = Vault::open(dir.path(), VaultConfig::default())?;
    let hard = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 200,
        request_id: *EntityId::now().as_bytes(),
    }
    .encode();
    target.apply_replayed_tombstone(&fixture.soft, &hard)?;
    let path = dir.path().join("manifest");
    fs::write(&path, b"bad")?;
    assert!(
        recover_vault_window(
            &target,
            &crate::sync::bridge::Materializer::new(),
            &path,
            &fixture.snapshot,
            RecoveryBudget::default()
        )
        .is_err()
    );
    assert!(target.get_raw(&fixture.soft)?.is_none());
    assert!(target.get_raw(&fixture.note)?.is_none());
    assert_eq!(fs::read(&path)?, b"bad");
    assert!(!invalid_artifact_path(&path, 1).exists());
    Ok(())
}

#[test]
fn canonical_capture_preserves_absent_roots_and_refuses_nonmap_carriers() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let window = LoroDoc::new();
    let before = window.get_deep_value();
    let snapshot = capture_canonical_window(&vault, "2026-09", &window)?;
    assert!(snapshot.entity_blobs.is_empty());
    assert_eq!(window.get_deep_value(), before);

    window
        .get_text("entities")
        .insert(0, "not a carrier map")
        .unwrap();
    window.commit();
    let before = window.get_deep_value();
    assert!(matches!(
        capture_canonical_window(&vault, "2026-09", &window),
        Err(crate::Error::Artifact(
            ArtifactError::InvalidRecoveryArtifact(_)
        ))
    ));
    assert_eq!(window.get_deep_value(), before);
    Ok(())
}
