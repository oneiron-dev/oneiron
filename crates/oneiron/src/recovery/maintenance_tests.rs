//! The canonical snapshot as one owner maintenance act (ARCH-0038 escape
//! hatch, recovery ladder and the no-kept-snapshot ordering).

use super::*;
use crate::store::GateDecisionId;
use crate::sync::bridge::Materializer;
use crate::sync::types::WindowKey;
use crate::sync::window::{LoadedWindow, reverse_rematerialize};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault, VaultConfig};
use std::sync::Arc;

/// The recovery directory's file names, sorted.
fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// ARCH-0038 done-means: capture a window with its writers stopped, corrupt
/// the manifest, recover, then check the tier and the quarantine file. The
/// act also repairs a damaged LMDB row, and no snapshot file outlives it, on
/// success or failure.
#[test]
fn owner_window_recovery_quarantines_a_bad_manifest_repairs_lmdb_and_keeps_no_snapshot()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open_owned(
        root.path().join("vault"),
        VaultConfig::default(),
    )?);
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    let learned_at = 1_772_400_000; // 2026-03
    let rows = [EntityId::now(), EntityId::now()];
    for (row, name) in rows.iter().zip(["first", "second"]) {
        vault.put_entity(
            row,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &crate::conversation_dag::fixtures::body(name),
        )?;
    }
    let key = WindowKey::from_timestamp(learned_at);
    // The window's durable CRDT state, mirrored and persisted as a window
    // open does; no window stays loaded afterwards.
    {
        let window =
            LoadedWindow::new("local", key.clone(), &vault, &Arc::new(Materializer::new()));
        reverse_rematerialize(&vault, &window.doc, &key)?;
        window.persist_state(&vault)?;
    }
    let window = key.as_str();
    let dir = root.path().join("recovery");
    let manifest = dir.join(format!("{window}.manifest"));

    let first = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &dir,
        RecoveryBudget::default(),
    )?;
    assert_eq!(first.tier, RecoveryTier::FullRebuild, "no manifest yet");
    assert_eq!(first.quarantine_path, None);
    assert_eq!(files(&dir), [format!("{window}.manifest")]);
    let healthy = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &dir,
        RecoveryBudget::default(),
    )?;
    assert_eq!(healthy.tier, RecoveryTier::Healthy);
    assert_eq!(healthy.snapshot_blake3, first.snapshot_blake3);

    // Corrupt the manifest and lose one LMDB row; an interrupted act also
    // left its artifact behind.
    std::fs::write(&manifest, b"corrupt manifest")?;
    let original = vault.get_raw(&rows[1])?.unwrap();
    vault.with_write_txn(|txn| {
        vault.store.entities.delete(txn, rows[1].as_bytes())?;
        Ok(())
    })?;
    assert_eq!(vault.get_raw(&rows[1])?, None);
    std::fs::write(dir.join(format!("{window}.canonical")), b"left by a crash")?;

    let repaired = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &dir,
        RecoveryBudget::default(),
    )?;
    assert_eq!(repaired.tier, RecoveryTier::FullRebuild);
    let quarantine = dir.join(format!("{window}.manifest.invalid-1"));
    assert_eq!(
        repaired.quarantine_path.as_deref(),
        Some(quarantine.as_path())
    );
    assert_eq!(std::fs::read(&quarantine)?, b"corrupt manifest");
    assert_eq!(
        RecoveryManifest::decode(&std::fs::read(&manifest)?)?.snapshot_blake3,
        repaired.snapshot_blake3
    );
    assert_eq!(vault.get_raw(&rows[1])?, Some(original));
    assert_eq!(
        files(&dir),
        [
            format!("{window}.manifest"),
            format!("{window}.manifest.invalid-1")
        ],
        "no snapshot file remains"
    );

    // A failed act keeps no snapshot either, and leaves the manifest alone.
    let kept = std::fs::read(&manifest)?;
    let starved = RecoveryBudget {
        max_bytes: 64,
        max_obligations: 4096,
    };
    assert!(
        vault
            .recover_window_from_canonical_snapshot(&owner, window, &dir, starved)
            .is_err()
    );
    assert_eq!(std::fs::read(&manifest)?, kept);
    assert_eq!(
        files(&dir),
        [
            format!("{window}.manifest"),
            format!("{window}.manifest.invalid-1")
        ]
    );
    Ok(())
}

/// The act runs only with the window's writers stopped: a vault this process
/// does not own is refused before anything is captured.
#[test]
fn owner_window_recovery_refuses_a_vault_without_the_writer_lease() -> Result<()> {
    let root = tempfile::tempdir()?;
    let vault = Vault::open(root.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    let dir = root.path().join("recovery");
    assert!(matches!(
        vault.recover_window_from_canonical_snapshot(
            &owner,
            "2026-03",
            &dir,
            RecoveryBudget::default()
        ),
        Err(Error::ConcurrentWrite(_))
    ));
    assert!(!dir.exists());
    Ok(())
}
