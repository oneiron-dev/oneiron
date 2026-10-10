//! The canonical snapshot as one owner maintenance act (ARCH-0038 escape
//! hatch, recovery ladder and the no-kept-snapshot ordering).

use super::canonical::held_bytes;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::{ArtifactError, GateError};
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
        .expect("recovery directory")
        .map(|entry| {
            entry
                .expect("recovery directory entry")
                .file_name()
                .into_string()
                .expect("utf-8 file name")
        })
        .collect();
    names.sort();
    names
}

/// A personal vault owned by this process, holding one window's durable
/// CRDT state over its rows, as a window open mirrors and persists it; no
/// window stays loaded afterwards.
struct Fixture {
    root: tempfile::TempDir,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    rows: Vec<EntityId>,
    key: WindowKey,
}

/// The window over two small rows.
fn fixture() -> Result<Fixture> {
    fixture_of(&["first", "second"])
}

/// The window over one row per name.
fn fixture_of(names: &[&str]) -> Result<Fixture> {
    let root = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open_owned(
        root.path().join("vault"),
        VaultConfig::default(),
    )?);
    let actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault.authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())?;
    let learned_at = 1_772_400_000; // 2026-03
    let rows: Vec<_> = names.iter().map(|_| EntityId::now()).collect();
    for (row, name) in rows.iter().zip(names) {
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
    {
        let window =
            LoadedWindow::new("local", key.clone(), &vault, &Arc::new(Materializer::new()));
        reverse_rematerialize(&vault, &window.doc, &key)?;
        window.persist_state(&vault)?;
    }
    Ok(Fixture {
        root,
        vault,
        owner,
        rows,
        key,
    })
}

/// ARCH-0038 done-means: capture a window with its writers stopped, corrupt
/// the manifest, recover, then check the tier and the quarantine file. The
/// act also repairs a damaged LMDB row, and leaves no snapshot file behind.
#[test]
fn owner_window_recovery_quarantines_a_bad_manifest_repairs_lmdb_and_keeps_no_snapshot()
-> Result<()> {
    let Fixture {
        root,
        vault,
        owner,
        rows,
        key,
    } = fixture()?;
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

    // Corrupt the manifest and lose one LMDB row. The row was cited, so its
    // document is retained and only its live projection is lost, the shape
    // the revision store rebuilds a row from.
    std::fs::write(&manifest, b"corrupt manifest")?;
    let original = vault.get_raw(&rows[1])?.unwrap();
    vault.pin_entity_revision(&rows[1])?;
    vault.with_write_txn(|txn| {
        vault.store.entities.delete(txn, rows[1].as_bytes())?;
        Ok(())
    })?;
    assert_eq!(vault.get_raw(&rows[1])?, None);

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
    Ok(())
}

/// Sol F1 (REV-9 D2a): the snapshot is a plaintext image, so it never
/// touches disk, where a crash between writing and unlinking it would keep
/// it. A healthy act recovers through a directory nothing can be written
/// into, and a window too large for the act's memory budget is refused with
/// a typed error rather than spilled.
#[cfg(unix)]
#[test]
fn owner_window_recovery_writes_no_snapshot_byte_to_disk() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let Fixture {
        root,
        vault,
        owner,
        key,
        ..
    } = fixture()?;
    let window = key.as_str();
    let dir = root.path().join("recovery");
    let manifest = dir.join(format!("{window}.manifest"));
    let first = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &dir,
        RecoveryBudget::default(),
    )?;
    assert_eq!(first.tier, RecoveryTier::FullRebuild);

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500))?;
    let healthy = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &dir,
        RecoveryBudget::default(),
    );
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    assert_eq!(healthy?.tier, RecoveryTier::Healthy);

    let kept = std::fs::read(&manifest)?;
    let starved = RecoveryBudget {
        max_bytes: 64,
        max_obligations: 4096,
    };
    assert!(matches!(
        vault.recover_window_from_canonical_snapshot(&owner, window, &dir, starved),
        Err(Error::Artifact(ArtifactError::OverlayLimit {
            limit: 64,
            ..
        }))
    ));
    assert_eq!(std::fs::read(&manifest)?, kept);
    assert_eq!(files(&dir), [format!("{window}.manifest")]);
    Ok(())
}

/// Sol F7 (REV-9 D2a): an authenticated human is not by that alone the
/// vault's owner. Another PERSON's proof is refused before anything is
/// captured, even with the writer lease held and the writers stopped.
#[test]
fn owner_window_recovery_refuses_a_human_who_is_no_owner() -> Result<()> {
    let Fixture {
        root, vault, key, ..
    } = fixture()?;
    let stranger = EntityId::now();
    vault.put_entity(
        &stranger,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange {
            start: 1_772_400_000,
            end: 1_772_400_000,
        },
        1_772_400_000,
        &crate::conversation_dag::fixtures::body("stranger"),
    )?;
    let proof =
        vault.authenticate_owner(stranger, &stranger.to_hex(), true, GateDecisionId::now())?;
    let dir = root.path().join("recovery");
    assert!(matches!(
        vault.recover_window_from_canonical_snapshot(
            &proof,
            key.as_str(),
            &dir,
            RecoveryBudget::default()
        ),
        Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
    ));
    assert!(!dir.exists());
    Ok(())
}

/// The act runs only with the window's writers stopped: a vault this process
/// does not own is refused before anything is captured.
#[test]
fn owner_window_recovery_refuses_a_vault_without_the_writer_lease() -> Result<()> {
    let root = tempfile::tempdir()?;
    let vault = Vault::open(root.path(), VaultConfig::default())?;
    let actor = vault.ensure_embedded_owner_actor().unwrap();
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

/// Greptile P2 (#1340): the act's budget bounds the memory it spends, not
/// only the artifact it keeps. A window many times the budget is refused
/// with `OverlayLimit` once its capture has copied the budget's worth, never
/// the whole window; an artifact over its limit is written up to the limit
/// and no further.
#[test]
fn owner_window_recovery_stops_copying_a_window_at_its_budget() -> Result<()> {
    let names: Vec<String> = (0..64).map(|row| format!("{row:0>8192}")).collect();
    let Fixture {
        root,
        vault,
        owner,
        key,
        ..
    } = fixture_of(&names.iter().map(String::as_str).collect::<Vec<_>>())?;
    let window = key.as_str();
    let budget = RecoveryBudget {
        max_bytes: 32 * 1024,
        max_obligations: 4096,
    };
    held_bytes::take_peak();
    let refused = vault.recover_window_from_canonical_snapshot(
        &owner,
        window,
        &root.path().join("recovery"),
        budget,
    );
    let held = held_bytes::take_peak();
    assert!(
        matches!(
            refused,
            Err(Error::Artifact(ArtifactError::OverlayLimit { limit, .. }))
                if limit == budget.max_bytes
        ),
        "a 512 KiB window over a 32 KiB budget is refused, got {refused:?}"
    );
    assert!(
        held > 0 && held <= budget.max_bytes,
        "the act held {held} bytes of the window, over its {} byte budget",
        budget.max_bytes
    );

    let loaded = LoadedWindow::new("local", key.clone(), &vault, &Arc::new(Materializer::new()));
    let snapshot = capture_canonical_window(&vault, window, &loaded.doc)?;
    let whole = snapshot.encode()?.len();
    assert!(whole > 8 * budget.max_bytes, "the whole window encodes");
    held_bytes::take_peak();
    assert!(matches!(
        snapshot.encode_within(budget.max_bytes),
        Err(Error::Artifact(ArtifactError::OverlayLimit { .. }))
    ));
    let written = held_bytes::take_peak();
    assert!(
        written > 0 && written <= budget.max_bytes,
        "the encoding wrote {written} of {whole} bytes past its {} byte limit",
        budget.max_bytes
    );
    Ok(())
}
