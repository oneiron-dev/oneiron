//! Census L7-21 (ARCH-0002 `#turn-time-built`): a TURN's learned time feeds
//! the consolidation watermark, so the witness and structural doors refuse a
//! TURN learned past the store clock plus their 300 s skew. The public raw
//! batch door now holds a TURN to the same ceiling. A whole-vault import
//! keeps the archive's learned time instead (Engine ruling 16:27, 13 Nov): a
//! TURN the archive learned ahead of this store's clock is restored.
//!
//! Fleet command: `cargo test --locked -p oneiron --all-features --test
//! turn_learned_time_ceiling` (public paths only).

use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The store clock's reading, in seconds.
const NOW: u64 = 1_800_000_000;
/// The skew the witness door tolerates past the store clock.
const SKEW_SECS: u64 = 300;
/// How far the clock of the install that wrote an archive runs ahead of the
/// importing store's clock: ten minutes, past the skew.
const ARCHIVE_AHEAD_SECS: u64 = 600;

fn open_vault(dir: &std::path::Path, clock: &Arc<ManualClock>) -> TestResult<Vault> {
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    Ok(Vault::open(dir, config)?)
}

/// Puts one TURN row learned at `learned_at` through the public raw batch
/// door and commits it.
fn put_turn(vault: &Vault, id: EntityId, learned_at: u64) -> oneiron::Result<()> {
    let body = rmp_serde::to_vec_named(&BTreeMap::from([("text", "the ferry leaves at nine")]))
        .map_err(|error| oneiron::Error::InvalidConfig(error.to_string()))?;
    vault
        .batch()
        .put(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .commit()
}

/// A TURN learned one second past the ceiling is refused by the raw batch
/// door, as the witness door refuses it, and nothing is stored. Once the
/// store clock reaches it, the same row lands. On main the raw door stored
/// it at once.
#[test]
fn a_raw_batch_turn_learned_past_the_ceiling_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let vault = open_vault(dir.path(), &clock)?;
    let turn = EntityId::now();
    let learned_at = NOW + SKEW_SECS + 1;

    let refused = put_turn(&vault, turn, learned_at);
    assert!(
        matches!(&refused, Err(error) if error.to_string().contains("turn time is in the future")),
        "a TURN learned past the ceiling was not refused: {refused:?}"
    );
    assert!(vault.get(&turn)?.is_none(), "the refused TURN was stored");

    clock.set(learned_at);
    put_turn(&vault, turn, learned_at)?;
    assert!(
        vault.get(&turn)?.is_some(),
        "the TURN did not land once the clock reached it"
    );
    Ok(())
}

/// A TURN learned exactly at the ceiling, or in the past, still lands.
#[test]
fn a_raw_batch_turn_at_the_ceiling_lands() -> TestResult {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let vault = open_vault(dir.path(), &clock)?;
    let at_ceiling = EntityId::now();
    let past = EntityId::now();

    put_turn(&vault, at_ceiling, NOW + SKEW_SECS)?;
    put_turn(&vault, past, NOW - 60)?;
    assert!(vault.get(&at_ceiling)?.is_some());
    assert!(vault.get(&past)?.is_some());
    Ok(())
}

/// A whole-vault import of an archive whose TURN was learned ten minutes
/// ahead of this store's clock lands, and the TURN keeps the archive's
/// learned time. Before the import's exemption the public door's ceiling
/// refused the TURN and the whole import failed.
#[test]
fn an_archive_turn_learned_ahead_of_the_store_clock_imports_with_its_time() -> TestResult {
    let source_dir = tempfile::tempdir()?;
    let source_clock = ManualClock::new(NOW + ARCHIVE_AHEAD_SECS);
    let source = open_vault(source_dir.path(), &source_clock)?;
    let turn = EntityId::now();
    let learned_at = NOW + ARCHIVE_AHEAD_SECS;
    put_turn(&source, turn, learned_at)?;
    let archive = source.export_whole_vault(true)?;

    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(NOW);
    let vault = open_vault(dir.path(), &clock)?;
    let imported = vault.import_whole_vault_archive(archive.bytes());
    assert!(
        imported.is_ok(),
        "the import of an archive whose TURN is ahead failed: {:?}",
        imported.err()
    );
    assert!(
        vault.get(&turn)?.is_some(),
        "the archived TURN did not land"
    );

    let restored = vault.export_whole_vault(true)?;
    let document = vault.read_whole_vault_archive(restored.bytes())?;
    let kept = document
        .evidence_ledger
        .entities
        .iter()
        .find(|row| row.id == turn.to_hex())
        .map(|row| row.learned_at);
    assert_eq!(
        kept,
        Some(learned_at),
        "the restored TURN does not keep the archive's learned time"
    );
    Ok(())
}
