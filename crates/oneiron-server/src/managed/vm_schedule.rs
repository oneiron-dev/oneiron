//! The standalone VM host's acknowledged wake ledger. It survives a host
//! restart even when the guest is asleep; it contains no credential frame.
//!
//! It holds one complete report at a time (FIX 9549): its head, the training
//! setting it carried and every entry still owed, each with the second it
//! fires (FIX 9498). An exact alarm fires at its `at`. A window fires at one
//! second inside it, chosen once for this vault, alarm and window
//! ([`window_fire_at`]) and kept with the entry, so vaults sharing a window
//! spread across it and a replay or a restart never moves the second. Every
//! due check and the next wake read the kept second.

use oneiron_vault_contract::{
    LedgerReport, LedgerReportHead, ManagedTrainingSetting, Schedule, UnixTs, WakeEntry,
    validate_wake_entries,
};
use serde::{Deserialize, Serialize};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

/// The BLAKE3 key-derivation context a window's fire time is chosen under.
const FIRE_AT_CONTEXT: &str = "oneiron vm wake window fire time v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    vault: String,
    /// The committed report's head; `null` before the first.
    #[serde(deserialize_with = "Option::deserialize")]
    report: Option<LedgerReportHead>,
    /// The committed report's training setting; `null` as `report` is.
    #[serde(deserialize_with = "Option::deserialize")]
    training: Option<ManagedTrainingSetting>,
    /// The report's entries not yet delivered, each with when it fires.
    entries: Vec<ScheduledWake>,
}

/// One wake entry as the vault declared it, and the second it fires.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScheduledWake {
    entry: WakeEntry,
    fire_at: UnixTs,
}

pub(super) struct VmWakeSchedule {
    path: PathBuf,
    ledger: Ledger,
}

/// The second the window `start..=end` of `vault`'s alarm `id` fires in
/// (FIX 9498): the BLAKE3 of the vault, the alarm's id and the window's
/// bounds, each with its length, picks one second of the window. The same
/// alarm and window always get the same second; the report's revision and
/// training setting play no part.
fn window_fire_at(vault: &str, id: &str, start: UnixTs, end: UnixTs) -> UnixTs {
    let mut hasher = blake3::Hasher::new_derive_key(FIRE_AT_CONTEXT);
    for field in [
        vault.as_bytes(),
        id.as_bytes(),
        &start.to_le_bytes()[..],
        &end.to_le_bytes()[..],
    ] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    let mut pick = [0u8; 16];
    pick.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    // Widened, so a window ending at u64::MAX still has its width.
    let width = u128::from(end.saturating_sub(start)) + 1;
    // Below `width`, which is at most 2^64: it fits.
    start.saturating_add((u128::from_le_bytes(pick) % width) as u64)
}

impl VmWakeSchedule {
    pub(super) fn load(path: PathBuf, vault: &str) -> anyhow::Result<Self> {
        let ledger = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Ledger>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ledger {
                vault: vault.to_owned(),
                report: None,
                training: None,
                entries: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            ledger.vault == vault,
            "VM wake ledger belongs to another vault"
        );
        for held in &ledger.entries {
            held.entry.validate()?;
        }
        Ok(Self { path, ledger })
    }

    fn save(&self, ledger: &Ledger) -> anyhow::Result<()> {
        let temporary = self.path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(ledger)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        std::fs::File::open(self.path.parent().expect("VM state directory"))?.sync_all()?;
        Ok(())
    }

    /// When `entry` fires: an exact alarm's `at`, a window's second kept for
    /// the same alarm and window, or else the one [`window_fire_at`] picks.
    fn fire_at(&self, entry: &WakeEntry) -> UnixTs {
        match entry.at {
            Schedule::Exact { at } => at,
            Schedule::Window { start, end } => self
                .ledger
                .entries
                .iter()
                .find(|held| held.entry.id == entry.id && held.entry.at == entry.at)
                .map_or_else(
                    || window_fire_at(&self.ledger.vault, &entry.id, start, end),
                    |held| held.fire_at,
                ),
        }
    }

    /// Commits `report`, a complete one whose digest checked, as the one the
    /// host holds, with each entry's fire time, durably and in one rename.
    /// A report older than the one held is acknowledged without replacing
    /// it, and a replay of the one held without restoring alarms already
    /// delivered; another report under the held revision is refused.
    /// Persistence precedes acknowledgement and snapshot.
    pub(super) fn replace(&mut self, report: LedgerReport) -> anyhow::Result<()> {
        validate_wake_entries(&report.entries)?;
        if let Some(held) = &self.ledger.report {
            if report.head.rev == held.rev {
                anyhow::ensure!(
                    report.head.report_digest == held.report_digest,
                    "another ledger report under the revision the host holds"
                );
                return Ok(());
            }
            if report.head.rev < held.rev {
                return Ok(());
            }
        }
        let entries = report
            .entries
            .into_iter()
            .map(|entry| ScheduledWake {
                fire_at: self.fire_at(&entry),
                entry,
            })
            .collect();
        let ledger = Ledger {
            vault: self.ledger.vault.clone(),
            report: Some(report.head),
            training: Some(report.training),
            entries,
        };
        self.save(&ledger)?;
        self.ledger = ledger;
        Ok(())
    }

    pub(super) fn due(&self, now: UnixTs) -> Vec<WakeEntry> {
        self.ledger
            .entries
            .iter()
            .filter(|held| held.fire_at <= now)
            .map(|held| held.entry.clone())
            .collect()
    }

    pub(super) fn has_due(&self, now: UnixTs) -> bool {
        self.ledger.entries.iter().any(|held| held.fire_at <= now)
    }

    /// The earliest second an owed entry fires: what a sleep hands its
    /// supervisor as the next wake.
    pub(super) fn next_wake(&self) -> Option<UnixTs> {
        self.ledger.entries.iter().map(|held| held.fire_at).min()
    }

    /// Only after the guest acknowledged alarm_due. A crash before this
    /// write may redeliver the same stable alarm id, never lose it. Every
    /// other entry keeps its fire time.
    pub(super) fn delivered(&mut self, entry: &WakeEntry) -> anyhow::Result<()> {
        let ledger = Ledger {
            vault: self.ledger.vault.clone(),
            report: self.ledger.report.clone(),
            training: self.ledger.training.clone(),
            entries: self
                .ledger
                .entries
                .iter()
                .filter(|pending| pending.entry != *entry)
                .cloned()
                .collect(),
        };
        self.save(&ledger)?;
        self.ledger = ledger;
        Ok(())
    }
}
