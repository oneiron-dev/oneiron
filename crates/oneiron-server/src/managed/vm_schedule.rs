//! The standalone VM host's acknowledged wake ledger. It survives a host
//! restart even when the guest is asleep; it contains no credential frame.

use oneiron_vault_contract::{Schedule, UnixTs, WakeEntry, validate_wake_entries};
use serde::{Deserialize, Serialize};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    vault: String,
    rev: Option<u64>,
    entries: Vec<WakeEntry>,
}

pub(super) struct VmWakeSchedule {
    path: PathBuf,
    ledger: Ledger,
}

fn wake_at(entry: &WakeEntry) -> UnixTs {
    match entry.at {
        Schedule::Exact { at } => at,
        Schedule::Window { start, .. } => start,
    }
}

impl VmWakeSchedule {
    pub(super) fn load(path: PathBuf, vault: &str) -> anyhow::Result<Self> {
        let ledger = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<Ledger>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ledger {
                vault: vault.to_owned(),
                rev: None,
                entries: Vec::new(),
            },
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            ledger.vault == vault,
            "VM wake ledger belongs to another vault"
        );
        validate_wake_entries(&ledger.entries)?;
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

    /// A stale or repeated push is acknowledged without replacing alarms
    /// already delivered. Persistence precedes acknowledgement and snapshot.
    pub(super) fn replace(&mut self, rev: u64, entries: Vec<WakeEntry>) -> anyhow::Result<()> {
        validate_wake_entries(&entries)?;
        if self.ledger.rev.is_some_and(|current| rev <= current) {
            return Ok(());
        }
        let ledger = Ledger {
            vault: self.ledger.vault.clone(),
            rev: Some(rev),
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
            .filter(|entry| wake_at(entry) <= now)
            .cloned()
            .collect()
    }

    pub(super) fn has_due(&self, now: UnixTs) -> bool {
        self.ledger
            .entries
            .iter()
            .any(|entry| wake_at(entry) <= now)
    }

    /// Only after the guest acknowledged alarm_due. A crash before this
    /// write may redeliver the same stable alarm id, never lose it.
    pub(super) fn delivered(&mut self, entry: &WakeEntry) -> anyhow::Result<()> {
        let ledger = Ledger {
            vault: self.ledger.vault.clone(),
            rev: self.ledger.rev,
            entries: self
                .ledger
                .entries
                .iter()
                .filter(|pending| *pending != entry)
                .cloned()
                .collect(),
        };
        self.save(&ledger)?;
        self.ledger = ledger;
        Ok(())
    }
}
