//! Boot-lifetime replay of the companion's already authenticated lifecycle
//! requests. A replacement restores this before it can carry any work.

use super::{BackupPlanRoot, Gate, Registry, open_dir_at, open_dir_path, register};
use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

const STATE: &str = "runtime.json";
const TEMP: &str = ".runtime.json.tmp";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    vault: String,
    uid: u32,
    parked: bool,
    backup: Backup,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Backup {
    Unregistered,
    Registered { dir: PathBuf, label: String },
}

pub(in crate::managed::vm_outbox) struct Runtime {
    dir: File,
    snapshot: Snapshot,
}

impl Runtime {
    /// Initial starts reset the record before the engine runs. Only a
    /// replacement reads it, with the same actual vault and UID.
    pub(in crate::managed::vm_outbox) fn prepare(
        vault: &str,
        uid: u32,
        resuming: bool,
        gate: &Gate,
        registry: &Registry,
    ) -> io::Result<Self> {
        let dir = open_dir_at(
            &open_dir_path(Path::new(super::ENDPOINT_PARENT))?,
            super::ENDPOINT_DIR,
        )?;
        let snapshot = if resuming {
            let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let file = File::from(rustix::fs::openat(&dir, STATE, flags, Mode::empty())?);
            serde_json::from_reader::<_, Snapshot>(file).map_err(io::Error::other)?
        } else {
            Snapshot {
                vault: vault.to_owned(),
                uid,
                parked: false,
                backup: Backup::Unregistered,
            }
        };
        if snapshot.vault != vault || snapshot.uid != uid {
            return Err(io::Error::other(
                "the companion runtime names another vault or UID",
            ));
        }
        let plan: Option<BackupPlanRoot> = match &snapshot.backup {
            Backup::Unregistered => None,
            Backup::Registered { dir, label } => {
                Some(register(dir, label, uid).map_err(io::Error::other)?)
            }
        };
        if snapshot.parked {
            // No carrier has started, so there can be no commit to wait for.
            gate.park();
        }
        *registry.lock().unwrap_or_else(PoisonError::into_inner) = plan;
        let runtime = Self { dir, snapshot };
        if !resuming {
            runtime.write(&runtime.snapshot)?;
        }
        Ok(runtime)
    }

    pub(super) fn set_parked(&mut self, parked: bool) -> io::Result<()> {
        let mut next = self.snapshot.clone();
        next.parked = parked;
        self.write(&next)?;
        self.snapshot = next;
        Ok(())
    }

    pub(super) fn set_backup(&mut self, dir: &Path, label: &str) -> io::Result<()> {
        let mut next = self.snapshot.clone();
        next.backup = Backup::Registered {
            dir: dir.to_owned(),
            label: label.to_owned(),
        };
        self.write(&next)?;
        self.snapshot = next;
        Ok(())
    }

    fn write(&self, snapshot: &Snapshot) -> io::Result<()> {
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut file = File::from(rustix::fs::openat(
            &self.dir,
            TEMP,
            flags,
            Mode::from_raw_mode(0o600),
        )?);
        serde_json::to_writer(&mut file, snapshot).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        rustix::fs::renameat(&self.dir, TEMP, &self.dir, STATE)?;
        self.dir.sync_all()
    }
}
