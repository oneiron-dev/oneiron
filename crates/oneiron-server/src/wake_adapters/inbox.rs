//! A local handoff inbox and occurrence-id acknowledgements. The TASK in
//! the vault remains the durable mailbox; this spool is host-owned only.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use oneiron::context_board::WakeEnvelope;
use rand_core::{OsRng, RngCore as _};

pub(super) struct Inbox {
    directory: PathBuf,
}

impl Inbox {
    pub(super) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn ensure_directory(&self) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.directory)
    }

    pub(super) fn lock(&self) -> io::Result<File> {
        self.ensure_directory()?;
        let lock = open_new_or_existing(&self.directory.join(".lock"))?;
        lock.lock()?;
        Ok(lock)
    }

    fn path(&self, event_ref: &str, extension: &str) -> PathBuf {
        let key = blake3::hash(event_ref.as_bytes()).to_hex();
        self.directory.join(format!("{key}.{extension}"))
    }

    /// False means this exact occurrence was already handed over or acked.
    pub(super) fn enqueue(&self, wake: &WakeEnvelope) -> anyhow::Result<bool> {
        self.ensure_directory()?;
        if self.path(&wake.event_ref, "ack").exists() {
            return Ok(false);
        }
        let path = self.path(&wake.event_ref, "json");
        let created = atomic_new(&path, &serde_json::to_vec(wake)?)?;
        Ok(created && !self.path(&wake.event_ref, "ack").exists())
    }

    pub(super) fn pending(&self) -> anyhow::Result<Vec<WakeEnvelope>> {
        self.ensure_directory()?;
        let mut wakes = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let wake: WakeEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
            if !self.path(&wake.event_ref, "ack").exists() {
                wakes.push(wake);
            }
        }
        Ok(wakes)
    }

    pub(super) fn acknowledge(&self, event_ref: &str) -> anyhow::Result<()> {
        self.ensure_directory()?;
        let path = self.path(event_ref, "json");
        let ack = self.path(event_ref, "ack");
        if !ack.exists() {
            let wake: WakeEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
            anyhow::ensure!(
                wake.event_ref == event_ref,
                "wake occurrence does not match"
            );
            atomic_new(&ack, event_ref.as_bytes())?;
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn open_new_or_existing(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Publish whole, without overwriting an occurrence another bridge already
/// handed over. A partial stage is never a visible inbox item.
fn atomic_new(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let staged = path.with_extension(format!("{:016x}.tmp", OsRng.next_u64()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&staged, path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(staged);
    result
}
