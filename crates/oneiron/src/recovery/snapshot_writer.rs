//! Off-hot-path publication of canonical Layer-1 window artifacts.

use std::{fs, io::Write, path::Path};

use loro::LoroDoc;

use super::{CanonicalSnapshot, canonical::capture_canonical_window, quarantine};
use crate::{Error, Result, Vault};

/// Capture and durably publish a canonical window without replacing an existing artifact.
///
/// The caller must stop writers for this window during capture. This is an explicit
/// maintenance operation, never a write-path hook. The path must be on a local
/// filesystem whose atomic no-replace rename and directory sync are supported.
/// The returned blake3 digest covers the entire recovery-artifact envelope.
pub fn write_canonical_window_snapshot(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
    path: impl AsRef<Path>,
) -> Result<[u8; 32]> {
    let snapshot = capture_canonical_window(vault, window, doc)?;
    publish(&snapshot, path.as_ref())
}

fn publish(snapshot: &CanonicalSnapshot, path: &Path) -> Result<[u8; 32]> {
    let bytes = snapshot.encode()?;
    let digest = *blake3::hash(&bytes).as_bytes();
    let temporary = path.with_extension(format!("snapshot-{}", crate::EntityId::now().to_hex()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    // A snapshot contains private entity bytes; never expose them via a
    // world-readable temporary file, even briefly before publication.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    let outcome = (|| {
        file.write_all(&bytes)?;
        file.sync_all()?;
        quarantine::rename_no_replace(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::ConcurrentWrite("canonical snapshot already exists")
            } else {
                error.into()
            }
        })?;
        quarantine::sync_parent(path)?;
        Ok(digest)
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome
}
