//! The supervisor's private per-launch manifest (DESIGN-V2 R2): one file per
//! launch binding the bytes the supervisor verified before it started the
//! worker (its code bundle, its environment lock and installed environment,
//! its native binary, its weights' install record, and the model, template
//! and tokenizer digests those bytes give) to one fresh launch nonce.
//!
//! The worker gets its path. An EXL3 worker echoes the SHA-256 of its exact
//! bytes beside its own epoch in every answer, and names the manifest's
//! `runtime` as its build; a llama.cpp launch answers under the alias of its
//! own identity manifest, which this one names. Either way the probe checks
//! the echo against the launch it started, so a stale or foreign process
//! never qualifies. The worker's backend digests keep their own definitions:
//! an install record's digest is never a backend model digest.
use std::path::{Path, PathBuf};

use oneiron::llm::{CacheIdentity, WorkerKind};
use rand_core::RngCore as _;
use serde::Serialize;

use super::bundle::sha256_hex;

/// The schema this supervisor writes.
const SCHEMA_VERSION: u64 = 1;

/// What a launch's build is: the digest an EXL3 worker names as its
/// `runtime`.
#[derive(Serialize)]
pub(super) struct BuildSection<'a> {
    pub(super) bundle_sha256: &'a str,
    pub(super) env_freeze_sha256: Option<&'a str>,
    pub(super) env_lock_sha256: Option<&'a str>,
    pub(super) python_version: Option<&'a str>,
}

impl BuildSection<'_> {
    /// SHA-256 of the section's compact JSON.
    pub(super) fn digest(&self) -> String {
        sha256_hex(&serde_json::to_vec(self).unwrap_or_default())
    }
}

/// One launch's manifest, its keys in name order.
#[derive(Serialize)]
pub(super) struct LaunchManifest<'a> {
    /// What the backend's identity names as its loaded weights: EXL3's
    /// weights-manifest digest, or the target GGUF's SHA-256.
    pub(super) backend_model: Option<&'a str>,
    pub(super) bundle_sha256: &'a str,
    pub(super) draft_record_sha256: Option<&'a str>,
    pub(super) env_freeze_sha256: Option<&'a str>,
    pub(super) env_lock_sha256: Option<&'a str>,
    pub(super) kind: WorkerKind,
    /// 32 random hex digits, new for every launch.
    pub(super) launch_nonce: String,
    /// The llama.cpp launch's own identity manifest digest.
    pub(super) llama_identity_sha256: Option<&'a str>,
    pub(super) model: &'a str,
    pub(super) native_binary_sha256: Option<&'a str>,
    pub(super) python_version: Option<&'a str>,
    /// The build digest the worker names as its `runtime`.
    pub(super) runtime: &'a str,
    pub(super) schema_version: u64,
    pub(super) template_sha256: Option<&'a str>,
    pub(super) tokenizer_sha256: Option<&'a str>,
    /// The PR-a install record's digest of the target's manifest.
    pub(super) weights_record_sha256: &'a str,
    pub(super) wire_model: &'a str,
    pub(super) worker_id: &'a str,
}

/// A fresh launch nonce: 32 hex digits.
pub(super) fn launch_nonce() -> String {
    let mut nonce = [0_u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    nonce.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The schema version a manifest carries.
pub(super) const fn schema_version() -> u64 {
    SCHEMA_VERSION
}

/// What one launch must answer with: the digest of the manifest it was
/// given, the alias a llama.cpp launch was given, and the identity its
/// verified bytes give; and where an EXL3 launch answers natively, when it
/// was given a socket.
#[derive(Clone, Debug)]
pub(super) struct LaunchRecord {
    pub(super) manifest_sha256: String,
    pub(super) llama_alias: Option<String>,
    pub(super) pins: CacheIdentity,
    pub(super) native_socket: Option<PathBuf>,
}

/// The current launch's record, shared by a worker's launcher, which fills
/// it before each launch, and its probe, which checks the answer against it.
pub(super) type LaunchSlot = std::sync::Mutex<Option<LaunchRecord>>;

/// Writes `manifest` as `<dir>/<sha256>.json`, readable by this user alone,
/// and removes the earlier launches' manifests there. Returns its path and
/// digest.
pub(super) fn write(
    dir: &Path,
    manifest: &LaunchManifest<'_>,
) -> std::io::Result<(PathBuf, String)> {
    let bytes = serde_json::to_vec(manifest).map_err(std::io::Error::other)?;
    let digest = sha256_hex(&bytes);
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.join(format!("{digest}.json"));
    let temp = dir.join(format!(".{digest}.tmp"));
    std::fs::write(&temp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temp, &path)?;
    for entry in std::fs::read_dir(dir)?.flatten() {
        let earlier = entry.path();
        if earlier != path && earlier.extension().is_some_and(|ext| ext == "json") {
            let _ = std::fs::remove_file(earlier);
        }
    }
    Ok((path, digest))
}
