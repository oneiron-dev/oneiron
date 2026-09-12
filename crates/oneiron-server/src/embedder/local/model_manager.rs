//! Where the local model's files live, and how they get there.
//!
//! Six files, one repository, one commit, one sha256 each. The digests are
//! pinned in this file because the Hugging Face tree API exposes no LFS oid at
//! a revision: the only way to know the bytes are the bytes we measured is to
//! measure them once and refuse anything else afterwards.
//!
//! Nothing here runs at boot. The worker calls it on its first pass, so a vault
//! whose model has never been fetched still opens and still answers BM25 while
//! the download runs (OF-022, the two-tier write rule).

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::config::LocalEmbedderConfig;

/// Where the pinned artifacts live. Only a test ever points this elsewhere.
const HUGGINGFACE_BASE_URL: &str = "https://huggingface.co";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Refuse a file larger than this before writing it: a redirect to the wrong
/// place must not fill the disk.
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// One file of the model, with the digest that makes it that file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PinnedArtifact {
    /// Path within the repository, also the path under the model directory.
    pub(crate) file: &'static str,
    pub(crate) sha256: &'static str,
    /// Size in bytes at the pinned revision, checked before the digest so an
    /// obviously wrong download fails without hashing a gigabyte.
    pub(crate) bytes: u64,
}

/// The default local model's files at the pinned revision.
///
/// Digests measured on the first verified download, 2026-09-11. `model.safetensors`
/// carries the official bf16 weights; the Q8_0 the provider runs is produced at
/// load time and never stored.
pub(crate) const HARRIER_06_FILES: [PinnedArtifact; 6] = [
    PinnedArtifact {
        file: "config.json",
        sha256: "eb15983a1c7f53ecf3d3f1880e676a56967650b0c3c4ed2387c3851133f2d7ef",
        bytes: 1_355,
    },
    PinnedArtifact {
        file: "modules.json",
        sha256: "84e40c8e006c9b1d6c122e02cba9b02458120b5fb0c87b746c41e0207cf642cf",
        bytes: 349,
    },
    PinnedArtifact {
        file: "config_sentence_transformers.json",
        sha256: "ad2096929147368b5d0ba5322ea394d50911be4d348091c9f3b0ad06c3763d91",
        bytes: 351,
    },
    PinnedArtifact {
        file: "1_Pooling/config.json",
        sha256: "7652a48b1c8ceb3f7d1c96e4b53d50b79231be6876f40e37534ecccdffbd5551",
        bytes: 297,
    },
    PinnedArtifact {
        file: "tokenizer.json",
        sha256: "def76fb086971c7867b829c23a26261e38d9d74e02139253b38aeb9df8b4b50a",
        bytes: 11_423_705,
    },
    PinnedArtifact {
        file: "model.safetensors",
        sha256: "6bb124227f33c3dbf7fbbd38119b2afa8be959e93666d3c9be7142b66708b66c",
        bytes: 1_192_133_232,
    },
];

/// The files the local provider needs, for the configured repository.
///
/// Only the default repository has pinned digests. A host that points `repo` at
/// something else is telling the server it knows better, so the same six names
/// are required and the digest check is skipped rather than failed.
pub(crate) fn model_files(config: &LocalEmbedderConfig) -> Vec<PinnedArtifact> {
    if config.repo == crate::config::embedder::DEFAULT_LOCAL_REPO
        && config.revision == crate::config::embedder::DEFAULT_LOCAL_REVISION
    {
        return HARRIER_06_FILES.to_vec();
    }
    HARRIER_06_FILES
        .iter()
        .map(|artifact| PinnedArtifact {
            file: artifact.file,
            sha256: UNPINNED,
            bytes: 0,
        })
        .collect()
}

/// Digest placeholder for a repository this build has never measured.
pub(crate) const UNPINNED: &str = "unpinned";

/// Root the downloaded models live under: `<root>/<org>/<name>/<rev>/<file>`.
///
/// Follows the CJK-dictionary convention already in this crate — the XDG data
/// directory first, then the home directory's share tree — so a host has one
/// place to look for everything the server downloads.
pub(crate) fn models_root(config: &LocalEmbedderConfig) -> oneiron::Result<PathBuf> {
    resolve_models_root(
        config.models_dir.as_deref(),
        absolute_env_dir("XDG_DATA_HOME"),
        absolute_env_dir("HOME"),
    )
}

/// The root resolution itself, with the environment passed in.
///
/// A host with neither variable set has no data directory to write to, and a
/// relative fallback would scatter a 1.19 GB checkpoint through whatever
/// directory the process happened to start in — and then download it again
/// from the next one. So the resolution fails and says which three settings
/// would fix it.
pub(super) fn resolve_models_root(
    configured: Option<&Path>,
    xdg_data_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> oneiron::Result<PathBuf> {
    if let Some(configured) = configured {
        return Ok(configured.to_path_buf());
    }
    if let Some(xdg) = xdg_data_home {
        return Ok(xdg.join("oneiron").join("models"));
    }
    if let Some(home) = home {
        return Ok(home
            .join(".local")
            .join("share")
            .join("oneiron")
            .join("models"));
    }
    Err(oneiron::Error::InvalidConfig(
        "embedder models root is unresolvable: neither XDG_DATA_HOME nor HOME names an absolute \
         directory; set embedder.models_dir (--embedder-models-dir / \
         ONEIRON_EMBEDDER_MODELS_DIR) to the directory the model artifacts belong in"
            .to_owned(),
    ))
}

/// An environment variable read as an absolute directory.
///
/// Unset, empty and relative are the same answer here: none of them names a
/// place a gigabyte of model may be written to.
fn absolute_env_dir(key: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(key)?);
    path.is_absolute().then_some(path)
}

/// The directory the six files sit in.
pub(crate) fn model_dir(config: &LocalEmbedderConfig) -> oneiron::Result<PathBuf> {
    if let Some(configured) = config.model_dir.as_ref() {
        return Ok(configured.clone());
    }
    let mut dir = models_root(config)?;
    for segment in config.repo.split('/') {
        dir.push(segment);
    }
    dir.push(&config.revision);
    Ok(dir)
}

/// Fetches and verifies the local model's files.
///
/// Lives on the embedder slot, never in a process global: the artifacts belong
/// to the server that is going to load them, and the worker holds that slot
/// across every retry.
pub(in crate::embedder) struct ModelManager {
    /// Host the artifacts are fetched from, without a trailing slash.
    base_url: String,
    /// Artifacts verified in this process, as they looked when they passed.
    ///
    /// A load that fails for a reason that is not the artifacts — a device this
    /// build cannot reach, a width the vault disagrees with — sends the worker
    /// round a backoff that tops out at a minute, and every pass used to hash
    /// 1.19 GB again before reaching the same failure. A file that has not
    /// changed since it was verified is not hashed again.
    ///
    /// A field on the manager the slot owns, never a process static: two vaults
    /// in one process keep their own answers, and nothing here outlives the
    /// server that asked.
    verified: Mutex<HashMap<PathBuf, FileStamp>>,
}

impl Default for ModelManager {
    /// The public Hugging Face host, which is where the pinned artifacts live.
    fn default() -> Self {
        Self {
            base_url: HUGGINGFACE_BASE_URL.to_owned(),
            verified: Mutex::new(HashMap::new()),
        }
    }
}

/// What a file looked like when it was verified.
///
/// Size and modification time: enough to notice the file being replaced, and
/// cheap enough to read on every pass, which a gigabyte of sha256 is not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    bytes: u64,
    modified: Option<SystemTime>,
}

impl FileStamp {
    fn read(path: &Path) -> oneiron::Result<Self> {
        let metadata = std::fs::metadata(path).map_err(oneiron::Error::Io)?;
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

impl ModelManager {
    /// Fetches from somewhere other than Hugging Face.
    ///
    /// Test-only, and the narrowest door that makes the fetch path reachable
    /// without the network: a row that must prove what happens to a bad file on
    /// disk points this at a stub on loopback.
    #[cfg(test)]
    pub(in crate::embedder) fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            ..Self::default()
        }
    }

    /// Makes every file present and verified, downloading what is missing.
    ///
    /// Returns the directory holding them. `model_dir` set in config
    /// short-circuits the download entirely: the operator supplied the files,
    /// so the server checks they exist and nothing else.
    pub(in crate::embedder) fn ensure_all(
        &self,
        config: &LocalEmbedderConfig,
    ) -> oneiron::Result<PathBuf> {
        let dir = model_dir(config)?;
        let files = model_files(config);
        if config.model_dir.is_some() {
            for artifact in &files {
                let path = dir.join(artifact.file);
                if !path.is_file() {
                    return Err(missing_file(&path));
                }
            }
            return Ok(dir);
        }
        let mut fetched = 0usize;
        for artifact in &files {
            if self.ensure_one(config, &dir, artifact)? {
                fetched += 1;
            }
        }
        if fetched > 0 {
            tracing::info!(dir = %dir.display(), fetched, "embedder model artifacts ready");
        }
        Ok(dir)
    }

    /// Returns whether the file had to be downloaded.
    pub(super) fn ensure_one(
        &self,
        config: &LocalEmbedderConfig,
        dir: &Path,
        artifact: &PinnedArtifact,
    ) -> oneiron::Result<bool> {
        let path = dir.join(artifact.file);
        if path.is_file() {
            match self.verify_unless_unchanged(&path, artifact) {
                Ok(()) => return Ok(false),
                Err(error) => {
                    // A file that does not match its digest is not a file we can
                    // use, and leaving it in place would fail the same way on every
                    // restart. Remove it and fetch it again.
                    tracing::warn!(path = %path.display(), ?error, "embedder artifact failed verification; refetching");
                    self.forget(&path);
                    std::fs::remove_file(&path).map_err(oneiron::Error::Io)?;
                }
            }
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(oneiron::Error::Io)?;
        }
        let url = format!(
            "{}/{}/resolve/{}/{}",
            self.base_url, config.repo, config.revision, artifact.file
        );
        tracing::info!(file = artifact.file, "downloading embedder model artifact");
        download(&url, &path, artifact)?;
        self.verify_unless_unchanged(&path, artifact)
            .inspect_err(|_| {
                // Never leave a bad artifact on disk: the next start would load it.
                let _ = std::fs::remove_file(&path);
            })?;
        Ok(true)
    }

    /// Verifies a file, unless it is the one this process already verified.
    fn verify_unless_unchanged(
        &self,
        path: &Path,
        artifact: &PinnedArtifact,
    ) -> oneiron::Result<()> {
        let stamp = FileStamp::read(path)?;
        if self
            .verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(path)
            == Some(&stamp)
        {
            return Ok(());
        }
        verify(path, artifact)?;
        self.verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(path.to_path_buf(), stamp);
        Ok(())
    }

    /// Drops what this process remembers about a file it is about to remove.
    fn forget(&self, path: &Path) {
        self.verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(path);
    }
}

/// Fetches one file to a temporary sibling, then renames it into place.
///
/// The rename is what makes a killed download safe: a partial file never
/// carries the final name, so the next start refetches rather than loading a
/// truncated tensor file.
fn download(url: &str, path: &Path, artifact: &PinnedArtifact) -> oneiron::Result<()> {
    // Redirects ARE followed here, unlike the rest of this crate's transports:
    // Hugging Face answers a large-file `resolve` URL with a redirect to its
    // CDN, and the digest check below is what makes following one safe.
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .build()
        .map_err(|e| download_failed(artifact.file, &format!("client: {e}")))?;
    let response = client
        .get(url)
        .send()
        .map_err(|e| download_failed(artifact.file, &transport_class(&e)))?;
    if !response.status().is_success() {
        return Err(download_failed(
            artifact.file,
            &format!("HTTP {}", response.status()),
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_ARTIFACT_BYTES)
    {
        return Err(download_failed(artifact.file, "exceeds the artifact cap"));
    }
    let temp = path.with_extension("partial");
    let mut file = std::fs::File::create(&temp).map_err(oneiron::Error::Io)?;
    let written = std::io::copy(&mut response.take(MAX_ARTIFACT_BYTES + 1), &mut file)
        .map_err(oneiron::Error::Io)?;
    drop(file);
    if written > MAX_ARTIFACT_BYTES {
        let _ = std::fs::remove_file(&temp);
        return Err(download_failed(artifact.file, "exceeds the artifact cap"));
    }
    std::fs::rename(&temp, path).map_err(oneiron::Error::Io)
}

/// Size first, then digest.
pub(crate) fn verify(path: &Path, artifact: &PinnedArtifact) -> oneiron::Result<()> {
    let metadata = std::fs::metadata(path).map_err(oneiron::Error::Io)?;
    if artifact.bytes != 0 && metadata.len() != artifact.bytes {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder artifact {} is {} bytes, expected {}",
            artifact.file,
            metadata.len(),
            artifact.bytes
        )));
    }
    if artifact.sha256 == UNPINNED {
        return Ok(());
    }
    let digest = sha256_file(path)?;
    if digest != artifact.sha256 {
        return Err(oneiron::Error::InvalidConfig(format!(
            "embedder artifact {} has sha256 {digest}, expected {}",
            artifact.file, artifact.sha256
        )));
    }
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> oneiron::Result<String> {
    let mut file = std::fs::File::open(path).map_err(oneiron::Error::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer).map_err(oneiron::Error::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn transport_class(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else {
        "failed".to_owned()
    }
}

fn download_failed(file: &str, reason: &str) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: "embedder-model-download",
        code: format!("{file}: {reason}"),
    }
}

fn missing_file(path: &Path) -> oneiron::Error {
    oneiron::Error::InvalidConfig(format!(
        "embedder model_dir is missing {}; the directory must hold every model file",
        path.display()
    ))
}
