//! The shipped Oneironer releases, and the fetch that places one on this
//! machine (FIX 6828).
//!
//! A release is a bundle pinned file by file, size and SHA-256, under the
//! stack its `oneironer.json` hashes to. The catalogue sits here, outside the
//! bundle: the bytes of `oneironer.json` are the stack, so nothing about the
//! release can live in them. Each bundle is fetched from a Hugging Face model
//! repo at a git ref named by its `stack_sha16`, by the embedder's grammar:
//! `https://huggingface.co/<repo>/resolve/<stack_sha16>/<file>`.
//!
//! The repo stays private until the owner calls the model final, and goes
//! public under [`ONEIRONER_LICENCE`] then. So the repo id is a setting, not
//! an assumption, and a read token is optional: read from a file, sent to
//! Hugging Face alone, and never printed.
//!
//! [`fetch_release`] lands a bundle as `<models root>/oneironer/<stack>/`, the
//! shared model root's layout. It is the self-hosted and supervisor-side
//! fetch: a managed engine never downloads a bundle; its supervisor places
//! one in the shared root.

use std::borrow::Cow;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use reqwest::header::HeaderValue;

use crate::embedder::model_manager::{self, PinnedArtifact, ResumableFetch};

/// The Hugging Face model repo releases are fetched from unless the fetch
/// names another. Private until the owner calls the model final.
pub(crate) const ONEIRONER_RELEASE_REPO: &str = "oneiron-dev/oneironer";

/// The licence every release here carries, as an SPDX id.
pub(crate) const ONEIRONER_LICENCE: &str = "Apache-2.0";

/// The directory under a models root the bundles sit in, one per stack.
const CLASS_DIR: &str = "oneironer";

/// Names the fetch in a transfer failure.
const FETCH_TOOL: &str = "oneironer-model-download";

/// Why a `404` stops a fetch.
const UNPUBLISHED: &str = "not found (404): the release is not published yet";

/// Why a `401` or `403` stops a fetch.
const PRIVATE: &str = "refused (401/403): a private release needs --token-file with a read token";

/// A placed bundle directory's mode: the shared model root admits no group-
/// or other-writable path, and a vault's user must enter it.
#[cfg(unix)]
const DIR_MODE: u32 = 0o755;

/// A placed bundle file's mode: read by every vault's user, written by none.
#[cfg(unix)]
const FILE_MODE: u32 = 0o644;

/// One shipped bundle: its identity and every file, pinned.
#[derive(Debug)]
pub(crate) struct OneironerRelease {
    /// SHA-256 prefix of the exact `oneironer.json` bytes; also the git ref
    /// the release is fetched at and the directory it lands in.
    pub(crate) stack_sha16: &'static str,
    /// SHA-256 prefix of `trunk.safetensors`.
    pub(crate) checkpoint_sha16: &'static str,
    pub(crate) label_count: u32,
    pub(crate) licence: &'static str,
    /// Every file of the bundle, flat under its directory, smallest first so
    /// an unpublished or private release is known before the weights move.
    pub(crate) files: &'static [PinnedArtifact],
}

/// Stack `fde950a412728a86`: checkpoint `eeeaf8bea4e8d166`, 53 labels.
const FDE950A412728A86_FILES: [PinnedArtifact; 5] = [
    PinnedArtifact {
        file: Cow::Borrowed("oneironer.json"),
        sha256: "fde950a412728a86a755a92c65cd25e9159896727e41a32c4dd680150544f6c0",
        bytes: 1_821,
    },
    PinnedArtifact {
        file: Cow::Borrowed("config.json"),
        sha256: "2ea2cb7d559c6315558e91dab54893c169a0af12c762bd5fff303e7a996e5768",
        bytes: 1_349,
    },
    PinnedArtifact {
        file: Cow::Borrowed("char_config.json"),
        sha256: "c7a097ff34650e547c9cb43fc2229ca0fa612e81d71ac57359bf43d42306945c",
        bytes: 139_172,
    },
    PinnedArtifact {
        file: Cow::Borrowed("tokenizer.json"),
        sha256: "f59925fcb90c92b894cb93e51bb9b4a6105c5c249fe54ce1c704420ac39b81af",
        bytes: 17_082_756,
    },
    PinnedArtifact {
        file: Cow::Borrowed("trunk.safetensors"),
        sha256: "eeeaf8bea4e8d166f0fa252124b13d6d8c2d8d8081253d20a02ad47873e93008",
        bytes: 1_226_637_420,
    },
];

const FDE950A412728A86: OneironerRelease = OneironerRelease {
    stack_sha16: "fde950a412728a86",
    checkpoint_sha16: "eeeaf8bea4e8d166",
    label_count: 53,
    licence: ONEIRONER_LICENCE,
    files: &FDE950A412728A86_FILES,
};

/// Every shipped release, the default first.
const ONEIRONER_RELEASES: &[OneironerRelease] = &[FDE950A412728A86];

/// The release `stack` names, or the default when it names none.
pub(crate) fn find(stack: Option<&str>) -> Option<&'static OneironerRelease> {
    let Some(stack) = stack else {
        return ONEIRONER_RELEASES.first();
    };
    ONEIRONER_RELEASES
        .iter()
        .find(|release| release.stack_sha16 == stack)
}

/// Every release's stack, for a refusal to list.
pub(crate) fn known_stacks() -> String {
    ONEIRONER_RELEASES
        .iter()
        .map(|release| release.stack_sha16)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `<models_root>/oneironer/<stack>/`: where a release lands, and the path a
/// managed vault's `oneironer.model_dir` names under the shared model root.
pub(crate) fn bundle_dir(models_root: &Path, release: &OneironerRelease) -> PathBuf {
    models_root.join(CLASS_DIR).join(release.stack_sha16)
}

/// The models root a fetch lands under when it names none: the embedder's,
/// `$XDG_DATA_HOME/oneiron/models`, else `$HOME/.local/share/oneiron/models`.
pub(crate) fn default_models_root() -> Result<PathBuf, OneironerFetchError> {
    model_manager::resolve_models_root(
        None,
        model_manager::absolute_env_dir("XDG_DATA_HOME"),
        model_manager::absolute_env_dir("HOME"),
    )
    .map_err(|_| OneironerFetchError::NoModelsRoot)
}

/// The `[oneironer]` section that serves `release` from `dir`, ready to paste
/// into a settings file.
pub(crate) fn oneironer_block(release: &OneironerRelease, dir: &Path) -> String {
    let model_dir = toml::Value::String(dir.to_string_lossy().into_owned());
    let checkpoint = release.checkpoint_sha16;
    let stack = release.stack_sha16;
    let labels = release.label_count;
    format!(
        "[oneironer]\n\
         provider = \"local\"\n\
         model_dir = {model_dir}\n\
         checkpoint_sha16 = \"{checkpoint}\"\n\
         stack_sha16 = \"{stack}\"\n\
         label_count = {labels}\n"
    )
}

/// A read token for a private release repo, held as the `Authorization`
/// value it is sent as. It is read from a file and nowhere else; its `Debug`
/// shows nothing of it, and no error, log or outcome here carries it.
pub(crate) struct ReleaseToken(HeaderValue);

impl std::fmt::Debug for ReleaseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReleaseToken(<redacted>)")
    }
}

impl ReleaseToken {
    /// Reads the token from `path`, surrounding whitespace dropped: a file a
    /// supervisor passes as a credential (`$CREDENTIALS_DIRECTORY/<name>`).
    pub(crate) fn read(path: &Path) -> Result<Self, OneironerFetchError> {
        let refused = |reason: &str| OneironerFetchError::TokenFile {
            path: path.display().to_string(),
            reason: reason.to_owned(),
        };
        let raw = std::fs::read_to_string(path).map_err(|error| refused(&error.to_string()))?;
        let token = raw.trim();
        if token.is_empty() {
            return Err(refused("it holds no token"));
        }
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| refused("it holds characters a header cannot carry"))?;
        value.set_sensitive(true);
        Ok(Self(value))
    }
}

/// Where a release is fetched from: the repo, and its token when it is
/// private.
#[derive(Debug)]
pub(crate) struct ReleaseSource {
    repo: String,
    token: Option<ReleaseToken>,
}

impl ReleaseSource {
    /// The repo `repo` names, [`ONEIRONER_RELEASE_REPO`] when absent, with
    /// the token `token_file` holds; anonymous without one. A repo that is
    /// not a plain `org/name` is refused: it becomes URL path segments.
    pub(crate) fn new(
        repo: Option<String>,
        token_file: Option<&Path>,
    ) -> Result<Self, OneironerFetchError> {
        let repo = repo.unwrap_or_else(|| ONEIRONER_RELEASE_REPO.to_owned());
        if !plain_repo(&repo) {
            return Err(OneironerFetchError::Repo(repo));
        }
        let token = token_file.map(ReleaseToken::read).transpose()?;
        Ok(Self { repo, token })
    }

    pub(crate) fn repo(&self) -> &str {
        &self.repo
    }

    fn authorization(&self) -> Option<&HeaderValue> {
        self.token.as_ref().map(|token| &token.0)
    }
}

/// Whether `repo` is a plain `org/name`, checked as the embedder's cache
/// identity is: each segment ASCII letters, digits, `.`, `_` and `-`, and
/// none of them only dots.
fn plain_repo(repo: &str) -> bool {
    let plain = |segment: &str| {
        segment.bytes().any(|byte| byte != b'.')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    };
    repo.split_once('/')
        .is_some_and(|(org, name)| plain(org) && plain(name))
}

/// What a fetch did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum OneironerFetchOutcome {
    /// The bundle was already in place, and verified whole.
    Reused { dir: PathBuf },
    /// The bundle was fetched, verified and placed. `bytes` came over the
    /// network on this run; `resumed_bytes` were on disk from an earlier
    /// one, in partial or staged files.
    Downloaded {
        dir: PathBuf,
        bytes: u64,
        resumed_bytes: u64,
    },
    /// The repo has no such file at the release's ref (`404`): the release
    /// is not published yet. Nothing was placed.
    NotPublished { file: String },
    /// Hugging Face refused the file (`401`, `403`): the repo is private and
    /// the fetch had no token, or one without access. Nothing was placed.
    Unauthorized { file: String },
}

impl OneironerFetchOutcome {
    /// The outcome's name in the command's output.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Reused { .. } => "reused",
            Self::Downloaded { .. } => "downloaded",
            Self::NotPublished { .. } => "not_published",
            Self::Unauthorized { .. } => "unauthorized",
        }
    }

    /// The bundle's directory, when the fetch left it in place.
    pub(crate) fn placed(&self) -> Option<&Path> {
        match self {
            Self::Reused { dir } | Self::Downloaded { dir, .. } => Some(dir.as_path()),
            Self::NotPublished { .. } | Self::Unauthorized { .. } => None,
        }
    }

    /// The bytes a download fetched on this run, and those it resumed.
    pub(crate) fn transferred(&self) -> Option<(u64, u64)> {
        match self {
            Self::Downloaded {
                bytes,
                resumed_bytes,
                ..
            } => Some((*bytes, *resumed_bytes)),
            _ => None,
        }
    }

    /// The file a refused fetch stopped at.
    pub(crate) fn refused_file(&self) -> Option<&str> {
        match self {
            Self::NotPublished { file } | Self::Unauthorized { file } => Some(file.as_str()),
            Self::Reused { .. } | Self::Downloaded { .. } => None,
        }
    }

    /// Why a refused fetch stopped, and what would get it further.
    pub(crate) fn refusal(&self, repo: &str, stack: &str) -> Option<String> {
        let (file, why) = match self {
            Self::NotPublished { file } => (file, UNPUBLISHED),
            Self::Unauthorized { file } => (file, PRIVATE),
            Self::Reused { .. } | Self::Downloaded { .. } => return None,
        };
        Some(format!("{repo}@{stack} {file}: {why}"))
    }
}

/// Why a fetch stopped short of an outcome. None of these carries the token.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OneironerFetchError {
    #[error("no models root: XDG_DATA_HOME and HOME name no absolute directory; pass --into")]
    NoModelsRoot,
    #[error("release repo {0:?} is not a plain org/name")]
    Repo(String),
    #[error("token file {path}: {reason}")]
    TokenFile { path: String, reason: String },
    #[error("release file {file} is not its pinned {expected} bytes ({found}); partial removed")]
    SizeMismatch {
        file: String,
        expected: u64,
        found: String,
    },
    #[error("release file {file} has sha256 {found}, pinned {expected}; partial removed")]
    DigestMismatch {
        file: String,
        expected: &'static str,
        found: String,
    },
    #[error("release file {file} stopped at {held} of {expected} bytes; fetch again to resume")]
    Incomplete {
        file: String,
        held: u64,
        expected: u64,
    },
    #[error("release file {file}: {reason}; fetch again to resume")]
    Transfer { file: String, reason: String },
    #[error("{dir} is not the pinned release ({reason}); it was left as it is")]
    ExistingInvalid { dir: String, reason: String },
    #[error("{action} {path}: {reason}")]
    Io {
        action: &'static str,
        path: String,
        reason: String,
    },
}

/// Places `release` under `models_root` as `<root>/oneironer/<stack>/`.
///
/// A bundle already there is verified whole, every file's size and then its
/// SHA-256, and reused; one that fails is an error, and it is never replaced
/// or removed. Otherwise the files are staged in
/// `<root>/oneironer/.staging-<stack>/`, under the lock file beside it. Each
/// is fetched to `<file>.partial`, resuming what an earlier run left there,
/// checked for size and then SHA-256, and renamed to its own name. Once every
/// file is staged, the directory is renamed into place whole, directories
/// `0755` and files `0644` on Unix. A transfer that fails keeps its partial
/// for the next run; a file of the wrong size or digest loses it. A second
/// fetch of the same stack waits on the lock, then finds the bundle placed.
pub(crate) fn fetch_release(
    release: &OneironerRelease,
    source: &ReleaseSource,
    models_root: &Path,
) -> Result<OneironerFetchOutcome, OneironerFetchError> {
    let dir = bundle_dir(models_root, release);
    if dir.symlink_metadata().is_ok() {
        verify_placed(release, &dir)?;
        return Ok(OneironerFetchOutcome::Reused { dir });
    }
    std::fs::create_dir_all(models_root).map_err(io_error("creating", models_root))?;
    let class = models_root.join(CLASS_DIR);
    ensure_dir(&class)?;
    let stack = release.stack_sha16;
    let _lock = lock(&class.join(format!(".staging-{stack}.lock")))?;
    // A fetch that held the lock first may have placed it meanwhile.
    if dir.symlink_metadata().is_ok() {
        verify_placed(release, &dir)?;
        return Ok(OneironerFetchOutcome::Reused { dir });
    }
    let staging = class.join(format!(".staging-{stack}"));
    ensure_dir(&staging)?;
    let (mut bytes, mut resumed_bytes) = (0_u64, 0_u64);
    for artifact in release.files {
        let file = artifact.file.to_string();
        match stage(release, source, &staging, artifact)? {
            Staged::Ready { kept, fetched } => {
                resumed_bytes += kept;
                bytes += fetched;
            }
            Staged::NotPublished => return Ok(OneironerFetchOutcome::NotPublished { file }),
            Staged::Unauthorized => return Ok(OneironerFetchOutcome::Unauthorized { file }),
        }
    }
    commit(release, &staging, &dir)?;
    Ok(OneironerFetchOutcome::Downloaded {
        dir,
        bytes,
        resumed_bytes,
    })
}

/// What staging one file came to.
enum Staged {
    /// Staged and verified: `kept` bytes were on disk before this run,
    /// `fetched` came over the network.
    Ready {
        kept: u64,
        fetched: u64,
    },
    NotPublished,
    Unauthorized,
}

/// Makes `<staging>/<file>` the pinned file: kept when an earlier run staged
/// it and it still checks, else fetched to its partial, checked there and
/// renamed.
fn stage(
    release: &OneironerRelease,
    source: &ReleaseSource,
    staging: &Path,
    artifact: &PinnedArtifact,
) -> Result<Staged, OneironerFetchError> {
    let file: &str = &artifact.file;
    let staged = staging.join(file);
    if staged.is_file() {
        if check(&staged, artifact).is_ok() {
            return Ok(Staged::Ready {
                kept: artifact.bytes,
                fetched: 0,
            });
        }
        // Only a checked file is ever renamed to this name; one that no
        // longer checks is this staging's own to drop.
        std::fs::remove_file(&staged).map_err(io_error("removing", &staged))?;
    }
    let partial = staging.join(format!("{file}.partial"));
    let url = model_manager::hub_url(&source.repo, release.stack_sha16, file);
    let auth = source.authorization();
    let answer = model_manager::fetch_resumable(&url, &partial, artifact, auth, FETCH_TOOL);
    let (kept, fetched) = match answer.map_err(transfer_error(file))? {
        ResumableFetch::Written { kept, fetched } => (kept, fetched),
        ResumableFetch::NotFound => return Ok(Staged::NotPublished),
        ResumableFetch::Unauthorized => return Ok(Staged::Unauthorized),
        ResumableFetch::WrongSize { offered } => {
            let found = offered.map_or_else(
                || "the source holds fewer".to_owned(),
                |offered| format!("the source offers {offered}"),
            );
            return Err(drop_partial(&partial, size_mismatch(artifact, found)));
        }
    };
    let held = std::fs::metadata(&partial)
        .map_err(io_error("reading", &partial))?
        .len();
    if held < artifact.bytes {
        return Err(OneironerFetchError::Incomplete {
            file: file.to_owned(),
            held,
            expected: artifact.bytes,
        });
    }
    if let Err(error) = check(&partial, artifact) {
        return Err(drop_partial(&partial, error));
    }
    std::fs::rename(&partial, &staged).map_err(io_error("staging", &partial))?;
    Ok(Staged::Ready { kept, fetched })
}

/// Size first, then SHA-256, against the pin.
fn check(path: &Path, artifact: &PinnedArtifact) -> Result<(), OneironerFetchError> {
    let held = std::fs::metadata(path)
        .map_err(io_error("reading", path))?
        .len();
    if held != artifact.bytes {
        return Err(size_mismatch(artifact, format!("{held} arrived")));
    }
    let digest = model_manager::sha256_file(path).map_err(io_error("hashing", path))?;
    if digest != artifact.sha256 {
        return Err(OneironerFetchError::DigestMismatch {
            file: artifact.file.to_string(),
            expected: artifact.sha256,
            found: digest,
        });
    }
    Ok(())
}

/// Checks a placed bundle whole without touching it: a directory, each file
/// a plain file of its pinned size, then each file's SHA-256.
fn verify_placed(release: &OneironerRelease, dir: &Path) -> Result<(), OneironerFetchError> {
    let invalid = |reason: String| OneironerFetchError::ExistingInvalid {
        dir: dir.display().to_string(),
        reason,
    };
    let is_dir = dir
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_dir());
    if !is_dir {
        return Err(invalid("not a directory".to_owned()));
    }
    for artifact in release.files {
        let file: &str = &artifact.file;
        let pinned = artifact.bytes;
        let held = match dir.join(file).symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_file() => metadata.len(),
            _ => return Err(invalid(format!("{file} is missing or not a plain file"))),
        };
        if held != pinned {
            return Err(invalid(format!("{file} is {held} bytes, pinned {pinned}")));
        }
    }
    for artifact in release.files {
        let file: &str = &artifact.file;
        let pinned = artifact.sha256;
        let path = dir.join(file);
        let digest = model_manager::sha256_file(&path).map_err(io_error("hashing", &path))?;
        if digest != pinned {
            return Err(invalid(format!(
                "{file} has sha256 {digest}, pinned {pinned}"
            )));
        }
    }
    Ok(())
}

/// Sets the staged files' and directory's modes, then renames the directory
/// into place whole.
fn commit(
    release: &OneironerRelease,
    staging: &Path,
    dir: &Path,
) -> Result<(), OneironerFetchError> {
    #[cfg(unix)]
    {
        for artifact in release.files {
            set_mode(&staging.join(artifact.file.as_ref()), FILE_MODE)?;
        }
        set_mode(staging, DIR_MODE)?;
    }
    #[cfg(not(unix))]
    let _ = release;
    std::fs::rename(staging, dir).map_err(io_error("placing", staging))
}

/// Creates one directory, `0755` on Unix, or takes the one already there.
fn ensure_dir(path: &Path) -> Result<(), OneironerFetchError> {
    if path.is_dir() {
        return Ok(());
    }
    if let Err(error) = std::fs::create_dir(path) {
        // Another fetch may have made it meanwhile.
        return if path.is_dir() {
            Ok(())
        } else {
            Err(io_error("creating", path)(error))
        };
    }
    #[cfg(unix)]
    set_mode(path, DIR_MODE)?;
    Ok(())
}

/// Sets a mode whatever the umask made it.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), OneironerFetchError> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(io_error("setting the mode of", path))
}

/// Opens the staging lock and holds it until the returned file drops.
fn lock(path: &Path) -> Result<std::fs::File, OneironerFetchError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error("opening", path))?;
    file.lock().map_err(io_error("locking", path))?;
    Ok(file)
}

/// Removes a partial whose bytes are not the pinned file's, and passes the
/// error on: resuming it would only fail the same way.
fn drop_partial(partial: &Path, error: OneironerFetchError) -> OneironerFetchError {
    let _ = std::fs::remove_file(partial);
    error
}

fn size_mismatch(artifact: &PinnedArtifact, found: String) -> OneironerFetchError {
    OneironerFetchError::SizeMismatch {
        file: artifact.file.to_string(),
        expected: artifact.bytes,
        found,
    }
}

fn transfer_error(file: &str) -> impl FnOnce(oneiron::Error) -> OneironerFetchError {
    let file = file.to_owned();
    move |error| OneironerFetchError::Transfer {
        file,
        reason: error.to_string(),
    }
}

fn io_error<E: std::fmt::Display>(
    action: &'static str,
    path: &Path,
) -> impl FnOnce(E) -> OneironerFetchError {
    let path = path.display().to_string();
    move |error| OneironerFetchError::Io {
        action,
        path,
        reason: error.to_string(),
    }
}
