//! Closed-shape constants, the small shared error constructors, and vault-path
//! resolution for the serving and door roots.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Vault;
use crate::credential_door::CredentialDoorError;
use crate::error::{CodeError, Error, Result};

/// Directory under the vault root that holds the served bare repositories.
/// It is the `GIT_PROJECT_ROOT` of every serve invocation.
pub const ORIGIN_SERVING_ROOT_NAME: &str = "origin";

/// Directory under the vault root that holds the per-request door-owned hook
/// directories. Deliberately OUTSIDE the serving root: a hook directory is
/// never addressable as a repository.
pub const ORIGIN_DOOR_ROOT_NAME: &str = "origin-door";

/// Suffix of a served bare repository directory.
pub const ORIGIN_REPO_DIR_SUFFIX: &str = ".git";

/// The closed serve baseline. Exactly these keys, and nothing else, form the
/// non-request half of the child environment.
///
/// `GIT_NO_REPLACE_OBJECTS` is in the baseline rather than in argv because it
/// has to reach git children this process never spawns: `http-backend` spawns
/// `receive-pack`, which spawns the door hook, which spawns the plumbing that
/// reads the pushed bytes. An environment variable travels that whole chain,
/// and a replacement lookup anywhere in it would show the scan bytes other than
/// the ones the push makes durable.
pub const SERVE_BASE_ENV_KEYS: [&str; 5] = [
    "GIT_DIR",
    "GIT_HTTP_EXPORT_ALL",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_PROJECT_ROOT",
    "PATH",
];

/// The closed CGI request half of the child environment. Every value is
/// constructed from the typed [`ServeRequest`](super::ServeRequest); none is read from the ambient
/// environment.
///
/// These are exactly the request-scoped names `git http-backend` reads:
/// `HTTP_CONTENT_ENCODING` (a stock client gzips its RPC bodies) and
/// `HTTP_GIT_PROTOCOL` (the negotiated wire version) carry their CGI spelling,
/// because that is the spelling the backend looks for.
///
/// The allowlist is what a served child MAY be given, not what it is always
/// given: `HTTP_GIT_PROTOCOL` is currently never emitted, because the ref
/// advertisement is gated by the publication projection and protocol v2 moves
/// the ref list somewhere that projection cannot reach.
pub const SERVE_REQUEST_ENV_KEYS: [&str; 9] = [
    "CONTENT_LENGTH",
    "CONTENT_TYPE",
    "HTTP_CONTENT_ENCODING",
    "HTTP_GIT_PROTOCOL",
    "PATH_INFO",
    "QUERY_STRING",
    "REMOTE_ADDR",
    "REMOTE_USER",
    "REQUEST_METHOD",
];

/// The one vetted hook the door-owned directory contains.
pub const DOOR_PRE_RECEIVE_HOOK_NAME: &str = "pre-receive";

/// Longest repository name the origin will resolve.
pub const ORIGIN_MAX_REPO_NAME_BYTES: usize = 100;

/// The most ref moves one push may propose.
///
/// It mirrors GitWire's publication bound, because the landing publishes what
/// the push moved through exactly one publication set: a batch the landing
/// could not carry is refused BEFORE `git receive-pack` moves anything, rather
/// than discovered after the refs are already elsewhere.
pub const ORIGIN_MAX_REF_UPDATES: usize = 64;

/// The ref namespace this origin never lets a push write.
///
/// A `refs/replace/<oid>` entry rewrites what every later object lookup in this
/// repository sees. The door scans the bytes a push makes durable, so a push
/// that could plant a replacement is a push that could aim the next scan at
/// bytes nobody is landing.
pub const ORIGIN_REFUSED_REF_PREFIX: &str = "refs/replace/";

/// Bound on the CGI header block. This bounds a protocol preamble, not a body:
/// request and response bodies stream unbounded and unbuffered.
pub(super) const SERVE_MAX_CGI_HEADER_BYTES: usize = 64 * 1024;

/// Streaming chunk size for both directions.
pub(super) const SERVE_STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Bound on the captured child stderr used for diagnostics only.
pub(super) const SERVE_MAX_STDERR_BYTES: usize = 16 * 1024;

/// How often the door window looks for the hook's request.
pub(super) const DOOR_WINDOW_POLL: Duration = Duration::from_millis(2);

/// How long the door window waits for a hook that never arrives before failing
/// closed. A push whose door window cannot complete is refused, never admitted.
pub const DOOR_WINDOW_TIMEOUT: Duration = Duration::from_secs(300);

/// The verdict line the vetted hook accepts as an admission.
pub(super) const DOOR_VERDICT_OK: &str = "ok";

/// How much of a refused ref name a refusal echoes back to the client. A
/// diagnostic names the ref; it never becomes a channel of its own.
pub(super) const DOOR_REFUSAL_NAME_CHARS: usize = 100;

pub(super) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(super) fn serve_failed(reason: impl Into<String>) -> Error {
    Error::Code(CodeError::GitHttpServeFailed {
        reason: reason.into(),
    })
}

/// Carries a door refusal out through the crate error surface without ever
/// carrying a secret: the door's messages name paths and reason codes only.
pub(super) fn door_refused(error: &CredentialDoorError) -> Error {
    Error::Code(CodeError::ReceivePackDoorRejected {
        reason: error.to_string(),
    })
}

/// Validates a repository name from the route.
///
/// Closed shape: ASCII alphanumerics, `.`, `_`, `-`, never leading `.`, never
/// a path component of its own. The serve invocation's `PATH_INFO` is built
/// from the validated name, so no request can address anything but a
/// repository directory directly under the serving root.
pub fn validate_repo_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > ORIGIN_MAX_REPO_NAME_BYTES {
        return Err(Error::Code(CodeError::GitHttpInvalidRepoName(
            "origin repo name must be non-empty and at most 100 bytes",
        )));
    }
    if name.starts_with('.') {
        return Err(Error::Code(CodeError::GitHttpInvalidRepoName(
            "origin repo name must not start with a dot",
        )));
    }
    let shaped = name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !shaped {
        return Err(Error::Code(CodeError::GitHttpInvalidRepoName(
            "origin repo name must be [A-Za-z0-9._-]",
        )));
    }
    Ok(())
}

/// The serving root of one vault: the `GIT_PROJECT_ROOT` of every invocation.
pub fn origin_serving_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_SERVING_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// The per-request door root. Never inside the serving root, so it is never
/// addressable as a repository.
pub(super) fn origin_door_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(ORIGIN_DOOR_ROOT_NAME);
    fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// Resolves an existing served repository directory.
///
/// Phase A serves; it does not create. A name that resolves to nothing is a
/// miss, never an implicit `git init`.
pub fn origin_repo_dir(vault: &Vault, repo_name: &str) -> Result<PathBuf> {
    validate_repo_name(repo_name)?;
    let root = origin_serving_root(vault)?;
    let dir = root.join(format!("{repo_name}{ORIGIN_REPO_DIR_SUFFIX}"));
    if !dir.is_dir() {
        return Err(Error::Code(CodeError::GitHttpRepoNotFound {
            repo: repo_name.to_owned(),
        }));
    }
    let dir = dir.canonicalize()?;
    if !dir.starts_with(&root) {
        return Err(Error::Code(CodeError::GitHttpInvalidRepoName(
            "origin repo path escapes the serving root",
        )));
    }
    Ok(dir)
}
