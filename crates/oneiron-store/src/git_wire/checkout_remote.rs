//! Lease-bound worktree remotes. No upstream URL, credential, or helper is copied.

use crate::git_wire::argv::os_args;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::repo::GitWireRepo;
use crate::git_wire::repo::lock_repository;
use std::path::Path;

/// Whether `endpoint` is a checkout door base this wire accepts: an origin
/// base such as `https://host.example/git`, HTTP only on loopback, with no
/// userinfo, query or fragment. The host's own door base setting (FIX
/// 7181) is judged here too, at configuration.
///
/// # Errors
/// Names what the base lacks.
pub fn validate_checkout_door(endpoint: &str) -> GitWireResult<()> {
    let authority = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .ok_or_else(|| invalid("door endpoint must be HTTP(S)"))?;
    let (host, path) = authority
        .split_once('/')
        .ok_or_else(|| invalid("door endpoint path missing"))?;
    if path != "git"
        || host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:-[]".contains(&b))
        || endpoint.starts_with("http://")
            && !(host == "localhost"
                || host.starts_with("localhost:")
                || host == "127.0.0.1"
                || host.starts_with("127.0.0.1:")
                || host == "[::1]"
                || host.starts_with("[::1]:"))
    {
        return Err(invalid("door endpoint has unsafe authority or path"));
    }
    Ok(())
}

/// The door name of the served bare store `repo`: its common directory's
/// name without `.git`.
pub fn served_repo_name(repo: &GitWireRepo) -> GitWireResult<&str> {
    repo.common_dir()
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".git"))
        .ok_or_else(|| invalid("door checkout requires a served bare repository"))
}

/// Whether a remote URL names a credential in its userinfo: any userinfo on
/// HTTP(S) (a token passed as the user), a password on any other scheme. An
/// SSH user such as `git@host` is not a credential.
pub fn url_carries_credential(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let Some((userinfo, _)) = authority.rsplit_once('@') else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    scheme == "http" || scheme == "https" || userinfo.contains(':')
}
