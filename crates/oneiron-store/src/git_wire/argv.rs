//! Frozen typed argv: one constructor per git verb plus the token validators.

use std::borrow::Cow;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::git_wire::config::GIT_WIRE_MAX_ARG_BYTES;
use crate::git_wire::config::GIT_WIRE_MAX_REF_BYTES;
use crate::git_wire::failure::GitWireResult;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::ids::GitRefPublication;
use crate::git_wire::objects::GitCommitRequest;
use crate::git_wire::objects::GitTreeEntry;
use crate::git_wire::objects::encode_mktree_entries;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::path_text::git_path_os_str;
use oneiron_base::error::Result;

/// Stdin revisions for a `--stdin` walk: each of `include`, then each of
/// `exclude` as `^<oid>`.
pub fn revision_lines(include: &[GitOid], exclude: &[GitOid]) -> Vec<u8> {
    let mut payload = Vec::new();
    for oid in include {
        payload.extend_from_slice(oid.as_str().as_bytes());
        payload.push(b'\n');
    }
    for oid in exclude {
        payload.push(b'^');
        payload.extend_from_slice(oid.as_str().as_bytes());
        payload.push(b'\n');
    }
    payload
}

pub fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(|arg| OsString::from(*arg)).collect()
}

pub fn validate_revision(revision: &str) -> Result<()> {
    if revision.is_empty() || revision.len() > GIT_WIRE_MAX_REF_BYTES {
        return Err(invalid("git revision must be non-empty and bounded"));
    }
    if revision.starts_with('-') {
        return Err(invalid("git revision must not be parsed as an option"));
    }
    if revision
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(invalid(
            "git revision must not contain control or space bytes",
        ));
    }
    Ok(())
}

pub fn validate_path_arg(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(invalid("git path argument must be non-empty"));
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(invalid("git path argument must not contain NUL"));
    }
    if !path.is_absolute() {
        return Err(invalid("git path argument must be absolute"));
    }
    Ok(())
}

/// One bridged argv token as the child takes it (FIX 21326): bounded, and
/// NUL only as the escape of a Git path byte outside UTF-8, which the OS form
/// turns back into that byte. A token without NUL is passed as it is.
///
/// # Errors
/// A token past the length bound, or one whose NUL is not the canonical
/// escape of a Git path byte.
pub fn bridged_argv_token(arg: &str) -> Result<OsString> {
    if arg.len() > GIT_WIRE_MAX_ARG_BYTES {
        return Err(invalid("git argument exceeds the frozen length bound"));
    }
    git_path_os_str(arg)
        .map(Cow::into_owned)
        .map_err(|_| invalid("git argument must not contain NUL"))
}

pub fn validate_argv_token(arg: &str) -> Result<()> {
    if arg.len() > GIT_WIRE_MAX_ARG_BYTES {
        return Err(invalid("git argument exceeds the frozen length bound"));
    }
    if arg.contains('\0') {
        return Err(invalid("git argument must not contain NUL"));
    }
    Ok(())
}
