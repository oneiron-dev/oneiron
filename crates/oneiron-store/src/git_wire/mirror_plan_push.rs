//! The outbound half of an automatic mirror push plan (FIX 6866 part 2): an
//! authenticated read of a frozen plan's refs at an https mirror, and one
//! push of one frozen batch of them.
//!
//! Both ride the mirror push's fixed profile: https only, no redirect, no
//! proxy, no hook, no Git-LFS bytes, no submodule, no follow-tags, the one
//! credential the custody door's `Authorization` header, and the mirror
//! push's own ten minutes and 4 MiB of output a child, at most
//! [`MIRROR_PUSH_REFSPECS`] refs a child. A ref whose tip the plan read goes
//! as `<new>:<ref>` (a deletion `:<ref>`) under
//! `--force-with-lease=<ref>:<tip read>` (empty: absent): the lease alone
//! permits the forced update, so a mirror whose ref moved since refuses it
//! and no `+` refspec overrides the lease. A ref whose tip could not be read
//! goes as the scheduled mirror always sent it, `+<new>:<ref>` or `:<ref>`,
//! unleased (CALLS "FIX 6866 automatic unknown tip"): never a lease on a
//! guessed absence. Each child inherits the caller's per-mirror hold and
//! never the repository's coordinator, so a child that outlives its parent
//! keeps the mirror held until it exits and no inbound push waits on it.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::Path;

use crate::git_wire::argv::os_args;
use crate::git_wire::argv::validate_argv_token;
use crate::git_wire::failure::invalid;
use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::mirror_push::MIRROR_PUSH_MAX_OUTPUT_BYTES;
use crate::git_wire::mirror_push::MIRROR_PUSH_REFSPECS;
use crate::git_wire::mirror_push::MIRROR_PUSH_TIMEOUT;
use crate::git_wire::mirror_push::MirrorEgress;
use crate::git_wire::operation::GitWireOperation;
use crate::git_wire::publish_push::REMOTE_READ_TIMEOUT;
use crate::git_wire::repo::GitWireRepo;
use oneiron_base::error::Result;

/// One ref of a frozen plan batch, as it goes out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPlanRef {
    /// The full ref at the mirror.
    pub name: GitRefName,
    /// What the mirror's ref becomes; `None` deletes it.
    pub new: Option<GitOid>,
    /// What the plan read there: `Some(None)` absent, `Some(Some(oid))` at
    /// `oid`. `None` when the read failed: the ref goes unleased.
    pub lease: Option<Option<GitOid>>,
}

/// How one ref of a pushed batch ended, as the child's porcelain said (or,
/// for a ref the mirror already held, the child's clean exit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitPlanRefOutcome {
    /// The mirror took it, or already held it.
    Applied,
    /// The mirror refused it: a stale lease, a protected ref, a hook.
    Rejected,
    /// No outcome for it: the child failed, timed out or named none.
    Unknown,
}

/// What one batch push reported: each ref's outcome, in batch order, and
/// the redacted cause (class, exit, digest) when the child did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitPlanPushReport {
    pub outcomes: Vec<GitPlanRefOutcome>,
    pub failure: Option<String>,
}

/// Each ref a `push --porcelain` run reported, by its destination name, with
/// its one-byte flag.
pub fn porcelain_flags(stdout: &[u8]) -> HashMap<String, char> {
    let mut flags = HashMap::new();
    for line in String::from_utf8_lossy(stdout).lines() {
        let mut fields = line.split('\t');
        let (Some(flag), Some(spec)) = (fields.next(), fields.next()) else {
            continue;
        };
        let mut chars = flag.chars();
        let (Some(flag), None) = (chars.next(), chars.next()) else {
            continue;
        };
        if let Some((_, to)) = spec.rsplit_once(':') {
            flags.insert(to.to_owned(), flag);
        }
    }
    flags
}
