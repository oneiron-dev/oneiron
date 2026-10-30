//! What the kernel isolated an organ process with, as its start found it
//! (`sandbox`): plain facts, read on the organ's status and carried on each
//! call's receipt, so a mesh caller learns them too (FIX 10582).

use serde::{Deserialize, Serialize};

/// What the kernel isolates an organ process with, as its start found it
/// (FIX 7886, 7887). Nothing here refused the start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct OrganIsolation {
    /// Its user and network namespaces.
    pub namespaces: NamespaceFact,
    /// What ends its descendants when the host ends it.
    pub descendants: DescendantFence,
}

/// Whether an organ got its own user and network namespaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NamespaceFact {
    /// Its own: it shares neither the host's users nor its network.
    Isolated,
    /// The kernel refused `unshare(CLONE_NEWUSER | CLONE_NEWNET)` with
    /// `errno` (a host that forbids unprivileged user namespaces): the organ
    /// runs in the host's namespaces, on the host's network.
    Refused { errno: i32 },
    /// The start could not read the child's word on them.
    Unobserved,
    /// This platform has no namespaces to make.
    NotOnPlatform,
}

/// What ends an organ's descendants when the host ends the organ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DescendantFence {
    /// A cgroup of its own: ending it ends every process in it, one that
    /// left the organ's process group included.
    Cgroup,
    /// Its process group only: a descendant that calls `setsid` outlives
    /// the kill. `why` says what this host lacks for a cgroup.
    ProcessGroup { why: String },
}
