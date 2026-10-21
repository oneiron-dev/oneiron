//! The memory cgroup this process runs in (FIX 8067), and what its limits
//! leave (FIX 8066). The process's own group is read from
//! `/proc/self/cgroup` (cgroup v1's `memory` controller line, else v2's
//! `0::<path>` line), and every group from it up to its hierarchy's root is
//! read where that hierarchy is mounted: a limit set on any of them (a
//! container's, or a systemd unit's `MemoryMax=` on a nested group) binds
//! the process. A group whose files cannot be read sets no limit.

use std::path::{Component, Path, PathBuf};

/// One hierarchy's memory files.
#[derive(Clone, Copy)]
struct Files {
    /// Where the hierarchy is mounted.
    mount: &'static str,
    /// The group's limit: its bytes, or `max` (v2) for none.
    limit: &'static str,
    /// The memory the group holds now, its reclaimable page cache included.
    usage: &'static str,
    /// The `memory.stat` key of the group's inactive file pages: cache the
    /// kernel reclaims before the group pages, as `MemAvailable` counts it.
    inactive: &'static str,
}

const V2: Files = Files {
    mount: "/sys/fs/cgroup",
    limit: "memory.max",
    usage: "memory.current",
    inactive: "inactive_file",
};

const V1: Files = Files {
    mount: "/sys/fs/cgroup/memory",
    limit: "memory.limit_in_bytes",
    usage: "memory.usage_in_bytes",
    inactive: "total_inactive_file",
};

/// One group on the way from this process's own group to the root, read now.
pub(super) struct Level {
    /// Its memory limit; `None` where it sets none or cannot be read.
    pub(super) limit: Option<u64>,
    /// What that limit leaves past the memory the group holds, less the
    /// inactive file pages the kernel reclaims first (FIX 8066): page cache,
    /// LMDB's mapped pages among it, is no memory the group lacks. `None`
    /// without a limit, or without a usage that can be read.
    pub(super) headroom: Option<u64>,
}

/// Every group from this process's own memory group up to its hierarchy's
/// root, the own group first, read now. Where `/proc/self/cgroup` names no
/// group, both hierarchies' roots, as their mounts show them.
pub(super) fn levels() -> Vec<Level> {
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    groups(&own)
        .into_iter()
        .map(|(files, dir)| read(files, &dir))
        .collect()
}

/// The group directories `own` (a `/proc/self/cgroup` text) puts this
/// process under, its own group first, each with the files it is read
/// through.
fn groups(own: &str) -> Vec<(Files, PathBuf)> {
    // A v1 memory controller line comes first: on a hybrid host the unified
    // hierarchy carries no memory controller.
    let v1 = own.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _id = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers
            .split(',')
            .any(|name| name == "memory")
            .then_some(path)
    });
    let v2 = own.lines().find_map(|line| line.strip_prefix("0::"));
    match (v1, v2) {
        (Some(path), _) => up_from(V1, path),
        (None, Some(path)) => up_from(V2, path),
        (None, None) => vec![(V2, PathBuf::from(V2.mount)), (V1, PathBuf::from(V1.mount))],
    }
}

/// The directories of the group at `path`, as `/proc/self/cgroup` names it,
/// and of each group above it, under `files`' mount. A path that climbs out
/// of the mount (a group outside this cgroup namespace) is read at the
/// mount's root alone.
fn up_from(files: Files, path: &str) -> Vec<(Files, PathBuf)> {
    let relative = Path::new(path.trim_start_matches('/'));
    let mount = Path::new(files.mount);
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return vec![(files, mount.to_path_buf())];
    }
    relative
        .ancestors()
        .map(|group| (files, mount.join(group)))
        .collect()
}

/// The limit and headroom the group in `dir` shows now.
fn read(files: Files, dir: &Path) -> Level {
    let number = |name: &str| -> Option<u64> {
        std::fs::read_to_string(dir.join(name))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    let limit = number(files.limit);
    let headroom = limit.and_then(|limit| {
        let usage = number(files.usage)?;
        // A stat that cannot be read reclaims nothing.
        let inactive = std::fs::read_to_string(dir.join("memory.stat"))
            .ok()
            .and_then(|stat| {
                stat.lines().find_map(|line| {
                    let (key, value) = line.split_once(' ')?;
                    (key == files.inactive).then(|| value.trim().parse::<u64>().ok())?
                })
            })
            .unwrap_or(0);
        Some(limit.saturating_sub(usage.saturating_sub(inactive)))
    });
    Level { limit, headroom }
}
