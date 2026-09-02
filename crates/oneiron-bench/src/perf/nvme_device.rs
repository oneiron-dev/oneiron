//! Honest backing-device resolution for the ONE-1579 NVMe descriptor.
//!
//! Mounted aliases, partitions, and one-leaf virtual stacks are resolved through
//! sysfs. Zero- or multi-leaf stacks fail closed rather than being named NVMe
//! from a convenient virtual-device string.

use std::path::Path;

use serde::Serialize;

use super::cells::Cell;
use super::provenance::{mount_facts, read_trimmed};

/// Backing block device facts for the NVMe row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BlockDeviceFacts {
    /// Device named by the measured mount (for example `/dev/mapper/vault`).
    pub(crate) device: String,
    /// Leaf physical block device whose queue is being described.
    pub(crate) disk: String,
    /// Full sysfs chain from the mounted device to that leaf. A partition
    /// records both the partition and parent disk; dm/LVM/MD stacks retain
    /// every resolved hop.
    pub(crate) resolution_chain: Vec<String>,
    pub(crate) resolution_source: &'static str,
    pub(crate) is_nvme: bool,
    pub(crate) rotational: Cell<bool>,
}

/// Resolves `dir`'s mounted block device through sysfs to exactly one physical
/// leaf, then reports whether THAT leaf is NVMe. `/dev/mapper/*`, LVM, dm-crypt
/// and MD devices are virtual: their names alone say nothing about the physical
/// queue. A stack with zero leaves or multiple leaves is deliberately
/// unresolved because one descriptive fsync row cannot honestly name one
/// device for it.
pub(crate) fn block_device_facts(dir: &Path) -> Option<BlockDeviceFacts> {
    let mount = mount_facts(dir)?;
    let device = mount.device;
    let sys_root = Path::new("/sys");
    let name = resolve_mount_device_name(&device, Path::new("/dev"), sys_root)?;
    let (disk, resolution_chain) = resolve_single_leaf_disk(&name, sys_root)?;
    let is_nvme = disk.starts_with("nvme");
    let rotational = Cell::from_option(
        read_trimmed_path(&sys_root.join(format!("block/{disk}/queue/rotational"))).and_then(
            |raw| match raw.as_str() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            },
        ),
        format!("/sys/block/{disk}/queue/rotational is not readable"),
    );
    Some(BlockDeviceFacts {
        device,
        disk,
        resolution_chain,
        resolution_source: "mounted /dev node -> sysfs class/block -> recursively resolved slaves; exactly one leaf required",
        is_nvme,
        rotational,
    })
}

fn read_trimmed_path(path: &Path) -> Option<String> {
    path.to_str().and_then(read_trimmed)
}

/// Maps `/dev/nvme0n1p2`, `/dev/dm-0`, and `/dev/mapper/name` to a kernel block
/// device name present under `sys_root/class/block`. Mapper aliases are resolved
/// by canonicalizing the `/dev` node; a mere `/dev/mapper/...` basename is never
/// treated as a physical disk.
fn resolve_mount_device_name(device: &str, dev_root: &Path, sys_root: &Path) -> Option<String> {
    let raw = device.strip_prefix("/dev/")?;
    if raw.is_empty() {
        return None;
    }
    let direct = Path::new(raw)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)?;
    if sys_root.join("class/block").join(direct).exists() {
        return Some(direct.to_owned());
    }

    let dev_path = dev_root.join(raw);
    let canonical = std::fs::canonicalize(dev_path).ok()?;
    let name = canonical.file_name()?.to_str()?;
    sys_root
        .join("class/block")
        .join(name)
        .exists()
        .then(|| name.to_owned())
}

/// Resolves partitions to their parent disk and virtual devices through their
/// `slaves` recursively. Exactly one leaf is required; multi-device RAID and a
/// virtual device with no readable dependency are not collapsed into a guess.
fn resolve_single_leaf_disk(name: &str, sys_root: &Path) -> Option<(String, Vec<String>)> {
    let mut chain = Vec::new();
    let leaf = resolve_leaf_recursive(name, sys_root, &mut chain, &mut Vec::new())?;
    Some((leaf, chain))
}

fn resolve_leaf_recursive(
    name: &str,
    sys_root: &Path,
    chain: &mut Vec<String>,
    visiting: &mut Vec<String>,
) -> Option<String> {
    if visiting.iter().any(|seen| seen == name) {
        return None;
    }
    let class_entry = sys_root.join("class/block").join(name);
    if !class_entry.exists() {
        return None;
    }
    visiting.push(name.to_owned());
    chain.push(name.to_owned());

    // Partition class entries do not expose a `slaves` directory. Resolve the
    // parent through the canonical sysfs path before handling whole/virtual
    // disks, and retain both hops in the evidence chain.
    if class_entry.join("partition").exists() {
        let disk = parent_disk_from_sysfs(name, sys_root)?;
        if disk != name {
            chain.push(disk.clone());
        }
        visiting.pop();
        return Some(disk);
    }

    let slaves_dir = class_entry.join("slaves");
    let entries = std::fs::read_dir(&slaves_dir).ok()?;
    let mut slaves: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    slaves.sort();
    let resolved = if slaves.is_empty() {
        parent_disk_from_sysfs(name, sys_root)
    } else if slaves.len() == 1 {
        resolve_leaf_recursive(&slaves[0], sys_root, chain, visiting)
    } else {
        None
    };
    visiting.pop();
    resolved
}

/// Partitions expose a `partition` file and their class symlink target's parent
/// directory is the whole disk. This avoids parsing names (`nvme...pN`, `mmc`,
/// `loop`, and future schemes) and only falls back to the same name for a whole
/// disk already present under `/sys/block`.
fn parent_disk_from_sysfs(name: &str, sys_root: &Path) -> Option<String> {
    let class_entry = sys_root.join("class/block").join(name);
    if class_entry.join("partition").exists() {
        let canonical = std::fs::canonicalize(&class_entry).ok()?;
        let parent = canonical.parent()?.file_name()?.to_str()?.to_owned();
        return sys_root
            .join("block")
            .join(&parent)
            .exists()
            .then_some(parent);
    }
    sys_root
        .join("block")
        .join(name)
        .exists()
        .then(|| name.to_owned())
}

#[cfg(test)]
fn make_block_entry(sys: &Path, name: &str, whole_disk: bool) {
    std::fs::create_dir_all(sys.join("class/block").join(name).join("slaves"))
        .expect("class block entry");
    if whole_disk {
        std::fs::create_dir_all(sys.join("block").join(name)).expect("whole disk entry");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct disks, one-leaf device-mapper stacks, and multi-leaf stacks have
    /// different truth values. Only the first two may resolve to one physical
    /// disk; the third stays unavailable instead of selecting a convenient
    /// slave or classifying `dm-1` from its virtual name.
    #[cfg(unix)]
    #[test]
    fn sysfs_device_resolution_requires_exactly_one_physical_leaf() {
        let root = tempfile::tempdir().expect("tempdir");
        let sys = root.path().join("sys");
        make_block_entry(&sys, "nvme0n1", true);
        make_block_entry(&sys, "dm-0", true);
        make_block_entry(&sys, "dm-1", true);
        make_block_entry(&sys, "sda", true);
        std::os::unix::fs::symlink(
            sys.join("class/block/nvme0n1"),
            sys.join("class/block/dm-0/slaves/nvme0n1"),
        )
        .expect("single slave");
        std::os::unix::fs::symlink(
            sys.join("class/block/nvme0n1"),
            sys.join("class/block/dm-1/slaves/nvme0n1"),
        )
        .expect("first multi-device slave");
        std::os::unix::fs::symlink(
            sys.join("class/block/sda"),
            sys.join("class/block/dm-1/slaves/sda"),
        )
        .expect("second multi-device slave");

        let partition_target = sys.join("devices/mock/nvme0n1/nvme0n1p1");
        std::fs::create_dir_all(&partition_target).expect("partition target");
        std::fs::write(partition_target.join("partition"), "1\n").expect("partition marker");
        std::os::unix::fs::symlink(&partition_target, sys.join("class/block/nvme0n1p1"))
            .expect("partition class link");

        let direct = resolve_single_leaf_disk("nvme0n1", &sys).expect("direct leaf");
        assert_eq!(direct.0, "nvme0n1");
        assert_eq!(direct.1, vec!["nvme0n1"]);

        let partition =
            resolve_single_leaf_disk("nvme0n1p1", &sys).expect("partition resolves to parent");
        assert_eq!(partition.0, "nvme0n1");
        assert_eq!(partition.1, vec!["nvme0n1p1", "nvme0n1"]);

        let mapped = resolve_single_leaf_disk("dm-0", &sys).expect("one-leaf mapper resolves");
        assert_eq!(mapped.0, "nvme0n1");
        assert_eq!(mapped.1, vec!["dm-0", "nvme0n1"]);

        assert!(
            resolve_single_leaf_disk("dm-1", &sys).is_none(),
            "a multi-leaf stack cannot honestly be described as one NVMe device"
        );
    }
}
