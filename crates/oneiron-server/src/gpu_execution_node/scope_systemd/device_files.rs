//! Which device files a leased device is (pass 33, 7.8 "GPU"; pass 34, 2.2:
//! `DeviceAllow` is built from the device claims, and none means no
//! device). The root-owned node file may name a device's files outright
//! (`device_files`); an NVIDIA card with no entry is found by its UUID in
//! the driver's own table, with the driver's control nodes beside it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The driver's per-card tables.
const NVIDIA_GPUS_DIR: &str = "/proc/driver/nvidia/gpus";

/// The NVIDIA driver's control nodes a CUDA process opens besides its card.
const NVIDIA_CONTROL_NODES: [&str; 4] = [
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
];

/// The files of `device_id`, from the node file's `device_files` first, else
/// from the NVIDIA driver's table.
///
/// # Errors
///
/// `device_files_unknown: <id>` when neither names it.
pub fn files_of(
    device_id: &str,
    configured: &BTreeMap<String, Vec<PathBuf>>,
) -> Result<Vec<PathBuf>, String> {
    if let Some(files) = configured.get(device_id) {
        return Ok(files.clone());
    }
    if let Some(minor) = nvidia_minor(Path::new(NVIDIA_GPUS_DIR), device_id) {
        let mut files = vec![PathBuf::from(format!("/dev/nvidia{minor}"))];
        files.extend(
            NVIDIA_CONTROL_NODES
                .iter()
                .map(PathBuf::from)
                .filter(|path| path.exists()),
        );
        return Ok(files);
    }
    Err(format!("device_files_unknown: {device_id}"))
}

/// Device files on this machine that no claim of this job names: every
/// other configured device's files, and every NVIDIA card node not allowed.
/// The proof of device closure tries to open one.
#[must_use]
pub fn files_denied(
    allowed: &[PathBuf],
    configured: &BTreeMap<String, Vec<PathBuf>>,
) -> Vec<PathBuf> {
    let mut denied: Vec<PathBuf> = configured
        .values()
        .flatten()
        .filter(|path| !allowed.contains(path) && path.exists())
        .cloned()
        .collect();
    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let is_card = name
                .strip_prefix("nvidia")
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()));
            let path = entry.path();
            if is_card && !allowed.contains(&path) {
                denied.push(path);
            }
        }
    }
    denied.sort();
    denied.dedup();
    denied
}

/// The minor number of the NVIDIA card whose UUID is `device_id`, from the
/// driver's `information` files ("GPU UUID:" and "Device Minor:" lines).
fn nvidia_minor(dir: &Path, device_id: &str) -> Option<u32> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path().join("information")) else {
            continue;
        };
        if let Some(minor) = minor_for_uuid(&text, device_id) {
            return Some(minor);
        }
    }
    None
}

fn minor_for_uuid(information: &str, device_id: &str) -> Option<u32> {
    let field = |name: &str| {
        information.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
    };
    (field("GPU UUID")? == device_id)
        .then(|| field("Device Minor")?.parse().ok())
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_card_is_found_by_its_uuid_in_the_drivers_table() {
        let text = "Model: \t\t NVIDIA GeForce RTX 4090\nIRQ:   \t\t 189\nGPU UUID: \t GPU-6a1c\nDevice Minor: \t 0\n";
        assert_eq!(minor_for_uuid(text, "GPU-6a1c"), Some(0));
        assert_eq!(minor_for_uuid(text, "GPU-other"), None);
    }

    #[test]
    fn a_configured_device_names_its_own_files() {
        let mut configured = BTreeMap::new();
        configured.insert("QUAL-0".to_owned(), vec![PathBuf::from("/dev/qual/dev0")]);
        assert_eq!(
            files_of("QUAL-0", &configured),
            Ok(vec![PathBuf::from("/dev/qual/dev0")])
        );
        assert!(files_of("QUAL-1", &configured).is_err());
    }
}
