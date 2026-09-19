//! Host-only image pins and jailer profile validation.

use super::refused;
use crate::Result;
use crate::code_sandbox::microvm::GuestImage;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
};

/// Digests are supplied out of band by the host, never by guest output.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuestArtifactPins {
    pub kernel: [u8; 32],
    pub rootfs: [u8; 32],
    pub component: [u8; 32],
}
impl GuestArtifactPins {
    pub(super) fn verify(&self, image: &GuestImage) -> Result<()> {
        for (path, expected, max) in [
            (&image.kernel, self.kernel, 64 * 1024 * 1024),
            (&image.rootfs, self.rootfs, 4 * 1024 * 1024 * 1024_u64),
            (&image.component, self.component, 64 * 1024 * 1024),
        ] {
            if digest_file(path, max)? != expected {
                return Err(refused("guest artifact pin mismatch"));
            }
        }
        Ok(())
    }
}

/// A host-provisioned jailer profile. The engine does not create system users,
/// cgroup controllers, guest images or install Firecracker.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerHostConfig {
    pub firecracker: PathBuf,
    pub jailer: PathBuf,
    pub scratch_root: PathBuf,
    pub chroot_base: PathBuf,
    /// Non-root uid/gid used INSIDE the jail. Jailer itself requires root.
    pub uid: u32,
    pub gid: u32,
    pub vcpus: u8,
    /// V2 hierarchy parent, e.g. `oneiron`. Controllers must be provisioned.
    pub cgroup_parent: String,
    pub pins: GuestArtifactPins,
}

impl FirecrackerHostConfig {
    pub(super) fn validate(&self) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(refused("Firecracker requires Linux"));
        }
        if self.uid == 0 || self.gid == 0 || !(1..=32).contains(&self.vcpus) {
            return Err(refused(
                "jailer requires non-root identity and bounded vcpus",
            ));
        }
        if self.cgroup_parent.is_empty()
            || self.cgroup_parent.len() > 64
            || !self
                .cgroup_parent
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(refused("invalid cgroup parent"));
        }
        for path in [&self.firecracker, &self.jailer] {
            if !path.is_absolute() {
                return Err(refused("jailer binary path must be absolute"));
            }
            let metadata = regular_metadata(path, 256 * 1024 * 1024)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = metadata.permissions().mode();
                if mode & 0o111 == 0 || mode & 0o022 != 0 {
                    return Err(refused("jailer binary permissions refused"));
                }
            }
            #[cfg(not(unix))]
            let _ = metadata;
        }
        for path in [&self.scratch_root, &self.chroot_base] {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err(refused("jailer state path must be absolute and normalized"));
            }
        }
        #[cfg(target_os = "linux")]
        {
            // SAFETY: geteuid only reads effective identity and has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                return Err(refused("jailer launch requires a privileged host"));
            }
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .map_err(|_| refused("KVM unavailable"))?;
            let controllers = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
                .map_err(|_| refused("cgroup v2 unavailable"))?;
            if !["memory", "pids", "cpu"]
                .iter()
                .all(|axis| controllers.split_whitespace().any(|c| c == *axis))
            {
                return Err(refused("required cgroup controllers unavailable"));
            }
        }
        Ok(())
    }
}

pub(super) fn regular_metadata(path: &Path, max: u64) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| refused("host artifact unavailable"))?;
    if !metadata.is_file() || metadata.is_symlink() || metadata.len() > max {
        return Err(refused("host artifact is not a bounded regular file"));
    }
    Ok(metadata)
}

pub(super) fn read_regular_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    regular_metadata(path, max)?;
    let file = open_artifact(path)?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused("host artifact read failed"))?;
    if bytes.len() as u64 > max {
        return Err(refused("host artifact grew past its bound"));
    }
    Ok(bytes)
}

fn digest_file(path: &Path, max: u64) -> Result<[u8; 32]> {
    regular_metadata(path, max)?;
    let file = open_artifact(path)?;
    let mut reader = BufReader::new(file).take(max + 1);
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = [0; 65_536];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| refused("artifact pin read failed"))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > max {
            return Err(refused("artifact pin size limit"));
        }
        hasher.update(&buffer[..count]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn open_artifact(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| refused("host artifact open failed"))?;
    if !file
        .metadata()
        .map_err(|_| refused("host artifact metadata failed"))?
        .is_file()
    {
        return Err(refused("host artifact is not a regular file"));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(super) fn stage_artifact(source: &Path, target: &Path, max: u64) -> Result<()> {
    use std::io::Write;
    let input = open_artifact(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|_| refused("artifact staging target unavailable"))?;
    let count = std::io::copy(&mut input.take(max + 1), &mut output)
        .map_err(|_| refused("artifact staging failed"))?;
    if count > max {
        return Err(refused("artifact staging size limit"));
    }
    output
        .flush()
        .map_err(|_| refused("artifact staging flush failed"))
}
