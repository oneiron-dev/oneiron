//! A vault VM image's guest runtime (FIX 7671, placement A): what the image
//! stages for the vault's fenced browser and desktop guests, as one typed
//! descriptor.
//!
//! The image builder stages a pinned rootless container CLI with the files
//! it runs (its OCI runner and monitor, the distro's set-user-ID mapping
//! helpers, their libraries and config), the host fence launcher, and both
//! guests' image archives in the read-only root filesystem, each file root's
//! with the mode its row names. It writes this descriptor at
//! [`VM_GUEST_RUNTIME_DESCRIPTOR`](crate::vm::VM_GUEST_RUNTIME_DESCRIPTOR)
//! and as the image manifest's `guest_runtime`, beside its
//! `vm_guest_runtime_revision`
//! ([`VM_GUEST_RUNTIME_REVISION`](crate::vm::VM_GUEST_RUNTIME_REVISION)).
//! Every key is required. The paths are the guest's own: no host path is in
//! it. The root bootstrap checks every staged file against its row, then
//! imports both archives into the vault UID's own image store; a host takes
//! the runtime bindings of an image whose manifest holds this descriptor
//! only.

use crate::vm::{
    VM_GUEST_BROWSER_IMAGE_ARCHIVE, VM_GUEST_DESKTOP_IMAGE_ARCHIVE, VM_GUEST_RUNTIME_DESCRIPTOR,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The permission bits a staged file may carry: set-user-ID, and no write
/// for its group or for others.
const ALLOWED_MODE_BITS: u32 = 0o4755;

/// The guest runtime an image stages, by guest path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmGuestRuntimeDescriptor {
    /// The Docker-compatible rootless container CLI: the one path a runtime
    /// binding file on the config drive may name.
    pub cli: PathBuf,
    /// The host fence launcher the engine mounts as each guest's entrypoint
    /// (`ONEIRON_FENCE_LAUNCHER`).
    pub fence: PathBuf,
    /// Every file the runtime stages, `cli` and `fence` among them.
    pub closure: Vec<VmGuestRuntimeFile>,
    /// The browser guest's image archive.
    pub browser_image: VmGuestImageArchive,
    /// The desktop guest's image archive.
    pub desktop_image: VmGuestImageArchive,
}

/// One staged file of the runtime: root's, with exactly these bytes and
/// this mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmGuestRuntimeFile {
    pub guest_path: PathBuf,
    /// The file's SHA-256, 64 lowercase hex digits.
    pub sha256: String,
    /// Its permission bits as a number (04755 is 2541): at most
    /// set-user-ID and 0755.
    pub mode: u32,
}

/// One guest's image archive (`docker save` form), root's and read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmGuestImageArchive {
    pub guest_path: PathBuf,
    /// The archive's SHA-256, 64 lowercase hex digits.
    pub sha256: String,
    /// The image id the archive's own manifest names, `sha256:` and 64
    /// lowercase hex digits: the id a store answers once it is loaded.
    pub image_id: String,
}

impl VmGuestRuntimeDescriptor {
    /// Why a guest cannot take this, if it cannot: a path that is not an
    /// absolute guest path, a file named twice or at the descriptor's or
    /// an archive's path, a digest or an image id not in its form, a mode
    /// beyond set-user-ID and 0755, a CLI or fence that is not a staged file
    /// every UID may run, or an archive not at its fixed path.
    pub fn validate(&self) -> Result<(), &'static str> {
        let mut seen = HashSet::new();
        for file in &self.closure {
            if !guest_path(&file.guest_path) {
                return Err("a staged file's path is not an absolute guest path");
            }
            if !seen.insert(file.guest_path.as_path())
                || [
                    VM_GUEST_RUNTIME_DESCRIPTOR,
                    VM_GUEST_BROWSER_IMAGE_ARCHIVE,
                    VM_GUEST_DESKTOP_IMAGE_ARCHIVE,
                ]
                .iter()
                .any(|fixed| file.guest_path == Path::new(fixed))
            {
                return Err("a staged file's path is named twice");
            }
            if !lower_hex(&file.sha256) {
                return Err("a staged file's sha256 is not 64 lowercase hex digits");
            }
            if file.mode & !ALLOWED_MODE_BITS != 0 {
                return Err("a staged file's mode is beyond set-user-ID and 0755");
            }
        }
        for program in [&self.cli, &self.fence] {
            let staged = self.closure.iter().find(|file| file.guest_path == *program);
            if !staged.is_some_and(|file| file.mode & 0o001 != 0) {
                return Err("the CLI or the fence is not a staged file every UID may run");
            }
        }
        for (archive, fixed) in [
            (&self.browser_image, VM_GUEST_BROWSER_IMAGE_ARCHIVE),
            (&self.desktop_image, VM_GUEST_DESKTOP_IMAGE_ARCHIVE),
        ] {
            if archive.guest_path != Path::new(fixed) {
                return Err("an image archive is not at its fixed path");
            }
            if !lower_hex(&archive.sha256) {
                return Err("an image archive's sha256 is not 64 lowercase hex digits");
            }
            if !archive
                .image_id
                .strip_prefix("sha256:")
                .is_some_and(lower_hex)
            {
                return Err("an image id is not sha256: and 64 lowercase hex digits");
            }
        }
        Ok(())
    }
}

/// An absolute guest path in UTF-8: `/`, then parts that are neither empty
/// nor `.` nor `..`.
fn guest_path(path: &Path) -> bool {
    path.to_str()
        .and_then(|text| text.strip_prefix('/'))
        .is_some_and(|rest| {
            rest.split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
        })
}

/// 64 lowercase hex digits.
fn lower_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
