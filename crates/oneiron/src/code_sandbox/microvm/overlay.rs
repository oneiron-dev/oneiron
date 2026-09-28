//! The host-side scratch root and the bounded overlay walk that turns guest writes into proposals.

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::code_sandbox::{
    SANDBOX_WORKSPACE_ROOT, SandboxBoundaryContract, SandboxDirectoryOpaqueProposal,
    SandboxFileDeleteProposal, SandboxFileWriteProposal, SandboxMount, SandboxMountTable,
    SandboxProposalWrite, SandboxVirtualPath,
};
use crate::{EntityId, Error, Result};

use super::backend::backend_error;
use super::handle::MicroVmHandle;
use crate::error::CodeError;

/// Provisions the overlay + egress layout every backend shares.
///
/// The base mount is recorded read-only on the handle and is not created or
/// touched here; only the upper directory the guest writes into is made.
///
/// # Errors
///
/// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the contract is not
/// propose-only or the overlay directory cannot be created.
pub fn prepare_overlay_handle(
    root: &Path,
    backend: &'static str,
    contract: &SandboxBoundaryContract,
    mounts: &SandboxMountTable,
) -> Result<MicroVmHandle> {
    if contract.links_write_imports() || !contract.has_proposal_delta_channel() {
        return Err(backend_error(backend, "guest contract is not propose-only"));
    }

    ensure_private_scratch_root(root, backend)?;

    let base_root = mounts.resolve_host_path(&SandboxVirtualPath::try_new(SANDBOX_WORKSPACE_ROOT)?);
    let vm_id = EntityId::now().to_hex();
    let (vm_root, scratch) = super::scratch::provision(root, &vm_id, backend)?;
    let overlay_upper = vm_root.join("upper");
    fs::create_dir(&overlay_upper)
        .map_err(|error| backend_error(backend, overlay_io_detail("upper", &error)))?;

    Ok(MicroVmHandle::new(
        vm_id,
        contract.tier(),
        base_root,
        overlay_upper,
        vm_root.join("egress.sock"),
    )?
    .with_scratch(scratch))
}

fn ensure_private_scratch_root(root: &Path, backend: &'static str) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => validate_scratch_root(root, backend, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(|error| {
                backend_error(backend, scratch_root_io_detail(root, "create", &error))
            })?;
            let metadata = fs::symlink_metadata(root).map_err(|error| {
                backend_error(backend, scratch_root_io_detail(root, "inspect", &error))
            })?;
            validate_scratch_root(root, backend, &metadata)?;
        }
        Err(error) => {
            return Err(backend_error(
                backend,
                scratch_root_io_detail(root, "inspect", &error),
            ));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|error| {
            backend_error(backend, scratch_root_io_detail(root, "chmod 0700", &error))
        })?;
    }

    Ok(())
}

fn validate_scratch_root(
    root: &Path,
    backend: &'static str,
    metadata: &fs::Metadata,
) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(backend_error(
            backend,
            format!("scratch root `{}` is a symlink", root.display()),
        ));
    }
    if !metadata.is_dir() {
        return Err(backend_error(
            backend,
            format!("scratch root `{}` is not a directory", root.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: `geteuid` has no preconditions and only reads the process's
        // effective user identity; it dereferences no caller-provided pointer.
        let expected_uid = unsafe { libc::geteuid() };
        validate_scratch_root_owner(root, backend, metadata.uid(), expected_uid)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_scratch_root_owner(
    root: &Path,
    backend: &'static str,
    actual_uid: u32,
    expected_uid: u32,
) -> Result<()> {
    if actual_uid != expected_uid {
        return Err(backend_error(
            backend,
            format!(
                "scratch root `{}` has unexpected ownership: expected owner uid {expected_uid}, actual owner uid {actual_uid}",
                root.display()
            ),
        ));
    }
    Ok(())
}

fn scratch_root_io_detail(root: &Path, operation: &str, error: &std::io::Error) -> String {
    format!(
        "scratch root `{}` {operation} failed: {}",
        root.display(),
        error.kind()
    )
}

/// Maximum bytes accepted from one overlay file during proposal export.
pub(super) const MAX_OVERLAY_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum aggregate bytes accepted from one overlay during proposal export.
pub(super) const MAX_OVERLAY_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum regular-file count accepted from one overlay during proposal export.
pub(super) const MAX_OVERLAY_FILES: usize = 8_192;

/// Maximum directory count accepted below one overlay upper root.
pub(super) const MAX_OVERLAY_DIRECTORIES: usize = 8_192;

/// Maximum directory depth below the overlay upper root.
pub(super) const MAX_OVERLAY_DEPTH: usize = 64;

#[derive(Default)]
pub(super) struct OverlayWalkBounds {
    pub(super) total_bytes: u64,
    pub(super) file_count: usize,
    pub(super) directory_count: usize,
}

/// Collects an overlay upper directory into typed review proposals.
/// A whiteout is a deletion; an opaque marker is a directory hide request.
/// A whiteout paired with a new file does not prove a rename of one document:
/// explicit rename intent must come from the guest protocol.
///
/// Backends share this so the "writes are proposals" shape is identical across
/// the dev and isolating lanes. The base mount is never opened here.
///
/// # Errors
///
/// Returns [`CodeError::MicroVmOverlayError`](crate::error::CodeError::MicroVmOverlayError) when the overlay root is missing or
/// invalid, an entry vanishes during traversal, a resource bound is exceeded,
/// or an entry has a non-UTF-8 name, is a symlink, or is an unsupported type.
pub fn collect_overlay_writes(
    upper_root: &Path,
    mount: SandboxMount,
) -> Result<Vec<SandboxProposalWrite>> {
    let root_metadata = fs::symlink_metadata(upper_root).map_err(|error| {
        overlay_error(format!(
            "overlay root `{}` is unavailable: {}",
            upper_root.display(),
            error.kind()
        ))
    })?;
    if root_metadata.file_type().is_symlink() {
        return Err(overlay_error(format!(
            "overlay root `{}` is a symlink",
            upper_root.display()
        )));
    }
    if !root_metadata.is_dir() {
        return Err(overlay_error(format!(
            "overlay root `{}` is not a directory",
            upper_root.display()
        )));
    }

    let mut files = BTreeMap::<OverlayKey, SandboxProposalWrite>::new();
    let mut bounds = OverlayWalkBounds::default();
    let mut stack = vec![(upper_root.to_path_buf(), String::new(), 0_usize)];
    while let Some((dir, prefix, depth)) = stack.pop() {
        walk_overlay_dir(
            &dir,
            &prefix,
            depth,
            mount,
            &mut files,
            &mut stack,
            &mut bounds,
        )?;
    }

    Ok(files.into_values().collect())
}

/// Keep directory effects separate from file effects, even if a real file is
/// literally named `.opaque` in that directory. Opaque markers sort first, so
/// a reviewer applying the list in order hides lower children before writes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum OverlayKey {
    Opaque(String),
    File(String),
}

pub(super) fn walk_overlay_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    mount: SandboxMount,
    files: &mut BTreeMap<OverlayKey, SandboxProposalWrite>,
    stack: &mut Vec<(PathBuf, String, usize)>,
    bounds: &mut OverlayWalkBounds,
) -> Result<()> {
    // The root and each nested directory may carry the kernel's opaque xattr.
    // An OCI-style .wh..wh..opq marker is handled as an entry below.
    if is_opaque(dir)? {
        let path = SandboxVirtualPath::try_new(if prefix.is_empty() {
            mount.root().to_owned()
        } else {
            format!("{}/{prefix}", mount.root())
        })?;
        files.insert(
            OverlayKey::Opaque(path.as_str().to_owned()),
            SandboxProposalWrite::DirectoryOpaque(SandboxDirectoryOpaqueProposal { path }),
        );
    }
    let entries = fs::read_dir(dir).map_err(|error| {
        overlay_error(format!(
            "overlay directory `{}` disappeared or cannot be read: {}",
            dir.display(),
            error.kind()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let entry_path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| overlay_error("overlay entry name is not utf-8"))?;
        let metadata = fs::symlink_metadata(&entry_path)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        if metadata.is_symlink() {
            return Err(overlay_error(format!(
                "overlay entry `{name}` is a symlink"
            )));
        }

        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if name == ".wh..wh..opq" {
            if !metadata.is_file() || metadata.len() != 0 {
                return Err(overlay_error("invalid opaque directory marker"));
            }
            let path = SandboxVirtualPath::try_new(if prefix.is_empty() {
                mount.root().to_owned()
            } else {
                format!("{}/{prefix}", mount.root())
            })?;
            files.insert(
                OverlayKey::Opaque(path.as_str().to_owned()),
                SandboxProposalWrite::DirectoryOpaque(SandboxDirectoryOpaqueProposal { path }),
            );
            count_entry(bounds, &relative)?;
            continue;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            if target.is_empty() || !metadata.is_file() || metadata.len() != 0 {
                return Err(overlay_error("invalid whiteout marker"));
            }
            let target = if prefix.is_empty() {
                target.to_owned()
            } else {
                format!("{prefix}/{target}")
            };
            add_delete(&target, mount, files)?;
            count_entry(bounds, &relative)?;
            continue;
        }
        #[cfg(unix)]
        if metadata.file_type().is_char_device() {
            use std::os::unix::fs::MetadataExt;
            if metadata.rdev() != 0 {
                return Err(overlay_error(format!(
                    "overlay entry `{relative}` is not a whiteout"
                )));
            }
            add_delete(&relative, mount, files)?;
            count_entry(bounds, &relative)?;
            continue;
        }
        if metadata.is_dir() {
            let child_depth = depth + 1;
            if child_depth > MAX_OVERLAY_DEPTH {
                return Err(overlay_error(format!(
                    "overlay depth bound {MAX_OVERLAY_DEPTH} exceeded at `{relative}`"
                )));
            }
            let next_directory_count = bounds.directory_count.checked_add(1).ok_or_else(|| {
                overlay_error(format!(
                    "overlay directory count bound {MAX_OVERLAY_DIRECTORIES} exceeded at `{relative}`"
                ))
            })?;
            if next_directory_count > MAX_OVERLAY_DIRECTORIES {
                return Err(overlay_error(format!(
                    "overlay directory count bound {MAX_OVERLAY_DIRECTORIES} exceeded at `{relative}`"
                )));
            }
            bounds.directory_count = next_directory_count;
            stack.push((entry_path, relative, child_depth));
            continue;
        }
        if !metadata.is_file() {
            return Err(overlay_error(format!(
                "overlay entry `{relative}` is not a plain file"
            )));
        }

        let file_bytes = metadata.len();
        if file_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}` ({file_bytes} bytes)"
            )));
        }
        if bounds.file_count >= MAX_OVERLAY_FILES {
            return Err(overlay_error(format!(
                "overlay file count bound {MAX_OVERLAY_FILES} exceeded at `{relative}`"
            )));
        }
        let next_total = bounds.total_bytes.checked_add(file_bytes).ok_or_else(|| {
            overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}`"
            ))
        })?;
        if next_total > MAX_OVERLAY_TOTAL_BYTES {
            return Err(overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}` ({next_total} bytes)"
            )));
        }

        let remaining_total = MAX_OVERLAY_TOTAL_BYTES - bounds.total_bytes;
        let read_limit = MAX_OVERLAY_FILE_BYTES.min(remaining_total);
        let file = fs::File::open(&entry_path)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut file.take(read_limit + 1), &mut bytes)
            .map_err(|error| overlay_error(overlay_io_detail("entry", &error)))?;
        let actual_bytes = u64::try_from(bytes.len()).map_err(|_| {
            overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}`"
            ))
        })?;
        if actual_bytes > MAX_OVERLAY_FILE_BYTES {
            return Err(overlay_error(format!(
                "overlay file byte bound {MAX_OVERLAY_FILE_BYTES} exceeded at `{relative}`"
            )));
        }
        let actual_total = bounds.total_bytes + actual_bytes;
        if actual_total > MAX_OVERLAY_TOTAL_BYTES {
            return Err(overlay_error(format!(
                "overlay aggregate byte bound {MAX_OVERLAY_TOTAL_BYTES} exceeded at `{relative}` ({actual_total} bytes)"
            )));
        }

        bounds.file_count += 1;
        bounds.total_bytes = actual_total;
        let path = SandboxVirtualPath::try_new(format!("{}/{relative}", mount.root()))?;
        if files
            .insert(
                OverlayKey::File(path.as_str().to_owned()),
                SandboxProposalWrite::FileWrite(SandboxFileWriteProposal::new(path, bytes)),
            )
            .is_some()
        {
            return Err(overlay_error("overlay path has conflicting entries"));
        }
    }
    Ok(())
}

pub(super) fn overlay_io_detail(class: &str, error: &std::io::Error) -> String {
    format!("overlay {class} io failed: {}", error.kind())
}

pub(super) fn overlay_error(detail: impl Into<String>) -> Error {
    Error::Code(CodeError::MicroVmOverlayError {
        detail: detail.into(),
    })
}

fn count_entry(bounds: &mut OverlayWalkBounds, path: &str) -> Result<()> {
    if bounds.file_count >= MAX_OVERLAY_FILES {
        return Err(overlay_error(format!(
            "overlay file count bound {MAX_OVERLAY_FILES} exceeded at `{path}`"
        )));
    }
    bounds.file_count += 1;
    Ok(())
}

fn add_delete(
    relative: &str,
    mount: SandboxMount,
    files: &mut BTreeMap<OverlayKey, SandboxProposalWrite>,
) -> Result<()> {
    let path = SandboxVirtualPath::try_new(format!("{}/{relative}", mount.root()))?;
    if files
        .insert(
            OverlayKey::File(path.as_str().to_owned()),
            SandboxProposalWrite::FileDelete(SandboxFileDeleteProposal { path }),
        )
        .is_some()
    {
        return Err(overlay_error("overlay path has conflicting entries"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_opaque(dir: &Path) -> Result<bool> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| overlay_error("invalid overlay directory name"))?;
    for key in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        let mut value = [0_u8; 2];
        // SAFETY: both C strings and the writable buffer remain valid for the call.
        let size = unsafe {
            libc::lgetxattr(
                path.as_ptr(),
                key.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if size == -1 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENODATA | libc::ENOTSUP | libc::EPERM)
            ) {
                continue;
            }
            return Err(overlay_error(overlay_io_detail("opaque xattr", &error)));
        }
        if size == 1 && value[0] == b'y' {
            return Ok(true);
        }
        return Err(overlay_error("invalid overlay opaque xattr"));
    }
    Ok(false)
}

#[cfg(not(target_os = "linux"))]
fn is_opaque(_dir: &Path) -> Result<bool> {
    Ok(false)
}

/// Reclaim crash leftovers when an isolating backend starts, before it accepts VMs.
#[cfg(all(unix, any(test, feature = "microvm-firecracker")))]
pub(in crate::code_sandbox) fn reap_overlay_scratch(
    root: &Path,
    backend: &'static str,
) -> Result<()> {
    ensure_private_scratch_root(root, backend)?;
    super::scratch::reap(root, backend)
}
