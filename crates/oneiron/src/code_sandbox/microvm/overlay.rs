//! The host-side scratch root and the bounded overlay walk that turns guest writes into proposals.

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use crate::code_sandbox::{
    SANDBOX_WORKSPACE_ROOT, SandboxBoundaryContract, SandboxFileWriteProposal, SandboxMount,
    SandboxMountTable, SandboxProposalWrite, SandboxVirtualPath,
};
use crate::{EntityId, Error, Result};

use super::backend::backend_error;
use super::handle::MicroVmHandle;

/// Provisions the overlay + egress layout every backend shares.
///
/// The base mount is recorded read-only on the handle and is not created or
/// touched here; only the upper directory the guest writes into is made.
///
/// # Errors
///
/// Returns [`Error::MicroVmBackendError`] when the contract is not
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
    let vm_root = root.join(&vm_id);
    let overlay_upper = vm_root.join("upper");
    fs::create_dir_all(&overlay_upper)
        .map_err(|error| backend_error(backend, overlay_io_detail("upper", &error)))?;

    MicroVmHandle::new(
        vm_id,
        contract.tier(),
        base_root,
        overlay_upper,
        vm_root.join("egress.sock"),
    )
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

/// Diffs an overlay upper directory into write proposals.
///
/// Backends share this so the "writes are proposals" shape is identical across
/// the dev and isolating lanes. The base mount is never opened here.
///
/// # Errors
///
/// Returns [`Error::MicroVmOverlayError`] when the overlay root is missing or
/// invalid, an entry vanishes during traversal, a resource bound is exceeded,
/// or an entry has a non-UTF-8 name, is a symlink, or is not a plain file.
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

    let mut files = BTreeMap::<String, Vec<u8>>::new();
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

    let mut writes = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        let virtual_path = SandboxVirtualPath::try_new(&path)?;
        writes.push(SandboxProposalWrite::FileWrite(
            SandboxFileWriteProposal::new(virtual_path, bytes),
        ));
    }
    Ok(writes)
}

pub(super) fn walk_overlay_dir(
    dir: &Path,
    prefix: &str,
    depth: usize,
    mount: SandboxMount,
    files: &mut BTreeMap<String, Vec<u8>>,
    stack: &mut Vec<(PathBuf, String, usize)>,
    bounds: &mut OverlayWalkBounds,
) -> Result<()> {
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
            name
        } else {
            format!("{prefix}/{name}")
        };
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
        files.insert(format!("{}/{relative}", mount.root()), bytes);
    }
    Ok(())
}

pub(super) fn overlay_io_detail(class: &str, error: &std::io::Error) -> String {
    format!("overlay {class} io failed: {}", error.kind())
}

pub(super) fn overlay_error(detail: impl Into<String>) -> Error {
    Error::MicroVmOverlayError {
        detail: detail.into(),
    }
}
