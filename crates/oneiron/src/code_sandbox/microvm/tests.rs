use super::*;

use crate::ErrorKind;

fn destination(scheme: &str, host: &str) -> CredentialDestination {
    CredentialDestination::new(scheme, host).expect("destination")
}

fn test_mounts(root: &Path) -> SandboxMountTable {
    SandboxMountTable::new(
        root.join("base/workspace"),
        root.join("base/uploads"),
        root.join("base/outputs"),
        root.join("base/skills"),
    )
}

#[test]
fn code_sandbox_microvm_overlay_rejects_directory_count_breach() {
    let dir = tempfile::tempdir().expect("tempdir");
    for index in 0..=MAX_OVERLAY_DIRECTORIES {
        fs::create_dir(dir.path().join(format!("d{index}"))).expect("overlay directory");
    }

    let error = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
        .expect_err("a broad tree of empty directories must be bounded");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn code_sandbox_microvm_read_file_bounds_base_mount_bytes() {
    struct UnusedResolver;

    impl CredentialResolver for UnusedResolver {
        fn resolve_for(
            &self,
            _handle: &SandboxCredentialHandle,
            _dest: &CredentialDestination,
        ) -> Result<Vec<u8>> {
            Err(backend_error("test-resolver", "unused resolver"))
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path().join("base/workspace");
    fs::create_dir_all(&workspace).expect("base workspace");
    fs::write(workspace.join("small.bin"), b"small base file").expect("small base file");
    let oversized = workspace.join("oversized.bin");
    let file = fs::File::create(&oversized).expect("create sparse base file");
    file.set_len(64 * 1024 * 1024 + 1)
        .expect("size sparse base file");

    let backend: Box<dyn MicroVmBackend> = Box::new(DevProcessBackend::new(dir.path().join("vm")));
    let adapter = MicroVmSandboxAdapter::new(
        SandboxGuestTier::Foreign,
        test_mounts(dir.path()),
        backend,
        Arc::new(UnusedResolver),
        CredentialAllowlist::new(),
    )
    .expect("adapter");

    let small_path = SandboxVirtualPath::try_new("/mnt/workspace/small.bin").expect("path");
    let small = adapter
        .read_file(SandboxReadFile::new(small_path))
        .expect("file under the bound");
    assert_eq!(small.bytes, b"small base file");

    let oversized_path = SandboxVirtualPath::try_new("/mnt/workspace/oversized.bin").expect("path");
    let result = adapter.read_file(SandboxReadFile::new(oversized_path));
    assert!(
        result.is_err(),
        "a base-mount file above the byte bound must be refused"
    );
    let error = result.expect_err("oversized base-mount refusal");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
    assert!(error.to_string().contains("file byte bound"));
    assert!(error.to_string().contains("oversized.bin"));
}

#[cfg(unix)]
#[test]
fn code_sandbox_microvm_validate_refuses_synthetic_uid_mismatch() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("scratch");
    fs::create_dir(&root).expect("scratch root");
    let metadata = fs::symlink_metadata(&root).expect("scratch metadata");
    let actual_uid = metadata.uid();
    let expected_uid = actual_uid.checked_add(1).unwrap_or(0);
    assert_ne!(actual_uid, expected_uid);

    let error = validate_scratch_root_owner(&root, DEV_BACKEND_NAME, actual_uid, expected_uid)
        .expect_err("a synthetic owner mismatch must be refused");
    assert_eq!(error.kind(), ErrorKind::MicroVmBackendError);
}

#[cfg(unix)]
#[test]
fn code_sandbox_microvm_read_file_refuses_fifo_before_open() {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::FileTypeExt},
    };

    struct UnusedResolver;
    impl CredentialResolver for UnusedResolver {
        fn resolve_for(
            &self,
            _: &SandboxCredentialHandle,
            _: &CredentialDestination,
        ) -> Result<Vec<u8>> {
            Err(backend_error("test-resolver", "unused resolver"))
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let workspace = dir.path().join("base/workspace");
    fs::create_dir_all(&workspace).expect("base workspace");
    let fifo = workspace.join("guest-pipe");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
    // SAFETY: the path is a valid NUL-free CString and mode is valid.
    let result = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
    assert_eq!(result, 0, "mkfifo: {}", std::io::Error::last_os_error());
    assert!(
        fs::symlink_metadata(&fifo)
            .expect("fifo metadata")
            .file_type()
            .is_fifo()
    );

    let mounts = test_mounts(dir.path());
    let path = SandboxVirtualPath::try_new("/mnt/workspace/guest-pipe").expect("path");
    // Exercise the adapter's read path; the non-regular check must happen
    // before File::open, which would block on this FIFO.
    let backend: Box<dyn MicroVmBackend> = Box::new(DevProcessBackend::new(dir.path().join("vm")));
    let adapter = MicroVmSandboxAdapter::new(
        SandboxGuestTier::Foreign,
        mounts,
        backend,
        Arc::new(UnusedResolver),
        CredentialAllowlist::new(),
    )
    .expect("adapter");
    let error = adapter
        .read_file(SandboxReadFile::new(path))
        .expect_err("FIFO refusal");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn code_sandbox_microvm_overlay_rejects_oversized_single_file_before_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let oversized = dir.path().join("oversized.bin");
    let file = fs::File::create(&oversized).expect("create sparse file");
    file.set_len(MAX_OVERLAY_FILE_BYTES + 1)
        .expect("size sparse file");

    let error = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
        .expect_err("oversized overlay file must be rejected");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn code_sandbox_microvm_overlay_rejects_aggregate_byte_breach() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("next.bin"), b"x").expect("overlay file");
    let mut files = BTreeMap::new();
    let mut stack = Vec::new();
    let mut bounds = OverlayWalkBounds {
        total_bytes: MAX_OVERLAY_TOTAL_BYTES,
        file_count: 1,
        directory_count: 0,
    };

    let error = walk_overlay_dir(
        dir.path(),
        "",
        0,
        SandboxMount::Workspace,
        &mut files,
        &mut stack,
        &mut bounds,
    )
    .expect_err("aggregate byte bound must be enforced before reading");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
    assert!(error.to_string().contains("aggregate byte bound"));
    assert!(error.to_string().contains("next.bin"));
}

#[test]
fn code_sandbox_microvm_overlay_rejects_file_count_breach() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("next.bin"), b"x").expect("overlay file");
    let mut files = BTreeMap::new();
    let mut stack = Vec::new();
    let mut bounds = OverlayWalkBounds {
        total_bytes: 0,
        file_count: MAX_OVERLAY_FILES,
        directory_count: 0,
    };

    let error = walk_overlay_dir(
        dir.path(),
        "",
        0,
        SandboxMount::Workspace,
        &mut files,
        &mut stack,
        &mut bounds,
    )
    .expect_err("file count bound must be enforced before reading");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
    assert!(error.to_string().contains("file count bound"));
    assert!(error.to_string().contains("next.bin"));
}

#[test]
fn code_sandbox_microvm_overlay_rejects_over_depth_descent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut nested = dir.path().to_path_buf();
    for index in 0..=MAX_OVERLAY_DEPTH {
        nested.push(format!("d{index}"));
    }
    fs::create_dir_all(&nested).expect("deep overlay tree");

    let error = collect_overlay_writes(dir.path(), SandboxMount::Workspace)
        .expect_err("over-depth overlay tree must be rejected");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn code_sandbox_microvm_overlay_nested_directory_disappearance_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let nested = dir.path().join("nested");
    fs::create_dir(&nested).expect("nested dir");
    let mut files = BTreeMap::new();
    let mut stack = Vec::new();
    let mut bounds = OverlayWalkBounds::default();
    walk_overlay_dir(
        dir.path(),
        "",
        0,
        SandboxMount::Workspace,
        &mut files,
        &mut stack,
        &mut bounds,
    )
    .expect("discover nested dir");
    fs::remove_dir(&nested).expect("remove nested dir between walk steps");
    let (nested_path, prefix, depth) = stack.pop().expect("queued nested dir");

    let error = walk_overlay_dir(
        &nested_path,
        &prefix,
        depth,
        SandboxMount::Workspace,
        &mut files,
        &mut stack,
        &mut bounds,
    )
    .expect_err("vanished nested dir must fail closed");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn code_sandbox_microvm_prepare_creates_private_scratch_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("scratch");
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
    let handle =
        prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
            .expect("prepare overlay");
    assert!(handle.overlay_upper().is_dir());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::symlink_metadata(&root)
            .expect("scratch metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[cfg(unix)]
#[test]
fn code_sandbox_microvm_prepare_refuses_symlinked_scratch_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target");
    let root = dir.path().join("scratch");
    fs::create_dir(&target).expect("target dir");
    std::os::unix::fs::symlink(&target, &root).expect("scratch symlink");
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);

    let error =
        prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
            .expect_err("symlinked scratch root must be rejected");
    assert_eq!(error.kind(), ErrorKind::MicroVmBackendError);
}

#[test]
fn code_sandbox_microvm_destination_matching_respects_label_boundaries() {
    let allowed = destination("https", "example.com");
    assert!(allowed.matches(&destination("https", "example.com")));
    assert!(allowed.matches(&destination("https", "api.example.com")));
    assert!(allowed.matches(&destination("HTTPS", "API.Example.com.")));
    assert!(!allowed.matches(&destination("https", "notexample.com")));
    assert!(!allowed.matches(&destination("http", "example.com")));
    assert!(!allowed.matches(&destination("https", "example.com.evil.test")));

    assert!(CredentialDestination::new("", "example.com").is_err());
    assert!(CredentialDestination::new("https", "").is_err());
    assert!(CredentialDestination::new("https", "example.com/path").is_err());
    assert!(CredentialDestination::new("ht tps", "example.com").is_err());
}

#[test]
fn code_sandbox_microvm_allowlist_defaults_to_deny() {
    let bound = SandboxCredentialHandle::new("cred.bound").expect("handle");
    let unbound = SandboxCredentialHandle::new("cred.unbound").expect("handle");
    let mut allowlist = CredentialAllowlist::new();
    allowlist.allow(&bound, destination("https", "example.com"));

    assert!(allowlist.permits(&bound, &destination("https", "api.example.com")));
    assert!(!allowlist.permits(&bound, &destination("https", "evil.test")));
    assert!(!allowlist.permits(&unbound, &destination("https", "example.com")));
}

#[test]
fn code_sandbox_microvm_isolating_tiers_never_fall_through_silently() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        match select_backend_for_tier(tier) {
            Ok(selected) => {
                let backend = selected.expect("isolating tier requires a backend");
                assert_eq!(backend.name(), "firecracker");
            }
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::MicroVmBackendUnavailable);
            }
        }
    }

    // Assert the typed release fail-closed refusal independently of this build's cfg.
    let refusal = backend_unavailable(SandboxGuestTier::Foreign);
    assert_eq!(refusal.kind(), ErrorKind::MicroVmBackendUnavailable);
}

#[test]
fn code_sandbox_microvm_whiteouts_and_opaque_directories_are_typed() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir(dir.path().join("renamed")).expect("nested dir");
    fs::write(dir.path().join(".wh.old.txt"), []).expect("OCI whiteout");
    fs::write(dir.path().join("new.txt"), b"moved bytes").expect("rename destination");
    fs::write(dir.path().join("renamed/.wh..wh..opq"), []).expect("opaque marker");
    fs::write(dir.path().join("renamed/kept.txt"), b"new").expect("overlay file");
    let writes = collect_overlay_writes(dir.path(), SandboxMount::Workspace).expect("delta");
    assert_eq!(writes.len(), 4);
    assert!(writes.iter().any(|write| matches!(write,
        SandboxProposalWrite::FileDelete(delete) if delete.path.as_str() == "/mnt/workspace/old.txt")));
    assert!(writes.iter().any(|write| matches!(write,
        SandboxProposalWrite::DirectoryOpaque(opaque) if opaque.path.as_str() == "/mnt/workspace/renamed")));
    assert!(writes.iter().any(|write| matches!(write,
        SandboxProposalWrite::FileWrite(file) if file.path.as_str() == "/mnt/workspace/new.txt" && file.bytes == b"moved bytes")));
    assert!(!writes.iter().any(|write| matches!(write,
        SandboxProposalWrite::FileWrite(file) if file.path.as_str().contains(".wh."))));
}

#[test]
fn code_sandbox_microvm_malformed_whiteouts_fail_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("ordinary.txt"), b"valid").expect("valid write");
    fs::write(dir.path().join(".wh.old"), b"not a marker").expect("invalid marker");
    assert_eq!(
        collect_overlay_writes(dir.path(), SandboxMount::Workspace)
            .expect_err("invalid whiteout must abort entire delta")
            .kind(),
        ErrorKind::MicroVmOverlayError
    );
}

#[test]
fn code_sandbox_microvm_last_clone_releases_scratch_on_success_and_run_error() {
    struct UnusedResolver;
    impl CredentialResolver for UnusedResolver {
        fn resolve_for(
            &self,
            _: &SandboxCredentialHandle,
            _: &CredentialDestination,
        ) -> Result<Vec<u8>> {
            unreachable!("no credential read")
        }
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    for success in [true, false] {
        let backend: Box<dyn MicroVmBackend> = Box::new(DevProcessBackend::new(&scratch));
        let mut adapter = MicroVmSandboxAdapter::new(
            SandboxGuestTier::Foreign,
            test_mounts(dir.path()),
            backend,
            Arc::new(UnusedResolver),
            CredentialAllowlist::new(),
        )
        .expect("adapter");
        let clone = adapter.vm().clone();
        let vm_root = clone
            .overlay_upper()
            .parent()
            .expect("VM directory")
            .to_path_buf();
        let image = GuestImage::new(
            dir.path().join("kernel"),
            dir.path().join("rootfs"),
            dir.path().join("component"),
        );
        if success {
            for path in [&image.kernel, &image.rootfs, &image.component] {
                fs::write(path, b"image").expect("artifact");
            }
            fs::write(clone.overlay_upper().join("output"), b"proposal").expect("staged write");
            assert_eq!(
                adapter
                    .run(&image, ExecutionBudget::new(5, 128, 32))
                    .expect("run")
                    .status,
                0
            );
            assert_eq!(
                adapter.collect_overlay_proposals().expect("collect").len(),
                1
            );
        } else {
            assert_eq!(
                adapter
                    .run(&image, ExecutionBudget::new(0, 128, 32))
                    .expect_err("unbounded run refused")
                    .kind(),
                ErrorKind::MicroVmBackendError
            );
        }
        drop(adapter);
        assert!(vm_root.exists(), "a cloned handle still owns scratch");
        drop(clone);
        assert!(!vm_root.exists(), "the last handle must clean scratch");
    }
}

#[cfg(unix)]
#[test]
fn code_sandbox_microvm_reaper_skips_live_and_removes_crashed_vm_scratch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let scratch = dir.path().join("scratch");
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
    let handle = prepare_overlay_handle(
        &scratch,
        DEV_BACKEND_NAME,
        &contract,
        &test_mounts(dir.path()),
    )
    .expect("first VM");
    let live = handle
        .overlay_upper()
        .parent()
        .expect("VM root")
        .to_path_buf();
    let stale = scratch.join("1234567890abcdef1234567890abcdef");
    fs::create_dir(&stale).expect("crashed VM fixture");
    fs::write(stale.join("old"), b"stale bytes").expect("crashed VM output");
    let unrelated = scratch.join("keep-me");
    fs::create_dir(&unrelated).expect("other data");
    let second = prepare_overlay_handle(
        &scratch,
        DEV_BACKEND_NAME,
        &contract,
        &test_mounts(dir.path()),
    )
    .expect("reap and prepare");
    assert!(!stale.exists(), "orphan is reaped during next prepare");
    assert!(live.exists(), "live VM must not be reaped");
    assert!(
        unrelated.exists(),
        "unrelated directory must not be deleted"
    );
    drop(handle);
    drop(second);
    assert!(!live.exists());
}

#[test]
fn code_sandbox_microvm_opaque_marker_preserves_real_dot_opaque_file_in_both_orders() {
    for marker_first in [false, true] {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        let file = || fs::write(nested.join(".opaque"), b"actual edit").expect("file");
        let marker = || fs::write(nested.join(".wh..wh..opq"), []).expect("marker");
        if marker_first {
            marker();
            file();
        } else {
            file();
            marker();
        }
        let deltas = collect_overlay_writes(dir.path(), SandboxMount::Workspace).expect("delta");
        assert_eq!(deltas.len(), 2);
        assert!(deltas.iter().any(|entry| matches!(entry,
            SandboxProposalWrite::FileWrite(write) if write.path.as_str() == "/mnt/workspace/nested/.opaque" && write.bytes == b"actual edit")));
        assert!(deltas.iter().any(|entry| matches!(entry,
            SandboxProposalWrite::DirectoryOpaque(dir) if dir.path.as_str() == "/mnt/workspace/nested")));
    }
}

#[cfg(unix)]
#[test]
fn code_sandbox_microvm_concurrent_last_drop_prepare_and_startup_reap() {
    use std::sync::{Arc, Barrier};
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("scratch");
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::Foreign);
    for _ in 0..32 {
        let handle =
            prepare_overlay_handle(&root, DEV_BACKEND_NAME, &contract, &test_mounts(dir.path()))
                .expect("live VM");
        let old_root = handle
            .overlay_upper()
            .parent()
            .expect("VM root")
            .to_path_buf();
        let barrier = Arc::new(Barrier::new(3));
        std::thread::scope(|scope| {
            let drop_barrier = barrier.clone();
            scope.spawn(move || {
                drop_barrier.wait();
                drop(handle);
            });
            let reap_barrier = barrier.clone();
            let root_ref = &root;
            scope.spawn(move || {
                reap_barrier.wait();
                reap_overlay_scratch(root_ref, DEV_BACKEND_NAME)
                    .expect("concurrent startup reaper");
            });
            barrier.wait();
            let new_vm = prepare_overlay_handle(
                &root,
                DEV_BACKEND_NAME,
                &contract,
                &test_mounts(dir.path()),
            )
            .expect("concurrent prepare");
            assert!(new_vm.overlay_upper().is_dir());
        });
        assert!(!old_root.exists());
    }
}
