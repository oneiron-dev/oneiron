//! [MICROVM-INTERMEDIATE-SYMLINK-NOTFOUND]: a base-mount read whose path
//! crosses a symlinked directory is refused in the overlay walker's refusal
//! class (`MicroVmOverlayError`, FIX 17063), not reported as a missing file.
//! On Linux an `O_DIRECTORY | O_NOFOLLOW` open of a symlink fails with
//! ENOTDIR, which the walk read as `EntityNotFound`.
//!
//! This integration target builds the library and this file only, so it runs
//! independently of unrelated library test targets.
#![cfg(all(unix, any(debug_assertions, feature = "microvm-dev")))]

use std::fs;
use std::path::Path;
use std::sync::Arc;

use oneiron::code_sandbox::microvm::{
    CredentialAllowlist, CredentialDestination, CredentialResolver, DevProcessBackend,
    MicroVmBackend, MicroVmSandboxAdapter,
};
use oneiron::code_sandbox::{
    SandboxBoundaryAdapter, SandboxCredentialHandle, SandboxGuestTier, SandboxMountTable,
    SandboxReadFile, SandboxVirtualPath,
};
use oneiron::{ErrorKind, Result};

/// A resolver no read reaches.
struct NoResolver;

impl CredentialResolver for NoResolver {
    fn resolve_for(
        &self,
        _handle: &SandboxCredentialHandle,
        _dest: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        panic!("a base-mount read resolves no credential")
    }
}

fn adapter(root: &Path) -> MicroVmSandboxAdapter {
    let backend: Box<dyn MicroVmBackend> = Box::new(DevProcessBackend::new(root.join("vm")));
    MicroVmSandboxAdapter::new(
        SandboxGuestTier::Foreign,
        SandboxMountTable::new(
            root.join("base/workspace"),
            root.join("base/uploads"),
            root.join("base/outputs"),
            root.join("base/skills"),
        ),
        backend,
        Arc::new(NoResolver),
        CredentialAllowlist::new(),
    )
    .expect("adapter")
}

fn read(adapter: &MicroVmSandboxAdapter, path: &str) -> Result<Vec<u8>> {
    let path = SandboxVirtualPath::try_new(path).expect("path");
    adapter
        .read_file(SandboxReadFile::new(path))
        .map(|read| read.bytes)
}

struct Fixture {
    _dir: tempfile::TempDir,
    adapter: MicroVmSandboxAdapter,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let base = dir.path().join("base/workspace");
    fs::create_dir_all(base.join("inner")).expect("base workspace");
    fs::write(base.join("inner/kept.txt"), b"base bytes").expect("stage base file");
    fs::write(base.join("plain.txt"), b"plain bytes").expect("stage plain file");
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).expect("outside dir");
    fs::write(outside.join("secret.txt"), b"outside-secret-bytes").expect("secret bytes");
    std::os::unix::fs::symlink(&outside, base.join("escape")).expect("symlink");
    let adapter = adapter(dir.path());
    Fixture { _dir: dir, adapter }
}

#[test]
fn read_through_a_symlinked_directory_is_an_overlay_refusal() {
    let fixture = fixture();
    let error = read(&fixture.adapter, "/mnt/workspace/escape/secret.txt")
        .expect_err("an intermediate symlink must not smuggle host bytes");
    assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
}

#[test]
fn read_through_a_plain_file_as_directory_is_still_not_found() {
    let fixture = fixture();
    let error = read(&fixture.adapter, "/mnt/workspace/plain.txt/secret.txt")
        .expect_err("a plain file has no entries");
    assert_eq!(error.kind(), ErrorKind::EntityNotFound);
}

#[test]
fn read_through_a_missing_directory_is_still_not_found() {
    let fixture = fixture();
    let error =
        read(&fixture.adapter, "/mnt/workspace/absent/secret.txt").expect_err("no such directory");
    assert_eq!(error.kind(), ErrorKind::EntityNotFound);
}

#[test]
fn read_through_a_real_directory_returns_the_base_bytes() {
    let fixture = fixture();
    let bytes = read(&fixture.adapter, "/mnt/workspace/inner/kept.txt").expect("plain read");
    assert_eq!(bytes, b"base bytes");
}
