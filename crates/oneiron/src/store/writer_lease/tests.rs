//! Focused process-owner lease and bootstrap regressions.

#[cfg(unix)]
use super::*;
use crate::{Vault, VaultConfig};

#[cfg(unix)]
#[test]
fn forked_child_drop_does_not_unlock_parent_lease() {
    let dir = tempfile::tempdir().expect("tempdir");
    let lease = VaultWriterLease::acquire(dir.path()).expect("parent lease");
    // SAFETY: the child only closes its duplicated File descriptors and exits
    // with _exit. It never accesses Rust locks, LMDB, or parent-owned threads.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        drop(lease);
        // SAFETY: no inherited process cleanup may run after the close probe.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    // SAFETY: pid is our live child and status points to a writable c_int.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert!(matches!(
        VaultWriterLease::acquire(dir.path()),
        Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD))
    ));
    drop(lease);
    VaultWriterLease::acquire(dir.path()).expect("last owner drop releases lease");
}

#[cfg(unix)]
#[test]
fn owned_vault_keeps_lease_until_last_arc_and_releases_failed_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = std::sync::Arc::new(
        Vault::open_owned(dir.path(), VaultConfig::default()).expect("open owner"),
    );
    let held = std::sync::Arc::clone(&vault);
    drop(vault);
    assert!(matches!(
        VaultWriterLease::acquire(dir.path()),
        Err(Error::ConcurrentWrite(VAULT_WRITER_LEASE_HELD))
    ));
    drop(held);
    let bad = VaultConfig {
        dimensions: 17,
        ..VaultConfig::default()
    };
    assert!(Vault::open_owned(dir.path(), bad).is_err());
    Vault::open_owned(dir.path(), VaultConfig::default()).expect("failed open released lease");
}

/// A forked child that only waits to be killed. It holds a copy of every
/// descriptor this process had open at the fork, exactly as a sibling test's
/// `Command` spawn does between its fork and exec, but for as long as the
/// test needs. Killed and reaped on drop, panics included.
#[cfg(unix)]
struct ParkedChild(libc::pid_t);

#[cfg(unix)]
impl ParkedChild {
    fn fork() -> Self {
        // SAFETY: the child calls only the async-signal-safe `pause` until the
        // parent kills it. It never allocates, locks, or touches LMDB.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            loop {
                // SAFETY: `pause` takes no arguments and touches no memory.
                unsafe { libc::pause() };
            }
        }
        Self(pid)
    }
}

#[cfg(unix)]
impl Drop for ParkedChild {
    fn drop(&mut self) {
        let mut status = 0;
        // SAFETY: `self.0` is our own unreaped child and `status` points to a
        // writable c_int.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            libc::waitpid(self.0, &mut status, 0);
        }
    }
}

#[cfg(unix)]
#[test]
fn owner_drop_releases_lease_a_forked_child_still_holds_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("open owner");
    let child = ParkedChild::fork();
    drop(vault);
    VaultWriterLease::acquire(dir.path()).expect("owner drop released lease");
    drop(child);
}

#[cfg(unix)]
#[test]
fn failed_open_releases_lease_a_forked_child_still_holds_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    drop(Vault::open_owned(dir.path(), VaultConfig::default()).expect("create vault"));
    let canonical = dir.path().canonicalize().expect("canonical root");
    let (forked, child) = std::sync::mpsc::channel();
    // Fires after the failing open took its lease and opened LMDB, before the
    // HNSW shape gate refuses the bad dimensions.
    crate::store::test_hooks::arm_after_lmdb_open(canonical, move |_| {
        forked
            .send(ParkedChild::fork())
            .expect("hand the child to the test");
    });
    let bad = VaultConfig {
        dimensions: 17,
        ..VaultConfig::default()
    };
    assert!(Vault::open_owned(dir.path(), bad).is_err());
    let child = child
        .try_recv()
        .expect("child forked inside the failed open");
    Vault::open_owned(dir.path(), VaultConfig::default()).expect("failed open released lease");
    drop(child);
}

#[cfg(target_os = "linux")]
#[test]
fn owned_open_binds_lmdb_and_cleanup_to_leased_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("vault");
    std::fs::create_dir(&path).expect("create root");
    let canonical = path.canonicalize().expect("canonical root");
    let moved = dir.path().join("moved");
    let moved_in_hook = moved.clone();
    crate::store::test_hooks::arm_before_lmdb_open(canonical, move |root| {
        std::fs::rename(root, &moved_in_hook).expect("rename leased directory");
        std::fs::create_dir(root).expect("replace directory");
        std::fs::write(root.join("sentinel"), b"replacement").expect("replacement marker");
    });
    assert!(Vault::open_owned(&path, VaultConfig::default()).is_err());
    assert_eq!(
        std::fs::read(path.join("sentinel")).expect("marker"),
        b"replacement"
    );
    for root in [&path, &moved] {
        assert!(!root.join("data.mdb").exists());
        assert!(!root.join("lock.mdb").exists());
    }
}

#[test]
fn embedded_owner_bootstrap_refuses_permanent_hard_delete_after_reopen() {
    for reason in [
        crate::DeleteReason::UserHardDelete,
        crate::DeleteReason::GdprDelete,
        crate::DeleteReason::PolicyDelete,
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        let owner = vault.ensure_embedded_owner_actor().expect("bootstrap");
        assert_eq!(
            vault.ensure_embedded_owner_actor().expect("idempotent"),
            owner
        );
        vault
            .delete_entity_with_reason(&owner, reason)
            .expect("erase owner");
        assert!(vault.get_raw(&owner).expect("read owner").is_none());
        drop(vault);
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("reopen vault");
        let before = vault.store.env.read_txn().expect("marker snapshot");
        assert!(
            vault
                .local_hard_delete_marker_exists_in_txn(&before, &owner)
                .expect("marker")
        );
        drop(before);
        let error = vault
            .ensure_embedded_owner_actor()
            .expect_err("erased owner stays erased");
        assert_eq!(error.code, crate::memory::MEMORY_CODE_FORBIDDEN);
        assert!(vault.get_raw(&owner).expect("read owner").is_none());
    }
}
