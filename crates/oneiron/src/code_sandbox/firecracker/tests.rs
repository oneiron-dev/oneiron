use super::*;
use crate::code_sandbox::{SandboxGuestTier, SandboxMountTable};

#[test]
fn binary_only_firecracker_profile_cannot_authorize_execution() {
    let root = tempfile::tempdir().expect("test fixture");
    let backend = FirecrackerBackend::new("/missing/firecracker", root.path());
    let mounts = SandboxMountTable::new(root.path(), root.path(), root.path(), root.path());
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        assert_eq!(
            backend
                .prepare(&SandboxBoundaryContract::for_tier(tier), &mounts)
                .unwrap_err()
                .kind(),
            crate::error::ErrorKind::MicroVmBackendError
        );
    }
}

#[test]
fn guest_artifact_pin_refuses_substitution_and_missing_files() -> Result<()> {
    let dir = tempfile::tempdir().expect("test fixture");
    let image = GuestImage::new(
        dir.path().join("kernel"),
        dir.path().join("rootfs"),
        dir.path().join("component"),
    );
    for path in [&image.kernel, &image.rootfs, &image.component] {
        std::fs::write(path, b"pinned").expect("test fixture");
    }
    let digest = *blake3::hash(b"pinned").as_bytes();
    let pins = GuestArtifactPins {
        kernel: digest,
        rootfs: digest,
        component: digest,
    };
    pins.verify(&image)?;
    std::fs::write(&image.component, b"substituted").expect("test fixture");
    assert!(pins.verify(&image).is_err());
    std::fs::remove_file(&image.rootfs).expect("test fixture");
    assert!(pins.verify(&image).is_err());
    Ok(())
}

#[test]
fn configured_backend_refuses_root_guest_identity_or_missing_jailer() {
    let root = tempfile::tempdir().expect("test fixture");
    let mut config = FirecrackerHostConfig {
        firecracker: root.path().join("absent-firecracker"),
        jailer: root.path().join("absent-jailer"),
        scratch_root: root.path().join("scratch"),
        chroot_base: root.path().join("jails"),
        uid: 0,
        gid: 1000,
        vcpus: 1,
        cgroup_parent: "oneiron".to_owned(),
        pins: GuestArtifactPins {
            kernel: [0; 32],
            rootfs: [0; 32],
            component: [0; 32],
        },
    };
    assert!(FirecrackerBackend::configured(config.clone()).is_err());
    config.uid = 1000;
    assert!(FirecrackerBackend::configured(config).is_err());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires host-provisioned root jailer, KVM, cgroup v2, pinned kernel/rootfs/component and protocol-v1 guest agent"]
fn firecracker_real_boot_returns_only_proposals() -> Result<()> {
    use crate::code_sandbox::microvm::{CredentialAllowlist, MicroVmSandboxAdapter};
    use crate::code_sandbox::microvm::{CredentialDestination, CredentialReadTransport};
    use crate::code_sandbox::{
        SandboxCredentialHandle, SandboxCredentialOperation, SandboxProposalWrite,
    };
    struct HostCredential(std::sync::Mutex<Vec<String>>);
    impl CredentialResolver for HostCredential {
        fn resolve_for(
            &self,
            handle: &SandboxCredentialHandle,
            destination: &CredentialDestination,
        ) -> Result<Vec<u8>> {
            self.0
                .lock()
                .unwrap()
                .push(format!("{}:{}", handle.as_str(), destination));
            Ok(b"host-only-conformance-credential".to_vec())
        }
    }
    struct HostTransport(std::sync::Mutex<Vec<String>>);
    impl CredentialReadTransport for HostTransport {
        fn read(
            &self,
            destination: &CredentialDestination,
            _: &SandboxCredentialOperation,
            _: &rmpv::Value,
            credential: &[u8],
        ) -> Result<()> {
            assert_eq!(credential, b"host-only-conformance-credential");
            self.0.lock().unwrap().push(destination.to_string());
            Ok(())
        }
    }
    let resolver = Arc::new(HostCredential(std::sync::Mutex::new(Vec::new())));
    let transport = Arc::new(HostTransport(std::sync::Mutex::new(Vec::new())));
    let backend = FirecrackerBackend::detect()
        .expect("host profile must be available")
        .with_read_transport(transport.clone());
    let kernel = std::env::var_os("ONEIRON_MICROVM_TEST_KERNEL").expect("kernel");
    let rootfs = std::env::var_os("ONEIRON_MICROVM_TEST_ROOTFS").expect("rootfs");
    let component = std::env::var_os("ONEIRON_MICROVM_TEST_COMPONENT").expect("component");
    let dir = tempfile::tempdir().expect("test fixture");
    std::fs::write(dir.path().join("input.txt"), b"base").expect("test fixture");
    let mounts = SandboxMountTable::new(dir.path(), dir.path(), dir.path(), dir.path());
    let mut allowlist = CredentialAllowlist::new();
    allowlist.allow(
        &SandboxCredentialHandle::new("conformance-handle")?,
        CredentialDestination::new("https", "example.com")?,
    );
    let mut adapter = MicroVmSandboxAdapter::new(
        SandboxGuestTier::Foreign,
        mounts,
        Box::new(backend),
        resolver.clone(),
        allowlist,
    )?;
    let image = GuestImage::new(kernel, rootfs, component);
    assert_eq!(
        adapter
            .run(&image, ExecutionBudget::new(15, 128, 64))?
            .status,
        0
    );
    let proposals = adapter.collect_overlay_proposals()?;
    assert!(
        !proposals.is_empty(),
        "the configured conformance guest must propose a file"
    );
    assert_eq!(
        std::fs::read(dir.path().join("input.txt")).expect("test fixture"),
        b"base"
    );
    assert!(!dir.path().join("result.txt").exists());
    assert_eq!(
        *resolver.0.lock().unwrap(),
        vec!["conformance-handle:https://api.example.com"]
    );
    assert_eq!(
        *transport.0.lock().unwrap(),
        vec!["https://api.example.com"]
    );
    assert!(
        proposals
            .iter()
            .all(|p| matches!(p.write(), SandboxProposalWrite::FileEdit(_)))
    );
    assert!(adapter.collect_overlay_proposals().is_err());
    Ok(())
}

#[test]
fn guest_pid_budget_matches_protocol_ceiling_before_boot() {
    for pids in [1, 4096] {
        validate_guest_budget(&ExecutionBudget::new(15, 128, pids)).unwrap();
    }
    for pids in [0, 4097, 65_536] {
        assert_eq!(
            validate_guest_budget(&ExecutionBudget::new(15, 128, pids))
                .unwrap_err()
                .kind(),
            crate::error::ErrorKind::MicroVmBackendError
        );
    }
}
