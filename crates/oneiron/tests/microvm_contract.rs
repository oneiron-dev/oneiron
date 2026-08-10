//! CODE-01 (ONE-1429): backend-agnostic contract suite for the microVM lane.
//!
//! What is proven here:
//!
//! * first-party code takes no microVM and foreign/untrusted code either gets
//!   an isolating backend or fails closed — never a silent no-sandbox run;
//! * guest writes leave the sandbox only as proposal deltas, with the base
//!   mount byte-identical (hash-compared) after the run;
//! * the credential proxy resolves at the network boundary against a recording
//!   test resolver, refuses off-allowlist destinations *before* resolution, and
//!   keeps secret material out of every guest-visible surface;
//! * the boundary semantics are backend-independent: the same op sequence over
//!   `FakeSandboxAdapter` and the dev microVM adapter yields the same shape.

use oneiron::{
    ErrorKind, SandboxBoundaryContract, SandboxGuestTier,
    code_sandbox::microvm::{dev_backend_compiled, firecracker_backend_compiled},
    select_backend_for_tier,
};

#[test]
fn microvm_contract_first_party_tier_takes_no_microvm() {
    let selected = select_backend_for_tier(SandboxGuestTier::FirstPartyDreamer)
        .expect("first-party selection succeeds");
    assert!(
        selected.is_none(),
        "first-party code stays in-process: no microVM backend is selected"
    );

    // `for_tier` is a pure contract value and is unaffected by routing.
    let contract = SandboxBoundaryContract::for_tier(SandboxGuestTier::FirstPartyDreamer);
    assert!(contract.links_write_imports());
    assert!(!contract.has_proposal_delta_channel());
}

#[test]
fn microvm_contract_isolating_tiers_route_or_fail_closed() {
    for tier in [SandboxGuestTier::Foreign, SandboxGuestTier::Untrusted] {
        match select_backend_for_tier(tier) {
            Ok(selected) => {
                let backend = selected.expect("an isolating tier never routes to `None`");
                assert!(
                    dev_backend_compiled() || firecracker_backend_compiled(),
                    "a backend was handed out with none compiled into this build"
                );
                assert!(!backend.name().is_empty(), "backends carry a stable label");
            }
            Err(error) => {
                assert!(
                    !dev_backend_compiled() && !firecracker_backend_compiled(),
                    "routing refused while a backend was compiled in"
                );
                assert_eq!(error.kind(), ErrorKind::MicroVmBackendUnavailable);
            }
        }

        // Whichever leg this build takes, the propose-only contract is the one
        // the microVM lane is constructed against.
        let contract = SandboxBoundaryContract::for_tier(tier);
        assert!(contract.has_proposal_delta_channel());
        assert!(!contract.links_write_imports());
    }
}

#[cfg(any(debug_assertions, feature = "microvm-dev"))]
mod dev_backend {
    use std::{
        collections::{BTreeMap, hash_map::DefaultHasher},
        fs,
        hash::{Hash, Hasher},
        path::Path,
        sync::{Arc, Mutex},
    };

    use oneiron::{
        ErrorKind, FakeSandboxAdapter, Result, SandboxBoundaryAdapter, SandboxCredentialCall,
        SandboxCredentialHandle, SandboxGuestTier, SandboxMountTable, SandboxProposalKind,
        SandboxProposalWrite, SandboxReadFile, SandboxVirtualPath,
        code_sandbox::microvm::{
            CredentialAllowlist, CredentialDestination, CredentialResolver, DevProcessBackend,
            ExecutionBudget, GuestImage, MicroVmBackend, MicroVmSandboxAdapter,
            SANDBOX_EGRESS_ABI_KEY_HOST, SANDBOX_EGRESS_ABI_KEY_SCHEME, select_backend_for_tier,
        },
    };
    use rmpv::Value;

    const SECRET: &[u8] = b"test-resolver-secret-material-8f2a";
    const HANDLE: &str = "cred.upstream.read";

    /// Test double standing in for the credential door: it records every
    /// resolution with the handle and destination it was asked for.
    struct RecordingResolver {
        calls: Mutex<Vec<(String, String)>>,
    }

    impl RecordingResolver {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, String)> {
            self.calls.lock().expect("resolver log").clone()
        }
    }

    impl CredentialResolver for RecordingResolver {
        fn resolve_for(
            &self,
            handle: &SandboxCredentialHandle,
            dest: &CredentialDestination,
        ) -> Result<Vec<u8>> {
            self.calls
                .lock()
                .expect("resolver log")
                .push((handle.as_str().to_owned(), dest.to_string()));
            Ok(SECRET.to_vec())
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        adapter: MicroVmSandboxAdapter,
        resolver: Arc<RecordingResolver>,
        base: std::path::PathBuf,
    }

    fn handle() -> SandboxCredentialHandle {
        SandboxCredentialHandle::new(HANDLE).expect("handle")
    }

    fn destination_args(scheme: &str, host: &str) -> Value {
        Value::Map(vec![
            (
                Value::from(SANDBOX_EGRESS_ABI_KEY_SCHEME),
                Value::from(scheme),
            ),
            (Value::from(SANDBOX_EGRESS_ABI_KEY_HOST), Value::from(host)),
        ])
    }

    fn mount_table(root: &Path) -> SandboxMountTable {
        SandboxMountTable::new(
            root.join("base/workspace"),
            root.join("base/uploads"),
            root.join("base/outputs"),
            root.join("base/skills"),
        )
    }

    fn fixture(tier: SandboxGuestTier) -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("base/workspace");
        fs::create_dir_all(&base).expect("base workspace");
        fs::write(base.join("input.txt"), b"base bytes").expect("stage base file");

        let resolver = Arc::new(RecordingResolver::new());
        let mut allowlist = CredentialAllowlist::new();
        allowlist.allow(
            &handle(),
            CredentialDestination::new("https", "example.test").expect("destination"),
        );

        let backend: Box<dyn MicroVmBackend> =
            Box::new(DevProcessBackend::new(dir.path().join("vm")));
        let adapter = MicroVmSandboxAdapter::new(
            tier,
            mount_table(dir.path()),
            backend,
            resolver.clone(),
            allowlist,
        )
        .expect("adapter");

        Fixture {
            _dir: dir,
            adapter,
            resolver,
            base,
        }
    }

    fn guest_image(root: &Path) -> GuestImage {
        let image_dir = root.join("image");
        fs::create_dir_all(&image_dir).expect("image dir");
        for artifact in ["kernel", "rootfs", "component"] {
            fs::write(image_dir.join(artifact), artifact.as_bytes()).expect("image artifact");
        }
        GuestImage::new(
            image_dir.join("kernel"),
            image_dir.join("rootfs"),
            image_dir.join("component"),
        )
    }

    /// Content hash of a directory tree: path + bytes, in sorted order.
    fn tree_hash(root: &Path) -> u64 {
        let mut files = BTreeMap::<String, Vec<u8>>::new();
        collect_tree(root, "", &mut files);
        let mut hasher = DefaultHasher::new();
        files.hash(&mut hasher);
        hasher.finish()
    }

    fn collect_tree(dir: &Path, prefix: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("dir entry");
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.path().is_dir() {
                collect_tree(&entry.path(), &relative, out);
            } else {
                out.insert(relative, fs::read(entry.path()).expect("read tree file"));
            }
        }
    }

    #[test]
    fn microvm_contract_foreign_tier_routes_to_a_named_backend() {
        let backend = select_backend_for_tier(SandboxGuestTier::Foreign)
            .expect("routing")
            .expect("foreign code requires an isolating backend");
        assert_eq!(
            backend.name(),
            "dev-process-isolation",
            "under a dev build the reference backend is the local proof path"
        );
    }

    #[test]
    fn microvm_contract_overlay_writes_become_proposals_with_base_unchanged() {
        let mut fixture = fixture(SandboxGuestTier::Foreign);
        let image = guest_image(fixture.base.parent().expect("base parent"));
        let before = tree_hash(&fixture.base);

        // Everything a guest "writes" lands in the overlay upper. The base is
        // never opened for writing by the lane.
        let upper = fixture.adapter.vm().overlay_upper().to_path_buf();
        fs::create_dir_all(upper.join("notes")).expect("overlay subdir");
        fs::write(upper.join("result.txt"), b"guest output").expect("overlay write");
        fs::write(upper.join("notes/deep.txt"), b"nested output").expect("overlay write");

        let exit = fixture
            .adapter
            .run(&image, ExecutionBudget::new(5, 128, 32))
            .expect("run");
        assert_eq!(exit.status, 0);
        assert!(exit.overlay_dirty, "the guest touched the overlay");

        let deltas = fixture
            .adapter
            .collect_overlay_proposals()
            .expect("overlay proposals");
        let mut proposed = deltas
            .iter()
            .map(|delta| {
                assert_eq!(delta.tier(), SandboxGuestTier::Foreign);
                assert_eq!(delta.kind(), SandboxProposalKind::FileWrite);
                match delta.write() {
                    SandboxProposalWrite::FileWrite(write) => {
                        (write.path.as_str().to_owned(), write.bytes.clone())
                    }
                    SandboxProposalWrite::ClaimCandidate(_) => unreachable!("file writes only"),
                }
            })
            .collect::<Vec<_>>();
        proposed.sort();

        assert_eq!(
            proposed,
            vec![
                (
                    "/mnt/workspace/notes/deep.txt".to_owned(),
                    b"nested output".to_vec()
                ),
                (
                    "/mnt/workspace/result.txt".to_owned(),
                    b"guest output".to_vec()
                ),
            ]
        );
        assert_eq!(
            tree_hash(&fixture.base),
            before,
            "the base mount must be byte-identical after a guest run"
        );
        assert_eq!(fixture.adapter.proposal_deltas().len(), 2);
    }

    #[test]
    fn microvm_contract_credential_proxy_resolves_at_the_boundary() {
        let mut fixture = fixture(SandboxGuestTier::Foreign);
        let call = SandboxCredentialCall::read_only(
            "http.get",
            handle(),
            destination_args("https", "api.example.test"),
        )
        .expect("credential call");

        let outcome = fixture.adapter.call_credential(call).expect("injection");
        assert_eq!(outcome.credential().as_str(), HANDLE);
        assert_eq!(outcome.operation().as_str(), "http.get");
        assert_eq!(
            fixture.resolver.calls(),
            vec![(HANDLE.to_owned(), "https://api.example.test".to_owned())],
            "the resolver is consulted with the handle and its destination"
        );

        let injections = fixture.adapter.credential_injections();
        assert_eq!(injections.len(), 1);
        assert_eq!(injections[0].injected_bytes(), SECRET.len());

        // No guest-visible surface carries the material: the outcome is
        // handle-only, and neither the receipt nor the adapter retains bytes.
        let secret = String::from_utf8(SECRET.to_vec()).expect("utf8 secret");
        for surface in [
            format!("{outcome:?}"),
            format!("{:?}", injections[0]),
            format!("{:?}", fixture.adapter),
        ] {
            assert!(
                !surface.contains(&secret),
                "credential material leaked into a host/guest surface: {surface}"
            );
        }
    }

    #[test]
    fn microvm_contract_off_allowlist_destination_is_refused_before_resolution() {
        let mut fixture = fixture(SandboxGuestTier::Foreign);
        for (scheme, host) in [
            ("https", "evil.test"),
            ("https", "notexample.test"),
            ("http", "api.example.test"),
        ] {
            let call = SandboxCredentialCall::read_only(
                "http.get",
                handle(),
                destination_args(scheme, host),
            )
            .expect("credential call");
            let error = fixture
                .adapter
                .call_credential(call)
                .expect_err("off-allowlist destination must be refused");
            assert_eq!(error.kind(), ErrorKind::MicroVmCredentialDestinationDenied);
        }

        assert!(
            fixture.resolver.calls().is_empty(),
            "the confused-deputy guard runs BEFORE the credential is resolved"
        );
        assert!(fixture.adapter.credential_injections().is_empty());

        // An unaddressed credential call is refused too — never resolved.
        let unaddressed =
            SandboxCredentialCall::read_only("http.get", handle(), Value::Map(Vec::new()))
                .expect("credential call");
        assert!(fixture.adapter.call_credential(unaddressed).is_err());
        assert!(fixture.resolver.calls().is_empty());
    }

    #[test]
    fn microvm_contract_run_refuses_unbounded_budget_and_incomplete_image() {
        let mut fixture = fixture(SandboxGuestTier::Untrusted);
        let image = guest_image(fixture.base.parent().expect("base parent"));

        let unbounded = fixture
            .adapter
            .run(&image, ExecutionBudget::new(0, 128, 32))
            .expect_err("an unbounded budget is refused");
        assert_eq!(unbounded.kind(), ErrorKind::MicroVmBackendError);

        let missing = GuestImage::new("/nonexistent/kernel", "/nonexistent/rootfs", "/none/comp");
        let incomplete = fixture
            .adapter
            .run(&missing, ExecutionBudget::new(5, 128, 32))
            .expect_err("an incomplete image is refused");
        assert_eq!(incomplete.kind(), ErrorKind::MicroVmBackendError);
    }

    #[test]
    fn microvm_contract_overlay_refuses_symlinked_entries() {
        let mut fixture = fixture(SandboxGuestTier::Foreign);
        let upper = fixture.adapter.vm().overlay_upper().to_path_buf();
        let target = fixture.base.join("input.txt");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, upper.join("escape.txt")).expect("symlink");
        #[cfg(not(unix))]
        {
            let _ = target;
            return;
        }

        let error = fixture
            .adapter
            .collect_overlay_proposals()
            .expect_err("a symlinked overlay entry would smuggle host bytes");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
        assert!(fixture.adapter.proposal_deltas().is_empty());
    }

    #[test]
    fn microvm_contract_read_file_refuses_intermediate_symlink_escape() {
        let fixture = fixture(SandboxGuestTier::Foreign);
        let outside = fixture._dir.path().join("outside");
        fs::create_dir_all(&outside).expect("outside dir");
        fs::write(outside.join("secret.txt"), b"outside-secret-bytes").expect("secret bytes");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, fixture.base.join("escape")).expect("symlink");
        #[cfg(not(unix))]
        {
            return;
        }

        // The escape symlink is an *intermediate* directory component: the OS
        // path resolver would follow it out of the workspace mount root, so
        // the read must be refused in the overlay walker’s refusal class
        // rather than surface as EntityNotFound or Ok(host bytes).
        let path = SandboxVirtualPath::try_new("/mnt/workspace/escape/secret.txt").expect("path");
        let error = fixture
            .adapter
            .read_file(SandboxReadFile::new(path))
            .expect_err("an intermediate symlink must not smuggle host bytes");
        assert_eq!(error.kind(), ErrorKind::MicroVmOverlayError);
    }

    /// One op sequence run against any boundary adapter. The summary is what
    /// the contract promises, independent of which backend is underneath.
    fn exercise_boundary(
        adapter: &mut dyn SandboxBoundaryAdapter,
        staged: &SandboxVirtualPath,
    ) -> Vec<String> {
        let mut summary = Vec::new();

        let read = adapter
            .read_file(SandboxReadFile::new(staged.clone()))
            .expect("staged read");
        summary.push(format!(
            "read:{}:{}",
            read.path.as_str(),
            String::from_utf8_lossy(&read.bytes)
        ));

        let missing = SandboxVirtualPath::try_new("/mnt/workspace/absent.txt").expect("path");
        let error = adapter
            .read_file(SandboxReadFile::new(missing))
            .expect_err("missing file");
        summary.push(format!("read_missing:{:?}", error.kind()));

        let call = SandboxCredentialCall::read_only(
            "http.get",
            handle(),
            destination_args("https", "api.example.test"),
        )
        .expect("credential call");
        let outcome = adapter.call_credential(call).expect("credential outcome");
        summary.push(format!(
            "credential:{}:{}:{}",
            outcome.operation().as_str(),
            outcome.operation().effect().as_str(),
            outcome.credential().as_str()
        ));

        let write = SandboxVirtualPath::try_new("/mnt/workspace/proposed.txt").expect("path");
        let delta = adapter
            .propose_write(SandboxProposalWrite::FileWrite(
                oneiron::SandboxFileWriteProposal::new(write, b"proposed".to_vec()),
            ))
            .expect("proposal");
        summary.push(format!(
            "proposal:{}:{}:{:?}",
            delta.kind().as_str(),
            delta.tier().as_str(),
            delta.approval()
        ));

        summary
    }

    #[test]
    fn microvm_contract_boundary_parity_with_fake_adapter() {
        let staged = SandboxVirtualPath::try_new("/mnt/workspace/input.txt").expect("path");

        let mut fixture = fixture(SandboxGuestTier::Foreign);
        let microvm_summary = exercise_boundary(&mut fixture.adapter, &staged);

        let dir = tempfile::tempdir().expect("tempdir");
        let mut fake = FakeSandboxAdapter::new(SandboxGuestTier::Foreign, mount_table(dir.path()));
        fake.stage_file(staged.clone(), b"base bytes".to_vec());
        let fake_summary = exercise_boundary(&mut fake, &staged);

        assert_eq!(
            microvm_summary, fake_summary,
            "boundary semantics must not depend on the backend underneath"
        );
    }
}
