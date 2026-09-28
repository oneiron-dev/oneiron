//! Stock Git checkout-to-door round trip with a live epoch-fenced lease.
use super::tests::{PublicationTestOrigin, git, served_repo};
use super::*;
use crate::checkout::lease::*;

struct Facts;
impl CheckoutFactSink for Facts {
    fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
        Ok(())
    }
}
#[derive(Default)]
struct Liveness(Option<CheckoutLivenessPulse>);
impl CheckoutLiveness for Liveness {
    fn publish(&mut self, pulse: CheckoutLivenessPulse) -> CheckoutResult<()> {
        self.0 = Some(pulse);
        Ok(())
    }
    fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(self.0.clone())
    }
    fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
        self.0 = None;
        Ok(())
    }
}

#[test]
fn real_checkout_remote_push_redeems_a_lease_and_never_copies_upstream_secret() {
    // A caller-supplied wall second can lead the vault's monotone authority
    // observation by one second at a second boundary. Share a test-local clock
    // between the claim and the real credential door instead of racing it.
    let now = crate::unix_seconds_now();
    let clock = crate::store::ports::ManualClock::new(now);
    let config = crate::VaultConfig {
        store_clock: clock.bundle(),
        ..Default::default()
    };
    let _dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(_dir.path(), config).unwrap());
    let (_source, repo_dir, _, head) = served_repo(&vault);
    // A source with remote config is not eligible: a linked worktree would
    // inherit it. The fixture source is copied as a bare repo, so remove the
    // clone's local-origin URL before it enters door custody.
    git(&repo_dir, &["remote", "remove", "origin"]);
    let principal = EntityId::now();
    let origin = PublicationTestOrigin::start(&vault, principal);
    let mut leases = CheckoutLeaseService::new(&vault, Facts, Liveness::default());
    let grant = leases
        .claim(CheckoutClaimRequest {
            checkout_id: CheckoutId::from_bytes(*EntityId::now().as_bytes()).unwrap(),
            task_ref: EntityId::now(),
            repo_ref: RepoRef::LocalFolder {
                path: repo_dir.to_string_lossy().into_owned(),
                commit: head.as_str().to_owned(),
            },
            holder_ref: principal.to_hex(),
            task_class: CheckoutTaskClass::Build,
            // This tests the live push and stale epoch, not lease expiry. Allow
            // a full busy CI run before reclaiming at the actual expiry below.
            ttl_secs: Some(24 * 60 * 60),
            now,
        })
        .unwrap();
    let lease = leases.get(grant.checkout_id).unwrap().unwrap();
    let secret = b"test-upstream-credential-kept-in-vault";
    vault
        .register_secret(crate::secret_custody::SecretCustodyRecord {
            schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
            name: "checkout.upstream".into(),
            class: crate::secret_custody::CustodyClass::CustodyPortable,
            device_only: false,
            value_bytes: secret.to_vec(),
            status: crate::secret_custody::SecretCustodyStatus::Active,
            registered_at: now,
            rotated_at: None,
            rotation_generation: 0,
            bindings: vec![crate::secret_custody::SecretBinding {
                effector: "door:receive-pack".into(),
                tier_ceiling: crate::secret_custody::CustodyTier::T0Doored,
                scopes: vec!["push".into()],
            }],
            manifest_ref: "secrets.toml".into(),
            declared_paths: vec![],
            policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
        })
        .unwrap();
    let wire = GitWire::new(&vault)
        .unwrap()
        .with_checkout_door(&origin.door_base_url())
        .unwrap();
    wire.materialize(&lease).unwrap();
    let tree = wire.checkout_worktree_path(&lease).unwrap();
    let expected = format!(
        "{}/lease/{}.{}/demo.git",
        origin.door_base_url(),
        grant.checkout_id,
        grant.epoch
    );
    assert_eq!(git(&tree, &["remote", "get-url", "origin"]), expected);
    assert_eq!(
        git(&tree, &["remote", "get-url", "--push", "origin"]),
        expected
    );
    // The complete worktree config and every workspace file contain no value.
    assert!(
        !git(&tree, &["config", "--show-origin", "--list"])
            .contains(std::str::from_utf8(secret).unwrap())
    );
    for entry in std::fs::read_dir(&tree).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            assert!(
                !std::fs::read(entry.path())
                    .unwrap()
                    .windows(secret.len())
                    .any(|part| part == secret)
            );
        }
    }
    std::fs::write(tree.join("FROM_CHECKOUT.md"), "lease scoped push\n").unwrap();
    git(&tree, &["add", "--", "FROM_CHECKOUT.md"]);
    git(
        &tree,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "checkout change",
        ],
    );
    let pushed = git(&tree, &["rev-parse", "HEAD"]);
    git(&tree, &["push", "origin", "HEAD:refs/heads/checkout"]);
    assert_eq!(
        git(&repo_dir, &["rev-parse", "refs/heads/checkout"]),
        pushed
    );
    let rows = vault.origin_publication_rows(None).unwrap();
    assert!(rows.iter().any(|row| row.actor_id == principal));
    let ticket = format!("{}.{}", grant.checkout_id, grant.epoch);
    let door = CredentialDoorService::new(Arc::clone(&vault));
    assert!(
        door.checkout_credential(&ticket, "unregistered:actor", &lease.repo_ref)
            .is_err()
    );
    // Epoch fencing remains authoritative after reclaim; the old URL grants
    // nothing even if its printable ticket has been copied.
    leases
        .reclaim_idempotent(
            grant.checkout_id,
            "replacement:holder".into(),
            lease.lease_expires_at.unwrap() + 1,
        )
        .unwrap();
    assert!(
        door.checkout_credential(&ticket, &principal.to_hex(), &lease.repo_ref)
            .is_err()
    );
}

// The transport is real stock Git through the lease URL. The build executor is
// deliberately test-only; production confinement remains a host obligation.
struct NoBuildEndpoint;
impl crate::dispatch_byoa::ByoEndpointBackendFactory for NoBuildEndpoint {
    fn resolve_backend(
        &self,
        _: &crate::dispatch_byoa::ByoEndpointSpec,
    ) -> crate::dispatch_byoa::ByoaResult<Arc<dyn crate::LlmBackend>> {
        Err(crate::dispatch_byoa::ByoaError::Backend(
            "not an endpoint".into(),
        ))
    }
}
struct NoBuildNetwork;
impl crate::dispatch_byoa::ByoaEgressPort for NoBuildNetwork {
    fn open(
        &mut self,
        _: &str,
        _: &str,
    ) -> crate::dispatch_byoa::ByoaResult<crate::dispatch_byoa::ByoaEgressLease> {
        Err(crate::dispatch_byoa::ByoaError::Backend(
            "network denied".into(),
        ))
    }
}
struct CheckoutRustBuild<'a> {
    wire: &'a GitWire<'a>,
    output: &'a std::path::Path,
}
impl crate::dispatch_byoa::ByoaCliExecutor for CheckoutRustBuild<'_> {
    fn run(
        &mut self,
        spec: &crate::dispatch_byoa::CliSandboxSpec,
        checkout: &CheckoutLeaseAct,
        boundary: crate::code_sandbox::SandboxBoundaryContract,
        budget: crate::code_sandbox::microvm::ExecutionBudget,
        _: &mut dyn FnMut(
            &str,
            u64,
        ) -> crate::dispatch_byoa::ByoaResult<
            crate::dispatch_byoa::ByoaEgressLease,
        >,
    ) -> crate::dispatch_byoa::ByoaResult<crate::dispatch_byoa::ByoaExhaust> {
        assert_eq!(spec.checkout_id, checkout.checkout_id);
        assert_eq!(
            boundary.tier(),
            crate::code_sandbox::SandboxGuestTier::Foreign
        );
        assert!(budget.is_bounded());
        let tree = self
            .wire
            .checkout_worktree_path(checkout)
            .map_err(|_| crate::dispatch_byoa::ByoaError::Backend("checkout unavailable".into()))?;
        let output = std::process::Command::new("rustc")
            .current_dir(tree)
            .args([
                "--crate-name",
                "lease_build",
                "--crate-type",
                "lib",
                "--emit",
                "metadata",
                "-o",
                self.output.join("build.rmeta").to_str().unwrap(),
                "lib.rs",
            ])
            .output()
            .map_err(|_| crate::dispatch_byoa::ByoaError::Backend("compiler unavailable".into()))?;
        if !output.status.success() {
            return Err(crate::dispatch_byoa::ByoaError::Backend(
                "build failed".into(),
            ));
        }
        Ok(crate::dispatch_byoa::ByoaExhaust {
            stdout: b"checkout build succeeded".to_vec(),
            stderr: output.stderr,
            ..Default::default()
        })
    }
}

#[test]
fn leased_door_checkout_build_captures_exhaust_and_reclaims_fail_closed() {
    use crate::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
    use crate::dispatch_byoa::{
        BYOA_ATTEMPT_KIND, ByoaConnectorSpec, ByoaDispatchOutcome, ByoaDispatcher,
        ByoaExecutionFence, ByoaTerminalDisposition, CaptureByoaExhaust, CliSandboxSpec,
        DispatchByoa, decode_byoa_exhaust,
    };
    let now = crate::unix_seconds_now();
    let clock = crate::store::ports::ManualClock::new(now);
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(
        Vault::open(
            dir.path(),
            crate::VaultConfig {
                store_clock: clock.bundle(),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let (_source, repo_dir, _, head) = served_repo(&vault);
    git(&repo_dir, &["remote", "remove", "origin"]);
    let principal = EntityId::now();
    let origin = PublicationTestOrigin::start(&vault, principal);
    let wire = GitWire::new(&vault)
        .unwrap()
        .with_checkout_door(&origin.door_base_url())
        .unwrap();
    let checkout_id = CheckoutId::from_bytes(*EntityId::now().as_bytes()).unwrap();
    let task_ref = EntityId::now();
    let repo_ref = RepoRef::LocalFolder {
        path: repo_dir.to_string_lossy().into_owned(),
        commit: head.as_str().to_owned(),
    };
    let mut leases = CheckoutLeaseService::new(&vault, Facts, Liveness::default());
    let first = leases
        .claim(CheckoutClaimRequest {
            checkout_id,
            task_ref,
            repo_ref: repo_ref.clone(),
            holder_ref: principal.to_hex(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(3600),
            now,
        })
        .unwrap();
    let lease = leases.get(checkout_id).unwrap().unwrap();
    wire.materialize(&lease).unwrap();
    let tree = wire.checkout_worktree_path(&lease).unwrap();
    std::fs::write(tree.join("lib.rs"), "pub fn value() -> u32 { 1897 }\n").unwrap();

    let mut dispatcher = ByoaDispatcher::new(&vault, NoBuildEndpoint, NoBuildNetwork);
    let dispatched = dispatcher
        .dispatch(DispatchByoa {
            user_login: false,
            connector: ByoaConnectorSpec::CliSandbox(CliSandboxSpec {
                program: "rustc".into(),
                argv: vec!["lib.rs".into()],
                checkout_id,
                egress_profile_ref: "test/no-network".into(),
                credential_handles: vec![],
            }),
            task_ref: Some(task_ref),
            parent_attempt_id: None,
            run_id: Some("checkout-build".into()),
            dedupe_key: None,
            now: now + 1,
        })
        .unwrap();
    assert!(matches!(dispatched, ByoaDispatchOutcome::Dispatched(_)));
    let ClaimOutcome::Claimed(attempt) = AttemptQueue::new(&vault)
        .claim_kind(
            BYOA_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "builder".into(),
                now: now + 2,
            },
        )
        .unwrap()
    else {
        panic!("build attempt not claimed");
    };
    let mut executor = CheckoutRustBuild {
        wire: &wire,
        output: dir.path(),
    };
    let exhaust = dispatcher
        .execute_cli(
            &ByoaExecutionFence {
                attempt_id: attempt.id,
                lease_owner: "builder".into(),
                attempt_count: attempt.attempt_count,
            },
            crate::code_sandbox::microvm::ExecutionBudget::new(60, 128, 8),
            &leases,
            &mut executor,
            now + 3,
        )
        .unwrap();
    assert!(dir.path().join("build.rmeta").exists());
    let terminal = dispatcher
        .capture_terminal_exhaust(CaptureByoaExhaust {
            attempt_id: attempt.id,
            lease_owner: "builder".into(),
            attempt_count: attempt.attempt_count,
            disposition: ByoaTerminalDisposition::Completed,
            exhaust,
            reason: None,
            now: now + 4,
        })
        .unwrap();
    let bytes = vault
        .read_blob_artifact_version(&terminal.artifact_id, 1)
        .unwrap()
        .unwrap();
    let (_, _, stored) = decode_byoa_exhaust(&bytes).unwrap();
    assert_eq!(stored.stdout, b"checkout build succeeded");

    git(&tree, &["add", "--", "lib.rs"]);
    git(
        &tree,
        &[
            "-c",
            "user.name=Oneiron",
            "-c",
            "user.email=oneiron@example.invalid",
            "commit",
            "-m",
            "build result",
        ],
    );
    let pushed = git(&tree, &["rev-parse", "HEAD"]);
    git(&tree, &["push", "origin", "HEAD:refs/heads/checkout-build"]);
    assert_eq!(
        git(&repo_dir, &["rev-parse", "refs/heads/checkout-build"]),
        pushed
    );
    let fence = CheckoutLeaseFence {
        checkout_id,
        epoch: first.epoch,
        holder_ref: principal.to_hex(),
    };
    let settled = leases
        .settle(CheckoutSettlementRequest {
            fence: fence.clone(),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "refs/heads/checkout-build".into(),
            result_ref: terminal.result_ref.as_str().to_owned(),
            now: now + 5,
        })
        .unwrap();
    assert_eq!(settled.result_ref, terminal.result_ref.as_str());
    let receipt = PushedHeadReceipt {
        receipt_ref: "origin-push".into(),
        observed_ref: "refs/heads/checkout-build".into(),
        pushed_head: pushed,
        checkout_id,
        epoch: first.epoch,
    };
    assert!(matches!(
        leases
            .teardown(fence, Some(&receipt), &wire, now + 6)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert!(!tree.exists());

    // Reuse the id after collection: tombstone epochs must not revive the old
    // bearer. Reclaim at expiry, then refuse stale settlement and teardown.
    let second = leases
        .claim(CheckoutClaimRequest {
            checkout_id,
            task_ref,
            repo_ref,
            holder_ref: principal.to_hex(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(30),
            now: now + 7,
        })
        .unwrap();
    assert!(second.epoch > first.epoch);
    let second_act = leases.get(checkout_id).unwrap().unwrap();
    wire.materialize(&second_act).unwrap();
    let second_tree = wire.checkout_worktree_path(&second_act).unwrap();
    let reclaimed = leases
        .reclaim_idempotent(checkout_id, "replacement".into(), now + 38)
        .unwrap();
    assert!(reclaimed.epoch > second.epoch);
    let stale = CheckoutLeaseFence {
        checkout_id,
        epoch: second.epoch,
        holder_ref: principal.to_hex(),
    };
    assert!(
        leases
            .settle(CheckoutSettlementRequest {
                fence: stale.clone(),
                disposition: CheckoutSettlementDisposition::Select,
                observed_ref: "refs/heads/checkout-build".into(),
                result_ref: terminal.result_ref.as_str().to_owned(),
                now: now + 39,
            })
            .is_err()
    );
    assert!(
        leases
            .teardown(stale, Some(&receipt), &wire, now + 39)
            .is_err()
    );
    let current = CheckoutLeaseFence {
        checkout_id,
        epoch: reclaimed.epoch,
        holder_ref: "replacement".into(),
    };
    assert!(matches!(
        leases.teardown(current, None, &wire, now + 39).unwrap(),
        CheckoutTeardownOutcome::Retained {
            reason: CheckoutRetainReason::MissingPushedHeadReceipt,
            ..
        }
    ));
    assert!(second_tree.exists());
}
