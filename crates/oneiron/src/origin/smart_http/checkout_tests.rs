//! Stock Git checkout-to-door round trip with a live epoch-fenced lease.
use super::tests::{PublicationTestOrigin, git, served_repo, temp_vault};
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
    let (_dir, vault) = temp_vault();
    let (_source, repo_dir, _, head) = served_repo(&vault);
    // A source with remote config is not eligible: a linked worktree would
    // inherit it. The fixture source is copied as a bare repo, so remove the
    // clone's local-origin URL before it enters door custody.
    git(&repo_dir, &["remote", "remove", "origin"]);
    let principal = EntityId::now();
    let origin = PublicationTestOrigin::start(&vault, principal);
    let now = crate::unix_seconds_now();
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
            ttl_secs: Some(600),
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
        .reclaim_idempotent(grant.checkout_id, "replacement:holder".into(), now + 601)
        .unwrap();
    assert!(
        door.checkout_credential(&ticket, &principal.to_hex(), &lease.repo_ref)
            .is_err()
    );
}
