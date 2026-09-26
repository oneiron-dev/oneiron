//! Lifecycle acceptance using a recording Docker-compatible executable.

use std::fs;
use std::path::Path;

use crate::VaultConfig;
use crate::secret_custody::{
    CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
    SecretCustodyStatus,
};

use super::*;
use crate::linkedin_connector::{LinkedInSeatSandboxPolicy, run_linkedin_kill_switch};

#[derive(Default)]
struct RecordingServices {
    calls: Vec<String>,
    fail_revoke: bool,
    fail_close: bool,
}

impl LinkedInSeatHostServices for RecordingServices {
    fn open_handoff(&mut self, host: &LinkedInSandboxHostConfig, sandbox: &str) -> Result<String> {
        self.calls.push(format!("open:{}:{sandbox}", host.seat_ref));
        Ok(format!(
            "https://login.example.test/once/{sandbox}?token=one-use-test-token"
        ))
    }
    fn complete_handoff(&mut self, host: &LinkedInSandboxHostConfig, _: &str) -> Result<()> {
        self.calls.push(format!("2fa:{}", host.seat_ref));
        Ok(())
    }
    fn close_handoff(&mut self, host: &LinkedInSandboxHostConfig, _: &str) -> Result<()> {
        self.calls.push(format!("close:{}", host.seat_ref));
        if self.fail_close {
            return Err(Error::InvalidConfig("gateway unavailable".into()));
        }
        Ok(())
    }
    fn revoke_verbs(&mut self, seat_ref: &str) -> Result<()> {
        self.calls.push(format!("revoke:{seat_ref}"));
        if self.fail_revoke {
            return Err(Error::InvalidConfig("catalog unavailable".into()));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn fake_runtime(root: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join("docker-stub");
    let containers = root.join("containers");
    fs::create_dir(&containers).unwrap();
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> '{root}/calls'\ncase \"$1\" in\n create) test ! -e '{root}/containers/'\"$3\"; : > '{root}/containers/'\"$3\" ;;\n start) test -e '{root}/containers/'\"$2\" ;;\n rm) rm -f '{root}/containers/'\"$3\" ;;\nesac\n",
        root = root.display()
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[cfg(unix)]
fn runtime_container(root: &Path, name: &str) -> PathBuf {
    root.join("containers").join(name)
}

fn vault(root: &Path) -> Vault {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    Vault::open(root, cfg).unwrap()
}

fn host_config(seat: &str) -> LinkedInSandboxHostConfig {
    LinkedInSandboxHostConfig::new(
        seat,
        format!("sandbox:{seat}"),
        format!("profile:{seat}"),
        format!("vault-secret:linkedin:{seat}:cookie"),
    )
    .unwrap()
}

fn put_cookie(vault: &Vault, seat: &str) {
    vault
        .register_secret(SecretCustodyRecord {
            schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
            name: format!("linkedin:{seat}:cookie"),
            class: CustodyClass::CustodyDeviceBound,
            device_only: true,
            value_bytes: b"opaque cookie".to_vec(),
            status: SecretCustodyStatus::Active,
            registered_at: 1_800_000_000,
            rotated_at: None,
            rotation_generation: 0,
            bindings: vec![],
            manifest_ref: String::new(),
            declared_paths: vec![],
            policy_floor_snapshot: SecretCustodyFloor::default(),
        })
        .unwrap();
}

#[cfg(unix)]
#[test]
fn linkedin_connector_container_host_provisions_login_and_kills_one_seat() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let v = vault(&tmp.path().join("vault"));
    let other_v = vault(&tmp.path().join("other-vault"));
    let root = tmp.path().join("custody");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = fake_runtime(tmp.path());
    let mut host = LinkedInContainerSandboxHost::new(
        &v,
        &root,
        &binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices::default(),
    )
    .unwrap();
    let alice = host_config("alice");
    let other_host = LinkedInContainerSandboxHost::new(
        &other_v,
        &root,
        &binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices::default(),
    )
    .unwrap();
    assert_ne!(host.sandbox_name(&alice), other_host.sandbox_name(&alice));
    let bob = host_config("bob");
    let a = host.provision(&alice).unwrap();
    assert!(root.join(&a.sandbox_name).is_dir());
    assert!(runtime_container(tmp.path(), &a.sandbox_name).exists());
    assert!(a.login_url.starts_with("https://login.example.test/once/"));
    assert!(host.complete_login(&alice).is_err()); // no cookie in this vault yet
    put_cookie(&other_v, "alice");
    assert!(host.complete_login(&alice).is_err()); // another vault's ref is not enough
    put_cookie(&v, "alice");
    host.complete_login(&alice).unwrap();
    let b = host.provision(&bob).unwrap();
    assert_ne!(a.sandbox_name, b.sandbox_name);
    assert!(root.join(&b.sandbox_name).exists());
    assert!(runtime_container(tmp.path(), &b.sandbox_name).exists());
    let policy = LinkedInSeatSandboxPolicy::active(alice.clone());
    let killed = run_linkedin_kill_switch(policy, &mut host, 1_800_000_100, "owner:off").unwrap();
    assert!(killed.verb_catalog().is_empty());
    assert!(!root.join(&a.sandbox_name).exists());
    assert!(root.join(&b.sandbox_name).exists());
    assert!(!runtime_container(tmp.path(), &a.sandbox_name).exists());
    assert!(runtime_container(tmp.path(), &b.sandbox_name).exists());
    let calls = &host.services().calls;
    assert!(calls.iter().any(|call| call == "2fa:alice"));
    assert!(calls.iter().any(|call| call == "revoke:alice"));
    assert!(calls.iter().any(|call| call == "close:alice"));
    let docker_calls = fs::read_to_string(tmp.path().join("calls")).unwrap();
    assert!(docker_calls.contains("create --name"));
    assert!(docker_calls.contains("--network private_egress"));
    assert!(docker_calls.contains("rm --force"));
    assert!(!docker_calls.contains("opaque cookie"));
}

#[cfg(unix)]
#[test]
fn linkedin_connector_kill_switch_attempts_destroy_when_revoke_fails() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let v = vault(&tmp.path().join("vault"));
    let root = tmp.path().join("custody");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = fake_runtime(tmp.path());
    let mut host = LinkedInContainerSandboxHost::new(
        &v,
        &root,
        binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices {
            fail_revoke: true,
            fail_close: true,
            ..RecordingServices::default()
        },
    )
    .unwrap();
    let config = host_config("alice");
    let sandbox = host.provision(&config).unwrap();
    let err = run_linkedin_kill_switch(
        LinkedInSeatSandboxPolicy::active(config),
        &mut host,
        10,
        "owner:off",
    );
    assert!(err.is_err());
    assert!(!root.join(&sandbox.sandbox_name).exists());
    assert!(!runtime_container(tmp.path(), &sandbox.sandbox_name).exists());
    assert!(
        host.services()
            .calls
            .iter()
            .any(|call| call == "revoke:alice")
    );
    assert!(
        host.services()
            .calls
            .iter()
            .any(|call| call == "close:alice")
    );
}

#[cfg(unix)]
#[test]
fn linkedin_connector_invalid_kill_reason_has_no_effects() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let v = vault(&tmp.path().join("vault"));
    let root = tmp.path().join("custody");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = fake_runtime(tmp.path());
    let mut host = LinkedInContainerSandboxHost::new(
        &v,
        &root,
        binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices::default(),
    )
    .unwrap();
    let config = host_config("alice");
    let sandbox = host.provision(&config).unwrap();
    let prior_calls = host.services().calls.clone();
    assert!(
        run_linkedin_kill_switch(
            LinkedInSeatSandboxPolicy::active(config),
            &mut host,
            10,
            " "
        )
        .is_err()
    );
    assert_eq!(host.services().calls, prior_calls);
    assert!(root.join(sandbox.sandbox_name).exists());
}

#[test]
fn linkedin_connector_sandbox_debug_redacts_one_use_login_credential() {
    let url = "https://login.example.test/once/seat?token=one-use-test-token";
    let sandbox = LinkedInSeatSandbox {
        sandbox_name: "seat-sandbox".into(),
        login_url: url.into(),
        browser_profile_ref: "profile:seat".into(),
        session_cookie_secret_ref: "vault-secret:seat".into(),
    };
    assert_eq!(sandbox.login_url, url); // usable by the member-facing handoff
    let diagnostic = format!("{sandbox:?}");
    assert!(diagnostic.contains("login_url: \"<redacted>\""));
    assert!(!diagnostic.contains(url));
    assert!(!diagnostic.contains("one-use-test-token"));
}

#[cfg(unix)]
#[test]
fn linkedin_connector_same_seat_alternate_refs_cannot_provision_twice_or_escape_kill() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let v = vault(&tmp.path().join("vault"));
    let root = tmp.path().join("custody");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let binary = fake_runtime(tmp.path());
    let mut host = LinkedInContainerSandboxHost::new(
        &v,
        &root,
        &binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices::default(),
    )
    .unwrap();
    let first = host_config("alice");
    let mut alternate = first.clone();
    alternate.sandbox_ref = "sandbox:another-configuration".into();
    alternate.browser_profile_ref = "profile:another-configuration".into();
    assert_eq!(host.sandbox_name(&first), host.sandbox_name(&alternate));
    let sandbox = host.provision(&first).unwrap();
    assert!(host.provision(&alternate).is_err());
    assert!(runtime_container(tmp.path(), &sandbox.sandbox_name).exists());
    assert!(root.join(&sandbox.sandbox_name).exists());

    // A second host using a different profile root still targets the same
    // vault/seat container identity; its create is refused by the runtime.
    let other_root = tmp.path().join("other-custody");
    fs::create_dir(&other_root).unwrap();
    fs::set_permissions(&other_root, fs::Permissions::from_mode(0o700)).unwrap();
    let mut second_host = LinkedInContainerSandboxHost::new(
        &v,
        &other_root,
        &binary,
        "browser@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "private_egress",
        RecordingServices::default(),
    )
    .unwrap();
    assert_eq!(
        host.sandbox_name(&first),
        second_host.sandbox_name(&alternate)
    );
    assert!(second_host.provision(&alternate).is_err());
    assert!(!other_root.join(&sandbox.sandbox_name).exists());
    assert!(runtime_container(tmp.path(), &sandbox.sandbox_name).exists());

    // Even if the caller retained the alternate config, destruction resolves
    // the canonical vault/seat identity, not the caller's sandbox_ref.
    let killed = run_linkedin_kill_switch(
        LinkedInSeatSandboxPolicy::active(alternate),
        &mut host,
        1_800_000_100,
        "owner:off",
    )
    .unwrap();
    assert!(killed.verb_catalog().is_empty());
    assert!(!runtime_container(tmp.path(), &sandbox.sandbox_name).exists());
    assert!(!root.join(&sandbox.sandbox_name).exists());
    assert_eq!(
        host.services()
            .calls
            .iter()
            .filter(|call| call.starts_with("open:alice:"))
            .count(),
        1
    );
    assert_eq!(
        host.services()
            .calls
            .iter()
            .filter(|call| call.starts_with("revoke:alice"))
            .count(),
        1
    );
    assert_eq!(
        host.services()
            .calls
            .iter()
            .filter(|call| call.as_str() == "close:alice")
            .count(),
        1
    );
}
