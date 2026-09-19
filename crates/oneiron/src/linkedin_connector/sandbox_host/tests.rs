use super::*;
#[derive(Default)]
struct Runtime {
    specs: Vec<LinkedInContainerSpec>,
    destroyed: Vec<String>,
    fail_destroy: bool,
}
impl LinkedInContainerRuntime for Runtime {
    fn provision(&mut self, spec: &LinkedInContainerSpec) -> Result<()> {
        self.specs.push(spec.clone());
        Ok(())
    }
    fn destroy(&mut self, name: &str) -> Result<()> {
        if self.fail_destroy {
            return Err(Error::InvalidConfig("destroy failed".into()));
        }
        self.destroyed.push(name.into());
        Ok(())
    }
}
#[test]
fn provision_then_kill_revokes_durable_seat_and_member_login() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let config = LinkedInSandboxHostConfig::new(
        "seat:a",
        "sandbox:a",
        "vault-profile:abc:profile",
        "vault-secret:abc:cookies",
    )?;
    let mut host = ProductionLinkedInSandboxHost::new(
        &vault,
        "abc".into(),
        format!("browser@sha256:{}", "a".repeat(64)),
        Runtime::default(),
    )?;
    let login = host.provision(config.clone(), 12345)?;
    assert_eq!(
        login.handoff,
        LinkedInLoginHandoff::one_time_remote_browser()
    );
    assert_eq!(host.verb_catalog("seat:a")?.len(), 2);
    assert!(host.provision(config.clone(), 12346).is_err());
    assert_eq!(host.runtime().specs.len(), 1);
    assert_eq!(
        host.runtime().specs[0].session_cookie_secret_ref,
        "vault-secret:abc:cookies"
    );
    let killed = super::super::run_linkedin_kill_switch(
        super::super::LinkedInSeatSandboxPolicy::active(config),
        &mut host,
        42,
        "owner-disabled",
    )?;
    assert!(killed.verb_catalog().is_empty());
    assert!(host.verb_catalog("seat:a")?.is_empty());
    assert!(host.remote_login("seat:a").is_err());
    assert_eq!(
        host.runtime().destroyed,
        vec![host.runtime().specs[0].name.clone()]
    );
    Ok(())
}
#[test]
fn cross_vault_refs_refuse_before_runtime_and_destroy_failure_revokes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let mut host = ProductionLinkedInSandboxHost::new(
        &vault,
        "abc".into(),
        format!("browser@sha256:{}", "a".repeat(64)),
        Runtime {
            fail_destroy: true,
            ..Runtime::default()
        },
    )?;
    let mut config = LinkedInSandboxHostConfig::new(
        "seat:a",
        "sandbox:a",
        "vault-profile:other:profile",
        "vault-secret:abc:cookies",
    )?;
    assert!(host.provision(config.clone(), 12345).is_err());
    assert!(host.runtime().specs.is_empty());
    config.browser_profile_ref = "vault-profile:abc:profile".into();
    host.provision(config.clone(), 12345)?;
    assert!(host.destroy_sandbox(&config).is_err());
    assert!(host.verb_catalog("seat:a")?.is_empty());
    Ok(())
}
