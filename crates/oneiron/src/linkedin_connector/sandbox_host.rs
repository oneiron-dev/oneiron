//! Vault-scoped container host for LinkedIn seats. No credentials are copied into receipts.
use super::normalize_keys::event_hash;
use super::{
    LinkedInLoginHandoff, LinkedInPasswordCustody, LinkedInSandboxHostConfig,
    LinkedInSandboxHostHarness, LinkedInSandboxRuntime,
};
use crate::{
    Vault,
    error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInContainerSpec {
    pub name: String,
    pub image: String,
    pub browser_profile_volume: String,
    pub session_cookie_secret_ref: String,
    pub localhost_port: u16,
}

/// Runtime seam also used by fixture hosts. Production uses the command runtime.
pub trait LinkedInContainerRuntime {
    fn provision(&mut self, spec: &LinkedInContainerSpec) -> Result<()>;
    fn destroy(&mut self, name: &str) -> Result<()>;
}

/// Runs a preinstalled Docker-compatible runtime without a shell or image pulls.
pub struct LinkedInContainerCommandRuntime {
    executable: std::path::PathBuf,
}
impl LinkedInContainerCommandRuntime {
    pub fn new(executable: std::path::PathBuf) -> Result<Self> {
        if !executable.is_absolute() {
            return Err(Error::InvalidConfig(
                "Container runtime path must be absolute".into(),
            ));
        }
        Ok(Self { executable })
    }
    fn run(&self, args: &[String]) -> Result<()> {
        let result = Command::new(&self.executable).args(args).output()?;
        if !result.status.success() {
            // Provider stderr can include secrets; it never becomes an engine error.
            return Err(Error::InvalidConfig(
                "LinkedIn container operation failed".into(),
            ));
        }
        Ok(())
    }
}
impl LinkedInContainerRuntime for LinkedInContainerCommandRuntime {
    fn provision(&mut self, spec: &LinkedInContainerSpec) -> Result<()> {
        self.run(&[
            "run".into(),
            "--detach".into(),
            "--pull=never".into(),
            "--name".into(),
            spec.name.clone(),
            "--read-only".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            "--pids-limit=256".into(),
            "--memory=2g".into(),
            "--cpus=2".into(),
            "--tmpfs=/tmp:rw,nosuid,nodev,size=256m".into(),
            "--shm-size=256m".into(),
            "--publish".into(),
            format!("127.0.0.1:{}:3000", spec.localhost_port),
            "--mount".into(),
            format!(
                "type=volume,source={},target=/profile",
                spec.browser_profile_volume
            ),
            "--env".into(),
            format!(
                "SESSION_COOKIE_SECRET_REF={}",
                spec.session_cookie_secret_ref
            ),
            spec.image.clone(),
        ])
    }
    fn destroy(&mut self, name: &str) -> Result<()> {
        self.run(&[
            "rm".into(),
            "--force".into(),
            "--volumes".into(),
            name.into(),
        ])?;
        self.run(&["volume".into(), "rm".into(), format!("{name}-profile")])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Seat {
    host: LinkedInSandboxHostConfig,
    container_name: String,
    localhost_port: u16,
    active: bool,
    verbs_revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedInRemoteLogin {
    pub loopback_url: String,
    pub handoff: LinkedInLoginHandoff,
}

/// One host owns one vault namespace. Seats are reserved durably before container
/// creation, so concurrent provisioning cannot create two browsers for one seat.
pub struct ProductionLinkedInSandboxHost<'a, R> {
    vault: &'a Vault,
    vault_ref: String,
    image: String,
    runtime: R,
}
impl<'a, R: LinkedInContainerRuntime> ProductionLinkedInSandboxHost<'a, R> {
    pub fn new(vault: &'a Vault, vault_ref: String, image: String, runtime: R) -> Result<Self> {
        let digest = image.rsplit_once("@sha256:").map(|(_, digest)| digest);
        if vault_ref.is_empty()
            || !vault_ref
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || image.starts_with('-')
            || !digest.is_some_and(|d| d.len() == 64 && d.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return Err(Error::InvalidConfig(
                "Sandbox requires a vault namespace and digest-pinned image".into(),
            ));
        }
        Ok(Self {
            vault,
            vault_ref,
            image,
            runtime,
        })
    }
    pub fn runtime(&self) -> &R {
        &self.runtime
    }
    fn key(&self, seat: &str) -> Vec<u8> {
        format!(
            "linkedin:sandbox:v1:{}",
            event_hash(&[&self.vault_ref, seat])
        )
        .into_bytes()
    }
    fn read(&self, seat: &str) -> Result<Seat> {
        let txn = self.vault.store.env.read_txn()?;
        let bytes = self
            .vault
            .store
            .vault_meta
            .get(&txn, &self.key(seat))?
            .ok_or_else(|| Error::InvalidConfig("LinkedIn seat is not provisioned".into()))?;
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::InvalidConfig("Invalid LinkedIn seat state".into()))
    }
    fn write(&self, seat: &Seat) -> Result<()> {
        let bytes = serde_json::to_vec(seat)
            .map_err(|_| Error::InvalidConfig("Invalid LinkedIn seat state".into()))?;
        self.vault.with_write_txn(|txn| {
            self.vault
                .store
                .vault_meta
                .put(txn, &self.key(&seat.host.seat_ref), &bytes)?;
            Ok(())
        })
    }
    pub fn provision(
        &mut self,
        host: LinkedInSandboxHostConfig,
        localhost_port: u16,
    ) -> Result<LinkedInRemoteLogin> {
        if host.runtime != LinkedInSandboxRuntime::Container
            || localhost_port == 0
            || !host
                .browser_profile_ref
                .starts_with(&format!("vault-profile:{}:", self.vault_ref))
            || !host
                .session_cookie_secret_ref
                .starts_with(&format!("vault-secret:{}:", self.vault_ref))
            || host.login_handoff != LinkedInLoginHandoff::one_time_remote_browser()
        {
            return Err(Error::InvalidConfig(
                "LinkedIn sandbox custody must remain vault-scoped and member-operated".into(),
            ));
        }
        let name = format!(
            "oneiron-linkedin-{}",
            event_hash(&[&self.vault_ref, &host.seat_ref])
        );
        let mut seat = Seat {
            host,
            container_name: name.clone(),
            localhost_port,
            active: false,
            verbs_revoked: true,
        };
        let bytes = serde_json::to_vec(&seat)
            .map_err(|_| Error::InvalidConfig("Invalid LinkedIn seat state".into()))?;
        self.vault.with_write_txn(|txn| {
            let key = self.key(&seat.host.seat_ref);
            if self.vault.store.vault_meta.get(txn, &key)?.is_some() {
                return Err(Error::InvalidConfig(
                    "LinkedIn seat already reserved".into(),
                ));
            }
            self.vault.store.vault_meta.put(txn, &key, &bytes)?;
            Ok(())
        })?;
        self.runtime.provision(&LinkedInContainerSpec {
            name: name.clone(),
            image: self.image.clone(),
            browser_profile_volume: format!("{name}-profile"),
            session_cookie_secret_ref: seat.host.session_cookie_secret_ref.clone(),
            localhost_port,
        })?;
        seat.active = true;
        seat.verbs_revoked = false;
        self.write(&seat)?;
        self.remote_login(&seat.host.seat_ref)
    }
    pub fn remote_login(&self, seat_ref: &str) -> Result<LinkedInRemoteLogin> {
        let seat = self.read(seat_ref)?;
        if !seat.active || seat.verbs_revoked {
            return Err(Error::InvalidConfig("LinkedIn seat is unavailable".into()));
        }
        Ok(LinkedInRemoteLogin {
            loopback_url: format!("http://127.0.0.1:{}", seat.localhost_port),
            handoff: LinkedInLoginHandoff {
                one_time_remote_browser: true,
                member_completes_2fa: true,
                password_custody: LinkedInPasswordCustody::MemberOnly,
            },
        })
    }
    pub fn verb_catalog(&self, seat_ref: &str) -> Result<&'static [&'static str]> {
        let seat = self.read(seat_ref)?;
        Ok(if seat.active && !seat.verbs_revoked {
            super::LINKEDIN_SEAT_VERB_CATALOG
        } else {
            &[]
        })
    }
}
impl<R: LinkedInContainerRuntime> LinkedInSandboxHostHarness
    for ProductionLinkedInSandboxHost<'_, R>
{
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> Result<()> {
        let mut seat = self.read(&host.seat_ref)?;
        if seat.host != *host {
            return Err(Error::InvalidConfig(
                "LinkedIn sandbox binding mismatch".into(),
            ));
        }
        // Revoke before touching the provider. A failed destroy stays fail-closed.
        seat.verbs_revoked = true;
        self.write(&seat)?;
        self.runtime.destroy(&seat.container_name)?;
        seat.active = false;
        self.write(&seat)
    }
    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> Result<()> {
        let mut seat = self.read(seat_ref)?;
        seat.verbs_revoked = true;
        self.write(&seat)
    }
}

#[cfg(test)]
mod tests;
