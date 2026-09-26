//! Container-backed, per-vault LinkedIn seat lifecycle. The remote gateway and
//! verb registry are host integrations; neither passwords nor cookies cross this API.

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::Vault;
use crate::error::{Error, Result};
use crate::secret_custody::{CustodyClass, SecretCustodyStatus};

use super::seat_policy::LinkedInSandboxHostHarness;
use super::{LinkedInSandboxHostConfig, LinkedInSandboxRuntime};

/// Host-owned remote browser and seat-catalog doors. The gateway must issue a
/// single-use HTTPS link bound to this sandbox and verify the member's login
/// and 2FA before `complete_handoff` returns. It must put the resulting cookie
/// in this vault's secret custody under `session_cookie_secret_ref`, never in
/// a receipt or the returned URL. Revocation must be durable and idempotent.
pub trait LinkedInSeatHostServices {
    fn open_handoff(&mut self, host: &LinkedInSandboxHostConfig, sandbox: &str) -> Result<String>;
    fn complete_handoff(&mut self, host: &LinkedInSandboxHostConfig, sandbox: &str) -> Result<()>;
    fn close_handoff(&mut self, host: &LinkedInSandboxHostConfig, sandbox: &str) -> Result<()>;
    fn revoke_verbs(&mut self, seat_ref: &str) -> Result<()>;
}

/// One active sandbox's opaque handle. The URL is an expiring one-use gateway
/// link; the caller must hand it to the member only, never persist it.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkedInSeatSandbox {
    pub sandbox_name: String,
    pub login_url: String,
    pub browser_profile_ref: String,
    pub session_cookie_secret_ref: String,
}

impl fmt::Debug for LinkedInSeatSandbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkedInSeatSandbox")
            .field("sandbox_name", &self.sandbox_name)
            .field("login_url", &"<redacted>")
            .field("browser_profile_ref", &self.browser_profile_ref)
            .field("session_cookie_secret_ref", &self.session_cookie_secret_ref)
            .finish()
    }
}

/// Docker-compatible host for one vault. `custody_root` must be a private,
/// canonical, vault-specific host directory (0700), outside the container's
/// control. The image must ship the browser and MCP server and expose its
/// remote-browser port only to the host gateway; this module never publishes
/// a port or stores credentials in an environment variable or CLI argument.
///
/// The runtime binary and image are host configuration, not caller inputs.
/// Docker's socket is a privileged boundary; only a trusted host may construct
/// this object. The gateway mediates the member-facing remote browser.
pub struct LinkedInContainerSandboxHost<'v, S> {
    vault: &'v Vault,
    custody_root: PathBuf,
    docker_binary: PathBuf,
    image: String,
    network: String,
    services: S,
}

impl<'v, S: LinkedInSeatHostServices> LinkedInContainerSandboxHost<'v, S> {
    pub fn new(
        vault: &'v Vault,
        custody_root: impl Into<PathBuf>,
        docker_binary: impl Into<PathBuf>,
        image: impl Into<String>,
        network: impl Into<String>,
        services: S,
    ) -> Result<Self> {
        let custody_root = custody_root.into();
        let metadata = fs::symlink_metadata(&custody_root)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || fs::canonicalize(&custody_root)? != custody_root
        {
            return Err(Error::InvalidConfig(
                "LinkedIn custody root must be a canonical directory".into(),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(Error::InvalidConfig(
                    "LinkedIn custody root must be private".into(),
                ));
            }
        }
        let image = image.into();
        let pinned = image.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
            !name.is_empty() && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())
        });
        if !pinned || image.contains(char::is_whitespace) {
            return Err(Error::InvalidConfig(
                "LinkedIn container image must be pinned by the host".into(),
            ));
        }
        let network = network.into();
        if network.is_empty()
            || !network
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::InvalidConfig(
                "LinkedIn network must be a host-owned network name".into(),
            ));
        }
        let docker_binary = docker_binary.into();
        if !docker_binary.is_absolute() {
            return Err(Error::InvalidConfig(
                "LinkedIn container runtime must be an absolute path".into(),
            ));
        }
        Ok(Self {
            vault,
            custody_root,
            docker_binary,
            image,
            network,
            services,
        })
    }

    fn sandbox_name(&self, host: &LinkedInSandboxHostConfig) -> String {
        let mut hasher = blake3::Hasher::new();
        for part in [
            self.vault.store.env.path().to_string_lossy().as_ref(),
            &host.seat_ref,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(&[0]);
        }
        format!("oneiron-linkedin-{}", &hasher.finalize().to_hex()[..32])
    }

    fn profile_path(&self, host: &LinkedInSandboxHostConfig) -> PathBuf {
        self.custody_root.join(self.sandbox_name(host))
    }

    fn command(&self, args: &[&str]) -> Result<()> {
        let status = Command::new(&self.docker_binary)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()?;
        if !status.success() {
            return Err(Error::InvalidConfig(format!(
                "LinkedIn sandbox runtime failed: {status}"
            )));
        }
        Ok(())
    }

    fn validate_host(&self, host: &LinkedInSandboxHostConfig) -> Result<()> {
        if host.runtime != LinkedInSandboxRuntime::Container {
            return Err(Error::InvalidConfig(
                "LinkedIn microVM runtime requires a microVM host".into(),
            ));
        }
        // Public config fields can be mutated or deserialized after construction.
        LinkedInSandboxHostConfig::new(
            &host.seat_ref,
            &host.sandbox_ref,
            &host.browser_profile_ref,
            &host.session_cookie_secret_ref,
        )?;
        if !host.login_handoff.one_time_remote_browser
            || !host.login_handoff.member_completes_2fa
            || host.login_handoff.password_custody != super::LinkedInPasswordCustody::MemberOnly
            || !host.mcp_server.persistent_browser_profile
        {
            return Err(Error::InvalidConfig(
                "LinkedIn host requires member-only remote login and a persistent profile".into(),
            ));
        }
        Ok(())
    }

    /// Creates one isolated container and opens a one-use member login link.
    /// No active policy should be published until `complete_login` succeeds.
    pub fn provision(&mut self, host: &LinkedInSandboxHostConfig) -> Result<LinkedInSeatSandbox> {
        self.validate_host(host)?;
        let name = self.sandbox_name(host);
        let profile = self.profile_path(host);
        fs::create_dir(&profile)?; // exclusive: never attach to another seat's profile
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&profile, fs::Permissions::from_mode(0o700))?;
        }
        let mount = format!(
            "type=bind,src={},dst=/var/lib/linkedin-profile",
            profile.display()
        );
        let created = self.command(&[
            "create",
            "--name",
            &name,
            "--network",
            &self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--mount",
            &mount,
            &self.image,
        ]);
        if let Err(err) = created {
            fs::remove_dir_all(&profile)?;
            return Err(err);
        }
        let launched = self.command(&["start", &name]);
        if let Err(err) = launched {
            // If removal fails, leave the private profile in place so a
            // running container cannot be handed another seat's new profile.
            self.command(&["rm", "--force", &name])?;
            fs::remove_dir_all(&profile)?;
            return Err(err);
        }
        let handoff = self.services.open_handoff(host, &name).and_then(|url| {
            if url.starts_with("https://")
                && url.len() > "https://".len()
                && !url.chars().any(char::is_whitespace)
            {
                Ok(url)
            } else {
                Err(Error::InvalidConfig(
                    "LinkedIn remote login requires an HTTPS handoff".into(),
                ))
            }
        });
        let login_url = match handoff {
            Ok(url) => url,
            Err(err) => {
                let _ = self.services.close_handoff(host, &name);
                self.command(&["rm", "--force", &name])?;
                fs::remove_dir_all(&profile)?;
                return Err(err);
            }
        };
        Ok(LinkedInSeatSandbox {
            sandbox_name: name,
            login_url,
            browser_profile_ref: host.browser_profile_ref.clone(),
            session_cookie_secret_ref: host.session_cookie_secret_ref.clone(),
        })
    }

    /// Accepts login only after the gateway attests member 2FA and the cookie
    /// is present as an active device-bound record in *this* vault.
    pub fn complete_login(&mut self, host: &LinkedInSandboxHostConfig) -> Result<()> {
        self.validate_host(host)?;
        self.services
            .complete_handoff(host, &self.sandbox_name(host))?;
        let name = host
            .session_cookie_secret_ref
            .strip_prefix("vault-secret:")
            .ok_or_else(|| {
                Error::InvalidConfig("LinkedIn session secret is not vault-scoped".into())
            })?;
        let id = self.vault.resolve_secret_ref(name)?.ok_or_else(|| {
            Error::InvalidConfig("LinkedIn session cookie missing from this vault".into())
        })?;
        let meta = self.vault.get_secret_metadata(&id)?.ok_or_else(|| {
            Error::InvalidConfig("LinkedIn session cookie metadata missing".into())
        })?;
        if meta.status != SecretCustodyStatus::Active
            || meta.class != CustodyClass::CustodyDeviceBound
        {
            return Err(Error::InvalidConfig(
                "LinkedIn session cookie must be active and device-bound".into(),
            ));
        }
        Ok(())
    }

    pub fn services(&self) -> &S {
        &self.services
    }
}

impl<S: LinkedInSeatHostServices> LinkedInSandboxHostHarness
    for LinkedInContainerSandboxHost<'_, S>
{
    fn destroy_sandbox(&mut self, host: &LinkedInSandboxHostConfig) -> Result<()> {
        self.validate_host(host)?;
        let name = self.sandbox_name(host);
        // A failed gateway close must not leave a live container behind.
        let closed = self.services.close_handoff(host, &name);
        self.command(&["rm", "--force", &name])?;
        let profile = self.profile_path(host);
        if profile.exists() {
            fs::remove_dir_all(profile)?;
        }
        closed
    }

    fn revoke_verb_catalog(&mut self, seat_ref: &str) -> Result<()> {
        self.services.revoke_verbs(seat_ref)
    }
}

#[cfg(test)]
mod tests;
