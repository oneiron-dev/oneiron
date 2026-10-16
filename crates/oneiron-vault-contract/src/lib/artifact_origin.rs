//! The artifact origin's naming and forwarding contract (OF-356, ARCH-0078).
//!
//! A vault's published artifacts are served on an origin apart from its API:
//! `<vault>.<domain>/<artifact>/…` for the vault, and `<app>--<vault>.<domain>/…`
//! for one app on an origin of its own. Which domains exist, their DNS and
//! their certificates are the cloud's: the engine takes the domains as
//! configuration and names none itself.
//!
//! Forwarding: a front sends each request for a name under one of its domains
//! to the named vault's artifact listener (a managed vault's
//! `--artifact-http-socket`, or [`crate::vm::VM_ARTIFACT_PORT`] in a vault VM),
//! with the request's own `Host` (or `:authority`), path, query and
//! credentials unchanged. The listener picks the vault and the app from that
//! authority alone and never reads a forwarded-host header, so nothing a
//! client sends can steer a request to another vault. A name that serves
//! nothing answers as a forbidden artifact does.

use crate::valid_vault_name;

/// Joins an app to its vault in one label: `<app>--<vault>`.
pub const APP_SEPARATOR: &str = "--";

/// One name under an artifact domain: a vault, and an app of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHost {
    pub vault: String,
    pub app: Option<String>,
}

/// Where a host falls among the artifact domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactHostRead {
    /// Under no artifact domain: not the artifact origin's to answer.
    Outside,
    /// Under a domain, naming a vault (and maybe an app).
    Named(ArtifactHost),
    /// Under a domain, naming nothing: the bare domain, a deeper name, or a
    /// label that is not one.
    Unnamed,
}

/// An app label: a DNS label that holds no [`APP_SEPARATOR`].
#[must_use]
pub fn valid_app_label(label: &str) -> bool {
    valid_vault_name(label) && !label.contains(APP_SEPARATOR)
}

/// A domain as both sides compare it: trimmed, without its edge dots, lower
/// case.
#[must_use]
pub fn normalize_artifact_domain(domain: &str) -> String {
    domain.trim().trim_matches('.').to_ascii_lowercase()
}

impl ArtifactHost {
    /// The vault's own origin.
    #[must_use]
    pub fn vault(vault: impl Into<String>) -> Self {
        Self {
            vault: vault.into(),
            app: None,
        }
    }

    /// The host name under `domain`. `None` when the vault is not a DNS label
    /// free of [`APP_SEPARATOR`], the app is not an app label, or the joined
    /// label passes 63 bytes.
    #[must_use]
    pub fn name(&self, domain: &str) -> Option<String> {
        let domain = normalize_artifact_domain(domain);
        if domain.is_empty() || !valid_app_label(&self.vault) {
            return None;
        }
        let label = match &self.app {
            None => self.vault.clone(),
            Some(app) if valid_app_label(app) => format!("{app}{APP_SEPARATOR}{}", self.vault),
            Some(_) => return None,
        };
        (label.len() <= 63).then(|| format!("{label}.{domain}"))
    }

    /// Reads `host` (a port and a trailing dot are dropped, case is ignored)
    /// against `domains`.
    #[must_use]
    pub fn read(host: &str, domains: &[String]) -> ArtifactHostRead {
        let host = normalize_host(host);
        for domain in domains
            .iter()
            .map(|domain| normalize_artifact_domain(domain))
        {
            if domain.is_empty() {
                continue;
            }
            if host == domain {
                return ArtifactHostRead::Unnamed;
            }
            let Some(label) = host
                .strip_suffix(domain.as_str())
                .and_then(|rest| rest.strip_suffix('.'))
            else {
                continue;
            };
            if label.contains('.') {
                return ArtifactHostRead::Unnamed;
            }
            let named = match label.split_once(APP_SEPARATOR) {
                None => Some(Self::vault(label)),
                Some((app, vault)) => {
                    (valid_app_label(app) && valid_app_label(vault)).then(|| Self {
                        vault: vault.to_owned(),
                        app: Some(app.to_owned()),
                    })
                }
            };
            return match named {
                Some(named) if valid_app_label(&named.vault) => ArtifactHostRead::Named(named),
                _ => ArtifactHostRead::Unnamed,
            };
        }
        ArtifactHostRead::Outside
    }
}

/// `host` without a port or a trailing dot, in lower case.
fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            name
        }
        _ => host,
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}
