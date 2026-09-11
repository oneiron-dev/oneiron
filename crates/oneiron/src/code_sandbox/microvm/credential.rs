//! Destination allowlisting, resolution and the egress proxy that injects a credential outside the guest.

use std::{collections::BTreeMap, fmt, sync::Arc};

use rmpv::Value;

use crate::code_sandbox::SandboxCredentialHandle;
use crate::{Error, Result};

use super::backend::backend_error;
use super::handle::MicroVmHandle;
use crate::error::CodeError;

/// Guest ABI key naming the scheme of an egress destination.
pub const SANDBOX_EGRESS_ABI_KEY_SCHEME: &str = "scheme";

/// Guest ABI key naming the host of an egress destination.
pub const SANDBOX_EGRESS_ABI_KEY_HOST: &str = "host";

/// Stable name of the host-side credential proxy in diagnostics.
pub const EGRESS_PROXY_NAME: &str = "credential-egress-proxy";

/// One destination in a credential handle's allowlist, and also the shape a
/// guest egress request is parsed into.
///
/// As an allowlist entry `host_suffix` is a domain suffix; as a request it is
/// the concrete host. Matching is label-boundary aware, so `example.com` never
/// admits `notexample.com`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialDestination {
    scheme: String,
    host_suffix: String,
}

impl CredentialDestination {
    /// Creates a normalized destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the scheme or host is blank,
    /// carries control characters, or embeds path/port separators.
    pub fn new(scheme: impl Into<String>, host_suffix: impl Into<String>) -> Result<Self> {
        let scheme = scheme.into().trim().to_lowercase();
        let host_suffix = host_suffix.into().trim().trim_matches('.').to_lowercase();

        if scheme.is_empty() || host_suffix.is_empty() {
            return Err(Error::InvalidClaimBody(
                "credential destination requires a scheme and a host",
            ));
        }
        if !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return Err(Error::InvalidClaimBody(
                "credential destination scheme is not a valid URI scheme",
            ));
        }
        if host_suffix
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | ':' | '@' | '?' | '#' | ' ' | '\\'))
        {
            return Err(Error::InvalidClaimBody(
                "credential destination host must be a bare host",
            ));
        }

        Ok(Self {
            scheme,
            host_suffix,
        })
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host_suffix(&self) -> &str {
        &self.host_suffix
    }

    /// True when `self` (an allowlist entry) admits `requested`.
    #[must_use]
    pub fn matches(&self, requested: &Self) -> bool {
        self.scheme == requested.scheme
            && (requested.host_suffix == self.host_suffix
                || requested
                    .host_suffix
                    .strip_suffix(&self.host_suffix)
                    .is_some_and(|head| head.ends_with('.')))
    }
}

impl fmt::Debug for CredentialDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_suffix)
    }
}

impl fmt::Display for CredentialDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host_suffix)
    }
}

/// Per-handle destination allowlist — the confused-deputy guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialAllowlist {
    entries: BTreeMap<String, Vec<CredentialDestination>>,
}

impl CredentialAllowlist {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds one destination to a credential handle.
    pub fn allow(&mut self, handle: &SandboxCredentialHandle, destination: CredentialDestination) {
        let bound = self.entries.entry(handle.as_str().to_owned()).or_default();
        if !bound.contains(&destination) {
            bound.push(destination);
        }
    }

    /// True when `handle` is bound to a destination admitting `requested`.
    /// An unknown handle is refused: the default is deny.
    #[must_use]
    pub fn permits(
        &self,
        handle: &SandboxCredentialHandle,
        requested: &CredentialDestination,
    ) -> bool {
        self.entries
            .get(handle.as_str())
            .is_some_and(|bound| bound.iter().any(|entry| entry.matches(requested)))
    }
}

/// Resolves credential handles into injectable bytes at the egress boundary.
///
/// Implementations enforce the handle's own binding as well; the proxy's
/// allowlist check is the outer of two gates, never the only one.
pub trait CredentialResolver: Send + Sync {
    /// Resolves `handle` for injection into a request addressed to `dest`.
    ///
    /// # Errors
    ///
    /// Returns an error when the handle is unknown, revoked, or not bound to
    /// `dest`. Callers treat any error as a refusal — no injection happens.
    fn resolve_for(
        &self,
        handle: &SandboxCredentialHandle,
        dest: &CredentialDestination,
    ) -> Result<Vec<u8>>;
}

/// Host receipt for one boundary injection. Carries no secret material.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialInjection {
    vm_id: String,
    credential: SandboxCredentialHandle,
    destination: CredentialDestination,
    injected_bytes: usize,
}

impl CredentialInjection {
    #[must_use]
    pub fn vm_id(&self) -> &str {
        &self.vm_id
    }

    #[must_use]
    pub const fn credential(&self) -> &SandboxCredentialHandle {
        &self.credential
    }

    #[must_use]
    pub const fn destination(&self) -> &CredentialDestination {
        &self.destination
    }

    /// Length of the injected material. The material itself is dropped at the
    /// boundary and is never stored on the receipt.
    #[must_use]
    pub const fn injected_bytes(&self) -> usize {
        self.injected_bytes
    }
}

impl fmt::Debug for CredentialInjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjection")
            .field("vm_id", &self.vm_id)
            .field("credential", &self.credential)
            .field("destination", &self.destination)
            .field("injected_bytes", &self.injected_bytes)
            .field("material", &"<never-retained>")
            .finish()
    }
}

/// Host-owned egress proxy: allowlist enforcement plus resolve-and-inject.
///
/// The proxy is armed by the backend before any injection is possible, so a
/// VM whose transport failed to come up refuses credentials instead of
/// silently running without one.
pub struct CredentialEgressProxy {
    allowlist: CredentialAllowlist,
    resolver: Arc<dyn CredentialResolver>,
    armed: bool,
}

impl CredentialEgressProxy {
    #[must_use]
    pub fn new(allowlist: CredentialAllowlist, resolver: Arc<dyn CredentialResolver>) -> Self {
        Self {
            allowlist,
            resolver,
            armed: false,
        }
    }

    #[must_use]
    pub fn resolver(&self) -> &dyn CredentialResolver {
        self.resolver.as_ref()
    }

    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// Marks the VM-internal transport as bound and ready.
    pub const fn arm(&mut self) {
        self.armed = true;
    }

    /// Resolves, measures and scrubs `credential` at the outbound boundary.
    ///
    /// The transport that will consume resolved material lands with SECRET-02;
    /// this method retains only a secret-free receipt.
    ///
    /// The allowlist is checked BEFORE the resolver is consulted, so an
    /// off-list destination never reaches secret material. The resolved bytes
    /// are scrubbed and dropped here; only a receipt travels onward.
    ///
    /// # Errors
    ///
    /// Returns [`CodeError::MicroVmBackendError`](crate::error::CodeError::MicroVmBackendError) when the proxy is not armed,
    /// [`CodeError::MicroVmCredentialDestinationDenied`](crate::error::CodeError::MicroVmCredentialDestinationDenied) when the handle is not
    /// bound to the destination, or the resolver's own refusal.
    pub fn inject(
        &self,
        vm: &MicroVmHandle,
        credential: &SandboxCredentialHandle,
        destination: &CredentialDestination,
    ) -> Result<CredentialInjection> {
        if !self.armed {
            return Err(backend_error(
                EGRESS_PROXY_NAME,
                "credential proxy is not armed for this vm",
            ));
        }
        if !self.allowlist.permits(credential, destination) {
            return Err(Error::Code(CodeError::MicroVmCredentialDestinationDenied {
                credential: credential.as_str().to_owned(),
                scheme: destination.scheme().to_owned(),
                host: destination.host_suffix().to_owned(),
            }));
        }

        let mut material = self.resolver.resolve_for(credential, destination)?;
        if material.is_empty() {
            return Err(backend_error(
                EGRESS_PROXY_NAME,
                "credential resolver returned empty material",
            ));
        }
        let injected_bytes = material.len();
        // Material is resolved, measured and scrubbed at this boundary. The
        // outbound transport lands with SECRET-02; bytes never travel guest-ward.
        for byte in &mut material {
            // SAFETY: `byte` is a valid, uniquely borrowed element of `material`.
            // Volatile writes prevent the scrub from being elided as a dead store.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        drop(material);

        Ok(CredentialInjection {
            vm_id: vm.id().to_owned(),
            credential: credential.clone(),
            destination: destination.clone(),
            injected_bytes,
        })
    }
}

impl fmt::Debug for CredentialEgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialEgressProxy")
            .field("allowlist", &self.allowlist)
            .field("armed", &self.armed)
            .field("resolver", &"<host-only>")
            .finish()
    }
}

/// Parses the egress destination a guest paired with its credential handle.
///
/// # Errors
///
/// Returns [`Error::InvalidClaimBody`] when the call carries no usable
/// destination — an unaddressed credential call is refused, never resolved.
pub fn egress_destination_from_args(args: &Value) -> Result<CredentialDestination> {
    let Value::Map(entries) = args else {
        return Err(Error::InvalidClaimBody(
            "sandbox credential call args must be a map",
        ));
    };
    let scheme = abi_str(entries, SANDBOX_EGRESS_ABI_KEY_SCHEME).ok_or(Error::InvalidClaimBody(
        "sandbox credential call must name a destination scheme",
    ))?;
    let host = abi_str(entries, SANDBOX_EGRESS_ABI_KEY_HOST).ok_or(Error::InvalidClaimBody(
        "sandbox credential call must name a destination host",
    ))?;
    CredentialDestination::new(scheme, host)
}

fn abi_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
}
