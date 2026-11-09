//! Lifted half of `oneiron::code_sandbox::microvm::credential` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::microvm::credential::*;
#[allow(unused_imports)]
use crate::ext::*;
use std::sync::Arc;
use crate::code_sandbox::SandboxCredentialHandle;
use crate::Error;
use crate::Result;
use super::backend::backend_error;
use super::handle::MicroVmHandle;
use crate::error::CodeError;

/// Methods of [`CredentialDestination`] that moved out of `oneiron` with `code_sandbox::microvm::credential` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmCredentialCredentialDestinationExt {
    /// Creates a normalized destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the scheme or host is blank,
    /// carries control characters, or embeds path/port separators.
    fn new(scheme: impl Into<String>, host_suffix: impl Into<String>) -> Result<Self>;
    /// True when `self` (an allowlist entry) admits `requested`.
    #[must_use]
    fn matches(&self, requested: &Self) -> bool;
}

impl CodeSandboxMicrovmCredentialCredentialDestinationExt for CredentialDestination {
    /// Creates a normalized destination.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidClaimBody`] when the scheme or host is blank,
    /// carries control characters, or embeds path/port separators.
    fn new(scheme: impl Into<String>, host_suffix: impl Into<String>) -> Result<Self> {
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

    /// True when `self` (an allowlist entry) admits `requested`.
    #[must_use]
    fn matches(&self, requested: &Self) -> bool {
            self.scheme == requested.scheme
                && (requested.host_suffix == self.host_suffix
                    || requested
                        .host_suffix
                        .strip_suffix(&self.host_suffix)
                        .is_some_and(|head| head.ends_with('.')))
        }
}

/// Methods of [`CredentialAllowlist`] that moved out of `oneiron` with `code_sandbox::microvm::credential` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmCredentialCredentialAllowlistExt {
    #[must_use]
    fn new() -> Self;
    /// Binds one destination to a credential handle.
    fn allow(&mut self, handle: &SandboxCredentialHandle, destination: CredentialDestination);
    /// True when `handle` is bound to a destination admitting `requested`.
    /// An unknown handle is refused: the default is deny.
    #[must_use]
    fn permits(
        &self,
        handle: &SandboxCredentialHandle,
        requested: &CredentialDestination,
    ) -> bool;
}

impl CodeSandboxMicrovmCredentialCredentialAllowlistExt for CredentialAllowlist {
    #[must_use]
    fn new() -> Self {
            Self::default()
        }

    /// Binds one destination to a credential handle.
    fn allow(&mut self, handle: &SandboxCredentialHandle, destination: CredentialDestination) {
            let bound = self.entries.entry(handle.as_str().to_owned()).or_default();
            if !bound.contains(&destination) {
                bound.push(destination);
            }
        }

    /// True when `handle` is bound to a destination admitting `requested`.
    /// An unknown handle is refused: the default is deny.
    #[must_use]
    fn permits(
            &self,
            handle: &SandboxCredentialHandle,
            requested: &CredentialDestination,
        ) -> bool {
            self.entries
                .get(handle.as_str())
                .is_some_and(|bound| bound.iter().any(|entry| entry.matches(requested)))
        }
}

/// Methods of [`CredentialInjection`] that moved out of `oneiron` with `code_sandbox::microvm::credential` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmCredentialCredentialInjectionExt {
    #[must_use]
    fn vm_id(&self) -> &str;
    #[must_use]
    fn credential(&self) -> &SandboxCredentialHandle;
    #[must_use]
    fn destination(&self) -> &CredentialDestination;
    /// Length of the injected material. The material itself is dropped at the
    /// boundary and is never stored on the receipt.
    #[must_use]
    fn injected_bytes(&self) -> usize;
}

impl CodeSandboxMicrovmCredentialCredentialInjectionExt for CredentialInjection {
    #[must_use]
    fn vm_id(&self) -> &str {
            &self.vm_id
        }

    #[must_use]
    fn credential(&self) -> &SandboxCredentialHandle {
            &self.credential
        }

    #[must_use]
    fn destination(&self) -> &CredentialDestination {
            &self.destination
        }

    /// Length of the injected material. The material itself is dropped at the
    /// boundary and is never stored on the receipt.
    #[must_use]
    fn injected_bytes(&self) -> usize {
            self.injected_bytes
        }
}

/// Methods of [`CredentialEgressProxy`] that moved out of `oneiron` with `code_sandbox::microvm::credential` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxMicrovmCredentialCredentialEgressProxyExt {
    #[must_use]
    fn new(allowlist: CredentialAllowlist, resolver: Arc<dyn CredentialResolver>) -> Self;
    #[must_use]
    fn resolver(&self) -> &dyn CredentialResolver;
    #[must_use]
    fn is_armed(&self) -> bool;
    /// Marks the VM-internal transport as bound and ready.
    fn arm(&mut self);
    /// Performs one allowlisted, read-only egress operation outside the guest.
    /// Material is scrubbed on success AND refusal. The guest gets no secret,
    /// request headers, host exception text, or reflected response body.
    fn forward_read(
        &self,
        vm: &MicroVmHandle,
        call: &crate::code_sandbox::SandboxCredentialCall,
        transport: &dyn CredentialReadTransport,
    ) -> Result<CredentialInjection>;
    /// Records a credential read refused for lack of transport, as metadata
    /// only. Never resolves or calls transport.
    fn record_transport_unavailable(
        &self,
        vm: &MicroVmHandle,
        call: &crate::code_sandbox::SandboxCredentialCall,
    );
}

impl CodeSandboxMicrovmCredentialCredentialEgressProxyExt for CredentialEgressProxy {
    #[must_use]
    fn new(allowlist: CredentialAllowlist, resolver: Arc<dyn CredentialResolver>) -> Self {
            Self {
                allowlist,
                resolver,
                armed: false,
                credential_relay: None,
            }
        }

    #[must_use]
    fn resolver(&self) -> &dyn CredentialResolver {
            self.resolver.as_ref()
        }

    #[must_use]
    fn is_armed(&self) -> bool {
            self.armed
        }

    /// Marks the VM-internal transport as bound and ready.
    fn arm(&mut self) {
            self.armed = true;
        }

    /// Performs one allowlisted, read-only egress operation outside the guest.
    /// Material is scrubbed on success AND refusal. The guest gets no secret,
    /// request headers, host exception text, or reflected response body.
    fn forward_read(
            &self,
            vm: &MicroVmHandle,
            call: &crate::code_sandbox::SandboxCredentialCall,
            transport: &dyn CredentialReadTransport,
        ) -> Result<CredentialInjection> {
            let destination = match egress_destination_from_args(call.args()) {
                Ok(destination) => destination,
                Err(error) => {
                    self.emit_credential(
                        vm.id(),
                        call.credential().as_str(),
                        Some(call.operation().as_str()),
                        Some(call.operation().effect().as_str()),
                        None,
                        None,
                        oneiron_container::CredentialEgressStatus::InvalidDestination,
                        None,
                    );
                    return Err(error);
                }
            };
            let credential = call.credential();
            let (outcome, status) = (|| {
                if !self.armed {
                    return (
                        Err(backend_error(
                            EGRESS_PROXY_NAME,
                            "credential proxy is not armed",
                        )),
                        oneiron_container::CredentialEgressStatus::Unarmed,
                    );
                }
                if !self.allowlist.permits(credential, &destination) {
                    return (
                        Err(Error::Code(CodeError::MicroVmCredentialDestinationDenied {
                            credential: credential.as_str().to_owned(),
                            scheme: destination.scheme().to_owned(),
                            host: destination.host_suffix().to_owned(),
                        })),
                        oneiron_container::CredentialEgressStatus::AllowlistDenied,
                    );
                }
                let material = match self.resolver.resolve_for(credential, &destination) {
                    Ok(material) => SecretMaterial(material),
                    Err(error) => {
                        return (
                            Err(error),
                            oneiron_container::CredentialEgressStatus::ResolverFailed,
                        );
                    }
                };
                if material.0.is_empty() {
                    return (
                        Err(backend_error(
                            EGRESS_PROXY_NAME,
                            "credential resolver returned empty material",
                        )),
                        oneiron_container::CredentialEgressStatus::EmptyMaterial,
                    );
                }
                let injected_bytes = material.0.len();
                match transport.read(&destination, call.operation(), call.args(), &material.0) {
                    Ok(()) => (
                        Ok(injected_bytes),
                        oneiron_container::CredentialEgressStatus::Forwarded,
                    ),
                    Err(error) => (
                        Err(error),
                        oneiron_container::CredentialEgressStatus::TransportFailed,
                    ),
                }
            })();
            let material_bytes = match &outcome {
                Ok(bytes) if status == oneiron_container::CredentialEgressStatus::Forwarded => {
                    Some(*bytes)
                }
                _ => None,
            };
            self.emit_credential(
                vm.id(),
                credential.as_str(),
                Some(call.operation().as_str()),
                Some(call.operation().effect().as_str()),
                Some(destination.scheme()),
                Some(destination.host_suffix()),
                status,
                material_bytes,
            );
            match outcome {
                Ok(injected_bytes) => Ok(CredentialInjection {
                    vm_id: vm.id().to_owned(),
                    credential: credential.clone(),
                    destination,
                    injected_bytes,
                }),
                Err(error) => Err(error),
            }
        }

    /// Records a credential read refused for lack of transport, as metadata
    /// only. Never resolves or calls transport.
    fn record_transport_unavailable(
            &self,
            vm: &MicroVmHandle,
            call: &crate::code_sandbox::SandboxCredentialCall,
        ) {
            let destination = egress_destination_from_args(call.args()).ok();
            self.emit_credential(
                vm.id(),
                call.credential().as_str(),
                Some(call.operation().as_str()),
                Some(call.operation().effect().as_str()),
                destination.as_ref().map(|dest| dest.scheme()),
                destination.as_ref().map(|dest| dest.host_suffix()),
                oneiron_container::CredentialEgressStatus::TransportUnavailable,
                None,
            );
        }
}

// The scope guard also scrubs on a transport error or unwind.
struct SecretMaterial(Vec<u8>);

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // SAFETY: each byte is a valid uniquely borrowed element.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
