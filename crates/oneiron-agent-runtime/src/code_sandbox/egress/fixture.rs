//! Lifted half of `oneiron::code_sandbox::egress::fixture` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::fixture::*;
#[allow(unused_imports)]
use crate::ext::*;
use super::*;

/// Methods of [`FixtureForward`] that moved out of `oneiron` with `code_sandbox::egress::fixture` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressFixtureFixtureForwardExt {
    /// The bench forward target rule (CALLS, FIX 8061): one numeric unicast
    /// IPv4 address off the host's loopback, with a nonzero port. The host's
    /// own loopback services, a fixture's private one among them, stay out
    /// of reach.
    ///
    /// # Errors
    /// Names the rule `target` breaks.
    fn new(target: SocketAddrV4) -> Result<Self, FixtureForwardError>;
    /// The upstream's address and port.
    #[must_use]
    const fn target(self) -> SocketAddrV4;
}

impl CodeSandboxEgressFixtureFixtureForwardExt for FixtureForward {
    /// The bench forward target rule (CALLS, FIX 8061): one numeric unicast
    /// IPv4 address off the host's loopback, with a nonzero port. The host's
    /// own loopback services, a fixture's private one among them, stay out
    /// of reach.
    ///
    /// # Errors
    /// Names the rule `target` breaks.
    fn new(target: SocketAddrV4) -> Result<Self, FixtureForwardError> {
            let address = target.ip();
            if address.is_loopback() {
                return Err(FixtureForwardError::Loopback);
            }
            if address.is_unspecified() {
                return Err(FixtureForwardError::Unspecified);
            }
            if address.is_multicast() {
                return Err(FixtureForwardError::Multicast);
            }
            if address.is_broadcast() {
                return Err(FixtureForwardError::Broadcast);
            }
            if target.port() == 0 {
                return Err(FixtureForwardError::ZeroPort);
            }
            Ok(Self(target))
        }

    /// The upstream's address and port.
    #[must_use]
    const fn target(self) -> SocketAddrV4 {
            self.0
        }
}
