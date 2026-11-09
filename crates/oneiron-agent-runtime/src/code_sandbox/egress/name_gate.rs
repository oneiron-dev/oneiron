//! Lifted half of `oneiron::code_sandbox::egress::name_gate` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::name_gate::*;
#[allow(unused_imports)]
use crate::ext::*;
use super::*;

/// Methods of [`EgressNameRefusal`] that moved out of `oneiron` with `code_sandbox::egress::name_gate` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressNameGateEgressNameRefusalExt {
    /// The refusal's stable reason.
    #[must_use]
    fn reason(&self) -> &'static str;
    /// The address and port the refused stream was connected to.
    #[must_use]
    fn target(&self) -> SocketAddr;
}

impl CodeSandboxEgressNameGateEgressNameRefusalExt for EgressNameRefusal {
    /// The refusal's stable reason.
    #[must_use]
    fn reason(&self) -> &'static str {
            match self {
                Self::Unverifiable { .. } => "egress_name_unverifiable",
                Self::Ungranted { .. } => "egress_name_ungranted",
            }
        }

    /// The address and port the refused stream was connected to.
    #[must_use]
    fn target(&self) -> SocketAddr {
            match self {
                Self::Unverifiable { target, .. } | Self::Ungranted { target, .. } => *target,
            }
        }
}

/// Methods of [`Fields`] that moved out of `oneiron` with `code_sandbox::egress::name_gate` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressNameGateFieldsExt<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]>;
    fn u16(&mut self) -> Option<u16>;
}

impl<'a> CodeSandboxEgressNameGateFieldsExt<'a> for Fields<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            let (head, rest) = self.0.split_at_checked(len)?;
            self.0 = rest;
            Some(head)
        }

    fn u16(&mut self) -> Option<u16> {
            self.take(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        }
}
