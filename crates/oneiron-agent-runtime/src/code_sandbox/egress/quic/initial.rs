//! Lifted half of `oneiron::code_sandbox::egress::quic::initial` (core split, `oneiron-agent-runtime`): the items below moved out of
//! `oneiron`; the items that stay there are re-exported here, so paths in this crate resolve as before.

pub use oneiron::code_sandbox::egress::quic::initial::*;
#[allow(unused_imports)]
use crate::ext::*;

/// Methods of [`Version`] that moved out of `oneiron` with `code_sandbox::egress::quic::initial` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressQuicInitialVersionExt {
    /// The version a long header's version field names, if the gate knows
    /// it. Version 0 is Version Negotiation.
    fn from_wire(version: u32) -> Option<Self>;
}

impl CodeSandboxEgressQuicInitialVersionExt for Version {
    /// The version a long header's version field names, if the gate knows
    /// it. Version 0 is Version Negotiation.
    fn from_wire(version: u32) -> Option<Self> {
            match version {
                0x0000_0001 => Some(Self::One),
                0x6b33_43cf => Some(Self::Two),
                _ => None,
            }
        }
}

/// Methods of [`Reader`] that moved out of `oneiron` with `code_sandbox::egress::quic::initial` (core split):
/// an inherent impl stays in its type's crate, so here they are an extension trait.
pub trait CodeSandboxEgressQuicInitialReaderExt<'a> {
    fn new(bytes: &'a [u8]) -> Self;
    fn is_empty(&self) -> bool;
    fn take(&mut self, len: usize) -> Option<&'a [u8]>;
    fn u8(&mut self) -> Option<u8>;
    fn u32(&mut self) -> Option<u32>;
    /// An ACK frame's fields after its type (RFC 9000 19.3).
    fn ack(&mut self, ecn: bool) -> Option<()>;
}

impl<'a> CodeSandboxEgressQuicInitialReaderExt<'a> for Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, at: 0 }
        }

    fn is_empty(&self) -> bool {
            self.at >= self.bytes.len()
        }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            let end = self.at.checked_add(len)?;
            let taken = self.bytes.get(self.at..end)?;
            self.at = end;
            Some(taken)
        }

    fn u8(&mut self) -> Option<u8> {
            self.take(1).map(|bytes| bytes[0])
        }

    fn u32(&mut self) -> Option<u32> {
            let bytes = self.take(4)?;
            Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

    /// An ACK frame's fields after its type (RFC 9000 19.3).
    fn ack(&mut self, ecn: bool) -> Option<()> {
            // Largest Acknowledged and ACK Delay.
            self.varint()?;
            self.varint()?;
            let ranges = self.varint()?;
            // First ACK Range, then each Gap and ACK Range Length.
            self.varint()?;
            for _ in 0..ranges {
                self.varint()?;
                self.varint()?;
            }
            if ecn {
                for _ in 0..3 {
                    self.varint()?;
                }
            }
            Some(())
        }
}
