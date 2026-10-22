//! A native call's input region: the conversation's bytes copied once into
//! an immutable shared region (`oneiron_organ_protocol::SharedRegion`: a
//! memfd sealed against write, grow and shrink on Linux, a read-only POSIX
//! shared-memory object elsewhere), whose one descriptor rides on the call's
//! `generate` frame.
//!
//! The host's descriptor lives until the worker has answered `accepted` or
//! `refused`; the copy the kernel passed is the worker's to map, read and
//! close. Nothing here maps the region, and nothing caps its size.
use std::io;
use std::os::fd::BorrowedFd;

use oneiron_organ_protocol::SharedRegion;

/// One call's input, ready to send.
pub(super) struct InputRegion {
    region: SharedRegion,
}

impl InputRegion {
    /// A region holding `bytes`, which are never empty: a conversation is
    /// at least `{}`.
    pub(super) fn new(bytes: &[u8]) -> io::Result<Self> {
        Ok(Self {
            region: SharedRegion::from_bytes(bytes)?,
        })
    }

    /// The region's length, as its description names it.
    pub(super) fn len(&self) -> u64 {
        self.region.len()
    }

    /// The descriptor to pass.
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.region.fd()
    }
}
