//! What an organ call proposed, checked by the host that ran it: on this
//! machine, or on another of the owner's nodes over the mesh.

use std::fmt;
use std::ops::Deref;
use std::sync::Mutex;

#[cfg(unix)]
use oneiron_organ_protocol::MappedRegion;
use oneiron_organ_protocol::{Hash32, TypedBody, Value};

use crate::budget::Kept;
use crate::receipt::CallReceipt;

/// What an organ proposed, checked by the host. Nothing here is in the vault
/// yet: the caller lands it through the write gate, or drops it.
#[derive(Debug)]
pub struct OrganOutcome {
    pub body: Option<TypedBody>,
    pub outputs: Vec<OrganOutput>,
    pub report: Value,
    pub receipt: CallReceipt,
}

/// One file an organ made, hashed by the host.
#[derive(Debug)]
pub struct OrganOutput {
    pub name: String,
    pub media_type: String,
    pub content_hash: Hash32,
    pub(crate) bytes: OutputBytes,
    /// The budget memory these bytes hold until they drop; none for bytes
    /// another node's host made.
    pub(crate) _kept: Option<Kept>,
    /// The machine's memory these bytes hold on the node that took them
    /// back from another (FIX 6196); none for bytes made here.
    pub(crate) _leased: Option<Leased>,
}

/// A lease of the machine's memory an output's bytes hold until they drop.
pub(crate) struct Leased {
    /// Never read: it goes back as the bytes drop.
    _held: Mutex<Box<dyn Send>>,
}

impl Leased {
    pub(crate) fn new(held: Box<dyn Send>) -> Self {
        Self {
            _held: Mutex::new(held),
        }
    }
}

impl fmt::Debug for Leased {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Leased")
    }
}

#[derive(Debug)]
pub(crate) enum OutputBytes {
    Inline(Vec<u8>),
    #[cfg(unix)]
    Mapped(MappedRegion),
}

impl Deref for OrganOutput {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match &self.bytes {
            OutputBytes::Inline(bytes) => bytes,
            #[cfg(unix)]
            OutputBytes::Mapped(region) => region,
        }
    }
}
