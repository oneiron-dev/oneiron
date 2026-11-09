//! The CRYPTO stream of one QUIC connection's Initials, reassembled by
//! offset until the ClientHello it opens with is whole (FIX 8991).
//!
//! Fragments may come in any order and may overlap. Where two carry bytes
//! for one offset, the bytes must agree. Only bytes a fragment carried are
//! kept, and each byte kept is held on the host-net byte floor.

use super::super::name_gate::CLIENT_HELLO;
use oneiron_container::{HostNetFloor, HostNetPermit};
use std::collections::BTreeMap;

/// Why CRYPTO reaches past the ClientHello.
pub const PAST_HELLO: &str = "the Initials carry CRYPTO data past the ClientHello";
/// Why two fragments disagree.
pub const CONFLICT: &str = "two CRYPTO frames carry different bytes for one offset";
/// Why the floor refused to hold a fragment or a datagram.
pub const BEYOND_FLOOR: &str = "the host-net byte floor cannot hold the ClientHello";

/// One connection's Initial CRYPTO stream so far.
#[derive(Default)]
pub struct CryptoStream {
    /// The bytes fragments carried, as runs by their start offset. Runs are
    /// apart: none overlaps or touches another.
    pub runs: BTreeMap<usize, Vec<u8>>,
    /// The floor room the runs hold.
    pub room: Vec<HostNetPermit>,
}

/// Whether `data`, carried at `offset`, agrees with `hello`, a ClientHello
/// already admitted: it lies inside it and carries its bytes.
pub(super) fn agrees(hello: &[u8], offset: u64, data: &[u8]) -> Result<(), &'static str> {
    let start = usize::try_from(offset).map_err(|_| PAST_HELLO)?;
    let end = start.checked_add(data.len()).ok_or(PAST_HELLO)?;
    match hello.get(start..end) {
        None => Err(PAST_HELLO),
        Some(bytes) if bytes != data => Err(CONFLICT),
        Some(_) => Ok(()),
    }
}
