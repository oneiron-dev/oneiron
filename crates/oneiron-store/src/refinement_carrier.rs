//! Raw refinement carrier framing used by value scans.

pub const MAGIC: &[u8] = b"oneiron.refinement-receipt.v1\0";

/// The receipt JSON a carrier wraps behind its magic and ids, for the
/// credential scans: read whether or not the carrier is canonical.
pub fn refinement_carrier_payload(bytes: &[u8]) -> Option<&[u8]> {
    bytes.strip_prefix(MAGIC)?.get(32..)
}
