//! Purposes of claims (`crates/oneiron/src/claim`).

purposes! {}

legacy_purposes! {
    /// A claim conflict packet's content address, the key of its packet row
    /// (`memory::claim_conflict::packet_digest`): plain BLAKE3, the tag's bytes (its NUL
    /// included), then the packet's stripped JSON bytes with its own id zeroed and every
    /// member's raw row cleared. Every load recomputes it.
    CONFLICT_PACKET = (Blake3, HashedFirst, "oneiron.consent_bundle.claim_conflict.v1\0");
}
