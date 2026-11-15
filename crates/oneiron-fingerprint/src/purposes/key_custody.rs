//! Purposes of key custody (`crates/oneiron/src/store/key_custody`, with its store half in
//! `oneiron-store`).

purposes! {}

legacy_purposes! {
    /// The publication policy's digest (`store::key_custody::publication_policy`): plain
    /// BLAKE3, the tag's bytes first, then each group's recovery root (a 1 and its 32 id
    /// bytes, or a 0), the world sets each as a u64-BE count and 16 bytes per world (the
    /// eligible credentials' two sets only when one is not empty), each group's admitted pad
    /// recipients after `pad-recipients` (only when a group names a world: per world its 16
    /// id bytes and a u64-BE count, per recipient its envelope recipient and its public key,
    /// each as a u64-BE length and its bytes), and the carried set's digest after
    /// `carried-world-pads` (only when one is carried). The custody log journals it in a
    /// `PublicationPolicy` frame, the `policy` record keeps it, and a head is sealed only
    /// while it is the policy in force.
    PUBLICATION_POLICY = (Blake3, HashedFirst, "oneiron/custody-publication-policy/v1");
}
