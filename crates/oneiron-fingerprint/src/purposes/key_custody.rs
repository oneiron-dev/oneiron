//! Purposes of key custody (`crates/oneiron/src/store/key_custody`, with its store half in
//! `oneiron-store`).

purposes! {}

legacy_purposes! {
    /// A compartment's commitment in its head's control compartment
    /// (`store::key_custody::head::carried_pads::wire_digest`): BLAKE3 derive-key with the
    /// tag as the context, over the canonical encoding (`rmp_serde::to_vec_named`) of the
    /// compartment's whole wire. The control compartment's digest root covers it, and a
    /// head whose compartments do not match the root is refused.
    COMPARTMENT_DIGEST = (Blake3, DeriveKeyContext, "oneiron/custody-head/compartment-digest/v2");

    /// A carried compartment's commitment (`store::key_custody::head::carried_pads`), as
    /// [`COMPARTMENT_DIGEST`] over the carried wire: the digest root covers it, and the
    /// publication policy's carried-set digest hashes it.
    CARRIED_DIGEST = (Blake3, DeriveKeyContext, "oneiron/custody-head/carried-digest/v2");

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
