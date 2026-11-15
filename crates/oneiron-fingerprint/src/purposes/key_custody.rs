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
}
