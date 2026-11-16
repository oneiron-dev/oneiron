//! Purposes of the vault shape (`crates/oneiron/src/vault_shape`).
//!
//! Both digests feed the reach rows (`vault_shape::reach::ReachRows::hash_into`): `reach`
//! and a NUL; each roster actor's id, its agent id (a u64 big-endian length and its bytes)
//! and one byte for `enabled`; a NUL, then each standing grant's bound digest; a NUL, then
//! each sending identity's id, its actor, its channel and address (each framed) and one
//! byte for whether it may send; a NUL, then each connector tool's key, a presence byte
//! and its actor, the count of excepted actors (u64 big-endian) and each one, its
//! connector and tool (each framed), its slate setting's name and one byte for `held`; a
//! NUL, then each standing outbound grant's id and its stored row's digest.

purposes! {}

legacy_purposes! {
    /// A shape plan's frontier (`vault_shape::plan::frontier`). Plain BLAKE3, the tag
    /// first; the seed's digest; the policy read-frontier; each live row's MessagePack
    /// (named fields) as a u64 big-endian length and its bytes, then its entity's hex (empty
    /// when none); the reach rows. Its hex is the plan's `frontier`, which apply compares
    /// with the vault's before it writes.
    FRONTIER = (Blake3, HashedFirst, "oneiron.vault_shape.frontier.v1\0");

    /// The dependencies a waiting approval stands on
    /// (`vault_shape::approval::approval_dependencies`). Plain BLAKE3, the tag first; the
    /// policy read-frontier; the reach rows. Its hex is the apply journal item's pin,
    /// `ShapeApprovalDependencies.digest`, compared before an approval lands.
    APPROVAL_DEPENDENCIES = (Blake3, HashedFirst, "oneiron.vault_shape.approval.v1\0");
}
