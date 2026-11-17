//! Legacy Gate digests that existing bindings hold.
//!
//! A standing outbound grant's binding and a witnessed MESSAGE write's binding
//! retain their exact bytes through the K door (K, PLAN-UC-04 stage 7).

purposes! {}

legacy_purposes! {
    /// Standing outbound grant binding: the domain
    /// `oneiron.gate.standing_outbound_grant.v0`, the principal, the origin's
    /// component and action, the origin receipt (1 and the ref, or 0) and the
    /// scope's name and fields, each string (the domain too) after its u64-LE
    /// byte length; no hashed tag (the tag is a registry name only).
    STANDING_OUTBOUND_GRANT = (Sha256, NotHashed, "oneiron.gate.standing_outbound_grant_binding.v1");

    /// Witnessed MESSAGE write: the tag with no length before it, then the
    /// actor's class, the actor's 16-byte entity ref, the body's u64-LE byte
    /// length and the canonical body bytes. The binding of one authorized
    /// MESSAGE write's whole envelope.
    WITNESS_MESSAGE = (Sha256, HashedFirst, "oneiron.gate.witness_message.v1");
}
