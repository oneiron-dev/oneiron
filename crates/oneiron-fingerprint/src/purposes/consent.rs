//! Purposes of consent (`oneiron-store`'s `consent_bound` and `crates/oneiron/src/consent`).

purposes! {}

legacy_purposes! {
    /// A grant bound's digest (`consent_bound::GrantBound::digest`). BLAKE3: the tag first;
    /// the domain; the subject (`actor`, the actor ref, then a presence byte and the actor
    /// class; or `audience`, the member count and each member); `class` and the class; the
    /// envelope (`envelope:disclosure`, the selector count and each selector, then a presence
    /// byte and the contact scope; or `envelope:action`, the selector count and each selector,
    /// a presence byte and the target, a presence byte and the budget (u64 big-endian), the
    /// receipt flag (one byte)). Every string is framed by its length and every count is
    /// written, each as a u64 big-endian. The contact scope writes `contact-scope-v1`, then for
    /// worlds, bands, audience and verbs one byte (0 bottom, 1 all, 2 some) and, for some, the
    /// count and each value, then the sensitivity ceiling as one byte (0 bottom, 1 public to 4
    /// restricted); never the facets. Its hex is the standing grant's row key and the
    /// standing-grant receipt's `diff_handle`, compared at each reuse.
    BOUND_DIGEST = (Blake3, HashedFirst, "oneiron.consent.bound_digest.v2\0");

    /// A composed effect's digest (`consent::effect::ComposedEffect::digest`). BLAKE3: the tag
    /// first; the operation kind; four bytes (fires hooks, triggers publish, external
    /// observers, undo fidelity 0 full to 3 unknown); the blast radius (u64 big-endian); the
    /// catastrophe class name (empty when none); the disclosure and then the action
    /// requirement's bound digest (each empty when none); then, only when the op has a place or
    /// is an erase, `place`, the project and the thread ids (each empty when none) and the
    /// erase flag (one byte). Every field but the bytes and the blast radius is framed by its
    /// length as a u64 big-endian. Approve-once markers, standing-grant use receipts and code
    /// consent waits store it.
    EFFECT_DIGEST = (Blake3, HashedFirst, "oneiron.consent.effect_digest.v1\0");
}
