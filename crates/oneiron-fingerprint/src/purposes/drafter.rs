//! Purposes of the drafter (`crates/oneiron/src/drafter`; FIX 12569).
//!
//! A drafter version pins its target, kept examples, held-out families, spec and load set
//! by the BLAKE3 of each one's sorted JSON. Versions store the pins, a binding is keyed by
//! its target's pin, and serving takes the load-set pin again over the files it loads and
//! compares it with the stored one. So they keep their bytes (K, PLAN-UC-04 stage 6.4a).

purposes! {}

legacy_purposes! {
    /// A drafter pin (`drafter::hash_json`, through `training_pack::pin::pin_digest`): plain
    /// BLAKE3 of the value's sorted JSON, with no tag or length, as a training pin; kept as
    /// 32 raw bytes. A value holding a non-finite float has no pin.
    PIN = (Blake3, NotHashed, "oneiron.drafter.pin.v1");
}
