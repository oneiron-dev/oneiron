//! Purposes of runtime hooks (`crates/oneiron/src/runtime_hooks`).
//!
//! Each fact a hook binding takes has an input hash, and a hook run's key starts with it:
//! the key keeps the run's memo, intent, receipt and index rows, so a run is taken once per
//! binding and fact. A run's memo stores the input hash and the run's params digest too.
//! So each keeps its bytes (K, PLAN-UC-04 stage 6.3).

purposes! {}

legacy_purposes! {
    /// A released tick's input hash (`runtime_hooks::source::schedule`): BLAKE3 derive-key
    /// with the tag as the context, then the TASK's 16 id bytes and its due time as a
    /// u64-BE, with no lengths. The release time is not hashed.
    TICK_INPUT = (Blake3, DeriveKeyContext, "oneiron.hook-tick.v1");

    /// A settled proposal's input hash (`runtime_hooks::source::settlement`): BLAKE3
    /// derive-key, then the proposal's 16 id bytes, the outcome's and the kind's one-byte
    /// discriminants, the settler's 16 id bytes and the 32-byte body hash (zeros when the
    /// proposal had no body). The settle time is not hashed.
    SETTLEMENT_INPUT = (Blake3, DeriveKeyContext, "oneiron.hook-settlement.v1");

    /// An admitted inbound event's input hash (`runtime_hooks::source::surface_inbound`):
    /// BLAKE3 derive-key, then the 16 attempt bytes, the receiving identity's and the
    /// actor's 16 id bytes, the connector, channel and action each as a u64-BE length and
    /// its bytes, and the receive time as a u64-BE. The admission time is not hashed.
    SURFACE_INBOUND_INPUT = (Blake3, DeriveKeyContext, "oneiron.hook-surface-inbound.v1");

    /// A hook run's params digest (`runtime_hooks::store`): plain BLAKE3 of the binding's
    /// selector JSON, then the binding's 16 id bytes, with no tag or lengths; written as 64
    /// lowercase hex digits. The run key's envelope carries it, and a run's memo stores it
    /// as its derivation's selector hash.
    RUN_PARAMS = (Blake3, NotHashed, "oneiron.runtime_hooks.run_params.v1");

    /// A hook run's key (`runtime_hooks::store::run_key`): BLAKE3 derive-key, then the
    /// derivation envelope's JSON, the fact source's one-byte tag and the position's bytes.
    RUN_KEY = (Blake3, DeriveKeyContext, "oneiron.hook-run-key.v1");
}
